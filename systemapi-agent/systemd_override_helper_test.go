package main

// Tests for the privilege-separated systemd drop-in override helper
// (systemd_override_helper.go), shared by sys:tweak resource-limit-set and
// unit-override-set.
//
// Threats exercised: the helper must not trust the caller. These tests prove it
// refuses a bad unit name, an out-of-set resource limit or bad value, a bad
// override name, oversized/null override content, a content hash that does not
// match the signed lease, and an unknown kind, even when the request
// file asks for them; that it rebuilds the resource-limit body itself (never
// writing a caller-supplied limit body); that the drop-in path always lands
// under /etc/systemd/system; that the handoff is one-shot and cleans up; and
// that refusals happen at the agent gate before any handoff. No test writes a
// real drop-in: the write seam (overrideHelperWrite) is replaced.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func withOverrideHelperStateDir(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "override-helper")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	prev := overrideHelperStateDir
	overrideHelperStateDir = dir
	t.Cleanup(func() { overrideHelperStateDir = prev })
	return dir
}

func withFakeOverrideWrite(t *testing.T, err error) *[][2]string {
	t.Helper()
	var calls [][2]string
	prev := overrideHelperWrite
	overrideHelperWrite = func(path, content string) error {
		calls = append(calls, [2]string{path, content})
		return err
	}
	t.Cleanup(func() { overrideHelperWrite = prev })
	return &calls
}

func writeOverrideReqFile(t *testing.T, dir, id string, req overrideHelperReq) {
	t.Helper()
	b, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, id+".req"), b, 0o600); err != nil {
		t.Fatal(err)
	}
}

func readOverrideResFile(t *testing.T, dir, id string) overrideHelperRes {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, id+".res"))
	if err != nil {
		t.Fatalf("read result: %v", err)
	}
	var res overrideHelperRes
	if err := json.Unmarshal(b, &res); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}
	return res
}

// unitOverrideReq builds a request with no lease, for refusals that must
// happen on shape alone (before any lease check).
func unitOverrideReq(unit, name, content string) overrideHelperReq {
	return overrideHelperReq{Kind: overrideKindUnit, Unit: unit, Name: name, Content: content}
}

// signOverrideReq attaches a valid sys_tweak lease for req's exact fields.
func signOverrideReq(t *testing.T, req overrideHelperReq) overrideHelperReq {
	t.Helper()
	priv := newHelperSigner(t)
	var payload string
	var err error
	if req.Kind == overrideKindLimit {
		payload, err = sysTweakLeasePayload("resource-limit-set", "", req.Value, req.Unit, req.Limit, "", "")
	} else {
		payload, err = sysTweakLeasePayload("unit-override-set", "", "", req.Unit, "", req.Name, sysSHA256Hex(req.Content))
	}
	if err != nil {
		t.Fatal(err)
	}
	req.Lease = signLease(t, priv, ptyTestHost, "sys_tweak", payload, inFuture(time.Minute))
	return req
}

func TestOverrideHelperWritesResourceLimit(t *testing.T) {
	dir := withOverrideHelperStateDir(t)
	calls := withFakeOverrideWrite(t, nil)
	writeOverrideReqFile(t, dir, testHelperID, signOverrideReq(t, overrideHelperReq{
		Kind: overrideKindLimit, Unit: "nginx.service", Limit: "LimitNOFILE", Value: "65536",
	}))
	if code := runOverrideHelper([]string{testHelperID}); code != 0 {
		t.Fatalf("exit=%d, want 0", code)
	}
	res := readOverrideResFile(t, dir, testHelperID)
	if !res.OK || res.Error != "" {
		t.Fatalf("result=%+v, want ok", res)
	}
	// The helper rebuilt the body and the path itself.
	wantPath := "/etc/systemd/system/nginx.service.d/limit-limitnofile.conf"
	wantBody := "[Service]\nLimitNOFILE=65536\n"
	if len(*calls) != 1 || (*calls)[0][0] != wantPath || (*calls)[0][1] != wantBody {
		t.Fatalf("write calls=%v", *calls)
	}
}

func TestOverrideHelperWritesUnitOverride(t *testing.T) {
	dir := withOverrideHelperStateDir(t)
	calls := withFakeOverrideWrite(t, nil)
	content := "[Service]\nLimitNOFILE=65536\n"
	writeOverrideReqFile(t, dir, testHelperID, signOverrideReq(t, unitOverrideReq("nginx.service", "limit-nofile", content)))
	if code := runOverrideHelper([]string{testHelperID}); code != 0 {
		t.Fatalf("exit=%d, want 0", code)
	}
	res := readOverrideResFile(t, dir, testHelperID)
	if !res.OK || res.Error != "" {
		t.Fatalf("result=%+v, want ok", res)
	}
	wantPath := "/etc/systemd/system/nginx.service.d/limit-nofile.conf"
	if len(*calls) != 1 || (*calls)[0][0] != wantPath || (*calls)[0][1] != content {
		t.Fatalf("write calls=%v", *calls)
	}
}

func TestOverrideHelperRefusesBadUnit(t *testing.T) {
	dir := withOverrideHelperStateDir(t)
	calls := withFakeOverrideWrite(t, nil)
	for _, bad := range []string{"", "bad unit", "../evil", "nginx/.service", "a\nb"} {
		writeOverrideReqFile(t, dir, testHelperID, unitOverrideReq(bad, "limit-nofile", "[Service]\nX=1\n"))
		if code := runOverrideHelper([]string{testHelperID}); code != 0 {
			t.Fatalf("exit=%d for unit %q", code, bad)
		}
		res := readOverrideResFile(t, dir, testHelperID)
		if res.OK || res.Error != "unit_denied" {
			t.Fatalf("unit %q: result=%+v, want unit_denied", bad, res)
		}
		_ = os.Remove(filepath.Join(dir, testHelperID+".res"))
	}
	if len(*calls) != 0 {
		t.Fatalf("write must not run for a bad unit: %v", *calls)
	}
}

func TestOverrideHelperRefusesBadLimit(t *testing.T) {
	dir := withOverrideHelperStateDir(t)
	calls := withFakeOverrideWrite(t, nil)
	// Limit not in the closed set.
	writeOverrideReqFile(t, dir, testHelperID, overrideHelperReq{
		Kind: overrideKindLimit, Unit: "nginx.service", Limit: "LimitBOGUS", Value: "1",
	})
	if code := runOverrideHelper([]string{testHelperID}); code != 0 {
		t.Fatalf("exit=%d", code)
	}
	if res := readOverrideResFile(t, dir, testHelperID); res.OK || res.Error != "limit_denied" {
		t.Fatalf("result=%+v, want limit_denied", res)
	}
	_ = os.Remove(filepath.Join(dir, testHelperID+".res"))
	// Bad value (shell metacharacters) for a valid limit.
	writeOverrideReqFile(t, dir, testHelperID, overrideHelperReq{
		Kind: overrideKindLimit, Unit: "nginx.service", Limit: "LimitNOFILE", Value: "1024; rm",
	})
	if code := runOverrideHelper([]string{testHelperID}); code != 0 {
		t.Fatalf("exit=%d", code)
	}
	if res := readOverrideResFile(t, dir, testHelperID); res.OK || res.Error != "value_denied" {
		t.Fatalf("result=%+v, want value_denied", res)
	}
	if len(*calls) != 0 {
		t.Fatalf("write must not run for a bad limit/value: %v", *calls)
	}
}

func TestOverrideHelperRefusesBadOverrideName(t *testing.T) {
	dir := withOverrideHelperStateDir(t)
	calls := withFakeOverrideWrite(t, nil)
	for _, bad := range []string{"", "bad name", "../evil", "a/b", ".hidden"} {
		writeOverrideReqFile(t, dir, testHelperID, unitOverrideReq("nginx.service", bad, "[Service]\nX=1\n"))
		if code := runOverrideHelper([]string{testHelperID}); code != 0 {
			t.Fatalf("exit=%d for name %q", code, bad)
		}
		if res := readOverrideResFile(t, dir, testHelperID); res.OK || res.Error != "name_denied" {
			t.Fatalf("name %q: result=%+v, want name_denied", bad, res)
		}
		_ = os.Remove(filepath.Join(dir, testHelperID+".res"))
	}
	if len(*calls) != 0 {
		t.Fatalf("write must not run for a bad override name: %v", *calls)
	}
}

func TestOverrideHelperRefusesBadContent(t *testing.T) {
	dir := withOverrideHelperStateDir(t)
	calls := withFakeOverrideWrite(t, nil)
	// Empty, oversized, and null-containing bodies are refused.
	for _, bad := range []string{"", strings.Repeat("a", overrideContentCap+1), "a\x00b"} {
		writeOverrideReqFile(t, dir, testHelperID, unitOverrideReq("nginx.service", "limit-nofile", bad))
		if code := runOverrideHelper([]string{testHelperID}); code != 0 {
			t.Fatalf("exit=%d", code)
		}
		if res := readOverrideResFile(t, dir, testHelperID); res.OK || res.Error != "content_denied" {
			t.Fatalf("result=%+v, want content_denied", res)
		}
		_ = os.Remove(filepath.Join(dir, testHelperID+".res"))
	}
	if len(*calls) != 0 {
		t.Fatalf("write must not run for bad content: %v", *calls)
	}
}

func TestOverrideHelperRefusesHashMismatch(t *testing.T) {
	dir := withOverrideHelperStateDir(t)
	calls := withFakeOverrideWrite(t, nil)
	// The lease binds "good\n"; the request carries "evil\n".
	req := signOverrideReq(t, unitOverrideReq("nginx.service", "limit-nofile", "good\n"))
	req.Content = "evil\n"
	writeOverrideReqFile(t, dir, testHelperID, req)
	if code := runOverrideHelper([]string{testHelperID}); code != 0 {
		t.Fatalf("exit=%d", code)
	}
	if res := readOverrideResFile(t, dir, testHelperID); res.OK || res.Error != "lease_payload_mismatch" {
		t.Fatalf("result=%+v, want lease_payload_mismatch", res)
	}
	if len(*calls) != 0 {
		t.Fatalf("write must not run on a hash mismatch: %v", *calls)
	}
}

func TestOverrideHelperRefusesBadKind(t *testing.T) {
	dir := withOverrideHelperStateDir(t)
	calls := withFakeOverrideWrite(t, nil)
	writeOverrideReqFile(t, dir, testHelperID, overrideHelperReq{Kind: "bogus", Unit: "nginx.service"})
	if code := runOverrideHelper([]string{testHelperID}); code != 0 {
		t.Fatalf("exit=%d", code)
	}
	if res := readOverrideResFile(t, dir, testHelperID); res.OK || res.Error != "bad_request" {
		t.Fatalf("result=%+v, want bad_request", res)
	}
	if len(*calls) != 0 {
		t.Fatalf("write must not run for a bad kind: %v", *calls)
	}
}

func TestOverrideHelperRefusesBadID(t *testing.T) {
	withOverrideHelperStateDir(t)
	for _, bad := range [][]string{
		{}, {"../../etc/passwd"}, {"NOTHEX"}, {testHelperID, "extra"},
		{"00112233445566778899aabbccddee"},
	} {
		if code := runOverrideHelper(bad); code != 2 {
			t.Fatalf("id %v: exit=%d, want 2", bad, code)
		}
	}
}

func TestOverrideHelperRecordsErrno(t *testing.T) {
	dir := withOverrideHelperStateDir(t)
	withFakeOverrideWrite(t, os.ErrPermission)
	writeOverrideReqFile(t, dir, testHelperID, signOverrideReq(t, overrideHelperReq{
		Kind: overrideKindLimit, Unit: "nginx.service", Limit: "LimitNOFILE", Value: "65536",
	}))
	if code := runOverrideHelper([]string{testHelperID}); code != 0 {
		t.Fatalf("exit=%d", code)
	}
	if res := readOverrideResFile(t, dir, testHelperID); res.OK || res.Error != "write_failed" {
		t.Fatalf("result=%+v, want write_failed", res)
	}
}

func TestOverrideSetViaHelperHandoffAndCleanup(t *testing.T) {
	dir := withOverrideHelperStateDir(t)
	calls := withFakeOverrideWrite(t, nil)
	prev := overrideHelperTrigger
	overrideHelperTrigger = func(id string) error {
		if !overrideHelperIDRE.MatchString(id) {
			t.Errorf("trigger got non-hex id %q", id)
		}
		runOverrideHelper([]string{id})
		return nil
	}
	t.Cleanup(func() { overrideHelperTrigger = prev })

	limit := signOverrideReq(t, overrideHelperReq{Kind: overrideKindLimit, Unit: "nginx.service", Limit: "LimitNOFILE", Value: "65536"})
	if err := resourceLimitSetViaHelper("nginx.service", "LimitNOFILE", "65536", limit.Lease); err != nil {
		t.Fatalf("resourceLimitSetViaHelper: %v", err)
	}
	content := "[Service]\nLimitNOFILE=1024\n"
	unit := signOverrideReq(t, unitOverrideReq("nginx.service", "limit-nofile", content))
	if err := unitOverrideSetViaHelper("nginx.service", "limit-nofile", content, unit.Lease); err != nil {
		t.Fatalf("unitOverrideSetViaHelper: %v", err)
	}
	if len(*calls) != 2 {
		t.Fatalf("want 2 writes, got %v", *calls)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("handoff files not cleaned up: %v", entries)
	}
}

func TestOverrideSetViaHelperRejectsBadUnitBeforeHandoff(t *testing.T) {
	withOverrideHelperStateDir(t)
	triggered := false
	prev := overrideHelperTrigger
	overrideHelperTrigger = func(id string) error { triggered = true; return nil }
	t.Cleanup(func() { overrideHelperTrigger = prev })

	if err := resourceLimitSetViaHelper("bad unit", "LimitNOFILE", "65536", &Lease{}); err == nil {
		t.Fatal("expected refusal for a bad unit")
	}
	if triggered {
		t.Fatal("helper must not be triggered for a bad unit")
	}
}

// The override helper must never write a drop-in for the agent's own unit, a
// mutation helper's unit, or a prefix/top-level drop-in that applies to them.
func TestOverrideHelperRefusesSelfUnits(t *testing.T) {
	dir := withOverrideHelperStateDir(t)
	calls := withFakeOverrideWrite(t, nil)
	for _, unit := range []string{
		"systemapi-agent.service", "sah-config-helper@.service", "sah-sysctl-helper@.service",
		"sah-systemd-override-helper@.service", "sah-config-helper@0123456789abcdef0123456789abcdef.service",
		"sah-future-helper@.service", "service", "sah-.service", "systemapi-.service",
	} {
		for _, req := range []overrideHelperReq{unitOverrideReq(unit, "x", "[Service]\nX=1\n"), {Kind: overrideKindLimit, Unit: unit, Limit: "LimitNOFILE", Value: "1024"}} {
			if _, _, _, _, code := overrideResolve(req); code != "unit_denied" {
				t.Fatalf("unit %q kind %s: code=%q, want unit_denied", unit, req.Kind, code)
			}
			writeOverrideReqFile(t, dir, testHelperID, req)
			if code := runOverrideHelper([]string{testHelperID}); code != 0 {
				t.Fatalf("exit=%d for unit %q", code, unit)
			}
			if res := readOverrideResFile(t, dir, testHelperID); res.OK || res.Error != "unit_denied" {
				t.Fatalf("unit %q: result=%+v, want unit_denied", unit, res)
			}
			_ = os.Remove(filepath.Join(dir, testHelperID+".res"))
		}
	}
	if len(*calls) != 0 {
		t.Fatalf("write must not run for a self unit: %v", *calls)
	}
	if _, _, _, _, code := overrideResolve(unitOverrideReq("nginx.service", "x", "[Service]\nX=1\n")); code != "" {
		t.Fatalf("nginx.service must still resolve: %q", code)
	}
}
