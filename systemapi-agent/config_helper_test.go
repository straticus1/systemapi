package main

// Tests for the privilege-separated sys:config write helper (config_helper.go).
//
// Threats exercised: the helper must not trust the caller. These tests prove it
// refuses a self-root target (/etc/systemapi-agent/...), a traversal/bad-shape
// target, oversized content, and content that does not match the signed
// lease, even when the request file asks for them (the lease checks
// themselves are in helper_auth_test.go); that it
// records a precise result and never performs the write in those cases; that
// the agent-side handoff is one-shot and cleans up; and that a self-root target
// is refused at the agent gate before any handoff. No test writes a real /etc
// file: the write seam (configHelperWrite) is replaced.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// withConfigHelperStateDir points the handoff dir at a temp dir and restores it.
func withConfigHelperStateDir(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "config-helper")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	prev := configHelperStateDir
	configHelperStateDir = dir
	t.Cleanup(func() { configHelperStateDir = prev })
	return dir
}

// withFakeConfigWrite replaces the real /etc write with a capture, and restores.
func withFakeConfigWrite(t *testing.T, err error) *[][2]string {
	t.Helper()
	var calls [][2]string
	prev := configHelperWrite
	configHelperWrite = func(path, content string) error {
		calls = append(calls, [2]string{path, content})
		return err
	}
	t.Cleanup(func() { configHelperWrite = prev })
	return &calls
}

func writeConfigReqFile(t *testing.T, dir, id string, req configHelperReq) {
	t.Helper()
	b, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, id+".req"), b, 0o600); err != nil {
		t.Fatal(err)
	}
}

func readConfigResFile(t *testing.T, dir, id string) configHelperRes {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, id+".res"))
	if err != nil {
		t.Fatalf("read result: %v", err)
	}
	var res configHelperRes
	if err := json.Unmarshal(b, &res); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}
	return res
}

// configReq builds a request with no lease, for refusals that must happen on
// shape alone (before any lease check).
func configReq(target, content string) configHelperReq {
	return configHelperReq{Target: target, Content: content}
}

// signedConfigReq builds a request carrying a valid lease for target/content.
func signedConfigReq(t *testing.T, target, content string) configHelperReq {
	t.Helper()
	priv := newHelperSigner(t)
	return configHelperReq{Target: target, Content: content, Lease: configWriteLease(t, priv, target, content, inFuture(time.Minute))}
}

func TestConfigHelperWritesGrantedTarget(t *testing.T) {
	dir := withConfigHelperStateDir(t)
	calls := withFakeConfigWrite(t, nil)
	writeConfigReqFile(t, dir, testHelperID, signedConfigReq(t, "/etc/nginx/nginx.conf", "server {}\n"))

	if code := runConfigHelper([]string{testHelperID}); code != 0 {
		t.Fatalf("exit=%d, want 0", code)
	}
	res := readConfigResFile(t, dir, testHelperID)
	if !res.OK || res.Error != "" {
		t.Fatalf("result=%+v, want ok", res)
	}
	if len(*calls) != 1 || (*calls)[0][0] != "/etc/nginx/nginx.conf" || (*calls)[0][1] != "server {}\n" {
		t.Fatalf("write calls=%v", *calls)
	}
}

func TestConfigHelperRefusesSelfRootTarget(t *testing.T) {
	dir := withConfigHelperStateDir(t)
	calls := withFakeConfigWrite(t, nil)
	// The agent's own config dir, and every other self-root, must be refused
	// even though the request file asks for it.
	for _, bad := range []string{
		"/etc/systemapi-agent/api-key", "/etc/systemapi-agent",
		"/etc/sahcore/sahcore.env", "/var/lib/systemapi-agent/agent.json",
		"/var/lib/postgresql/16/x.conf", "/proc/sys/kernel/x", "/boot/x",
	} {
		writeConfigReqFile(t, dir, testHelperID, configReq(bad, "x\n"))
		if code := runConfigHelper([]string{testHelperID}); code != 0 {
			t.Fatalf("exit=%d for %q", code, bad)
		}
		res := readConfigResFile(t, dir, testHelperID)
		if res.OK || res.Error != "target_denied" {
			t.Fatalf("%q: result=%+v, want target_denied", bad, res)
		}
		_ = os.Remove(filepath.Join(dir, testHelperID+".res"))
	}
	if len(*calls) != 0 {
		t.Fatalf("write must not run for a self-root target: %v", *calls)
	}
}

func TestConfigHelperRefusesBadShapeTarget(t *testing.T) {
	dir := withConfigHelperStateDir(t)
	calls := withFakeConfigWrite(t, nil)
	for _, bad := range []string{
		"", "/", "relative/path", "/etc/../root/.ssh/authorized_keys",
		"/etc/nginx/", "/etc/x\ny", "/etc/./x",
	} {
		writeConfigReqFile(t, dir, testHelperID, configReq(bad, "x\n"))
		if code := runConfigHelper([]string{testHelperID}); code != 0 {
			t.Fatalf("exit=%d for %q", code, bad)
		}
		res := readConfigResFile(t, dir, testHelperID)
		if res.OK || res.Error != "target_denied" {
			t.Fatalf("%q: result=%+v, want target_denied", bad, res)
		}
		_ = os.Remove(filepath.Join(dir, testHelperID+".res"))
	}
	if len(*calls) != 0 {
		t.Fatalf("write must not run for a bad-shape target: %v", *calls)
	}
}

func TestConfigHelperRefusesHashMismatch(t *testing.T) {
	dir := withConfigHelperStateDir(t)
	calls := withFakeConfigWrite(t, nil)
	// The lease is for "good\n" but the content is "evil\n": refuse.
	req := signedConfigReq(t, "/etc/nginx/nginx.conf", "good\n")
	req.Content = "evil\n"
	writeConfigReqFile(t, dir, testHelperID, req)
	if code := runConfigHelper([]string{testHelperID}); code != 0 {
		t.Fatalf("exit=%d, want 0", code)
	}
	res := readConfigResFile(t, dir, testHelperID)
	if res.OK || res.Error != "lease_payload_mismatch" {
		t.Fatalf("result=%+v, want lease_payload_mismatch", res)
	}
	if len(*calls) != 0 {
		t.Fatalf("write must not run on a hash mismatch: %v", *calls)
	}
}

func TestConfigHelperRefusesOversizedContent(t *testing.T) {
	dir := withConfigHelperStateDir(t)
	calls := withFakeConfigWrite(t, nil)
	big := strings.Repeat("a", configContentMax+1)
	writeConfigReqFile(t, dir, testHelperID, configReq("/etc/nginx/nginx.conf", big))
	if code := runConfigHelper([]string{testHelperID}); code != 0 {
		t.Fatalf("exit=%d, want 0", code)
	}
	res := readConfigResFile(t, dir, testHelperID)
	if res.OK || res.Error != "content_denied" {
		t.Fatalf("result=%+v, want content_denied", res)
	}
	if len(*calls) != 0 {
		t.Fatalf("write must not run for oversized content: %v", *calls)
	}
}

func TestConfigHelperRefusesBadID(t *testing.T) {
	withConfigHelperStateDir(t)
	for _, bad := range [][]string{
		{}, {"../../etc/passwd"}, {"NOTHEX"}, {testHelperID, "extra"},
		{"00112233445566778899aabbccddee"},
	} {
		if code := runConfigHelper(bad); code != 2 {
			t.Fatalf("id %v: exit=%d, want 2", bad, code)
		}
	}
}

func TestConfigHelperRecordsErrno(t *testing.T) {
	dir := withConfigHelperStateDir(t)
	withFakeConfigWrite(t, os.ErrPermission) // the sandbox denies the write
	writeConfigReqFile(t, dir, testHelperID, signedConfigReq(t, "/etc/nginx/nginx.conf", "x\n"))
	if code := runConfigHelper([]string{testHelperID}); code != 0 {
		t.Fatalf("exit=%d, want 0", code)
	}
	res := readConfigResFile(t, dir, testHelperID)
	if res.OK || res.Error != "write_failed" {
		t.Fatalf("result=%+v, want write_failed", res)
	}
}

func TestConfigWriteViaHelperHandoffAndCleanup(t *testing.T) {
	dir := withConfigHelperStateDir(t)
	calls := withFakeConfigWrite(t, nil)
	prev := configHelperTrigger
	configHelperTrigger = func(id string) error {
		if !configHelperIDRE.MatchString(id) {
			t.Errorf("trigger got non-hex id %q", id)
		}
		runConfigHelper([]string{id})
		return nil
	}
	t.Cleanup(func() { configHelperTrigger = prev })

	content := "server {}\n"
	req := signedConfigReq(t, "/etc/nginx/nginx.conf", content)
	if err := configWriteViaHelper("/etc/nginx/nginx.conf", content, req.Lease); err != nil {
		t.Fatalf("configWriteViaHelper: %v", err)
	}
	if len(*calls) != 1 || (*calls)[0][1] != content {
		t.Fatalf("write calls=%v", *calls)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("handoff files not cleaned up: %v", entries)
	}
}

func TestConfigWriteViaHelperRejectsSelfRootBeforeHandoff(t *testing.T) {
	withConfigHelperStateDir(t)
	triggered := false
	prev := configHelperTrigger
	configHelperTrigger = func(id string) error { triggered = true; return nil }
	t.Cleanup(func() { configHelperTrigger = prev })

	req := signedConfigReq(t, "/etc/nginx/nginx.conf", "x\n")
	if err := configWriteViaHelper("/etc/systemapi-agent/api-key", "x\n", req.Lease); err == nil {
		t.Fatal("expected refusal for a self-root target")
	}
	if triggered {
		t.Fatal("helper must not be triggered for a self-root target")
	}
}

func TestConfigWriteViaHelperRejectsMissingLeaseBeforeHandoff(t *testing.T) {
	withConfigHelperStateDir(t)
	triggered := false
	prev := configHelperTrigger
	configHelperTrigger = func(id string) error { triggered = true; return nil }
	t.Cleanup(func() { configHelperTrigger = prev })

	if err := configWriteViaHelper("/etc/nginx/nginx.conf", "x\n", nil); err == nil {
		t.Fatal("expected refusal without a lease")
	}
	if triggered {
		t.Fatal("helper must not be triggered without a lease")
	}
}
