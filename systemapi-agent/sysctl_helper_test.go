package main

// Tests for the privilege-separated sysctl mutation helper (sysctl_helper.go).
//
// Threats exercised: the helper must not trust the caller. These tests prove it
// refuses a denied key (kernel.core_pattern), a malformed key, and a malformed
// value even when the request file asks for them; that it records a precise
// result and never performs the write in those cases; that the agent-side
// handoff is one-shot and cleans up its files; and that the sysctl-set channel
// path routes through the helper rather than the backend while still refusing
// out-of-policy keys at the agent gate (unchanged). No test writes a real
// /proc/sys knob: the write seam (sysctlHelperWrite) is replaced.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// withHelperStateDir points the handoff dir at a temp dir and restores it.
func withHelperStateDir(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "sysctl-helper")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	prev := sysctlHelperStateDir
	sysctlHelperStateDir = dir
	t.Cleanup(func() { sysctlHelperStateDir = prev })
	return dir
}

// withFakeWrite replaces the real /proc/sys write with a capture, and restores.
func withFakeWrite(t *testing.T, err error) *[][2]string {
	t.Helper()
	var calls [][2]string
	prev := sysctlHelperWrite
	sysctlHelperWrite = func(path, value string) error {
		calls = append(calls, [2]string{path, value})
		return err
	}
	t.Cleanup(func() { sysctlHelperWrite = prev })
	return &calls
}

func writeReqFile(t *testing.T, dir, id string, req sysctlHelperReq) {
	t.Helper()
	b, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, id+".req"), b, 0o600); err != nil {
		t.Fatal(err)
	}
}

func readResFile(t *testing.T, dir, id string) sysctlHelperRes {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, id+".res"))
	if err != nil {
		t.Fatalf("read result: %v", err)
	}
	var res sysctlHelperRes
	if err := json.Unmarshal(b, &res); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}
	return res
}

const testHelperID = "00112233445566778899aabbccddeeff"

// signedSysctlReq builds a request carrying a valid sys_tweak lease.
func signedSysctlReq(t *testing.T, key, value string) sysctlHelperReq {
	t.Helper()
	priv := newHelperSigner(t)
	payload, err := sysTweakLeasePayload("sysctl-set", key, value, "", "", "", "")
	if err != nil {
		t.Fatal(err)
	}
	return sysctlHelperReq{Key: key, Value: value, Lease: signLease(t, priv, ptyTestHost, "sys_tweak", payload, inFuture(time.Minute))}
}

func TestSysctlHelperWritesGrantedKey(t *testing.T) {
	dir := withHelperStateDir(t)
	calls := withFakeWrite(t, nil)
	writeReqFile(t, dir, testHelperID, signedSysctlReq(t, "net.ipv4.ip_forward", "1"))

	if code := runSysctlHelper([]string{testHelperID}); code != 0 {
		t.Fatalf("exit=%d, want 0", code)
	}
	res := readResFile(t, dir, testHelperID)
	if !res.OK || res.Error != "" {
		t.Fatalf("result=%+v, want ok", res)
	}
	if len(*calls) != 1 || (*calls)[0][0] != "/proc/sys/net/ipv4/ip_forward" || (*calls)[0][1] != "1" {
		t.Fatalf("write calls=%v", *calls)
	}
}

func TestSysctlHelperRefusesDeniedKey(t *testing.T) {
	dir := withHelperStateDir(t)
	calls := withFakeWrite(t, nil)
	// kernel.core_pattern is in deniedSysctl; the helper must refuse it even
	// though the request file asks for it.
	writeReqFile(t, dir, testHelperID, sysctlHelperReq{Key: "kernel.core_pattern", Value: "|/evil"})

	if code := runSysctlHelper([]string{testHelperID}); code != 0 {
		t.Fatalf("exit=%d, want 0 (result recorded)", code)
	}
	res := readResFile(t, dir, testHelperID)
	if res.OK || res.Error != "key_denied" {
		t.Fatalf("result=%+v, want key_denied", res)
	}
	if len(*calls) != 0 {
		t.Fatalf("write must not run for a denied key: %v", *calls)
	}
}

func TestSysctlHelperRefusesMalformedKey(t *testing.T) {
	dir := withHelperStateDir(t)
	calls := withFakeWrite(t, nil)
	// Uppercase and a trailing newline both fail sysctlKeyRE.
	for _, bad := range []string{"Net.ipv4.ip_forward", "net.ipv4.ip_forward\n", "", "net/ipv4/ip_forward"} {
		writeReqFile(t, dir, testHelperID, sysctlHelperReq{Key: bad, Value: "1"})
		if code := runSysctlHelper([]string{testHelperID}); code != 0 {
			t.Fatalf("exit=%d for key %q", code, bad)
		}
		res := readResFile(t, dir, testHelperID)
		if res.OK || res.Error != "key_denied" {
			t.Fatalf("key %q: result=%+v, want key_denied", bad, res)
		}
		// One request per id in production; clear the result for the next case.
		_ = os.Remove(filepath.Join(dir, testHelperID+".res"))
	}
	if len(*calls) != 0 {
		t.Fatalf("write must not run for a malformed key: %v", *calls)
	}
}

func TestSysctlHelperRefusesBadValue(t *testing.T) {
	dir := withHelperStateDir(t)
	calls := withFakeWrite(t, nil)
	// A newline in the value is rejected by sysctlValueOK.
	writeReqFile(t, dir, testHelperID, sysctlHelperReq{Key: "net.ipv4.ip_forward", Value: "1\n2"})
	if code := runSysctlHelper([]string{testHelperID}); code != 0 {
		t.Fatalf("exit=%d, want 0", code)
	}
	res := readResFile(t, dir, testHelperID)
	if res.OK || res.Error != "value_denied" {
		t.Fatalf("result=%+v, want value_denied", res)
	}
	if len(*calls) != 0 {
		t.Fatalf("write must not run for a bad value: %v", *calls)
	}
}

func TestSysctlHelperRefusesBadID(t *testing.T) {
	withHelperStateDir(t)
	for _, bad := range [][]string{
		{},                                 // missing
		{"../../etc/passwd"},               // traversal / non-hex
		{"NOTHEX"},                         // non-hex
		{testHelperID, "extra"},            // too many args
		{"00112233445566778899aabbccddee"}, // too short (30)
	} {
		if code := runSysctlHelper(bad); code != 2 {
			t.Fatalf("id %v: exit=%d, want 2", bad, code)
		}
	}
}

func TestSysctlHelperRecordsErrno(t *testing.T) {
	dir := withHelperStateDir(t)
	// Simulate the sandbox denying the write (EACCES).
	withFakeWrite(t, os.ErrPermission)
	writeReqFile(t, dir, testHelperID, signedSysctlReq(t, "net.ipv4.ip_forward", "1"))
	if code := runSysctlHelper([]string{testHelperID}); code != 0 {
		t.Fatalf("exit=%d, want 0", code)
	}
	res := readResFile(t, dir, testHelperID)
	if res.OK || res.Error != "write_failed" {
		t.Fatalf("result=%+v, want write_failed", res)
	}
}

func TestSysctlSetViaHelperHandoffAndCleanup(t *testing.T) {
	dir := withHelperStateDir(t)
	calls := withFakeWrite(t, nil)
	// The trigger stands in for systemd: run the helper in-process on the id.
	prev := sysctlHelperTrigger
	sysctlHelperTrigger = func(id string) error {
		if !sysctlHelperIDRE.MatchString(id) {
			t.Errorf("trigger got non-hex id %q", id)
		}
		runSysctlHelper([]string{id})
		return nil
	}
	t.Cleanup(func() { sysctlHelperTrigger = prev })

	req := signedSysctlReq(t, "net.ipv4.ip_forward", "1")
	if err := sysctlSetViaHelper("net.ipv4.ip_forward", "1", req.Lease); err != nil {
		t.Fatalf("sysctlSetViaHelper: %v", err)
	}
	if len(*calls) != 1 || (*calls)[0][1] != "1" {
		t.Fatalf("write calls=%v", *calls)
	}
	// One-shot: no request/result files are left behind.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("handoff files not cleaned up: %v", entries)
	}
}

func TestSysctlSetViaHelperRejectsDeniedKeyBeforeHandoff(t *testing.T) {
	withHelperStateDir(t)
	triggered := false
	prev := sysctlHelperTrigger
	sysctlHelperTrigger = func(id string) error { triggered = true; return nil }
	t.Cleanup(func() { sysctlHelperTrigger = prev })

	req := signedSysctlReq(t, "net.ipv4.ip_forward", "1")
	if err := sysctlSetViaHelper("kernel.core_pattern", "|/x", req.Lease); err == nil {
		t.Fatal("expected refusal for a denied key")
	}
	if triggered {
		t.Fatal("helper must not be triggered for a denied key")
	}
}

// TestSysctlSetChannelRefusesDeniedKeyBeforeHandoff proves the agent gate is
// unchanged: a denied sysctl key never reaches the helper. The lease payload
// rebuild in sysTweak rejects the key (sysTweakLeasePayload returns bad_key),
// so the channel answers lease_required and no handoff is triggered. (The
// channel happy path and backend-bypass are covered by
// TestSysTweakSysctlSetHappyPath in sys_tweak_test.go.)
func TestSysctlSetChannelRefusesDeniedKeyBeforeHandoff(t *testing.T) {
	h := newSysTwkHarness(t, true)
	withHelperStateDir(t)
	triggered := false
	prev := sysctlHelperTrigger
	sysctlHelperTrigger = func(id string) error { triggered = true; return nil }
	t.Cleanup(func() { sysctlHelperTrigger = prev })

	rid := newSysRequestID(t)
	// A denied key cannot even be put in a signed lease, so send the frame
	// directly; the agent rejects it at payload rebuild, before the helper.
	h.send(t, map[string]interface{}{
		"type": "sys_tweak", "request_id": rid, "verb": "sysctl-set",
		"key": "kernel.core_pattern", "value": "|/x",
	})
	p := h.result(t, rid)
	if p["ok"] != false || p["error"] != "lease_required" {
		t.Fatalf("want lease_required (denied key rejected before handoff), got %v", p)
	}
	if triggered {
		t.Fatal("helper must not be triggered when the agent gate refuses")
	}
}
