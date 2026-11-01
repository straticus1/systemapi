package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// fakePkgMgr is an injected PackageManager returning deterministic argv so a
// test can assert the chosen verb without touching a real package manager.
type fakePkgMgr struct {
	avail bool
	err   error
}

func (f *fakePkgMgr) Name() string    { return "fakepkg" }
func (f *fakePkgMgr) Available() bool { return f.avail }
func (f *fakePkgMgr) InstallArgv(n string) ([]string, error) {
	return []string{"pkg", "install", n}, f.err
}
func (f *fakePkgMgr) RemoveArgv(n string) ([]string, error) {
	return []string{"pkg", "remove", n}, f.err
}
func (f *fakePkgMgr) UpgradeArgv(n string) ([]string, error) {
	return []string{"pkg", "upgrade", n}, f.err
}
func (f *fakePkgMgr) QueryArgv(n string) ([]string, error) { return []string{"pkg", "query", n}, f.err }
func (f *fakePkgMgr) ListArgv() ([]string, error)          { return []string{"pkg", "list"}, f.err }

type sysPkgHarness struct {
	priv   ed25519.PrivateKey
	out    *fakeOut
	ch     *channelConn
	pm     *fakePkgMgr
	ran    [][]string
	runErr error
}

func newSysPkgHarness(t *testing.T, avail bool) *sysPkgHarness {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	clearIdentity()
	if err := pinControlPublicKey(base64.StdEncoding.EncodeToString(pub), ptyTestHost); err != nil {
		t.Fatal(err)
	}
	h := &sysPkgHarness{priv: priv, out: newFakeOut(), pm: &fakePkgMgr{avail: avail}}
	prevPm := sysPackages
	prevRun := sysPackageRun
	sysPackages = func() PackageManager { return h.pm }
	sysPackageRun = func(_ context.Context, argv []string) (string, error) {
		h.ran = append(h.ran, argv)
		return "ran " + strings.Join(argv, " "), h.runErr
	}
	h.ch = newChannelConn(h.out, ptyTestHost)
	t.Cleanup(func() {
		h.ch.close("stopped")
		sysPackages = prevPm
		sysPackageRun = prevRun
		clearIdentity()
	})
	return h
}

func (h *sysPkgHarness) send(t *testing.T, v interface{}) {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	var peek struct {
		Type string `json:"type"`
	}
	_ = json.Unmarshal(raw, &peek)
	handled, err := h.ch.handle(peek.Type, raw)
	if !handled {
		t.Fatalf("%s not handled", peek.Type)
	}
	if err != nil {
		t.Fatalf("handle returned error: %v", err)
	}
}

func (h *sysPkgHarness) result(t *testing.T, rid string) map[string]interface{} {
	t.Helper()
	h.out.mu.Lock()
	defer h.out.mu.Unlock()
	for _, m := range h.out.jsons {
		if got, _ := m["request_id"].(string); m["type"] == "sys_result" && got == rid {
			p, _ := m["payload"].(map[string]interface{})
			return p
		}
	}
	t.Fatalf("no sys_result for %s", rid)
	return nil
}

// frame builds a signed sys_package frame. leaseName/leaseAction default to
// name/action; override them to forge a mismatch.
func (h *sysPkgHarness) frame(t *testing.T, rid, name, action, leaseName, leaseAction string, exp int64) map[string]interface{} {
	t.Helper()
	if leaseName == "" {
		leaseName = name
	}
	if leaseAction == "" {
		leaseAction = action
	}
	payload, err := sysPackageLeasePayload(leaseName, leaseAction)
	if err != nil {
		t.Fatalf("lease payload: %v", err)
	}
	lease := signLease(t, h.priv, ptyTestHost, "sys_package", payload, exp)
	return map[string]interface{}{
		"type": "sys_package", "request_id": rid, "name": name, "action": action, "lease": lease,
	}
}

func TestSysPackageInstallHappyPath(t *testing.T) {
	h := newSysPkgHarness(t, true)
	rid := newSysRequestID(t)
	h.send(t, h.frame(t, rid, "nginx", "install", "", "", inFuture(time.Minute)))
	p := h.result(t, rid)
	if p["ok"] != true || p["name"] != "nginx" || p["action"] != "install" {
		t.Fatalf("unexpected result: %v", p)
	}
	if len(h.ran) != 1 || strings.Join(h.ran[0], " ") != "pkg install nginx" {
		t.Fatalf("ran=%v", h.ran)
	}
}

func TestSysPackageQueryHappyPath(t *testing.T) {
	h := newSysPkgHarness(t, true)
	rid := newSysRequestID(t)
	h.send(t, h.frame(t, rid, "nginx", "query", "", "", inFuture(time.Minute)))
	p := h.result(t, rid)
	if p["ok"] != true || p["action"] != "query" {
		t.Fatalf("unexpected result: %v", p)
	}
	if len(h.ran) != 1 || strings.Join(h.ran[0], " ") != "pkg query nginx" {
		t.Fatalf("ran=%v", h.ran)
	}
}

func TestSysPackageRefusesWhenCapabilityAbsent(t *testing.T) {
	h := newSysPkgHarness(t, false)
	rid := newSysRequestID(t)
	h.send(t, h.frame(t, rid, "nginx", "install", "", "", inFuture(time.Minute)))
	p := h.result(t, rid)
	if p["ok"] != false || p["error"] != "package_unsupported" {
		t.Fatalf("want package_unsupported, got %v", p)
	}
	if len(h.ran) != 0 {
		t.Fatalf("nothing should have run, got %v", h.ran)
	}
}

func TestSysPackageRefusesNameNotInSignedLease(t *testing.T) {
	h := newSysPkgHarness(t, true)
	rid := newSysRequestID(t)
	// Lease signed for curl, frame asks to install nginx.
	h.send(t, h.frame(t, rid, "nginx", "install", "curl", "", inFuture(time.Minute)))
	p := h.result(t, rid)
	if p["ok"] != false || p["error"] != "lease_required" {
		t.Fatalf("want lease_required for name mismatch, got %v", p)
	}
	if len(h.ran) != 0 {
		t.Fatalf("nothing should have run, got %v", h.ran)
	}
}

func TestSysPackageLeaseBindsAction(t *testing.T) {
	h := newSysPkgHarness(t, true)
	rid := newSysRequestID(t)
	// A lease signed for install cannot drive a remove.
	h.send(t, h.frame(t, rid, "nginx", "remove", "", "install", inFuture(time.Minute)))
	p := h.result(t, rid)
	if p["ok"] != false || p["error"] != "lease_required" {
		t.Fatalf("want lease_required for action mismatch, got %v", p)
	}
	if len(h.ran) != 0 {
		t.Fatalf("nothing should have run, got %v", h.ran)
	}
}

func TestSysPackageRefusesUnknownAction(t *testing.T) {
	h := newSysPkgHarness(t, true)
	rid := newSysRequestID(t)
	// "search" is not a channel verb, so no lease can be built for it.
	h.send(t, map[string]interface{}{
		"type": "sys_package", "request_id": rid, "name": "nginx", "action": "search",
		"lease": signLease(t, h.priv, ptyTestHost, "sys_package", "nginx\nsearch", inFuture(time.Minute)),
	})
	p := h.result(t, rid)
	if p["ok"] != false || p["error"] != "lease_required" {
		t.Fatalf("want lease_required for unknown action, got %v", p)
	}
	if len(h.ran) != 0 {
		t.Fatalf("nothing should have run, got %v", h.ran)
	}
}

func TestSysPackageRefusesExpiredLease(t *testing.T) {
	h := newSysPkgHarness(t, true)
	rid := newSysRequestID(t)
	h.send(t, h.frame(t, rid, "nginx", "install", "", "", time.Now().Add(-10*time.Minute).Unix()))
	p := h.result(t, rid)
	if p["ok"] != false || p["error"] != "lease_required" {
		t.Fatalf("want lease_required for expired lease, got %v", p)
	}
	if len(h.ran) != 0 {
		t.Fatalf("nothing should have run, got %v", h.ran)
	}
}

func TestSysPackageRefusesWrongKey(t *testing.T) {
	h := newSysPkgHarness(t, true)
	rid := newSysRequestID(t)
	_, otherPriv, _ := ed25519.GenerateKey(rand.Reader)
	payload, _ := sysPackageLeasePayload("nginx", "install")
	lease := signLease(t, otherPriv, ptyTestHost, "sys_package", payload, inFuture(time.Minute))
	h.send(t, map[string]interface{}{
		"type": "sys_package", "request_id": rid, "name": "nginx", "action": "install", "lease": lease,
	})
	p := h.result(t, rid)
	if p["ok"] != false || p["error"] != "lease_required" {
		t.Fatalf("want lease_required for wrong key, got %v", p)
	}
	if len(h.ran) != 0 {
		t.Fatalf("nothing should have run, got %v", h.ran)
	}
}

func TestSysPackageReportsActionFailure(t *testing.T) {
	h := newSysPkgHarness(t, true)
	h.runErr = errPkgNameDenied // any non-nil error from the command
	rid := newSysRequestID(t)
	h.send(t, h.frame(t, rid, "nginx", "install", "", "", inFuture(time.Minute)))
	p := h.result(t, rid)
	if p["ok"] != false || p["error"] != "action_failed" {
		t.Fatalf("want action_failed, got %v", p)
	}
	if len(h.ran) != 1 {
		t.Fatalf("the command should still have been attempted, got %v", h.ran)
	}
}

func TestSysPackageLeasePayloadBuilder(t *testing.T) {
	// The Go builder must produce the exact string the server signs
	// (controlplane/lease.js sysPackagePayload): "<name>\n<action>".
	for _, action := range []string{"query", "install", "remove", "upgrade"} {
		got, err := sysPackageLeasePayload("nginx", action)
		if err != nil || got != "nginx\n"+action {
			t.Fatalf("payload %q err %v for %s", got, err, action)
		}
	}
	for _, c := range []struct {
		name, action, label string
	}{
		{"nginx", "search", "bad action"},
		{"nginx", "", "empty action"},
		{"ng*nx", "install", "star name"},
		{"ng nx", "install", "space name"},
		{"", "install", "empty name"},
	} {
		if _, err := sysPackageLeasePayload(c.name, c.action); err == nil {
			t.Fatalf("%s: accepted", c.label)
		}
	}
}
