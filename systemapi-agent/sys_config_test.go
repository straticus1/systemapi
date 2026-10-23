package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"testing"
	"time"
)

// fakeConfigStore is an injected ConfigStore that records writes and reloads.
type fakeConfigStore struct {
	avail     bool
	writes    [][2]string
	reloads   []string
	writeErr  error
	reloadErr error
	reloadOut string
}

func (f *fakeConfigStore) Name() string    { return "fakecfg" }
func (f *fakeConfigStore) Available() bool { return f.avail }
func (f *fakeConfigStore) AtomicWrite(path, content string) error {
	f.writes = append(f.writes, [2]string{path, content})
	return f.writeErr
}
func (f *fakeConfigStore) Validate(service, path string) (string, error) { return "", nil }
func (f *fakeConfigStore) Reload(service string) (string, error) {
	f.reloads = append(f.reloads, service)
	return f.reloadOut, f.reloadErr
}

type sysCfgHarness struct {
	priv     ed25519.PrivateKey
	out      *fakeOut
	ch       *channelConn
	cs       *fakeConfigStore
	readOut  string
	readErr  error
	readPath string
}

func newSysCfgHarness(t *testing.T, avail bool) *sysCfgHarness {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	clearIdentity()
	if err := pinControlPublicKey(base64.StdEncoding.EncodeToString(pub), ptyTestHost); err != nil {
		t.Fatal(err)
	}
	h := &sysCfgHarness{priv: priv, out: newFakeOut(), cs: &fakeConfigStore{avail: avail}, readOut: "listen 80;\n"}
	prevCfg := sysConfig
	prevRead := sysConfigReadFile
	sysConfig = func() ConfigStore { return h.cs }
	sysConfigReadFile = func(path string) (string, error) {
		h.readPath = path
		return h.readOut, h.readErr
	}
	h.ch = newChannelConn(h.out, ptyTestHost)
	t.Cleanup(func() {
		h.ch.close("stopped")
		sysConfig = prevCfg
		sysConfigReadFile = prevRead
		clearIdentity()
	})
	return h
}

func (h *sysCfgHarness) send(t *testing.T, v interface{}) {
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

func (h *sysCfgHarness) result(t *testing.T, rid string) map[string]interface{} {
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

// frame builds a signed sys_config frame. The lease* overrides forge a
// mismatch; leaseContent is the body the lease's hash was computed over (for a
// write), so passing a different content tests the content binding.
func (h *sysCfgHarness) frame(t *testing.T, rid, action, target, content, leaseAction, leaseTarget, leaseContent string, exp int64) map[string]interface{} {
	t.Helper()
	if leaseAction == "" {
		leaseAction = action
	}
	if leaseTarget == "" {
		leaseTarget = target
	}
	if leaseContent == "" {
		leaseContent = content
	}
	sha := ""
	if leaseAction == "write" {
		sha = sysSHA256Hex(leaseContent)
	}
	payload, err := sysConfigLeasePayload(leaseAction, leaseTarget, sha)
	if err != nil {
		t.Fatalf("lease payload: %v", err)
	}
	lease := signLease(t, h.priv, ptyTestHost, "sys_config", payload, exp)
	return map[string]interface{}{
		"type": "sys_config", "request_id": rid, "action": action, "target": target, "content": content, "lease": lease,
	}
}

func TestSysConfigReadHappyPath(t *testing.T) {
	h := newSysCfgHarness(t, true)
	rid := newSysRequestID(t)
	h.send(t, h.frame(t, rid, "read", "/etc/nginx/nginx.conf", "", "", "", "", inFuture(time.Minute)))
	p := h.result(t, rid)
	if p["ok"] != true || p["output"] != "listen 80;\n" {
		t.Fatalf("unexpected result: %v", p)
	}
	if h.readPath != "/etc/nginx/nginx.conf" {
		t.Fatalf("read path=%q", h.readPath)
	}
}

func TestSysConfigWriteHappyPath(t *testing.T) {
	// config write is privilege-separated now (config_helper.go): the channel
	// hands off to the helper instead of calling the ConfigStore. The trigger
	// stands in for systemd and runs the helper in-process; the write seam is
	// faked so no real /etc file is touched.
	h := newSysCfgHarness(t, true)
	withConfigHelperStateDir(t)
	calls := withFakeConfigWrite(t, nil)
	prev := configHelperTrigger
	configHelperTrigger = func(id string) error { runConfigHelper([]string{id}); return nil }
	t.Cleanup(func() { configHelperTrigger = prev })

	rid := newSysRequestID(t)
	h.send(t, h.frame(t, rid, "write", "/etc/nginx/nginx.conf", "server {}\n", "", "", "", inFuture(time.Minute)))
	p := h.result(t, rid)
	if p["ok"] != true || p["action"] != "write" {
		t.Fatalf("unexpected result: %v", p)
	}
	// The write went through the helper seam...
	if len(*calls) != 1 || (*calls)[0][0] != "/etc/nginx/nginx.conf" || (*calls)[0][1] != "server {}\n" {
		t.Fatalf("helper write calls=%v", *calls)
	}
	// ...and NOT through the Phase 0 ConfigStore.
	if len(h.cs.writes) != 0 {
		t.Fatalf("config write must not call the ConfigStore any more: %v", h.cs.writes)
	}
}

func TestSysConfigReloadHappyPath(t *testing.T) {
	h := newSysCfgHarness(t, true)
	h.cs.reloadOut = "reloaded"
	rid := newSysRequestID(t)
	h.send(t, h.frame(t, rid, "reload", "nginx.service", "", "", "", "", inFuture(time.Minute)))
	p := h.result(t, rid)
	if p["ok"] != true || p["output"] != "reloaded" {
		t.Fatalf("unexpected result: %v", p)
	}
	if len(h.cs.reloads) != 1 || h.cs.reloads[0] != "nginx.service" {
		t.Fatalf("reloads=%v", h.cs.reloads)
	}
}

func TestSysConfigRefusesWhenCapabilityAbsent(t *testing.T) {
	h := newSysCfgHarness(t, false)
	rid := newSysRequestID(t)
	h.send(t, h.frame(t, rid, "write", "/etc/nginx/nginx.conf", "x\n", "", "", "", inFuture(time.Minute)))
	p := h.result(t, rid)
	if p["ok"] != false || p["error"] != "config_unsupported" {
		t.Fatalf("want config_unsupported, got %v", p)
	}
	if len(h.cs.writes) != 0 {
		t.Fatalf("nothing should have been written, got %v", h.cs.writes)
	}
}

func TestSysConfigWriteRefusesTamperedContent(t *testing.T) {
	h := newSysCfgHarness(t, true)
	rid := newSysRequestID(t)
	// Lease signed over "good\n"; the frame carries "evil\n": the hash no
	// longer matches, so the lease does not verify.
	h.send(t, h.frame(t, rid, "write", "/etc/nginx/nginx.conf", "evil\n", "", "", "good\n", inFuture(time.Minute)))
	p := h.result(t, rid)
	if p["ok"] != false || p["error"] != "lease_required" {
		t.Fatalf("want lease_required for tampered content, got %v", p)
	}
	if len(h.cs.writes) != 0 {
		t.Fatalf("nothing should have been written, got %v", h.cs.writes)
	}
}

func TestSysConfigRefusesTargetNotInSignedLease(t *testing.T) {
	h := newSysCfgHarness(t, true)
	rid := newSysRequestID(t)
	// Lease signed for b.conf, frame reads a.conf.
	h.send(t, h.frame(t, rid, "read", "/etc/nginx/a.conf", "", "", "/etc/nginx/b.conf", "", inFuture(time.Minute)))
	p := h.result(t, rid)
	if p["ok"] != false || p["error"] != "lease_required" {
		t.Fatalf("want lease_required for target mismatch, got %v", p)
	}
	if h.readPath != "" {
		t.Fatalf("nothing should have been read, got %q", h.readPath)
	}
}

func TestSysConfigLeaseBindsAction(t *testing.T) {
	h := newSysCfgHarness(t, true)
	rid := newSysRequestID(t)
	// A lease signed for read cannot drive a write.
	h.send(t, h.frame(t, rid, "write", "/etc/nginx/nginx.conf", "x\n", "read", "", "", inFuture(time.Minute)))
	p := h.result(t, rid)
	if p["ok"] != false || p["error"] != "lease_required" {
		t.Fatalf("want lease_required for action mismatch, got %v", p)
	}
	if len(h.cs.writes) != 0 {
		t.Fatalf("nothing should have been written, got %v", h.cs.writes)
	}
}

func TestSysConfigRefusesUnknownAction(t *testing.T) {
	h := newSysCfgHarness(t, true)
	rid := newSysRequestID(t)
	h.send(t, map[string]interface{}{
		"type": "sys_config", "request_id": rid, "action": "validate", "target": "/etc/nginx/nginx.conf",
		"lease": signLease(t, h.priv, ptyTestHost, "sys_config", "validate\n/etc/nginx/nginx.conf", inFuture(time.Minute)),
	})
	p := h.result(t, rid)
	if p["ok"] != false || p["error"] != "lease_required" {
		t.Fatalf("want lease_required for unknown action, got %v", p)
	}
}

func TestSysConfigRefusesExpiredLease(t *testing.T) {
	h := newSysCfgHarness(t, true)
	rid := newSysRequestID(t)
	h.send(t, h.frame(t, rid, "read", "/etc/nginx/nginx.conf", "", "", "", "", time.Now().Add(-10*time.Minute).Unix()))
	p := h.result(t, rid)
	if p["ok"] != false || p["error"] != "lease_required" {
		t.Fatalf("want lease_required for expired lease, got %v", p)
	}
}

func TestSysConfigRefusesWrongKey(t *testing.T) {
	h := newSysCfgHarness(t, true)
	rid := newSysRequestID(t)
	_, otherPriv, _ := ed25519.GenerateKey(rand.Reader)
	payload, _ := sysConfigLeasePayload("read", "/etc/nginx/nginx.conf", "")
	lease := signLease(t, otherPriv, ptyTestHost, "sys_config", payload, inFuture(time.Minute))
	h.send(t, map[string]interface{}{
		"type": "sys_config", "request_id": rid, "action": "read", "target": "/etc/nginx/nginx.conf", "lease": lease,
	})
	p := h.result(t, rid)
	if p["ok"] != false || p["error"] != "lease_required" {
		t.Fatalf("want lease_required for wrong key, got %v", p)
	}
}

func TestSysConfigReportsActionFailure(t *testing.T) {
	// A failed config write surfaces as action_failed. The failure now comes
	// from the helper (its write seam returns an error), not the ConfigStore.
	h := newSysCfgHarness(t, true)
	withConfigHelperStateDir(t)
	calls := withFakeConfigWrite(t, os.ErrPermission) // the sandbox denies the write
	prev := configHelperTrigger
	configHelperTrigger = func(id string) error { runConfigHelper([]string{id}); return nil }
	t.Cleanup(func() { configHelperTrigger = prev })

	rid := newSysRequestID(t)
	h.send(t, h.frame(t, rid, "write", "/etc/nginx/nginx.conf", "x\n", "", "", "", inFuture(time.Minute)))
	p := h.result(t, rid)
	if p["ok"] != false || p["error"] != "action_failed" {
		t.Fatalf("want action_failed, got %v", p)
	}
	if len(*calls) != 1 {
		t.Fatalf("the helper write should still have been attempted, got %v", *calls)
	}
}

func TestSysConfigLeasePayloadBuilder(t *testing.T) {
	// read/reload and write (with a content hash) match the server's
	// sysConfigPayload (controlplane/lease.js).
	if got, err := sysConfigLeasePayload("read", "/etc/nginx/nginx.conf", ""); err != nil || got != "read\n/etc/nginx/nginx.conf" {
		t.Fatalf("read payload %q err %v", got, err)
	}
	if got, err := sysConfigLeasePayload("reload", "nginx.service", ""); err != nil || got != "reload\nnginx.service" {
		t.Fatalf("reload payload %q err %v", got, err)
	}
	sha := sysSHA256Hex("body\n")
	if got, err := sysConfigLeasePayload("write", "/etc/nginx/nginx.conf", sha); err != nil || got != "write\n/etc/nginx/nginx.conf\n"+sha {
		t.Fatalf("write payload %q err %v", got, err)
	}
	for _, c := range []struct {
		action, target, sha, label string
	}{
		{"validate", "/etc/x", "", "bad action"},
		{"read", "relative/x", "", "relative read path"},
		{"read", "/", "", "root read path"},
		{"reload", "/etc/x", "", "reload needs a unit, not a path"},
		{"write", "/etc/x", "nothex", "write needs a content hash"},
		{"write", "/etc/x", "", "write missing content hash"},
	} {
		if _, err := sysConfigLeasePayload(c.action, c.target, c.sha); err == nil {
			t.Fatalf("%s: accepted", c.label)
		}
	}
}
