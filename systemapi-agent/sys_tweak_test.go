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

// fakeTweaks is an injected Tweaks backend that records its calls.
type fakeTweaks struct {
	avail        bool
	getOut       string
	errGet       error
	errSet       error
	errLimit     error
	errOverride  error
	gets         [][]string
	sets         [][]string
	limits       [][]string
	overrides    [][]string
	lastAllowCfg []string
}

func (f *fakeTweaks) Name() string    { return "faketweak" }
func (f *fakeTweaks) Available() bool { return f.avail }
func (f *fakeTweaks) SysctlGet(key string, allow []string) (string, error) {
	f.gets = append(f.gets, append([]string{key}, allow...))
	return f.getOut, f.errGet
}
func (f *fakeTweaks) SysctlSet(key, value string, allow []string) error {
	f.sets = append(f.sets, append([]string{key, value}, allow...))
	return f.errSet
}
func (f *fakeTweaks) SetResourceLimit(unit, limit, value string, allowConfigWrite []string) error {
	f.limits = append(f.limits, []string{unit, limit, value})
	f.lastAllowCfg = allowConfigWrite
	return f.errLimit
}
func (f *fakeTweaks) SetUnitOverride(unit, name, content string, allowConfigWrite []string) error {
	f.overrides = append(f.overrides, []string{unit, name, content})
	f.lastAllowCfg = allowConfigWrite
	return f.errOverride
}

type sysTwkHarness struct {
	priv ed25519.PrivateKey
	out  *fakeOut
	ch   *channelConn
	tw   *fakeTweaks
}

func newSysTwkHarness(t *testing.T, avail bool) *sysTwkHarness {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	clearIdentity()
	if err := pinControlPublicKey(base64.StdEncoding.EncodeToString(pub), ptyTestHost); err != nil {
		t.Fatal(err)
	}
	// The mutation helpers verify the same lease against their own trust file.
	withHelperTrust(t, pub, ptyTestHost)
	h := &sysTwkHarness{priv: priv, out: newFakeOut(), tw: &fakeTweaks{avail: avail, getOut: "1\n"}}
	prev := sysTweaks
	sysTweaks = func() Tweaks { return h.tw }
	h.ch = newChannelConn(h.out, ptyTestHost)
	t.Cleanup(func() {
		h.ch.close("stopped")
		sysTweaks = prev
		clearIdentity()
	})
	return h
}

func (h *sysTwkHarness) send(t *testing.T, v interface{}) {
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
	// sys frames run off the read goroutine; wait for this one's result.
	h.ch.sysWait()
}

func (h *sysTwkHarness) result(t *testing.T, rid string) map[string]interface{} {
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

// tweakFrame signs a lease that matches the fields it carries.
func tweakFrame(t *testing.T, h *sysTwkHarness, rid, verb, key, value, unit, limit, name, content string, exp int64) map[string]interface{} {
	t.Helper()
	sha := ""
	if verb == "unit-override-set" {
		sha = sysSHA256Hex(content)
	}
	payload, err := sysTweakLeasePayload(verb, key, value, unit, limit, name, sha)
	if err != nil {
		t.Fatalf("lease payload: %v", err)
	}
	lease := signLease(t, h.priv, ptyTestHost, "sys_tweak", payload, exp)
	return map[string]interface{}{
		"type": "sys_tweak", "request_id": rid, "verb": verb, "key": key, "value": value,
		"unit": unit, "limit": limit, "name": name, "content": content, "lease": lease,
	}
}

func TestSysTweakSysctlGetHappyPath(t *testing.T) {
	h := newSysTwkHarness(t, true)
	rid := newSysRequestID(t)
	h.send(t, tweakFrame(t, h, rid, "sysctl-get", "net.ipv4.ip_forward", "", "", "", "", "", inFuture(time.Minute)))
	p := h.result(t, rid)
	if p["ok"] != true || p["output"] != "1\n" {
		t.Fatalf("unexpected result: %v", p)
	}
	if len(h.tw.gets) != 1 || h.tw.gets[0][0] != "net.ipv4.ip_forward" {
		t.Fatalf("gets=%v", h.tw.gets)
	}
}

func TestSysTweakSysctlSetHappyPath(t *testing.T) {
	// sysctl-set is privilege-separated now (sysctl_helper.go): the channel
	// hands off to the helper instead of calling the Tweaks backend. The
	// trigger stands in for systemd and runs the helper in-process; the write
	// seam is faked so no real /proc/sys knob is touched.
	h := newSysTwkHarness(t, true)
	withHelperStateDir(t)
	calls := withFakeWrite(t, nil)
	prev := sysctlHelperTrigger
	sysctlHelperTrigger = func(id string) error { runSysctlHelper([]string{id}); return nil }
	t.Cleanup(func() { sysctlHelperTrigger = prev })

	rid := newSysRequestID(t)
	h.send(t, tweakFrame(t, h, rid, "sysctl-set", "net.ipv4.ip_forward", "1", "", "", "", "", inFuture(time.Minute)))
	p := h.result(t, rid)
	if p["ok"] != true || p["key"] != "net.ipv4.ip_forward" {
		t.Fatalf("unexpected result: %v", p)
	}
	// The write went through the helper seam...
	if len(*calls) != 1 || (*calls)[0][0] != "/proc/sys/net/ipv4/ip_forward" || (*calls)[0][1] != "1" {
		t.Fatalf("helper write calls=%v", *calls)
	}
	// ...and NOT through the Phase 0 backend.
	if len(h.tw.sets) != 0 {
		t.Fatalf("sysctl-set must not call the backend any more: %v", h.tw.sets)
	}
}

func TestSysTweakResourceLimitHappyPath(t *testing.T) {
	// resource-limit-set is privilege-separated now
	// (systemd_override_helper.go): the channel hands off to the override
	// helper instead of calling the Tweaks backend. The trigger stands in for
	// systemd; the write seam is faked.
	h := newSysTwkHarness(t, true)
	withOverrideHelperStateDir(t)
	calls := withFakeOverrideWrite(t, nil)
	prev := overrideHelperTrigger
	overrideHelperTrigger = func(id string) error { runOverrideHelper([]string{id}); return nil }
	t.Cleanup(func() { overrideHelperTrigger = prev })

	rid := newSysRequestID(t)
	h.send(t, tweakFrame(t, h, rid, "resource-limit-set", "", "65536", "nginx.service", "LimitNOFILE", "", "", inFuture(time.Minute)))
	p := h.result(t, rid)
	if p["ok"] != true {
		t.Fatalf("unexpected result: %v", p)
	}
	// The helper rebuilt the drop-in body and path...
	wantPath := "/etc/systemd/system/nginx.service.d/limit-limitnofile.conf"
	wantBody := "[Service]\nLimitNOFILE=65536\n"
	if len(*calls) != 1 || (*calls)[0][0] != wantPath || (*calls)[0][1] != wantBody {
		t.Fatalf("helper write calls=%v", *calls)
	}
	// ...and NOT through the Phase 0 backend.
	if len(h.tw.limits) != 0 {
		t.Fatalf("resource-limit-set must not call the backend any more: %v", h.tw.limits)
	}
}

func TestSysTweakResourceLimitNeedsAValue(t *testing.T) {
	h := newSysTwkHarness(t, true)
	rid := newSysRequestID(t)
	// No value: the lease cannot be built (payload refuses it) so the agent
	// refuses before the backend is called.
	h.send(t, map[string]interface{}{
		"type": "sys_tweak", "request_id": rid, "verb": "resource-limit-set", "unit": "nginx.service", "limit": "LimitNOFILE",
		"lease": signLease(t, h.priv, ptyTestHost, "sys_tweak", "resource-limit-set\nnginx.service\nLimitNOFILE\n65536", inFuture(time.Minute)),
	})
	p := h.result(t, rid)
	if p["ok"] != false || p["error"] != "lease_required" {
		t.Fatalf("want lease_required, got %v", p)
	}
	if len(h.tw.limits) != 0 {
		t.Fatalf("nothing should have run, got %v", h.tw.limits)
	}
}

func TestSysTweakUnitOverrideHappyPath(t *testing.T) {
	// unit-override-set is privilege-separated now
	// (systemd_override_helper.go), through the same helper as
	// resource-limit-set. The trigger stands in for systemd; the write seam is
	// faked.
	h := newSysTwkHarness(t, true)
	withOverrideHelperStateDir(t)
	calls := withFakeOverrideWrite(t, nil)
	prev := overrideHelperTrigger
	overrideHelperTrigger = func(id string) error { runOverrideHelper([]string{id}); return nil }
	t.Cleanup(func() { overrideHelperTrigger = prev })

	rid := newSysRequestID(t)
	content := "[Service]\nLimitNOFILE=65536\n"
	h.send(t, tweakFrame(t, h, rid, "unit-override-set", "", "", "nginx.service", "", "limit-nofile", content, inFuture(time.Minute)))
	p := h.result(t, rid)
	if p["ok"] != true {
		t.Fatalf("unexpected result: %v", p)
	}
	// The write went through the helper seam (unit-override carries the body)...
	wantPath := "/etc/systemd/system/nginx.service.d/limit-nofile.conf"
	if len(*calls) != 1 || (*calls)[0][0] != wantPath || (*calls)[0][1] != content {
		t.Fatalf("helper write calls=%v", *calls)
	}
	// ...and NOT through the Phase 0 backend.
	if len(h.tw.overrides) != 0 {
		t.Fatalf("unit-override-set must not call the backend any more: %v", h.tw.overrides)
	}
}

func TestSysTweakRefusesWhenCapabilityAbsent(t *testing.T) {
	h := newSysTwkHarness(t, false)
	rid := newSysRequestID(t)
	h.send(t, tweakFrame(t, h, rid, "sysctl-set", "net.ipv4.ip_forward", "1", "", "", "", "", inFuture(time.Minute)))
	p := h.result(t, rid)
	if p["ok"] != false || p["error"] != "tweak_unsupported" {
		t.Fatalf("want tweak_unsupported, got %v", p)
	}
	if len(h.tw.sets) != 0 {
		t.Fatalf("nothing should have run, got %v", h.tw.sets)
	}
}

func TestSysTweakUnitOverrideRefusesTamperedBody(t *testing.T) {
	h := newSysTwkHarness(t, true)
	rid := newSysRequestID(t)
	// Lease signs the hash of "good\n"; the frame carries "evil\n".
	goodSHA := sysSHA256Hex("good\n")
	payload, _ := sysTweakLeasePayload("unit-override-set", "", "", "nginx.service", "", "limit-nofile", goodSHA)
	lease := signLease(t, h.priv, ptyTestHost, "sys_tweak", payload, inFuture(time.Minute))
	h.send(t, map[string]interface{}{
		"type": "sys_tweak", "request_id": rid, "verb": "unit-override-set", "unit": "nginx.service",
		"name": "limit-nofile", "content": "evil\n", "lease": lease,
	})
	p := h.result(t, rid)
	if p["ok"] != false || p["error"] != "lease_required" {
		t.Fatalf("want lease_required for tampered body, got %v", p)
	}
	if len(h.tw.overrides) != 0 {
		t.Fatalf("nothing should have run, got %v", h.tw.overrides)
	}
}

func TestSysTweakRefusesKeyNotInSignedLease(t *testing.T) {
	h := newSysTwkHarness(t, true)
	rid := newSysRequestID(t)
	payload, _ := sysTweakLeasePayload("sysctl-set", "net.ipv4.ip_forward", "1", "", "", "", "")
	lease := signLease(t, h.priv, ptyTestHost, "sys_tweak", payload, inFuture(time.Minute))
	// Frame key differs from the signed key.
	h.send(t, map[string]interface{}{
		"type": "sys_tweak", "request_id": rid, "verb": "sysctl-set", "key": "net.ipv4.conf.all.rp_filter", "value": "1", "lease": lease,
	})
	p := h.result(t, rid)
	if p["ok"] != false || p["error"] != "lease_required" {
		t.Fatalf("want lease_required for key mismatch, got %v", p)
	}
	if len(h.tw.sets) != 0 {
		t.Fatalf("nothing should have run, got %v", h.tw.sets)
	}
}

func TestSysTweakLeaseBindsVerb(t *testing.T) {
	h := newSysTwkHarness(t, true)
	rid := newSysRequestID(t)
	// Lease signed for sysctl-get cannot drive a sysctl-set.
	payload, _ := sysTweakLeasePayload("sysctl-get", "net.ipv4.ip_forward", "", "", "", "", "")
	lease := signLease(t, h.priv, ptyTestHost, "sys_tweak", payload, inFuture(time.Minute))
	h.send(t, map[string]interface{}{
		"type": "sys_tweak", "request_id": rid, "verb": "sysctl-set", "key": "net.ipv4.ip_forward", "value": "1", "lease": lease,
	})
	p := h.result(t, rid)
	if p["ok"] != false || p["error"] != "lease_required" {
		t.Fatalf("want lease_required for verb mismatch, got %v", p)
	}
	if len(h.tw.sets) != 0 {
		t.Fatalf("nothing should have run, got %v", h.tw.sets)
	}
}

func TestSysTweakRefusesExpiredLease(t *testing.T) {
	h := newSysTwkHarness(t, true)
	rid := newSysRequestID(t)
	h.send(t, tweakFrame(t, h, rid, "sysctl-get", "net.ipv4.ip_forward", "", "", "", "", "", time.Now().Add(-10*time.Minute).Unix()))
	p := h.result(t, rid)
	if p["ok"] != false || p["error"] != "lease_required" {
		t.Fatalf("want lease_required for expired lease, got %v", p)
	}
}

func TestSysTweakRefusesWrongKeyLease(t *testing.T) {
	h := newSysTwkHarness(t, true)
	rid := newSysRequestID(t)
	_, otherPriv, _ := ed25519.GenerateKey(rand.Reader)
	payload, _ := sysTweakLeasePayload("sysctl-get", "net.ipv4.ip_forward", "", "", "", "", "")
	lease := signLease(t, otherPriv, ptyTestHost, "sys_tweak", payload, inFuture(time.Minute))
	h.send(t, map[string]interface{}{
		"type": "sys_tweak", "request_id": rid, "verb": "sysctl-get", "key": "net.ipv4.ip_forward", "lease": lease,
	})
	p := h.result(t, rid)
	if p["ok"] != false || p["error"] != "lease_required" {
		t.Fatalf("want lease_required for wrong key, got %v", p)
	}
}

func TestSysTweakReportsActionFailure(t *testing.T) {
	// A failed sysctl write surfaces as action_failed. The failure now comes
	// from the helper (its write seam returns an error), not the backend.
	h := newSysTwkHarness(t, true)
	withHelperStateDir(t)
	withFakeWrite(t, os.ErrPermission) // the sandbox denies the write
	prev := sysctlHelperTrigger
	sysctlHelperTrigger = func(id string) error { runSysctlHelper([]string{id}); return nil }
	t.Cleanup(func() { sysctlHelperTrigger = prev })

	rid := newSysRequestID(t)
	h.send(t, tweakFrame(t, h, rid, "sysctl-set", "net.ipv4.ip_forward", "1", "", "", "", "", inFuture(time.Minute)))
	p := h.result(t, rid)
	if p["ok"] != false || p["error"] != "action_failed" {
		t.Fatalf("want action_failed, got %v", p)
	}
}

func TestSysTweakLeasePayloadBuilder(t *testing.T) {
	cases := []struct {
		verb, key, value, unit, limit, name, sha, want string
	}{
		{"sysctl-get", "net.ipv4.ip_forward", "", "", "", "", "", "sysctl-get\nnet.ipv4.ip_forward"},
		{"sysctl-set", "net.ipv4.ip_forward", "1", "", "", "", "", "sysctl-set\nnet.ipv4.ip_forward\n1"},
		{"resource-limit-set", "", "", "nginx.service", "LimitNOFILE", "", "", "resource-limit-set\nnginx.service\nLimitNOFILE\n"},
	}
	for _, c := range cases {
		value := c.value
		if c.verb == "resource-limit-set" {
			value = "65536"
			c.want += "65536"
		}
		got, err := sysTweakLeasePayload(c.verb, c.key, value, c.unit, c.limit, c.name, c.sha)
		if err != nil || got != c.want {
			t.Fatalf("%s: payload %q err %v", c.verb, got, err)
		}
	}
	sha := sysSHA256Hex("body\n")
	if got, err := sysTweakLeasePayload("unit-override-set", "", "", "nginx.service", "", "limit-nofile", sha); err != nil || got != "unit-override-set\nnginx.service\nlimit-nofile\n"+sha {
		t.Fatalf("override payload %q err %v", got, err)
	}
	for _, c := range []struct {
		verb, key, value, unit, limit, name, sha, label string
	}{
		{"bogus", "", "", "", "", "", "", "unknown verb"},
		{"sysctl-get", "kernel.core_pattern", "", "", "", "", "", "hard-denied sysctl"},
		{"sysctl-set", "net.ipv4.ip_forward", "bad\nvalue", "", "", "", "", "newline in value"},
		{"resource-limit-set", "", "", "nginx.service", "LimitNope", "", "", "unknown limit"},
		{"resource-limit-set", "", "", "nginx.service", "LimitNOFILE", "", "", "limit missing value"},
		{"unit-override-set", "", "", "nginx.service", "", "bad name!", "", "bad override name"},
		{"unit-override-set", "", "", "nginx.service", "", "ok", "nothex", "bad content hash"},
	} {
		value := c.value
		if c.label == "limit missing value" {
			value = ""
		}
		if _, err := sysTweakLeasePayload(c.verb, c.key, value, c.unit, c.limit, c.name, c.sha); err == nil {
			t.Fatalf("%s: accepted", c.label)
		}
	}
}
