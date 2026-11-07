package main

// helperAuthorize / helperPreflight with intents (contract 1.6; N28) and the
// approval classes the agent derives per lease (contract 3.1, 5.1).

import (
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestHelperIntentAndPin(t *testing.T) {
	priv := newHelperSigner(t)
	dir := withConfigHelperStateDir(t)
	calls := withFakeConfigWrite(t, nil)
	withRequireIntent(t, "")
	ih := &intentHarness{priv: priv, now: time.Now()}
	target, content := "/etc/nginx/nginx.conf", "server {}\n"
	payload, err := sysConfigLeasePayload("write", target, sysSHA256Hex(content))
	if err != nil {
		t.Fatal(err)
	}
	exp := inFuture(time.Minute)
	run := func(l *Lease, intent string) configHelperRes {
		return runConfigReq(t, dir, configHelperReq{Target: target, Content: content, Lease: l, Intent: intent})
	}
	want := func(name string, res configHelperRes, code string) {
		t.Helper()
		if code == "" && !res.OK || code != "" && res.Error != code {
			t.Fatalf("%s: %+v, want %q", name, res, code)
		}
	}
	// N28: new helper, no pin, a v1 lease without intent is accepted.
	want("N28 v1 no pin", run(signLease(t, priv, ptyTestHost, "sys_config", payload, exp), ""), "")
	text := ih.intent(t, "sys_config", payload, 0, nil)
	v2 := func() *Lease { return signLeaseV2(t, priv, ptyTestHost, "sys_config", payload, sha256Hex(text), exp) }
	want("v2", run(v2(), text), "")
	// N28: with the pin, the same v1 lease shape is refused.
	withRequireIntent(t, "sys-write\n")
	before := len(*calls)
	want("N28 v1 pinned", run(signLease(t, priv, ptyTestHost, "sys_config", payload, exp), ""), "intent_required")
	want("v2 pinned", run(v2(), text), "")
	want("v2 without intent", run(v2(), ""), "intent_mismatch")
	want("v1 with intent", run(signLease(t, priv, ptyTestHost, "sys_config", payload, exp), text), "intent_unexpected")
	other, _ := sysConfigLeasePayload("write", "/etc/nginx/other.conf", sysSHA256Hex(content))
	otherText := ih.intent(t, "sys_config", other, 0, nil)
	want("intent for another target", run(signLeaseV2(t, priv, ptyTestHost, "sys_config", payload, sha256Hex(otherText), exp), otherText), "intent_mismatch")
	stale := ih.intent(t, "sys_config", payload, 0, func(f *intentFields) {
		f.NotBefore, f.UseBy = ih.now.Unix()-3000, ih.now.Unix()-1000
	})
	want("helper own clock past use_by", run(signLeaseV2(t, priv, ptyTestHost, "sys_config", payload, sha256Hex(stale), exp), stale), "intent_window")
	withRequireIntent(t, "sys-write\nbogus\n")
	want("damaged pin", run(v2(), text), "intent_pin_unavailable")
	if got := len(*calls) - before; got != 1 {
		t.Fatalf("%d writes after the pin, want 1 (only the v2 lease)", got)
	}
}

func TestHelperPreflightIntent(t *testing.T) {
	priv := newHelperSigner(t)
	withConfigHelperStateDir(t)
	withFakeConfigWrite(t, nil)
	withRequireIntent(t, "sys-write\n")
	ih := &intentHarness{priv: priv, now: time.Now()}
	var triggered atomic.Int32
	prev := configHelperTrigger
	configHelperTrigger = func(id string) error {
		triggered.Add(1)
		runConfigHelper([]string{id})
		return nil
	}
	t.Cleanup(func() { configHelperTrigger = prev })
	target, content := "/etc/nginx/nginx.conf", "server {}\n"
	payload, _ := sysConfigLeasePayload("write", target, sysSHA256Hex(content))
	// A pinned v1 lease never starts the helper unit (the H0 rule, now with
	// the pin).
	err := configWriteViaHelper(target, content, signLease(t, priv, ptyTestHost, "sys_config", payload, inFuture(time.Minute)), "")
	if err == nil || !strings.Contains(err.Error(), "intent_required") || triggered.Load() != 0 {
		t.Fatalf("pinned v1: %v triggered=%d", err, triggered.Load())
	}
	text := ih.intent(t, "sys_config", payload, 0, nil)
	l := signLeaseV2(t, priv, ptyTestHost, "sys_config", payload, sha256Hex(text), inFuture(time.Minute))
	if err := configWriteViaHelper(target, content, l, "garbage"); err == nil || triggered.Load() != 0 {
		t.Fatalf("wrong intent text: %v triggered=%d", err, triggered.Load())
	}
	if err := configWriteViaHelper(target, content, l, text); err != nil || triggered.Load() != 1 {
		t.Fatalf("v2 handoff: %v triggered=%d", err, triggered.Load())
	}
}

func TestIntentClasses(t *testing.T) {
	cfgW, _ := sysConfigLeasePayload("write", "/etc/a", sha256Hex("x"))
	cfgR, _ := sysConfigLeasePayload("read", "/etc/a", "")
	sysctlGet, _ := sysTweakLeasePayload("sysctl-get", "vm.swappiness", "", "", "", "", "")
	sysctlSet, _ := sysTweakLeasePayload("sysctl-set", "vm.swappiness", "10", "", "", "", "")
	pkgQ, _ := sysPackageLeasePayload("nginx", "query")
	pkgI, _ := sysPackageLeasePayload("nginx", "install")
	for _, c := range []struct {
		action, payload string
		ents            *Entitlements
		want            string
	}{
		{"breakglass", "", nil, "breakglass"},
		{"pty_root", "", nil, "root-session"},
		{"file_root", "", nil, "root-session"},
		{"xfer_root", "", nil, "root-session"},
		{"pty", "", nil, ""},
		{"file", "", nil, ""},
		{"sys_config", cfgW, nil, "sys-write"},
		{"sys_config", cfgR, nil, ""},
		{"sys_tweak", sysctlGet, nil, ""},
		{"sys_tweak", sysctlSet, nil, "sys-write"},
		{"sys_service", "nginx.service\nrestart", nil, "sys-write"},
		{"sys_package", pkgQ, nil, ""},
		{"sys_package", pkgI, nil, "sys-write"},
		{"sysscript", "", &Entitlements{AllowFSRead: []string{"/var/log"}}, ""},
		{"sysscript", "", &Entitlements{AllowExec: true}, "sys-write,root-session"},
		{"sysscript_job", "", &Entitlements{AllowConfigWrite: []string{"/etc/x"}}, "sys-write,root-session"},
		{"converge_job", "j\n1\n1\na\nb\ncheck\n-", nil, ""},
		{"converge_job", "j\n1\n1\na\nb\napply\n" + strings.Repeat("c", 64), nil, "sys-write,root-session"},
	} {
		if got := strings.Join(intentClasses(c.action, c.payload, c.ents), ","); got != c.want {
			t.Fatalf("%s %q: %q, want %q", c.action, c.payload, got, c.want)
		}
	}
}
