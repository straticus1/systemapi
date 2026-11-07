package main

// helperAuthorize / helperPreflight with intents (contract 1.6; N28) and the
// approval classes the agent derives per lease (contract 3.1, 5.1).

import (
	"os"
	"path/filepath"
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

// N33 on the agent: the root-run sash verbs are dropped on a sys-write pin
// (or a damaged pin) whatever the grant says.
func TestSashRootVerbsDroppedOnSysWritePin(t *testing.T) {
	withRequireIntent(t, "")
	restarts := 0
	prevRestart := sashUnitRestart
	sashUnitRestart = func(string) (string, error) { restarts++; return "ok", nil }
	t.Cleanup(func() { sashUnitRestart = prevRestart })
	restart := func(purpose string) error {
		_, err := sashDispatch(sashGrant{Purpose: purpose, Entitlements: []string{"unit.restart"}}, sashTargets{Units: []string{"nginx"}}, sashLiveLease(), nil,
			sashCall{Key: "unit.restart", Argv: []string{"unit", "restart", "nginx"}})
		return err
	}
	if err := restart(sashPurposeOpen); err != nil || restarts != 1 {
		t.Fatalf("no pin: %v %d", err, restarts)
	}
	for _, body := range []string{"sys-write\n", "breakglass\nbogus\n"} {
		withRequireIntent(t, body)
		for _, p := range []string{sashPurposeOpen, sashPurposeRoot} {
			if err := restart(p); err == nil {
				t.Fatalf("pin %q purpose %s: restart allowed", body, p)
			}
		}
	}
	if restarts != 1 {
		t.Fatalf("helper called %d times", restarts)
	}
	g := sashGrant{Entitlements: []string{"package.install", "sysctl.set", "file.write"}}
	withRequireIntent(t, "sys-write\n")
	for _, k := range []string{"package.install", "sysctl.set"} {
		if !sashPinDenied(g, k) {
			t.Fatalf("%s not dropped", k)
		}
	}
	g.Purpose = sashPurposeOpen
	if sashPinDenied(g, "file.write") {
		t.Fatal("plain pty file.write dropped (it runs as the pty user)")
	}
	g.Purpose = sashPurposeRoot
	if !sashPinDenied(g, "file.write") {
		t.Fatal("pty_root file.write kept")
	}
	if sashPinDenied(g, "unit.status") || sashPinDenied(g, "file.read") {
		t.Fatal("read verb dropped")
	}
	withRequireIntent(t, "breakglass\n")
	if sashPinDenied(g, "unit.restart") {
		t.Fatal("dropped without a sys-write pin")
	}
}

// A missing pin file in an untrusted directory is not "no pin".
func TestRequireIntentMissingFileUntrustedDir(t *testing.T) {
	path := withRequireIntent(t, "")
	if got, err := loadRequireIntent(); err != nil || len(got) != 0 {
		t.Fatalf("trusted dir, no file: %v %v", got, err)
	}
	if err := os.Chmod(filepath.Dir(path), 0o777); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(filepath.Dir(path), 0o755) })
	if _, err := loadRequireIntent(); err == nil {
		t.Fatal("world-writable pin dir with no file accepted as no pin")
	}
	if requireIntentHeader() != "invalid" {
		t.Fatal("header")
	}
	requireIntentPath = filepath.Join(t.TempDir(), "absent", "require-intent")
	if got, err := loadRequireIntent(); err != nil || got != nil {
		t.Fatalf("no directory: %v %v", got, err)
	}
}
