package main

// Negative tests for the agent-side helper pre-flight (helperPreflight,
// helper_auth.go), run through each mutation helper's trigger seam.
//
// Threats exercised: a non-nil lease of the wrong capability (a terminal
// pty_root lease, as a sash session holds), a lease for another target or
// content, an expired, wrong-host or badly signed lease, a lease the agent has
// already dispatched, and an agent with no pinned control key. Each must be
// refused BEFORE the privileged helper unit is started: the trigger seam is
// never called. A valid lease triggers exactly once, and the helper (run
// in-process) still accepts it, so the pre-flight does not spend the helper's
// durable nonce; a lease that already passed the channel gate
// (authorizeCommand) still passes, so the two agent-side records do not
// collide.

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type preflightCase struct {
	name string
	// lease signs a lease for this helper over the given target/content
	// variant ("" = the one run uses).
	lease func(t *testing.T, priv ed25519.PrivateKey, host, variant string, exp int64) *Lease
	// setup points the handoff dir and write seam at temp state, installs
	// trigger as the helper's trigger seam, and returns the handoff dir.
	setup func(t *testing.T, trigger func(id string) error) string
	run   func(lease *Lease) error
	// helper runs the real helper subcommand for id in-process.
	helper func(id string)
}

func preflightCases() []preflightCase {
	return []preflightCase{
		{
			name: "config",
			lease: func(t *testing.T, priv ed25519.PrivateKey, host, variant string, exp int64) *Lease {
				target, content := "/etc/nginx/nginx.conf", "server {}\n"
				switch variant {
				case "target":
					target = "/etc/nginx/other.conf"
				case "content":
					content = "server { listen 81; }\n"
				}
				payload, err := sysConfigLeasePayload("write", target, sysSHA256Hex(content))
				if err != nil {
					t.Fatal(err)
				}
				return signLease(t, priv, host, "sys_config", payload, exp)
			},
			setup: func(t *testing.T, trigger func(string) error) string {
				dir := withConfigHelperStateDir(t)
				withFakeConfigWrite(t, nil)
				prev := configHelperTrigger
				configHelperTrigger = trigger
				t.Cleanup(func() { configHelperTrigger = prev })
				return dir
			},
			run: func(l *Lease) error {
				return configWriteViaHelper("/etc/nginx/nginx.conf", "server {}\n", l)
			},
			helper: func(id string) { runConfigHelper([]string{id}) },
		},
		{
			name: "sysctl",
			lease: func(t *testing.T, priv ed25519.PrivateKey, host, variant string, exp int64) *Lease {
				key, value := "vm.swappiness", "10"
				switch variant {
				case "target":
					key = "net.ipv4.ip_forward"
				case "content":
					value = "20"
				}
				payload, err := sysTweakLeasePayload("sysctl-set", key, value, "", "", "", "")
				if err != nil {
					t.Fatal(err)
				}
				return signLease(t, priv, host, "sys_tweak", payload, exp)
			},
			setup: func(t *testing.T, trigger func(string) error) string {
				dir := withHelperStateDir(t)
				withFakeWrite(t, nil)
				prev := sysctlHelperTrigger
				sysctlHelperTrigger = trigger
				t.Cleanup(func() { sysctlHelperTrigger = prev })
				return dir
			},
			run:    func(l *Lease) error { return sysctlSetViaHelper("vm.swappiness", "10", l) },
			helper: func(id string) { runSysctlHelper([]string{id}) },
		},
		{
			name: "override",
			lease: func(t *testing.T, priv ed25519.PrivateKey, host, variant string, exp int64) *Lease {
				unit, content := "nginx.service", "[Service]\nLimitNOFILE=1024\n"
				switch variant {
				case "target":
					unit = "redis.service"
				case "content":
					content = "[Service]\nLimitNOFILE=2048\n"
				}
				payload, err := sysTweakLeasePayload("unit-override-set", "", "", unit, "", "limit-nofile", sysSHA256Hex(content))
				if err != nil {
					t.Fatal(err)
				}
				return signLease(t, priv, host, "sys_tweak", payload, exp)
			},
			setup: func(t *testing.T, trigger func(string) error) string {
				dir := withOverrideHelperStateDir(t)
				withFakeOverrideWrite(t, nil)
				prev := overrideHelperTrigger
				overrideHelperTrigger = trigger
				t.Cleanup(func() { overrideHelperTrigger = prev })
				return dir
			},
			run: func(l *Lease) error {
				return unitOverrideSetViaHelper("nginx.service", "limit-nofile", "[Service]\nLimitNOFILE=1024\n", l)
			},
			helper: func(id string) { runOverrideHelper([]string{id}) },
		},
		{
			name: "resource-limit",
			lease: func(t *testing.T, priv ed25519.PrivateKey, host, variant string, exp int64) *Lease {
				unit, value := "nginx.service", "1024"
				switch variant {
				case "target":
					unit = "redis.service"
				case "content":
					value = "2048"
				}
				payload, err := sysTweakLeasePayload("resource-limit-set", "", value, unit, "LimitNOFILE", "", "")
				if err != nil {
					t.Fatal(err)
				}
				return signLease(t, priv, host, "sys_tweak", payload, exp)
			},
			setup: func(t *testing.T, trigger func(string) error) string {
				dir := withOverrideHelperStateDir(t)
				withFakeOverrideWrite(t, nil)
				prev := overrideHelperTrigger
				overrideHelperTrigger = trigger
				t.Cleanup(func() { overrideHelperTrigger = prev })
				return dir
			},
			run: func(l *Lease) error {
				return resourceLimitSetViaHelper("nginx.service", "LimitNOFILE", "1024", l)
			},
			helper: func(id string) { runOverrideHelper([]string{id}) },
		},
	}
}

// assertNoHandoff fails unless dir (removed before the call) still does not
// exist: a denial wrote no request file and did not create the handoff dir.
func assertNoHandoff(t *testing.T, dir string) {
	t.Helper()
	if _, err := os.Lstat(dir); !os.IsNotExist(err) {
		t.Fatalf("handoff dir %s exists after a denial (err=%v)", dir, err)
	}
}

func TestHelperPreflightRefusesBeforeTrigger(t *testing.T) {
	for _, hc := range preflightCases() {
		bad := []struct {
			name  string
			code  string
			lease func(t *testing.T, priv ed25519.PrivateKey) *Lease
		}{
			{"nil", "lease_missing", func(*testing.T, ed25519.PrivateKey) *Lease { return nil }},
			{"terminal pty_root lease", "lease_bad_action", func(t *testing.T, priv ed25519.PrivateKey) *Lease {
				exp := inFuture(time.Minute)
				return signLease(t, priv, ptyTestHost, "pty_root", terminalPayload(newSessionID(t), exp, "start"), exp)
			}},
			{"other target", "lease_payload_mismatch", func(t *testing.T, priv ed25519.PrivateKey) *Lease {
				return hc.lease(t, priv, ptyTestHost, "target", inFuture(time.Minute))
			}},
			{"other content", "lease_payload_mismatch", func(t *testing.T, priv ed25519.PrivateKey) *Lease {
				return hc.lease(t, priv, ptyTestHost, "content", inFuture(time.Minute))
			}},
			{"expired", "lease_expired", func(t *testing.T, priv ed25519.PrivateKey) *Lease {
				return hc.lease(t, priv, ptyTestHost, "", time.Now().Add(-2*time.Minute).Unix())
			}},
			{"wrong host", "lease_bad_host", func(t *testing.T, priv ed25519.PrivateKey) *Lease {
				return hc.lease(t, priv, "44444444-4444-4444-8444-444444444444", "", inFuture(time.Minute))
			}},
			{"bad signature", "lease_bad_signature", func(t *testing.T, priv ed25519.PrivateKey) *Lease {
				_, other, err := ed25519.GenerateKey(rand.Reader)
				if err != nil {
					t.Fatal(err)
				}
				return hc.lease(t, other, ptyTestHost, "", inFuture(time.Minute))
			}},
		}
		for _, bc := range bad {
			t.Run(hc.name+"/"+bc.name, func(t *testing.T) {
				priv := newHelperSigner(t)
				dir := hc.setup(t, func(string) error { t.Error("helper triggered"); return nil })
				if err := os.Remove(dir); err != nil {
					t.Fatal(err)
				}
				err := hc.run(bc.lease(t, priv))
				if err == nil || !strings.HasSuffix(err.Error(), ": "+bc.code) {
					t.Fatalf("err=%v, want code %s", err, bc.code)
				}
				assertNoHandoff(t, dir)
			})
		}
		t.Run(hc.name+"/not enrolled", func(t *testing.T) {
			priv := newHelperSigner(t)
			l := hc.lease(t, priv, ptyTestHost, "", inFuture(time.Minute))
			clearIdentity()
			dir := hc.setup(t, func(string) error { t.Error("helper triggered"); return nil })
			if err := os.Remove(dir); err != nil {
				t.Fatal(err)
			}
			if err := hc.run(l); err == nil || !strings.HasSuffix(err.Error(), ": not_enrolled") {
				t.Fatalf("err=%v, want not_enrolled", err)
			}
			assertNoHandoff(t, dir)
		})
	}
}

// A valid lease triggers the helper exactly once and the helper accepts it;
// the same lease again is refused as a replay before any second trigger.
func TestHelperPreflightValidTriggersOnceThenReplayRefused(t *testing.T) {
	for _, hc := range preflightCases() {
		t.Run(hc.name, func(t *testing.T) {
			priv := newHelperSigner(t)
			calls := 0
			hc.setup(t, func(id string) error { calls++; hc.helper(id); return nil })
			l := hc.lease(t, priv, ptyTestHost, "", inFuture(time.Minute))
			if err := hc.run(l); err != nil {
				t.Fatalf("valid lease: %v", err)
			}
			if calls != 1 {
				t.Fatalf("trigger calls=%d, want 1", calls)
			}
			if err := hc.run(l); err == nil || !strings.HasSuffix(err.Error(), ": replay") {
				t.Fatalf("replay: err=%v, want replay", err)
			}
			if calls != 1 {
				t.Fatalf("replay reached the trigger: calls=%d", calls)
			}
		})
	}
}

// A lease the channel gate already consumed (authorizeCommand records the
// nonce) still passes the pre-flight and the helper, which consumes it once.
// Restarting the agent (clearing its cache) does not let it run twice: the
// helper's durable store refuses it.
func TestHelperPreflightAfterChannelGate(t *testing.T) {
	hc := preflightCases()[0]
	priv := newHelperSigner(t)
	calls := 0
	hc.setup(t, func(id string) error { calls++; hc.helper(id); return nil })
	l := hc.lease(t, priv, ptyTestHost, "", inFuture(time.Minute))
	payload, err := sysConfigLeasePayload("write", "/etc/nginx/nginx.conf", sysSHA256Hex("server {}\n"))
	if err != nil {
		t.Fatal(err)
	}
	if err := authorizeCommand(ptyTestHost, "sys_config", payload, l, time.Now()); err != nil {
		t.Fatalf("authorizeCommand: %v", err)
	}
	if err := hc.run(l); err != nil {
		t.Fatalf("after channel gate: %v", err)
	}
	resetNonceCache()
	if err := hc.run(l); err == nil || !strings.HasSuffix(err.Error(), ": replay") {
		t.Fatalf("after agent cache reset: err=%v, want the helper's replay", err)
	}
	if calls != 2 {
		t.Fatalf("trigger calls=%d, want 2 (second refused by the helper)", calls)
	}
}

// Two concurrent handoffs with one valid lease: exactly one triggers the
// helper, the other is refused as a replay by the pre-flight.
func TestHelperPreflightConcurrentOneLease(t *testing.T) {
	for _, hc := range preflightCases() {
		t.Run(hc.name, func(t *testing.T) {
			priv := newHelperSigner(t)
			var calls atomic.Int32
			hc.setup(t, func(id string) error { calls.Add(1); hc.helper(id); return nil })
			l := hc.lease(t, priv, ptyTestHost, "", inFuture(time.Minute))
			var wg sync.WaitGroup
			start := make(chan struct{})
			errs := make([]error, 2)
			for i := range errs {
				wg.Add(1)
				go func(i int) {
					defer wg.Done()
					<-start
					errs[i] = hc.run(l)
				}(i)
			}
			close(start)
			wg.Wait()
			ok, replay := 0, 0
			for _, err := range errs {
				switch {
				case err == nil:
					ok++
				case strings.HasSuffix(err.Error(), ": replay"):
					replay++
				default:
					t.Errorf("unexpected err: %v", err)
				}
			}
			if ok != 1 || replay != 1 || calls.Load() != 1 {
				t.Fatalf("ok=%d replay=%d triggers=%d, want 1/1/1", ok, replay, calls.Load())
			}
		})
	}
}
