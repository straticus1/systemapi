//go:build unix

package main

// The replay-lock test needs flock(2), so it runs only where the helpers do.

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// The exclusive flock must be held while an expired entry is pruned and while
// the new nonce is recorded: O_EXCL alone does not serialise check+prune+
// record across helper processes (the count against helperReplayMax and a
// prune racing a consume both depend on it). The hook takes a second open
// file description of the lock and tries a non-blocking exclusive lock, which
// must fail while the consume holds it.
func TestHelperAuthReplayLockHeldDuringPruneAndRecord(t *testing.T) {
	newHelperSigner(t)
	now := time.Now()
	old := "0123456789abcdef0123456789abcdef"
	if err := consumeHelperNonce(old, now.Add(-time.Hour).Unix(), now.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	prev := helperReplayHook
	helperReplayHook = func(stage string) {
		seen[stage] = true
		f, err := os.OpenFile(filepath.Join(helperReplayDir, helperReplayLockName), os.O_RDWR, 0)
		if err != nil {
			t.Errorf("%s: open lock: %v", stage, err)
			return
		}
		defer f.Close()
		err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			t.Errorf("%s: replay lock is not held", stage)
			return
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) {
			t.Errorf("%s: flock: %v", stage, err)
		}
	}
	t.Cleanup(func() { helperReplayHook = prev })
	if err := consumeHelperNonce("fedcba9876543210fedcba9876543210", now.Add(time.Minute).Unix(), now); err != nil {
		t.Fatal(err)
	}
	if !seen["prune"] || !seen["record"] {
		t.Fatalf("hook stages seen: %v, want prune and record", seen)
	}
}

// Each helper and its agent-side handoff refuse a handoff directory that is a
// symlink, not a directory, not mode 0700, or not owned by root (the test's
// uid here): request files are never read or written through it, and the
// helper unit is never triggered.
func TestHelpersRefuseUntrustedHandoffDir(t *testing.T) {
	cases := []struct {
		name  string
		setup func(t *testing.T, dir string) string
	}{
		{"symlink", func(t *testing.T, dir string) string {
			link := filepath.Join(t.TempDir(), "link")
			if err := os.Symlink(dir, link); err != nil {
				t.Fatal(err)
			}
			return link
		}},
		{"not a directory", func(t *testing.T, dir string) string {
			f := filepath.Join(t.TempDir(), "file")
			if err := os.WriteFile(f, nil, 0o700); err != nil {
				t.Fatal(err)
			}
			return f
		}},
		{"mode 0755", func(t *testing.T, dir string) string {
			if err := os.Chmod(dir, 0o755); err != nil {
				t.Fatal(err)
			}
			return dir
		}},
		{"wrong owner", func(t *testing.T, dir string) string {
			helperHandoffOwnerUID = uint32(os.Getuid()) + 1
			return dir
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			lease := &Lease{}
			// config helper
			cdir := tc.setup(t, withConfigHelperStateDir(t))
			configHelperStateDir = cdir
			prevTrig := configHelperTrigger
			configHelperTrigger = func(string) error { t.Error("config helper triggered"); return nil }
			t.Cleanup(func() { configHelperTrigger = prevTrig })
			if err := configWriteViaHelper("/etc/nginx/nginx.conf", "x\n", lease); err == nil {
				t.Fatal("config: agent side accepted the handoff dir")
			}
			if code := runConfigHelper([]string{testHelperID}); code != 2 {
				t.Fatalf("config: helper exit=%d, want 2", code)
			}
			// sysctl helper
			sdir := tc.setup(t, withHelperStateDir(t))
			sysctlHelperStateDir = sdir
			prevS := sysctlHelperTrigger
			sysctlHelperTrigger = func(string) error { t.Error("sysctl helper triggered"); return nil }
			t.Cleanup(func() { sysctlHelperTrigger = prevS })
			if err := sysctlSetViaHelper("vm.swappiness", "10", lease); err == nil {
				t.Fatal("sysctl: agent side accepted the handoff dir")
			}
			if code := runSysctlHelper([]string{testHelperID}); code != 2 {
				t.Fatalf("sysctl: helper exit=%d, want 2", code)
			}
			// systemd override helper
			odir := tc.setup(t, withOverrideHelperStateDir(t))
			overrideHelperStateDir = odir
			if code := runOverrideHelper([]string{testHelperID}); code != 2 {
				t.Fatalf("override: helper exit=%d, want 2", code)
			}
		})
	}
}
