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
