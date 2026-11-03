//go:build linux

package main

import (
	"fmt"
	"testing"

	"golang.org/x/sys/unix"
)

// Only an openat2 refusal (ENOSYS, EPERM) flips the stored state to failed;
// a transient error such as EMFILE is returned but leaves it alone.
func TestOpenat2TransientErrorKeepsState(t *testing.T) {
	prev := openat2State.Load()
	defer openat2State.Store(prev)

	openat2State.Store(1)
	if err := recordOpenat2(unix.EMFILE); err == nil {
		t.Fatal("EMFILE swallowed")
	}
	if openat2State.Load() != 1 || !openat2Available() {
		t.Fatal("EMFILE flipped the openat2 state")
	}
	if err := recordOpenat2(fmt.Errorf("wrapped: %w", unix.ENOMEM)); err == nil || openat2State.Load() != 1 {
		t.Fatal("ENOMEM flipped the openat2 state")
	}

	for _, refusal := range []error{unix.ENOSYS, unix.EPERM} {
		openat2State.Store(1)
		if recordOpenat2(refusal) == nil || openat2State.Load() != 2 || openat2Available() {
			t.Fatalf("%v did not store the failed state", refusal)
		}
		// A transient error while failed keeps it failed.
		if recordOpenat2(unix.EMFILE) == nil || openat2State.Load() != 2 {
			t.Fatal("EMFILE changed the failed state")
		}
	}
	if recordOpenat2(nil) != nil || openat2State.Load() != 1 {
		t.Fatal("success did not restore the state")
	}
}
