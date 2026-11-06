//go:build linux

package main

import (
	"errors"
	"testing"
)

func TestSashFileWriteDefaultDeniesBeforeSpawn(t *testing.T) {
	_, err := sashFileWriteDefault(nil, "/tmp", "a", []byte("x"))
	if !errors.Is(err, errSashDenied) {
		t.Fatalf("nil id: %v", err)
	}
	for _, rel := range []string{".", "/abs", "..", "a/../b"} {
		_, err = sashFileWriteDefault(&ptyIdentity{}, "/tmp", rel, []byte("x"))
		if !errors.Is(err, errSashDenied) {
			t.Fatalf("%s: %v", rel, err)
		}
	}
	_, err = sashFileWriteDefault(&ptyIdentity{}, "/tmp", "a", make([]byte, fileReadMax+1))
	if !errors.Is(err, errSashDenied) {
		t.Fatalf("oversize: %v", err)
	}
}
