//go:build !linux

package main

import (
	"os"
	"path/filepath"
	"testing"
)

// Off Linux the root config read cannot rule out a symlinked parent, so it
// must refuse outright.
func TestSysConfigReadBeneathRefusesOffLinux(t *testing.T) {
	path := filepath.Join(t.TempDir(), "x.conf")
	if err := os.WriteFile(path, []byte("x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got, err := sysConfigReadBeneath(path); err == nil {
		t.Fatalf("read off Linux: %q", got)
	}
}
