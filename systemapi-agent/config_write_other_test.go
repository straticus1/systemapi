//go:build !linux

package main

import (
	"os"
	"path/filepath"
	"testing"
)

// Off Linux there is no openat2, so the helpers' write primitive cannot
// guarantee a symlink-free parent and must refuse outright.
func TestWriteFileAtomicSyncRefusesOffLinux(t *testing.T) {
	path := filepath.Join(t.TempDir(), "x.conf")
	if err := writeFileAtomicSync(path, "x\n", 0o644, nil); err == nil {
		t.Fatal("writeFileAtomicSync must refuse off Linux")
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("file written off Linux: %v", err)
	}
}
