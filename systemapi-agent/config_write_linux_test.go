//go:build linux

package main

// Negative tests for the helpers' atomic write primitive (config_write_linux.go).
// Threats: a symlink in any parent directory of the target redirecting a root
// /etc write somewhere else (for example a config dir swapped for a link to
// /etc/systemapi-agent), and a relative or unclean target.

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// TestWriteFileAtomicSyncReplacesContent proves the real write seam actually
// lands the bytes (temp-file, fsync, rename) in a temp dir, so the fake used by
// the other tests is standing in for a working primitive.
func TestWriteFileAtomicSyncReplacesContent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "x.conf")
	if err := os.WriteFile(path, []byte("old\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := writeFileAtomicSync(path, "new\n", 0o644); err != nil {
		t.Fatalf("writeFileAtomicSync: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "new\n" {
		t.Fatalf("content=%q, want new", got)
	}
	// No temp file left behind.
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Fatalf("stray files: %v", entries)
	}
}

func TestWriteFileAtomicSyncRefusesSymlinkedParent(t *testing.T) {
	base := t.TempDir()
	real := filepath.Join(base, "protected")
	if err := os.Mkdir(real, 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "granted")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	// Symlink as the immediate parent, and as a grandparent.
	if err := os.Mkdir(filepath.Join(real, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{filepath.Join(link, "x.conf"), filepath.Join(link, "sub", "x.conf")} {
		if err := writeFileAtomicSync(target, "evil\n", 0o644); err == nil {
			t.Fatalf("%s: a symlinked parent must be refused", target)
		}
	}
	for _, p := range []string{filepath.Join(real, "x.conf"), filepath.Join(real, "sub", "x.conf")} {
		if _, err := os.Lstat(p); !os.IsNotExist(err) {
			t.Fatalf("write landed through the symlink at %s: %v", p, err)
		}
	}
	entries, _ := os.ReadDir(real)
	if len(entries) != 1 {
		t.Fatalf("stray files in the link target: %v", entries)
	}
}

func TestWriteFileAtomicSyncRefusesBadPath(t *testing.T) {
	dir := t.TempDir()
	for _, p := range []string{"rel/x.conf", dir + "/../x.conf", dir + "//x.conf", "/"} {
		if err := writeFileAtomicSync(p, "x\n", 0o644); err == nil {
			t.Fatalf("%q must be refused", p)
		}
	}
}

// A failed directory fsync means the rename may not survive a crash; the
// write must report it, not claim success.
func TestWriteFileAtomicSyncReportsDirSyncFailure(t *testing.T) {
	prev := atomicDirSync
	atomicDirSync = func(int) error { return errors.New("injected fsync failure") }
	t.Cleanup(func() { atomicDirSync = prev })
	path := filepath.Join(t.TempDir(), "x.conf")
	if err := writeFileAtomicSync(path, "x\n", 0o644); err == nil {
		t.Fatal("a directory fsync failure must be returned")
	}
}
