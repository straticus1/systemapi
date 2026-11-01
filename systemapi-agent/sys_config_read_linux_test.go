//go:build linux

package main

// Negative tests for the root sys:config read (sys_config_read_linux.go).
// Threats: a symlinked parent directory or final component inside a granted
// path carrying a root read to /etc/shadow or the agent's own state, a hard
// link that is a second name for a protected file, a FIFO that blocks the
// read, and an unbounded read.

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestSysConfigReadBeneathHappyPathAndCap(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "app.conf")
	if err := os.WriteFile(path, []byte("listen 80;\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := sysConfigReadBeneath(path)
	if err != nil || got != "listen 80;\n" {
		t.Fatalf("got %q %v", got, err)
	}
	big := filepath.Join(dir, "big.conf")
	if err := os.WriteFile(big, []byte(strings.Repeat("x", sysConfigReadMax+100)), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err = sysConfigReadBeneath(big)
	if err != nil || len(got) != sysConfigReadMax {
		t.Fatalf("cap: len=%d err=%v", len(got), err)
	}
}

func TestSysConfigReadBeneathRefusesSymlinks(t *testing.T) {
	base := t.TempDir()
	protected := filepath.Join(base, "protected")
	if err := os.MkdirAll(filepath.Join(protected, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{filepath.Join(protected, "shadow"), filepath.Join(protected, "sub", "shadow")} {
		if err := os.WriteFile(p, []byte("root:secret\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	granted := filepath.Join(base, "granted")
	if err := os.Mkdir(granted, 0o755); err != nil {
		t.Fatal(err)
	}
	// A symlinked parent inside the grant (absolute and relative), a
	// symlinked grandparent, and a symlinked final component.
	if err := os.Symlink(protected, filepath.Join(granted, "abs")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../protected", filepath.Join(granted, "rel")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(protected, "shadow"), filepath.Join(granted, "final.conf")); err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{
		filepath.Join(granted, "abs", "shadow"),
		filepath.Join(granted, "rel", "shadow"),
		filepath.Join(granted, "abs", "sub", "shadow"),
		filepath.Join(granted, "final.conf"),
	} {
		if got, err := sysConfigReadBeneath(target); err == nil {
			t.Fatalf("%s: read through a symlink: %q", target, got)
		}
	}
}

func TestSysConfigReadBeneathRefusesHardLinkFifoDirAndBadPath(t *testing.T) {
	dir := t.TempDir()
	secret := filepath.Join(dir, "secret")
	if err := os.WriteFile(secret, []byte("s\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	hard := filepath.Join(dir, "hard.conf")
	if err := os.Link(secret, hard); err != nil {
		t.Fatal(err)
	}
	if _, err := sysConfigReadBeneath(hard); err == nil {
		t.Fatal("a file with two hard links must be refused")
	}
	fifo := filepath.Join(dir, "fifo.conf")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := sysConfigReadBeneath(fifo); err == nil {
		t.Fatal("a FIFO must be refused (and must not block)")
	}
	if _, err := sysConfigReadBeneath(dir); err == nil {
		t.Fatal("a directory must be refused")
	}
	for _, p := range []string{"rel/x", dir + "/../x", dir + "//x", "/"} {
		if _, err := sysConfigReadBeneath(p); err == nil {
			t.Fatalf("%q must be refused", p)
		}
	}
}
