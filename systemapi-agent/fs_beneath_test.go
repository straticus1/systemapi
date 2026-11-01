//go:build unix

package main

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"
)

// chownBeneath is the step after the policy check. These tests hand it a
// path whose final component or a parent was swapped for a symlink after
// the check, as a racing process would, and require a refusal.
func TestChownBeneathRefusesSwappedSymlinks(t *testing.T) {
	root := realTempDir(t)
	outside := realTempDir(t)
	secret := filepath.Join(outside, "secret")
	if err := os.WriteFile(secret, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	ok := filepath.Join(root, "ok")
	if err := os.WriteFile(ok, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(secret, filepath.Join(root, "final")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "dir")); err != nil {
		t.Fatal(err)
	}
	uid, gid := os.Getuid(), os.Getgid()
	if err := chownBeneath(root, ok, uid, gid); err != nil {
		t.Fatalf("plain file: %v", err)
	}
	if err := chownBeneath(root, root, uid, gid); err != nil {
		t.Fatalf("grant root: %v", err)
	}
	for _, target := range []string{filepath.Join(root, "final"), filepath.Join(root, "dir", "secret")} {
		if err := chownBeneath(root, target, uid, gid); err == nil {
			t.Errorf("%s: swapped symlink accepted", target)
		}
	}
	if err := chownBeneath(root, outside, uid, gid); err == nil {
		t.Error("target outside the root accepted")
	}
}

func TestReadFileCappedRefusesNonRegular(t *testing.T) {
	dir := realTempDir(t)
	fifo := filepath.Join(dir, "fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skip(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := readFileCapped(fifo, hostFileCap)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "not a regular file") {
			t.Fatalf("fifo: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("readFileCapped blocked on a FIFO")
	}
	if _, err := readFileCapped(dir, hostFileCap); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("dir: %v", err)
	}
	// A missing file reports the real error, not a size error.
	if _, err := readFileCapped(filepath.Join(dir, "missing"), hostFileCap); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("missing: %v", err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(fifo, link); err != nil {
		t.Fatal(err)
	}
	if _, err := readFileCapped(link, hostFileCap); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("symlink: %v", err)
	}
	// sys.fs.diff refuses a FIFO in the grant too.
	a := filepath.Join(dir, "a")
	if err := os.WriteFile(a, []byte("x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	engine := newTestEngine(&Entitlements{AllowFSRead: []string{dir}})
	if _, err := engine.Execute(`sys.fs.diff(` + strconvQuote(a) + `, ` + strconvQuote(fifo) + `)` + "\n"); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("diff fifo: %v", err)
	}
}

// The write, chmod and mkdir steps after the policy check: a final
// component swapped for a symlink is refused on every unix; on Linux a
// parent swapped for a symlink and a hard link to an outside file are
// refused too (openat2). The outside file stays untouched.
func TestBeneathOpsRefuseSwappedFinalSymlink(t *testing.T) {
	root := realTempDir(t)
	outside := realTempDir(t)
	secret := filepath.Join(outside, "secret")
	if err := os.WriteFile(secret, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	final := filepath.Join(root, "final")
	if err := os.Symlink(secret, final); err != nil {
		t.Fatal(err)
	}
	if err := writeBeneath(root, final, []byte("pwned"), 0o644); err == nil {
		t.Error("write through a final symlink accepted")
	}
	if err := chmodBeneath(root, final, 0o777); err == nil {
		t.Error("chmod through a final symlink accepted")
	}
	dirLink := filepath.Join(root, "dirlink")
	if err := os.Symlink(outside, dirLink); err != nil {
		t.Fatal(err)
	}
	if err := mkdirBeneath(root, dirLink, 0o755); err == nil {
		t.Error("mkdir onto a symlink accepted")
	}
	if b, err := os.ReadFile(secret); err != nil || string(b) != "x" {
		t.Fatalf("outside changed: %q %v", b, err)
	}
	if fi, _ := os.Stat(secret); fi.Mode().Perm() != 0o600 {
		t.Fatalf("outside mode changed: %v", fi.Mode())
	}
	// Inside the root they work.
	sub := filepath.Join(root, "a", "b")
	if err := mkdirBeneath(root, sub, 0o755); err != nil {
		t.Fatal(err)
	}
	f := filepath.Join(sub, "f")
	if err := writeBeneath(root, f, []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := writeBeneath(root, f, []byte("hi"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := chmodBeneath(root, f, 0o600); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(f); string(b) != "hi" {
		t.Fatalf("content %q", b)
	}
	if fi, _ := os.Stat(f); fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", fi.Mode())
	}
}

func TestBeneathOpsRefuseSwappedParentLinux(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("parent-swap safety needs openat2 (documented residual elsewhere)")
	}
	root := realTempDir(t)
	outside := realTempDir(t)
	secret := filepath.Join(outside, "secret")
	if err := os.WriteFile(secret, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	// root/dir was a real dir at check time, now a symlink out.
	if err := os.Symlink(outside, filepath.Join(root, "dir")); err != nil {
		t.Fatal(err)
	}
	if err := writeBeneath(root, filepath.Join(root, "dir", "secret"), []byte("pwned"), 0o644); err == nil {
		t.Error("write through a swapped parent accepted")
	}
	if err := writeBeneath(root, filepath.Join(root, "dir", "new"), []byte("pwned"), 0o644); err == nil {
		t.Error("create through a swapped parent accepted")
	}
	if err := chmodBeneath(root, filepath.Join(root, "dir", "secret"), 0o777); err == nil {
		t.Error("chmod through a swapped parent accepted")
	}
	if err := mkdirBeneath(root, filepath.Join(root, "dir", "made"), 0o755); err == nil {
		t.Error("mkdir through a swapped parent accepted")
	}
	for _, p := range []string{filepath.Join(outside, "new"), filepath.Join(outside, "made")} {
		if _, err := os.Lstat(p); err == nil {
			t.Errorf("%s created outside", p)
		}
	}
	// A hard link inside the root to an outside file.
	hl := filepath.Join(root, "hl")
	if err := os.Link(secret, hl); err != nil {
		t.Skip(err)
	}
	if err := writeBeneath(root, hl, []byte("pwned"), 0o644); err == nil {
		t.Error("write through a hard link accepted")
	}
	if err := chmodBeneath(root, hl, 0o777); err == nil {
		t.Error("chmod through a hard link accepted")
	}
	if b, _ := os.ReadFile(secret); string(b) != "x" {
		t.Fatalf("outside changed: %q", b)
	}
	if fi, _ := os.Stat(secret); fi.Mode().Perm() != 0o600 {
		t.Fatalf("outside mode changed: %v", fi.Mode())
	}
}
