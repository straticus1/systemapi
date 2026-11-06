//go:build linux

package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestSashFileDeniesBeforeHelperAndDoesNotReturnSecret(t *testing.T) {
	calls := 0
	prev := fileHelperExe
	fileHelperExe = func() (string, error) {
		calls++
		return "/bin/false", nil
	}
	t.Cleanup(func() { fileHelperExe = prev })

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "secret"), []byte("SECRET"), 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := sashFileDefault(nil, "cat", dir, "secret")
	if !errors.Is(err, errSashDenied) || bytes.Contains(res.Bytes, []byte("SECRET")) {
		t.Fatalf("nil id: %v %q", err, res.Bytes)
	}
	if calls != 0 {
		t.Fatalf("nil id spawned %d", calls)
	}
	id := &ptyIdentity{drop: false, home: "/tmp", shell: "/bin/sh"}
	res, err = sashFileDefault(id, "cat", dir, "/etc/shadow")
	if !errors.Is(err, errSashDenied) || bytes.Contains(res.Bytes, []byte("SECRET")) {
		t.Fatalf("abs rel: %v %q", err, res.Bytes)
	}
	if calls != 0 {
		t.Fatalf("abs rel spawned %d", calls)
	}
	res, err = sashFileDefault(id, "cat", dir, "secret")
	if !errors.Is(err, errSashDenied) || bytes.Contains(res.Bytes, []byte("SECRET")) {
		t.Fatalf("helper: %v %q", err, res.Bytes)
	}
	if calls != 1 {
		t.Fatalf("helper calls %d", calls)
	}
}
