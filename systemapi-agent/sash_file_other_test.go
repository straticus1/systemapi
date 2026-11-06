//go:build !linux

package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestSashFileOtherDoesNotOpen(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secret")
	if err := os.WriteFile(path, []byte("SECRET"), 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := sashFileDefault(nil, "cat", dir, "secret")
	if !errors.Is(err, errSashDenied) {
		t.Fatalf("err %v", err)
	}
	if bytes.Contains(res.Bytes, []byte("SECRET")) {
		t.Fatal("secret bytes")
	}
}
