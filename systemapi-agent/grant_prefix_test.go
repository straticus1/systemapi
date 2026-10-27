package main

// Negative tests for the Sysscript path-grant gate (pathGrantAllows), used by
// AllowConfigWrite, AllowFSRead and AllowFSWrite. Threats: a sibling path that
// shares a string prefix with a grant (/etc/example vs /etc/example-evil), a
// ".." traversal, a relative path, and a symlink inside a granted directory
// that points outside it.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPathGrantAllowsBoundary(t *testing.T) {
	grants := []string{"/etc/example", "/etc/nginx/"}
	for _, p := range []string{"/etc/example", "/etc/example/a.conf", "/etc/nginx/nginx.conf", "/etc/nginx"} {
		if !pathGrantAllows(p, grants) {
			t.Fatalf("%q should be allowed", p)
		}
	}
	for _, p := range []string{
		"/etc/example-evil", "/etc/example-evil/x", "/etc/examplex", "/etc/nginx2/x",
		"/etc/example/../shadow", "/etc/example/./a", "/etc/example//a", "/etc/example/",
		"etc/example/a", "", "/etc/example/a\nb",
	} {
		if pathGrantAllows(p, grants) {
			t.Fatalf("%q must be denied", p)
		}
	}
	if pathGrantAllows("/etc/passwd", nil) {
		t.Fatal("empty grant list is not allow-all")
	}
	if !pathGrantAllows("/anything", []string{"*"}) {
		t.Fatal("* should allow an absolute path")
	}
	if pathGrantAllows("relative", []string{"*"}) || pathGrantAllows("/a/../b", []string{"*"}) {
		t.Fatal("* must not admit a malformed path")
	}
	// A malformed grant grants nothing.
	if pathGrantAllows("/etc/x", []string{"/etc/../etc"}) || pathGrantAllows("/etc/x", []string{"etc"}) {
		t.Fatal("a malformed grant must not match")
	}
}

func TestPathGrantAllowsRefusesSymlinkEscape(t *testing.T) {
	root := t.TempDir()
	granted := filepath.Join(root, "granted")
	outside := filepath.Join(root, "outside")
	for _, d := range []string{granted, outside} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(outside, filepath.Join(granted, "link")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(outside, "f"), filepath.Join(granted, "flink")); err != nil {
		t.Fatal(err)
	}
	grants := []string{granted}
	if !pathGrantAllows(filepath.Join(granted, "new.conf"), grants) {
		t.Fatal("a plain path under the grant should be allowed")
	}
	for _, p := range []string{
		filepath.Join(granted, "link", "x.conf"), // dir symlink, file does not exist yet
		filepath.Join(granted, "link"),
		filepath.Join(granted, "flink"), // dangling file symlink pointing out
	} {
		if pathGrantAllows(p, grants) {
			t.Fatalf("%q escapes the grant through a symlink and must be denied", p)
		}
	}
}

func TestSysConfigWriteRefusesSiblingPrefix(t *testing.T) {
	engine := newTestEngine(&Entitlements{AllowConfigWrite: []string{"/etc/example"}})
	out, err := engine.Execute(`r = sys.config.write("/etc/example-evil/x.conf", "x")
print(r["success"], r["error"])`)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "False") || !strings.Contains(out, "not granted") {
		t.Fatalf("sibling prefix must be refused, got %q", out)
	}
}
