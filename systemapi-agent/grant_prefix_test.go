package main

// Negative tests for the Sysscript path-grant gate (fsGrantPath, via configWriteAllowed), used by
// AllowConfigWrite, AllowFSRead and AllowFSWrite. Threats: a sibling path that
// shares a string prefix with a grant (/etc/example vs /etc/example-evil), a
// ".." traversal, a relative path, and a symlink inside a granted directory
// that points outside it.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestPathGrantAllowsBoundary(t *testing.T) {
	grants := []string{"/etc/example", "/etc/nginx/"}
	for _, p := range []string{"/etc/example", "/etc/example/a.conf", "/etc/nginx/nginx.conf", "/etc/nginx"} {
		if !configWriteAllowed(p, grants) {
			t.Fatalf("%q should be allowed", p)
		}
	}
	for _, p := range []string{
		"/etc/example-evil", "/etc/example-evil/x", "/etc/examplex", "/etc/nginx2/x",
		"/etc/example/../shadow", "/etc/example/./a", "/etc/example//a", "/etc/example/",
		"etc/example/a", "", "/etc/example/a\nb",
	} {
		if configWriteAllowed(p, grants) {
			t.Fatalf("%q must be denied", p)
		}
	}
	if configWriteAllowed("/etc/passwd", nil) {
		t.Fatal("empty grant list is not allow-all")
	}
	if !configWriteAllowed("/anything", []string{"*"}) {
		t.Fatal("* should allow an absolute path")
	}
	if configWriteAllowed("relative", []string{"*"}) || configWriteAllowed("/a/../b", []string{"*"}) {
		t.Fatal("* must not admit a malformed path")
	}
	// A malformed grant grants nothing.
	if configWriteAllowed("/etc/x", []string{"/etc/../etc"}) || configWriteAllowed("/etc/x", []string{"etc"}) {
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
	if !configWriteAllowed(filepath.Join(granted, "new.conf"), grants) {
		t.Fatal("a plain path under the grant should be allowed")
	}
	for _, p := range []string{
		filepath.Join(granted, "link", "x.conf"), // dir symlink, file does not exist yet
		filepath.Join(granted, "link"),
		filepath.Join(granted, "flink"), // dangling file symlink pointing out
	} {
		if configWriteAllowed(p, grants) {
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

// A symlink loop such as a -> a/b must not hang or stack-overflow the agent:
// resolution is bounded and a path it cannot resolve is denied, even under "*".
func TestPathGrantAllowsSymlinkLoopDenied(t *testing.T) {
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	loop := filepath.Join(dir, "a")
	if err := os.Symlink(filepath.Join(loop, "b"), loop); err != nil {
		t.Fatal(err)
	}
	done := make(chan [2]bool, 1)
	go func() {
		done <- [2]bool{
			configWriteAllowed(filepath.Join(loop, "x"), []string{dir}),
			configWriteAllowed(loop, []string{"*"}),
		}
	}()
	select {
	case got := <-done:
		if got[0] || got[1] {
			t.Fatalf("a path through a symlink loop must be denied, got %v", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("configWriteAllowed did not return on a symlink loop")
	}
}
