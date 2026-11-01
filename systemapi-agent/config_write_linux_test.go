//go:build linux

package main

// Negative tests for the helpers' atomic write primitive (config_write_linux.go).
// Threats: a symlink in any parent directory of the target redirecting a root
// /etc write somewhere else (for example a config dir swapped for a link to
// /etc/systemapi-agent), and a relative or unclean target.

import (
	"crypto/sha256"
	"encoding/hex"
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
	if err := writeFileAtomicSync(path, "new\n", 0o644, nil); err != nil {
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
		if err := writeFileAtomicSync(target, "evil\n", 0o644, nil); err == nil {
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

// An absolute symlink is already refused by RESOLVE_BENEATH alone (it jumps to
// "/" during resolution). A RELATIVE link that stays beneath "/" is caught only
// by RESOLVE_NO_SYMLINKS, so this case is what pins that flag.
func TestWriteFileAtomicSyncRefusesRelativeSymlinkedParent(t *testing.T) {
	base := t.TempDir()
	real := filepath.Join(base, "protected")
	if err := os.MkdirAll(filepath.Join(real, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "granted")
	if err := os.Symlink("protected", link); err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{filepath.Join(link, "x.conf"), filepath.Join(link, "sub", "x.conf")} {
		if err := writeFileAtomicSync(target, "evil\n", 0o644, nil); err == nil {
			t.Fatalf("%s: a relative symlinked parent must be refused", target)
		}
	}
	for _, p := range []string{filepath.Join(real, "x.conf"), filepath.Join(real, "sub", "x.conf")} {
		if _, err := os.Lstat(p); !os.IsNotExist(err) {
			t.Fatalf("write landed through the relative symlink at %s: %v", p, err)
		}
	}
}

func TestWriteFileAtomicSyncRefusesBadPath(t *testing.T) {
	dir := t.TempDir()
	for _, p := range []string{"rel/x.conf", dir + "/../x.conf", dir + "//x.conf", "/"} {
		if err := writeFileAtomicSync(p, "x\n", 0o644, nil); err == nil {
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
	if err := writeFileAtomicSync(path, "x\n", 0o644, nil); err == nil {
		t.Fatal("a directory fsync failure must be returned")
	}
}

// A replaced regular file keeps its permission bits and owner; the helper
// must not reset a 0640 root:<group> config to 0644 helper-owned. setuid,
// setgid and sticky are never carried over.
func TestWriteFileAtomicSyncKeepsModeAndOwner(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "x.conf")
	if err := os.WriteFile(path, []byte("old\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	uid, gid := os.Getuid(), os.Getgid()
	if uid == 0 {
		uid, gid = 1234, 5678
		if err := os.Chown(path, uid, gid); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(path, 0o640); err != nil {
		t.Fatal(err)
	}
	if err := writeFileAtomicSync(path, "new\n", 0o644, nil); err != nil {
		t.Fatalf("writeFileAtomicSync: %v", err)
	}
	fi, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o640 {
		t.Fatalf("mode=%v, want 0640 kept", fi.Mode().Perm())
	}
	if gotUID, gotGID, ok := fileOwnerIDs(fi); !ok || gotUID != uid || gotGID != gid {
		t.Fatalf("owner=%d:%d, want %d:%d kept", gotUID, gotGID, uid, gid)
	}

	if err := os.Chmod(path, 0o4755); err != nil {
		t.Fatal(err)
	}
	if err := writeFileAtomicSync(path, "newer\n", 0o644, nil); err != nil {
		t.Fatalf("writeFileAtomicSync: %v", err)
	}
	fi, err = os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 || fi.Mode().Perm() != 0o755 {
		t.Fatalf("mode=%v, want 0755 without setuid", fi.Mode())
	}
}

// A new file, and one replacing a symlink, gets the default perm; the backup
// hook runs only for an existing regular file, and a final symlink is
// replaced, never followed or read.
func TestWriteFileAtomicSyncNewFileAndSymlinkDefaults(t *testing.T) {
	dir := t.TempDir()
	calls := 0
	backup := func([]byte) error { calls++; return nil }
	fresh := filepath.Join(dir, "new.conf")
	if err := writeFileAtomicSync(fresh, "x\n", 0o644, backup); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Lstat(fresh); err != nil || fi.Mode().Perm() != 0o644 {
		t.Fatalf("new file mode: %v %v", fi, err)
	}
	secret := filepath.Join(dir, "secret")
	if err := os.WriteFile(secret, []byte("s3cret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.conf")
	if err := os.Symlink(secret, link); err != nil {
		t.Fatal(err)
	}
	if err := writeFileAtomicSync(link, "y\n", 0o644, backup); err != nil {
		t.Fatal(err)
	}
	if calls != 0 {
		t.Fatalf("backup ran %d times for a new file / symlink", calls)
	}
	fi, err := os.Lstat(link)
	if err != nil || !fi.Mode().IsRegular() || fi.Mode().Perm() != 0o644 {
		t.Fatalf("symlink not replaced by a 0644 file: %v %v", fi, err)
	}
	if got, _ := os.ReadFile(secret); string(got) != "s3cret\n" {
		t.Fatalf("link target changed: %q", got)
	}
}

// The backup hook gets the old bytes before the rename; a backup failure
// aborts the write with the target untouched and no temp file left.
func TestWriteFileAtomicSyncBackupHook(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "x.conf")
	if err := os.WriteFile(path, []byte("old\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var got []byte
	if err := writeFileAtomicSync(path, "new\n", 0o644, func(old []byte) error { got = old; return nil }); err != nil {
		t.Fatal(err)
	}
	if string(got) != "old\n" {
		t.Fatalf("backup got %q, want the old bytes", got)
	}
	if err := writeFileAtomicSync(path, "evil\n", 0o644, func([]byte) error { return errors.New("disk full") }); err == nil {
		t.Fatal("a backup failure must fail the write")
	}
	if b, _ := os.ReadFile(path); string(b) != "new\n" {
		t.Fatalf("target changed after a failed backup: %q", b)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 1 {
		t.Fatalf("stray files: %v", entries)
	}
}

// The real config helper write backs the old content up outside the target
// directory, in the desired-state layout (<dir>/<sha256(path)>/<ns>, 0600).
func TestConfigHelperWriteBacksUpOutsideTargetDir(t *testing.T) {
	etc := t.TempDir()
	backups := filepath.Join(t.TempDir(), "config-backups")
	prev := configHelperBackupDir
	configHelperBackupDir = backups
	t.Cleanup(func() { configHelperBackupDir = prev })
	path := filepath.Join(etc, "app.conf")
	if err := os.WriteFile(path, []byte("v1\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := configHelperWrite(path, "v2\n"); err != nil {
		t.Fatalf("configHelperWrite: %v", err)
	}
	if b, _ := os.ReadFile(path); string(b) != "v2\n" {
		t.Fatalf("content=%q", b)
	}
	if entries, _ := os.ReadDir(etc); len(entries) != 1 {
		t.Fatalf("backup or temp left in the target dir: %v", entries)
	}
	sum := sha256.Sum256([]byte(path))
	bdir := filepath.Join(backups, hex.EncodeToString(sum[:]))
	entries, err := os.ReadDir(bdir)
	if err != nil || len(entries) != 1 {
		t.Fatalf("backups: %v %v", entries, err)
	}
	bp := filepath.Join(bdir, entries[0].Name())
	if b, _ := os.ReadFile(bp); string(b) != "v1\n" {
		t.Fatalf("backup=%q, want v1", b)
	}
	if fi, _ := os.Lstat(bp); fi.Mode().Perm() != 0o600 {
		t.Fatalf("backup mode %v", fi.Mode().Perm())
	}
	// A new file has nothing to back up.
	if err := configHelperWrite(filepath.Join(etc, "new.conf"), "x\n"); err != nil {
		t.Fatal(err)
	}
}
