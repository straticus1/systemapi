//go:build linux

package main

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// atomicDirSync fsyncs the target directory after the rename. A var only so
// tests can inject a failure.
var atomicDirSync = unix.Fsync

// writeFileAtomicSync writes content to path through a temp file in the SAME
// directory, fsyncs it, renames it over path, and fsyncs the directory so the
// rename is durable. Shared by the config and systemd-override helpers (both
// are independent, fail-closed /etc writers). It does not create a backup —
// the control plane holds the bytes and can re-push.
//
// Threats: a symlink in any parent directory redirecting a root write outside
// the path that was checked. The parent is opened with openat2 with
// RESOLVE_BENEATH "/", RESOLVE_NO_SYMLINKS and RESOLVE_NO_MAGICLINKS (no
// /proc magic links), so every component of the directory must be a real
// directory and the string path the callers deny-check (configTargetDenied,
// overrideResolve) is the path actually written. RESOLVE_NO_XDEV is
// deliberately NOT set: resolution may cross mount points, because a granted
// /etc subtree can legitimately sit on another mount (a separate /etc, bind
// mounts in containers or image-based distros) and refusing that would break
// valid writes; a mount only exists if root put it there (see below). The temp file is created O_EXCL|O_NOFOLLOW 0600
// relative to that directory fd, chmod'd to perm, fsync'd, and renamed with
// renameat on the same fd, so nothing after the open re-resolves the path. A
// symlink at the final component is replaced, not followed. A leftover temp is
// removed on any error. Does NOT protect against a bind mount placed over a
// parent by someone who already has root.
func writeFileAtomicSync(path, content string, perm os.FileMode) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" {
		return errors.New("write target is not a clean absolute path")
	}
	dir, base := filepath.Dir(path), filepath.Base(path)
	root, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(root)
	dfd := root
	if dir != "/" {
		dfd, err = unix.Openat2(root, dir[1:], &unix.OpenHow{
			Flags:   unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC,
			Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS,
		})
		if err != nil {
			return err
		}
		defer unix.Close(dfd)
	}
	rb := make([]byte, 8)
	if _, err := rand.Read(rb); err != nil {
		return err
	}
	tmpName := ".systemapi-helper-" + hex.EncodeToString(rb) + ".tmp"
	tfd, err := unix.Openat(dfd, tmpName, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return err
	}
	tmp := os.NewFile(uintptr(tfd), tmpName)
	// Remove the temp on any early return; a no-op after a successful rename.
	committed := false
	defer func() {
		if !committed {
			_ = unix.Unlinkat(dfd, tmpName, 0)
		}
	}()
	if _, err := tmp.WriteString(content); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(perm); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := unix.Renameat(dfd, tmpName, dfd, base); err != nil {
		return err
	}
	committed = true
	// The new content is in place, but without a durable directory entry a
	// crash may roll it back; report that rather than claim success.
	return atomicDirSync(dfd)
}
