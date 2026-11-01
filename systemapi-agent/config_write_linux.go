//go:build linux

package main

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
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
// are independent, fail-closed /etc writers). When path is an existing regular
// file the replacement keeps its permission bits (setuid, setgid and sticky
// dropped) and its owner and group, so rewriting a 0640 root:ssl-cert config
// does not widen or re-own it; a new file, or one replacing a non-regular
// entry such as a symlink, gets perm and the helper's owner. When backup is
// non-nil and path is an existing regular file, backup receives its current
// bytes (read through the same directory fd, at most atomicBackupMax) before
// the rename; a backup error aborts the write with path untouched.
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
// valid writes; a mount only exists if root put it there (see below). The old
// file is inspected with fstatat(AT_SYMLINK_NOFOLLOW) and read (for a backup)
// with openat O_NOFOLLOW|O_NONBLOCK on the same fd, checked to be the same
// inode, so a final symlink or a FIFO is never followed or blocked on. The
// temp file is created O_EXCL|O_NOFOLLOW 0600 relative to that directory fd,
// fchown'd and chmod'd, fsync'd, and renamed with renameat on the same fd, so
// nothing after the open re-resolves the path. A symlink at the final
// component is replaced, not followed. A leftover temp is removed on any
// error. Does NOT protect against a bind mount placed over a parent by
// someone who already has root, nor against the old file being swapped
// between the fstatat and the rename (only root can write these directories).
func writeFileAtomicSync(path, content string, perm os.FileMode, backup func(old []byte) error) error {
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
	mode, uid, gid := uint32(perm.Perm()), -1, -1
	var st unix.Stat_t
	err = unix.Fstatat(dfd, base, &st, unix.AT_SYMLINK_NOFOLLOW)
	switch {
	case err == nil && st.Mode&unix.S_IFMT == unix.S_IFREG:
		mode, uid, gid = st.Mode&0o777, int(st.Uid), int(st.Gid)
		if backup != nil {
			old, err := readRegularAt(dfd, base, st)
			if err != nil {
				return err
			}
			if err := backup(old); err != nil {
				return err
			}
		}
	case err != nil && !errors.Is(err, unix.ENOENT):
		return err
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
	if uid >= 0 {
		if err := tmp.Chown(uid, gid); err != nil {
			_ = tmp.Close()
			return err
		}
	}
	if err := tmp.Chmod(os.FileMode(mode)); err != nil {
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

// atomicBackupMax caps the old file a backup copies. A larger file fails the
// write closed rather than being replaced without a backup.
const atomicBackupMax = 8 << 20

// readRegularAt reads name in dfd without following a final symlink or
// blocking on a FIFO, and only if it is still the regular file st described.
func readRegularAt(dfd int, name string, st unix.Stat_t) ([]byte, error) {
	fd, err := unix.Openat(dfd, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), name)
	defer f.Close()
	var now unix.Stat_t
	if err := unix.Fstat(fd, &now); err != nil {
		return nil, err
	}
	if now.Mode&unix.S_IFMT != unix.S_IFREG || now.Dev != st.Dev || now.Ino != st.Ino {
		return nil, errors.New("backup: target changed during the write")
	}
	if now.Size > atomicBackupMax {
		return nil, errors.New("backup: target too large")
	}
	data, err := io.ReadAll(io.LimitReader(f, atomicBackupMax+1))
	if err != nil {
		return nil, err
	}
	if len(data) > atomicBackupMax {
		return nil, errors.New("backup: target too large")
	}
	return data, nil
}
