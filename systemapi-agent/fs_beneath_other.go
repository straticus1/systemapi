//go:build !linux

package main

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// Threats: without openat2 these helpers act on the resolved path with a
// final-component guard (Lchown, O_NOFOLLOW, an Lstat check) and re-resolve
// afterwards where the operation can be re-checked. Residual race: a parent
// directory swapped for a symlink between the policy check and the syscall
// is followed; Linux closes this with openat2 (fs_beneath_linux.go).

// chownBeneath uses Lchown, so a final component swapped for a symlink
// changes the link, not what it points to, then fails if target moved.
func chownBeneath(root, target string, uid, gid int) error {
	if err := os.Lchown(target, uid, gid); err != nil {
		return err
	}
	return recheckBeneath(root, target)
}

// chmodBeneath refuses a final symlink, then chmods. Residual race: the
// final component swapped between the Lstat and the chmod.
func chmodBeneath(root, target string, mode os.FileMode) error {
	fi, err := os.Lstat(target)
	if err != nil {
		return err
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("symlink or escape in path")
	}
	if err := os.Chmod(target, mode); err != nil {
		return err
	}
	return recheckBeneath(root, target)
}

// writeBeneath opens with O_NOFOLLOW (where the OS has it) and writes only a
// regular file.
func writeBeneath(root, target string, data []byte, perm os.FileMode) error {
	f, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|openNoFollow|openNonBlock, perm)
	if err != nil {
		return err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return err
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("not a regular file")
	}
	if err := recheckBeneath(root, target); err != nil {
		return err
	}
	if err := f.Truncate(0); err != nil {
		return err
	}
	_, err = f.Write(data)
	return err
}

// mkdirBeneath creates target, then fails if it resolves outside root.
func mkdirBeneath(root, target string, mode os.FileMode) error {
	if err := os.MkdirAll(target, mode); err != nil {
		return err
	}
	return recheckBeneath(root, target)
}

func recheckBeneath(root, target string) error {
	real, err := filepath.EvalSymlinks(target)
	if err != nil || real != target || !pathWithin(root, real) {
		return fmt.Errorf("path changed during operation")
	}
	return nil
}

// statBeneath lstat's target, then re-checks that its parent (the root for
// the root itself) still resolves to itself under root. A missing target is
// reported as not existing.
func statBeneath(root, target string) (pathFacts, error) {
	fi, err := os.Lstat(target)
	if errors.Is(err, fs.ErrNotExist) {
		return missingPath, nil
	}
	if err != nil {
		return pathFacts{}, err
	}
	dir := target
	if target != root {
		dir = filepath.Dir(target)
	}
	if err := recheckBeneath(root, dir); err != nil {
		return pathFacts{}, err
	}
	return pathFactsOf(fi), nil
}

// readBeneath reads a regular file with a single link (readFileCappedLinks),
// then re-checks it resolves to itself under root.
func readBeneath(root, target string, max int) ([]byte, error) {
	data, err := readFileCappedLinks(target, max, true)
	if err != nil {
		return nil, err
	}
	if err := recheckBeneath(root, target); err != nil {
		return nil, err
	}
	return []byte(data), nil
}

// removeBeneath removes target (a file, a link or an empty directory) after
// re-checking its parent; never recursive, never the root itself.
func removeBeneath(root, target string) error {
	if target == root {
		return fmt.Errorf("refusing to remove the grant root")
	}
	if err := recheckBeneath(root, filepath.Dir(target)); err != nil {
		return err
	}
	return os.Remove(target)
}

// replaceBeneath writes a fresh temp file beside target (os.CreateTemp:
// random name, O_EXCL), sets owner and mode, syncs and renames it over
// target, re-checking the directory before the create and the rename.
// Residual race as for the other helpers here: the directory swapped for a
// symlink between the re-check and the syscall.
func replaceBeneath(root, target string, data []byte, mode os.FileMode, uid, gid int) error {
	if target == root {
		return fmt.Errorf("is a directory")
	}
	dir := filepath.Dir(target)
	if err := recheckBeneath(root, dir); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, "."+filepath.Base(target)+".systemapi-*.tmp")
	if err != nil {
		return fmt.Errorf("create tmp: %w", err)
	}
	tmp := f.Name()
	fail := func(err error) error {
		_ = f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if uid >= 0 || gid >= 0 {
		if err := f.Chown(uid, gid); err != nil {
			return fail(fmt.Errorf("chown tmp: %w", err))
		}
	}
	if err := f.Chmod(mode.Perm()); err != nil {
		return fail(fmt.Errorf("chmod tmp: %w", err))
	}
	if _, err := f.Write(data); err != nil {
		return fail(fmt.Errorf("write tmp: %w", err))
	}
	if err := f.Sync(); err != nil {
		return fail(fmt.Errorf("sync tmp: %w", err))
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("close tmp: %w", err)
	}
	if err := recheckBeneath(root, dir); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, target); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("rename: %w", err)
	}
	return nil
}
