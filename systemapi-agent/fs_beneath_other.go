//go:build !linux

package main

import (
	"fmt"
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
