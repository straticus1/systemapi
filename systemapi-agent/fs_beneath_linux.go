//go:build linux

package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// Threats: the *Beneath helpers act on target, a symlink-free path that
// fsGrantPath already checked under the grant root, without following any
// symlink on the way. The root is opened with RESOLVE_NO_SYMLINKS and every
// further step resolves beneath it with RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS,
// so a component swapped for a symlink after the policy check fails (ELOOP
// for a parent, O_NOFOLLOW or an fstat check for the final component)
// instead of reaching outside the grant. Without openat2 (Linux < 5.6) they
// fail closed. Does NOT stop a hard link inside the grant to a file outside
// it; write and chmod refuse a target with more than one link for that
// reason, chown too.

// openBeneathRoot opens root and returns the target path relative to it.
func openBeneathRoot(root, target string) (int, string, error) {
	if !openat2Available() {
		return -1, "", fmt.Errorf("requires openat2 (Linux 5.6+)")
	}
	rel, err := filepath.Rel(root, target)
	if err != nil || rel == ".." || strings.HasPrefix(rel, "../") || filepath.IsAbs(rel) {
		return -1, "", fmt.Errorf("path escapes grant")
	}
	rootFD, err := openat2(unix.AT_FDCWD, root, unix.O_PATH|unix.O_DIRECTORY, unix.RESOLVE_NO_SYMLINKS)
	if err != nil {
		return -1, "", beneathErr(err)
	}
	return rootFD, rel, nil
}

// openPathBeneath opens target (O_PATH, final symlink refused) under root.
// The caller closes the fd.
func openPathBeneath(root, target string) (int, *unix.Stat_t, error) {
	rootFD, rel, err := openBeneathRoot(root, target)
	if err != nil {
		return -1, nil, err
	}
	fd := rootFD
	if rel != "." {
		fd, err = openat2(rootFD, rel, unix.O_PATH|unix.O_NOFOLLOW, fileResolve)
		_ = unix.Close(rootFD)
		if err != nil {
			return -1, nil, beneathErr(err)
		}
	}
	// O_PATH|O_NOFOLLOW hands back the link itself for a final symlink.
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		_ = unix.Close(fd)
		return -1, nil, err
	}
	if st.Mode&unix.S_IFMT == unix.S_IFLNK {
		_ = unix.Close(fd)
		return -1, nil, fmt.Errorf("symlink or escape in path")
	}
	return fd, &st, nil
}

func beneathErr(err error) error {
	if errors.Is(err, unix.ELOOP) || errors.Is(err, unix.EXDEV) {
		return fmt.Errorf("symlink or escape in path")
	}
	return err
}

func hardLinked(st *unix.Stat_t) bool {
	return st.Mode&unix.S_IFMT != unix.S_IFDIR && st.Nlink > 1
}

// chownBeneath changes the owner through an O_PATH fd (AT_EMPTY_PATH).
func chownBeneath(root, target string, uid, gid int) error {
	fd, st, err := openPathBeneath(root, target)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	if hardLinked(st) {
		return fmt.Errorf("refusing a file with more than one hard link")
	}
	return unix.Fchownat(fd, "", uid, gid, unix.AT_EMPTY_PATH)
}

// chmodBeneath changes the mode through /proc/self/fd/N of an O_PATH fd:
// fchmod refuses O_PATH fds and fchmodat(AT_EMPTY_PATH) needs Linux 6.6,
// while chmod of the magic link acts on the inode the fd holds (the glibc
// lchmod technique). The fd was checked not to be a symlink. Without /proc
// it fails closed.
func chmodBeneath(root, target string, mode os.FileMode) error {
	fd, st, err := openPathBeneath(root, target)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	if hardLinked(st) {
		return fmt.Errorf("refusing a file with more than one hard link")
	}
	return os.Chmod("/proc/self/fd/"+strconv.Itoa(fd), mode)
}

// writeBeneath truncates and writes target, creating it if needed, opened
// beneath root with O_NOFOLLOW|O_NONBLOCK; only a regular file is written.
func writeBeneath(root, target string, data []byte, perm os.FileMode) error {
	rootFD, rel, err := openBeneathRoot(root, target)
	if err != nil {
		return err
	}
	defer unix.Close(rootFD)
	if rel == "." {
		return fmt.Errorf("is a directory")
	}
	fd, err := unix.Openat2(rootFD, rel, &unix.OpenHow{
		Flags:   unix.O_WRONLY | unix.O_CREAT | unix.O_NOFOLLOW | unix.O_NONBLOCK | unix.O_CLOEXEC,
		Mode:    uint64(perm.Perm()),
		Resolve: fileResolve,
	})
	if err != nil {
		return beneathErr(err)
	}
	f := os.NewFile(uintptr(fd), target)
	defer f.Close()
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		return fmt.Errorf("not a regular file")
	}
	if hardLinked(&st) {
		return fmt.Errorf("refusing a file with more than one hard link")
	}
	if err := unix.Ftruncate(fd, 0); err != nil {
		return err
	}
	_, err = f.Write(data)
	return err
}

// mkdirBeneath creates target and its missing parents one component at a
// time with mkdirat beneath root, never following a symlink.
func mkdirBeneath(root, target string, mode os.FileMode) error {
	rootFD, rel, err := openBeneathRoot(root, target)
	if err != nil {
		return err
	}
	cur := rootFD
	defer func() { _ = unix.Close(cur) }()
	if rel == "." {
		return nil
	}
	for _, c := range strings.Split(rel, "/") {
		if err := unix.Mkdirat(cur, c, uint32(mode.Perm())); err != nil && !errors.Is(err, unix.EEXIST) {
			return err
		}
		next, err := openat2(cur, c, unix.O_PATH|unix.O_DIRECTORY|unix.O_NOFOLLOW, fileResolve)
		if err != nil {
			return beneathErr(err)
		}
		_ = unix.Close(cur)
		cur = next
	}
	return nil
}
