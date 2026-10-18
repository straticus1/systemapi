//go:build !windows

package main

import (
	"errors"
	"os"
	"os/exec"
	"syscall"

	"github.com/creack/pty"
)

// startWithIdentity opens a PTY, hands the slave to the session user, and
// starts cmd with uid, gid and supplementary groups dropped when id.drop is
// set. It mirrors pty.StartWithSize.
func startWithIdentity(cmd *exec.Cmd, id *ptyIdentity, sz *pty.Winsize) (*os.File, error) {
	ptmx, tty, err := pty.Open()
	if err != nil {
		return nil, err
	}
	defer func() { _ = tty.Close() }()
	if err := pty.Setsize(ptmx, sz); err != nil {
		_ = ptmx.Close()
		return nil, err
	}
	attrs := &syscall.SysProcAttr{Setsid: true, Setctty: true}
	if id.drop {
		if err := os.Chown(tty.Name(), int(id.uid), -1); err != nil {
			_ = ptmx.Close()
			return nil, err
		}
		if err := os.Chmod(tty.Name(), 0o620); err != nil {
			_ = ptmx.Close()
			return nil, err
		}
		attrs.Credential = &syscall.Credential{Uid: id.uid, Gid: id.gid, Groups: id.groups}
	}
	cmd.Stdin, cmd.Stdout, cmd.Stderr = tty, tty, tty
	cmd.SysProcAttr = attrs
	if err := cmd.Start(); err != nil {
		_ = ptmx.Close()
		return nil, err
	}
	return ptmx, nil
}

// checkRealDir refuses a symlink, a non-directory, or a directory owned by
// someone other than owner.
func checkRealDir(path string, owner uint32) error {
	st, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if st.Mode()&os.ModeSymlink != 0 || !st.IsDir() {
		return errors.New("not_a_directory")
	}
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok || sys.Uid != owner {
		return errors.New("wrong_owner")
	}
	return nil
}

// checkPrivateFile refuses a symlink, a non-regular file, group or other
// permission bits, or a file owned by someone other than owner.
func checkPrivateFile(path string, owner uint32) error {
	st, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !st.Mode().IsRegular() || st.Mode().Perm()&0o077 != 0 {
		return errors.New("bad_file_mode")
	}
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok || sys.Uid != owner {
		return errors.New("wrong_owner")
	}
	return nil
}

// signalTree sends sig to the process group pgid and to every process whose
// session id is pgid (Linux only). It reports whether anything was signalled.
// Callers hold the session's reap lock, so pgid still belongs to the shell
// (running or a zombie) and cannot have been reused.
func signalTree(pgid int, sig syscall.Signal) bool {
	hit := syscall.Kill(-pgid, sig) == nil
	for _, pid := range sessionMembers(pgid) {
		if signalSessionMember(pid, pgid, sig) {
			hit = true
		}
	}
	return hit
}

// freeBytes is the space available to the agent on path's filesystem.
func freeBytes(path string) (uint64, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return 0, err
	}
	return uint64(st.Bavail) * uint64(st.Bsize), nil
}

// fileOwner is the owning uid of a file, when the platform has one.
func fileOwner(st os.FileInfo) (uint32, bool) {
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return sys.Uid, true
}
