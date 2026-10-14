//go:build windows

package main

import (
	"errors"
	"os"
	"os/exec"
	"syscall"

	"github.com/creack/pty"
)

func startWithIdentity(cmd *exec.Cmd, id *ptyIdentity, sz *pty.Winsize) (*os.File, error) {
	return nil, errors.New("pty_unsupported")
}

func checkRealDir(path string, owner uint32) error {
	return errors.New("pty_unsupported")
}

func checkPrivateFile(path string, owner uint32) error {
	return errors.New("pty_unsupported")
}

func signalTree(pgid int, sig syscall.Signal) bool { return false }

func freeBytes(path string) (uint64, error) {
	return 0, errors.New("pty_unsupported")
}
