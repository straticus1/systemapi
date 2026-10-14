//go:build windows

package main

import (
	"errors"
	"os"
	"os/exec"

	"github.com/creack/pty"
)

func startWithIdentity(cmd *exec.Cmd, id *ptyIdentity, sz *pty.Winsize) (*os.File, error) {
	return nil, errors.New("pty_unsupported")
}

func checkRealDir(path string, owner uint32) error {
	return errors.New("pty_unsupported")
}
