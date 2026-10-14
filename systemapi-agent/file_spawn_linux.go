//go:build linux

// Starting the file-helper child (docs/sah-file-protocol.md §7, owner
// decision: Go cannot drop privileges safely per goroutine, so each session
// runs in its own process). Threats: file operations running with the
// agent's privileges (the child is started with SysProcAttr.Credential
// carrying the session uid, gid and supplementary groups, exactly as
// pty_unix.go does for --pty-user shells; only file:root on a root agent runs
// as root), a helper outliving the agent (Pdeathsig SIGKILL), and the
// agent's secrets reaching the helper (empty environment, no extra fds; the
// API key was already removed from the agent's environment at startup).
// Does NOT confine the helper beyond the kernel's permissions for its
// identity.
package main

import (
	"os"
	"os/exec"
	"syscall"
)

// fileHelperExe is the binary started as "file-helper"; tests point it at a
// copy of the test binary that the dropped identity can execute.
var fileHelperExe = os.Executable

func startFileHelperProc(id *ptyIdentity) (*exec.Cmd, error) {
	exe, err := fileHelperExe()
	if err != nil {
		return nil, err
	}
	cmd := exec.Command(exe, "file-helper")
	cmd.Env = []string{}
	cmd.Dir = "/"
	cmd.Stderr = os.Stderr
	attrs := &syscall.SysProcAttr{Setsid: true, Pdeathsig: syscall.SIGKILL}
	if id.drop {
		attrs.Credential = &syscall.Credential{Uid: id.uid, Gid: id.gid, Groups: id.groups}
	}
	cmd.SysProcAttr = attrs
	return cmd, nil
}
