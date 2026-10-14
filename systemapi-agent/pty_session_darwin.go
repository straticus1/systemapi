//go:build darwin

package main

import (
	"syscall"

	"golang.org/x/sys/unix"
)

// sessionMembers lists processes whose session id is sid, best effort.
// macOS is not a managed platform: there is no pidfd, so a PID can in
// principle be reused between the re-check and the signal.
func sessionMembers(sid int) []int {
	procs, err := unix.SysctlKinfoProcSlice("kern.proc.all")
	if err != nil {
		return nil
	}
	var out []int
	for _, p := range procs {
		pid := int(p.Proc.P_pid)
		if pid <= 1 || pid == sid {
			continue
		}
		if s, err := unix.Getsid(pid); err == nil && s == sid {
			out = append(out, pid)
		}
	}
	return out
}

func signalSessionMember(pid, sid int, sig syscall.Signal) bool {
	if s, err := unix.Getsid(pid); err != nil || s != sid {
		return false
	}
	return syscall.Kill(pid, sig) == nil
}

// waitExitedNoReap is not available on macOS (no waitid with WNOWAIT in
// x/sys); the caller reaps first.
func waitExitedNoReap(pid int) bool { return false }
