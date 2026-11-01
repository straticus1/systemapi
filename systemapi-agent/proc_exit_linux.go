//go:build linux

package main

import (
	"errors"

	"golang.org/x/sys/unix"
)

// waitExitNoReap returns once pid has exited, leaving it a zombie
// (WNOWAIT): its pid, and so its process group id, stays reserved until
// os/exec reaps it.
func waitExitNoReap(pid int) {
	for {
		var info unix.Siginfo
		err := unix.Waitid(unix.P_PID, pid, &info, unix.WEXITED|unix.WNOWAIT, nil)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		return
	}
}
