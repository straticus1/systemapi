//go:build !windows

package main

import (
	"os"
	"syscall"
)

// Process and file helpers of xfer_test.go that need unix syscalls; the
// windows versions (xfer_windows_test.go) only let the package's tests
// compile there.

func fdOpen(fd int) bool {
	var st syscall.Stat_t
	return syscall.Fstat(fd, &st) == nil
}

func killPid(pid int) {
	_ = syscall.Kill(pid, syscall.SIGKILL)
}

func fileUID(fi os.FileInfo) (uint32, bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return st.Uid, true
}
