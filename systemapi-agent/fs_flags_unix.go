//go:build unix

package main

import (
	"os"
	"syscall"
)

// openNoFollow and openNonBlock are added to open flags where the OS has
// them: a final symlink fails the open, and a FIFO does not block it.
const (
	openNoFollow = syscall.O_NOFOLLOW
	openNonBlock = syscall.O_NONBLOCK
)

// fileOwnerIDs returns the owner of fi, when the OS reports one.
func fileOwnerIDs(fi os.FileInfo) (int, int, bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, false
	}
	return int(st.Uid), int(st.Gid), true
}

// fileNlink returns the hard link count of fi (1 when unknown).
func fileNlink(fi os.FileInfo) uint64 {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 1
	}
	return uint64(st.Nlink)
}
