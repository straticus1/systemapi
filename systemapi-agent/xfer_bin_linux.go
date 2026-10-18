//go:build linux

package main

import (
	"fmt"
	"os"
	"strconv"

	"golang.org/x/sys/unix"
)

// openXferBin checks --xfer-bin, opens it once without following a symlink,
// re-checks the opened inode with fstat, and returns /proc/self/fd/N for
// exec, so a rename over the path between the check and execve changes
// nothing. N is at least 10: the fork child moves at most a few fds into
// the low range while it sets up ExtraFiles, and must not land on N. The
// fd is close-on-exec; the kernel resolves the path before closing it, and
// a process may always follow its own /proc/self/fd links, also after the
// credential drop. release closes the fd once the child has started.
func openXferBin(path string, agentUID int) (exe string, release func(), err error) {
	if err := checkXferBin(path, agentUID); err != nil {
		return "", nil, err
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return "", nil, fmt.Errorf("%w: --xfer-bin: %v", errXferBin, err)
	}
	high, err := unix.FcntlInt(uintptr(fd), unix.F_DUPFD_CLOEXEC, 10)
	unix.Close(fd)
	if err != nil {
		return "", nil, fmt.Errorf("%w: --xfer-bin: %v", errXferBin, err)
	}
	f := os.NewFile(uintptr(high), path)
	fi, err := f.Stat()
	if err == nil {
		err = checkXferBinMode(fi.Mode())
	}
	if err == nil {
		err = checkXferBinOwner(fi, agentUID)
	}
	if err != nil {
		f.Close()
		return "", nil, fmt.Errorf("%w: --xfer-bin: %v", errXferBin, err)
	}
	return "/proc/self/fd/" + strconv.Itoa(high), func() { f.Close() }, nil
}
