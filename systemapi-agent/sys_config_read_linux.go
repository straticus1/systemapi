//go:build linux

package main

import (
	"errors"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// sysConfigReadBeneath reads one sys:config target as root.
//
// Threats: the read runs as root, so a symlink anywhere in the path (for
// example a granted /etc/app whose parent or the file itself is swapped for a
// link to /etc/shadow or /var/lib/systemapi-agent/agent.json) must not carry
// it outside the path the lease, the control-plane allowlist and
// configTargetDenied checked. The whole path is opened from "/" with openat2
// RESOLVE_BENEATH, RESOLVE_NO_SYMLINKS and RESOLVE_NO_MAGICLINKS, the same
// resolution as the helpers' write (writeFileAtomicSync), with O_NOFOLLOW and
// O_NONBLOCK, so no component is a symlink and a FIFO cannot block the read.
// The opened file must be a regular file with exactly one hard link (a hard
// link to a protected file is not a second name for it here) and the read is
// capped at sysConfigReadMax. Does NOT protect against a bind mount over a
// parent placed by someone who already has root.
func sysConfigReadBeneath(path string) (string, error) {
	if !configTargetShapeOK(path) || filepath.Clean(path) != path {
		return "", errors.New("config read: bad path")
	}
	root, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return "", err
	}
	defer unix.Close(root)
	fd, err := unix.Openat2(root, path[1:], &unix.OpenHow{
		Flags:   unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_NONBLOCK | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS,
	})
	if err != nil {
		return "", err
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return "", err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		return "", errors.New("config read: not a regular file")
	}
	if st.Nlink != 1 {
		return "", errors.New("config read: file has more than one hard link")
	}
	buf, err := io.ReadAll(io.LimitReader(f, sysConfigReadMax))
	if err != nil {
		return "", err
	}
	return string(buf), nil
}
