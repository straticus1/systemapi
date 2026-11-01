//go:build !linux

package main

import "errors"

// sysConfigReadBeneath refuses off Linux: without openat2 the read cannot
// guarantee that no component of the path is a symlink
// (sys_config_read_linux.go), and a root read through a symlinked parent
// could reach any file. Fail closed.
func sysConfigReadBeneath(path string) (string, error) {
	return "", errors.New("config read unsupported on this platform")
}
