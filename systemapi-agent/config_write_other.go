//go:build !linux

package main

import (
	"errors"
	"os"
)

// writeFileAtomicSync refuses off Linux: without openat2 it cannot guarantee
// that no parent directory of the target is a symlink (config_write_linux.go),
// and the mutation helpers it serves only run under systemd on Linux.
func writeFileAtomicSync(path, content string, perm os.FileMode, backup func(old []byte) error) error {
	return errors.New("helper write unsupported on this platform")
}
