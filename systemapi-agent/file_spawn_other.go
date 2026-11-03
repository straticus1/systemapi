//go:build !linux

// The file channel needs openat2 (Linux 5.6 or later, FILE §5.4). Elsewhere
// the capability is never advertised and every file_open is refused with
// agent_unsupported.
package main

import (
	"fmt"
	"io"
	"os"
	"os/exec"
)

func startFileHelperProc(id *ptyIdentity) (*exec.Cmd, error) {
	return nil, errFileUnsupported
}

func runFileHelper(in io.Reader, out io.Writer) int {
	fmt.Fprintln(out, "file-helper: unsupported on this platform")
	return 2
}

func removeUploadTemp(root, path, uploadID string) error {
	return errFileUnsupported
}

func openat2Available() bool { return false }

// probeOpenat2Root: no openat2 off Linux.
func probeOpenat2Root() error { return errFileUnsupported }

// probeConfigOpen off Linux only checks that /etc is a directory: config
// stays advertised as before, and its read refuses here anyway
// (sys_config_read_other.go).
func probeConfigOpen() error {
	fi, err := os.Stat("/etc")
	if err != nil {
		return err
	}
	if !fi.IsDir() {
		return errCapMissing
	}
	return nil
}
