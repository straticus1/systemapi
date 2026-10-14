//go:build !linux

// The file channel needs openat2 (Linux 5.6 or later, FILE §5.4). Elsewhere
// the capability is never advertised and every file_open is refused with
// agent_unsupported.
package main

import (
	"fmt"
	"io"
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
