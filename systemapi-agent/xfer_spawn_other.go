//go:build !unix

// xfer needs a Unix credential drop; elsewhere every grant is refused and
// the capability is never advertised.
package main

import (
	"errors"
	"os"
	"os/exec"
)

var errXferUnsupported = errors.New("xfer unsupported on this platform")

func startXferProc(id *ptyIdentity, exe string, args ...string) (*exec.Cmd, error) {
	return nil, errXferUnsupported
}

func checkXferBinOwner(fi os.FileInfo, agentUID int) error { return errXferUnsupported }
