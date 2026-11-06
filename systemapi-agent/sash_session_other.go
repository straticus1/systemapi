//go:build !linux

package main

import (
	"os"
	"time"
)

// Threats: a non-Linux agent that falls open to bash when a sash grant is
// present. prepareSash refuses with sash_missing. The passwd shell stays
// until a later series. Does NOT exec sash. Does NOT read the grant.

func sashLogin(action string) bool { return false }

func prepareSash(grant []byte, fleetPath, emerPath string, b sashBind, targets sashTargets, leaseFn func() time.Time, id *ptyIdentity) (string, []string, []*os.File, func(), error) {
	return "", nil, nil, nil, errSashMissing
}
