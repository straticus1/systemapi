//go:build !linux

package main

// Threats: a non-Linux agent opening a path sash asked for. file.read is
// fulfilled by the Linux file helper. This default denies and does not open
// the path. Does NOT call os.Open. Does NOT shell out.

func sashFileDefault(id *ptyIdentity, op, root, rel string) (sashResult, error) {
	return sashResult{}, errSashDenied
}
