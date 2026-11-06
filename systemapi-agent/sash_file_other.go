//go:build !linux

package main

// Threats: a non-Linux agent opening or replacing a path sash asked for.
// file.read and file.write are fulfilled by the Linux file helper. These
// defaults deny and do not open the path. Does NOT call os.Open. Does NOT
// shell out.

func sashFileDefault(id *ptyIdentity, op, root, rel string) (sashResult, error) {
	return sashResult{}, errSashDenied
}

func sashFileWriteDefault(id *ptyIdentity, root, rel string, body []byte) (sashResult, error) {
	return sashResult{}, errSashDenied
}
