//go:build !linux

package main

// openXferBin checks --xfer-bin and returns its path. Without Linux's
// /proc/self/fd exec there is a window between this check and execve; the
// parent walk in checkXferBin leaves only root or the agent user able to
// replace the file in it. Darwin is a development target (decision 10).
func openXferBin(path string, agentUID int) (exe string, release func(), err error) {
	if err := checkXferBin(path, agentUID); err != nil {
		return "", nil, err
	}
	return path, func() {}, nil
}
