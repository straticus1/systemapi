package main

import "os"

// Windows stand-ins for xfer_unix_test.go, so GOOS=windows go vet and test
// builds type-check the package. xfer is not advertised on windows.

func fdOpen(int) bool { return false }

func killPid(pid int) {
	if p, err := os.FindProcess(pid); err == nil {
		_ = p.Kill()
	}
}

func fileUID(os.FileInfo) (uint32, bool) { return 0, false }
