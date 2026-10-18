//go:build unix && !linux

package main

import "syscall"

// No Pdeathsig here: recv stops on fd 3 EOF when the agent dies.
func setXferPdeathsig(attrs *syscall.SysProcAttr) {}
