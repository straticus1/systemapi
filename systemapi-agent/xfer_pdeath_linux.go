//go:build linux

package main

import "syscall"

// SIGTERM, not SIGKILL: recv deletes its temp file on the way out.
func setXferPdeathsig(attrs *syscall.SysProcAttr) { attrs.Pdeathsig = syscall.SIGTERM }
