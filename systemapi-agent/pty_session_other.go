//go:build !linux && !darwin

package main

import "syscall"

// sessionMembers is Linux only. Elsewhere the process group signal is all
// the agent sends.
func sessionMembers(sid int) []int { return nil }

func signalSessionMember(pid, sid int, sig syscall.Signal) bool { return false }

// waitExitedNoReap is Linux only (waitid with WNOWAIT). Elsewhere it returns
// false and the caller reaps first.
func waitExitedNoReap(pid int) bool { return false }
