//go:build !linux

package main

// sessionMembers is Linux only. Elsewhere the process group signal is all
// the agent sends.
func sessionMembers(sid int) []int { return nil }
