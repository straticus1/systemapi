//go:build linux

package main

import (
	"os"
	"strconv"
	"strings"
)

// sessionMembers lists processes whose session id is sid. It catches
// background jobs that a job-control shell put in their own process group
// (nohup, disown). A process that called setsid itself is not found.
func sessionMembers(sid int) []int {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil
	}
	var out []int
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil || pid == sid {
			continue
		}
		raw, err := os.ReadFile("/proc/" + e.Name() + "/stat")
		if err != nil {
			continue
		}
		// Fields after the ")" that ends comm: state ppid pgrp session ...
		stat := string(raw)
		i := strings.LastIndexByte(stat, ')')
		if i < 0 {
			continue
		}
		fields := strings.Fields(stat[i+1:])
		if len(fields) < 4 {
			continue
		}
		if s, err := strconv.Atoi(fields[3]); err == nil && s == sid {
			out = append(out, pid)
		}
	}
	return out
}
