//go:build linux

package main

import (
	"errors"
	"os"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
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
		if statSession(raw) == sid {
			out = append(out, pid)
		}
	}
	return out
}

// statSession returns the session id field of /proc/<pid>/stat, or -1.
func statSession(raw []byte) int {
	// Fields after the ")" that ends comm: state ppid pgrp session ...
	stat := string(raw)
	i := strings.LastIndexByte(stat, ')')
	if i < 0 {
		return -1
	}
	fields := strings.Fields(stat[i+1:])
	if len(fields) < 4 {
		return -1
	}
	s, err := strconv.Atoi(fields[3])
	if err != nil {
		return -1
	}
	return s
}

// signalSessionMember signals pid through a pidfd after re-checking that it
// is still in session sid, so a PID reused since the /proc scan is never
// signalled. Kernels without pidfd_open (before 5.3) fall back to kill(2)
// after the same re-check.
func signalSessionMember(pid, sid int, sig syscall.Signal) bool {
	fd, err := unix.PidfdOpen(pid, 0)
	if err != nil {
		if !errors.Is(err, unix.ENOSYS) {
			return false
		}
		raw, rerr := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
		if rerr != nil || statSession(raw) != sid {
			return false
		}
		return syscall.Kill(pid, sig) == nil
	}
	defer unix.Close(fd)
	raw, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil || statSession(raw) != sid {
		return false
	}
	return unix.PidfdSendSignal(fd, unix.Signal(sig), nil, 0) == nil
}

// waitExitedNoReap blocks until pid exits but leaves it a zombie, so its PID
// (and its process group and session ids) stay reserved until the caller
// reaps it.
func waitExitedNoReap(pid int) bool {
	var info unix.Siginfo
	for {
		err := unix.Waitid(unix.P_PID, pid, &info, unix.WEXITED|unix.WNOWAIT, nil)
		if err == nil {
			return true
		}
		if !errors.Is(err, unix.EINTR) {
			return false
		}
	}
}
