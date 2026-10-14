//go:build linux

package main

import (
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

func TestStatSessionParsesOddComm(t *testing.T) {
	raw := []byte("1234 (a) b (c) S 1 1234 4321 0 -1 4194560")
	if got := statSession(raw); got != 4321 {
		t.Fatalf("got %d", got)
	}
	if statSession([]byte("garbage")) != -1 {
		t.Fatal("parsed garbage")
	}
}

// waitExitedNoReap must leave the child a zombie so its PID stays reserved.
func TestWaitExitedNoReapKeepsZombie(t *testing.T) {
	cmd := exec.Command("/bin/sh", "-c", "exit 5")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	pid := cmd.Process.Pid
	if !waitExitedNoReap(pid) {
		t.Fatal("waitid failed")
	}
	stat, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		t.Fatalf("pid released before reaping: %v", err)
	}
	if fields := strings.Fields(string(stat[strings.LastIndexByte(string(stat), ')')+1:])); fields[0] != "Z" {
		t.Fatalf("state %s, want Z", fields[0])
	}
	_ = cmd.Wait()
	if cmd.ProcessState.ExitCode() != 5 {
		t.Fatalf("exit %d", cmd.ProcessState.ExitCode())
	}
}

// A process outside the session is never signalled, even by pid.
func TestSignalSessionMemberChecksSession(t *testing.T) {
	cmd := exec.Command("sleep", "30")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	sid, err := unix.Getsid(cmd.Process.Pid)
	if err != nil {
		t.Fatal(err)
	}
	if signalSessionMember(cmd.Process.Pid, sid+1, syscall.SIGKILL) {
		t.Fatal("signalled a process in another session")
	}
	if err := syscall.Kill(cmd.Process.Pid, 0); err != nil {
		t.Fatal("process was killed")
	}
	if !signalSessionMember(cmd.Process.Pid, sid, syscall.SIGKILL) {
		t.Fatal("did not signal a real member")
	}
}
