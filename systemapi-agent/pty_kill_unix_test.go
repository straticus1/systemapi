//go:build !windows

package main

import (
	"regexp"
	"runtime"
	"strconv"
	"syscall"
	"testing"
	"time"
)

// PTY tests that signal or inspect processes by pid, split from pty_test.go
// so GOOS=windows go vet type-checks the rest.

var bgPidRe = regexp.MustCompile(`BG=([0-9]+)[\r\n]`)

func pidFromOutput(t *testing.T, h *ptyHarness, sid string) int {
	t.Helper()
	var pid int
	waitFor(t, "BG pid", 5*time.Second, func() bool {
		m := bgPidRe.FindStringSubmatch(h.out.text(sid))
		if m == nil {
			return false
		}
		n, err := strconv.Atoi(m[1])
		pid = n
		return err == nil
	})
	return pid
}

func alive(pid int) bool {
	return syscall.Kill(pid, 0) == nil
}

func TestPTYStopKillsBackgroundJobs(t *testing.T) {
	h := newPTYHarness(t)
	ptyCfg.Shell = writeScript(t, "nohup sleep 1000 >/dev/null 2>&1 &\necho BG=$!\nwhile :; do sleep 1; done\n")
	sid := h.start(t, "pty", inFuture(60*time.Second), inFuture(time.Hour))
	bg := pidFromOutput(t, h, sid)
	if !alive(bg) {
		t.Fatal("background job not running")
	}
	handlePTYStop(sid)
	if _, reason := h.exitOf(t, sid, 5*time.Second); reason != "stopped" {
		t.Fatal(reason)
	}
	waitFor(t, "background job killed", 5*time.Second, func() bool { return !alive(bg) })
}

func TestPTYShellExitKillsLeftovers(t *testing.T) {
	h := newPTYHarness(t)
	ptyCfg.Shell = writeScript(t, "nohup sleep 1000 >/dev/null 2>&1 &\necho BG=$!\nsleep 0.3\nexit 0\n")
	sid := h.start(t, "pty", inFuture(60*time.Second), inFuture(time.Hour))
	bg := pidFromOutput(t, h, sid)
	if code, reason := h.exitOf(t, sid, 5*time.Second); code != 0 || reason != "exited" {
		t.Fatalf("%d %s", code, reason)
	}
	waitFor(t, "leftover killed", 5*time.Second, func() bool { return !alive(bg) })
}

// An interactive shell puts a background job in its own process group, so a
// group signal alone misses it. The session sweep (/proc on Linux, sysctl
// and getsid on macOS) must catch it.
func TestPTYStopKillsJobControlChildren(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skip("session sweep is Linux and macOS only")
	}
	h := newPTYHarness(t)
	sid := h.start(t, "pty", inFuture(60*time.Second), inFuture(time.Hour))
	s := lookupSession(sid)
	if s == nil {
		t.Fatal("not started")
	}
	handlePTYInput(sid, []byte("set -m; nohup sleep 1000 >/dev/null 2>&1 & echo BG=$!\n"))
	bg := pidFromOutput(t, h, sid)
	pgid, err := syscall.Getpgid(bg)
	if err != nil {
		t.Fatal(err)
	}
	if pgid == s.cmd.Process.Pid {
		t.Fatalf("background job shares the shell's group (%d); job control is off", pgid)
	}
	handlePTYStop(sid)
	h.exitOf(t, sid, 5*time.Second)
	waitFor(t, "job-control child killed", 5*time.Second, func() bool { return !alive(bg) })
}
