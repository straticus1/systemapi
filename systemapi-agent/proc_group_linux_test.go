//go:build linux

package main

import (
	"context"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// procStat returns the state and process group of pid from /proc, ok=false
// when the process is gone (reaped).
func procStat(pid int) (state byte, pgrp int, ok bool) {
	raw, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return 0, 0, false
	}
	s := string(raw)
	i := strings.LastIndexByte(s, ')')
	if i < 0 || i+2 >= len(s) {
		return 0, 0, false
	}
	f := strings.Fields(s[i+2:])
	if len(f) < 3 {
		return 0, 0, false
	}
	pg, err := strconv.Atoi(f[2])
	if err != nil {
		return 0, 0, false
	}
	return f[0][0], pg, true
}

// liveInGroup lists the processes of group pgid that are not zombies.
func liveInGroup(t *testing.T, pgid int) []int {
	t.Helper()
	ents, err := os.ReadDir("/proc")
	if err != nil {
		t.Fatal(err)
	}
	var pids []int
	for _, e := range ents {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		if st, pg, ok := procStat(pid); ok && pg == pgid && st != 'Z' {
			pids = append(pids, pid)
		}
	}
	return pids
}

func waitGroupEmpty(t *testing.T, pgid int, within time.Duration) {
	t.Helper()
	end := time.Now().Add(within)
	for {
		left := liveInGroup(t, pgid)
		if len(left) == 0 {
			return
		}
		if time.Now().After(end) {
			t.Fatalf("group %d still has %v", pgid, left)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestJobCommandDeadlineKillsGrandchildren(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	cmd := jobCommand(ctx, "sh", "-c", "sleep 60 & sleep 60")
	out := &capWriter{max: outputCap}
	cmd.Stdout = out
	cmd.Stderr = out
	start := time.Now()
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	pgid := cmd.Process.Pid
	if err := cmd.Wait(); err == nil {
		t.Fatal("killed command reported success")
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("took %s", d)
	}
	waitGroupEmpty(t, pgid, time.Second)
}

func TestExecRunDeadlineIsTimedOut(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	engine := newTestEngine(&Entitlements{AllowExec: true})
	engine.ctx = ctx
	start := time.Now()
	_, err := engine.Execute(`r = sys.exec.run("sh", "-c", "sleep 60 & sleep 60")` + "\n" + `print(r["error"])` + "\n")
	if err == nil || !strings.HasPrefix(err.Error(), "timed_out") {
		t.Fatalf("err=%v", err)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("took %s", d)
	}
}

func TestJobCommandTermIgnoredGetsKill(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	cmd := jobCommand(ctx, "sh", "-c", "trap '' TERM; sleep 600")
	start := time.Now()
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	pgid := cmd.Process.Pid
	if err := cmd.Wait(); err == nil {
		t.Fatal("killed command reported success")
	}
	if d := time.Since(start); d > jobKillGrace+time.Second {
		t.Fatalf("took %s", d)
	}
	if d := time.Since(start); d < jobKillGrace {
		t.Fatalf("SIGKILL came before the grace: %s", d)
	}
	waitGroupEmpty(t, pgid, time.Second)
}

// A terminal session runs in its own session (pty.go) and an xfer child in
// its own session too (xfer_spawn_unix.go); a job's group kill must not
// reach either.
func TestJobGroupKillSparesSessionChildren(t *testing.T) {
	ptyLike := exec.Command("sleep", "30")
	ptyLike.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	xferLike := exec.Command("sleep", "30")
	xferLike.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	for _, c := range []*exec.Cmd{ptyLike, xferLike} {
		if err := c.Start(); err != nil {
			t.Fatal(err)
		}
		c := c
		t.Cleanup(func() {
			_ = c.Process.Kill()
			_ = c.Wait()
		})
	}
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	job := jobCommand(ctx, "sh", "-c", "sleep 60 & sleep 60")
	if err := job.Start(); err != nil {
		t.Fatal(err)
	}
	pgid := job.Process.Pid
	_ = job.Wait()
	waitGroupEmpty(t, pgid, time.Second)
	for _, c := range []*exec.Cmd{ptyLike, xferLike} {
		if st, _, ok := procStat(c.Process.Pid); !ok || st == 'Z' {
			t.Fatalf("pid %d was killed by the job's group kill", c.Process.Pid)
		}
	}
}

// recordKills replaces groupKill. Each call records whether the leader was
// still present in /proc (alive or an unreaped zombie), which is what keeps
// its pid, the group id, from being reused.
type killRecord struct {
	sig         syscall.Signal
	leaderThere bool
	afterReap   bool
}

func recordKills(t *testing.T, reaped *atomic.Bool) func() []killRecord {
	var mu sync.Mutex
	var recs []killRecord
	orig := groupKill
	t.Cleanup(func() { groupKill = orig })
	groupKill = func(pgid int, sig syscall.Signal) error {
		_, _, there := procStat(pgid)
		mu.Lock()
		recs = append(recs, killRecord{sig: sig, leaderThere: there, afterReap: reaped.Load()})
		mu.Unlock()
		return orig(pgid, sig)
	}
	return func() []killRecord {
		mu.Lock()
		defer mu.Unlock()
		return append([]killRecord(nil), recs...)
	}
}

func TestJobCommandSignalsOnlyBeforeReap(t *testing.T) {
	var reaped atomic.Bool
	kills := recordKills(t, &reaped)

	// Cancelled mid-run: TERM then KILL, both while the leader is unreaped.
	ctx, cancel := context.WithCancel(context.Background())
	cmd := jobCommand(ctx, "sh", "-c", "sleep 60 & sleep 60")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	time.AfterFunc(100*time.Millisecond, cancel)
	_ = cmd.Wait()
	reaped.Store(true)
	recs := kills()
	if len(recs) != 2 || recs[0].sig != syscall.SIGTERM || recs[1].sig != syscall.SIGKILL {
		t.Fatalf("kills=%+v", recs)
	}
	for _, r := range recs {
		if !r.leaderThere || r.afterReap {
			t.Fatalf("signal with the leader reaped: %+v", r)
		}
	}

	// Finished normally, then the context ends: nothing is signalled.
	reaped.Store(false)
	ctx2, cancel2 := context.WithCancel(context.Background())
	done := jobCommand(ctx2, "true")
	if err := done.Run(); err != nil {
		t.Fatal(err)
	}
	reaped.Store(true)
	cancel2()
	time.Sleep(100 * time.Millisecond)
	if got := kills(); len(got) != 2 {
		t.Fatalf("signal after reap: %+v", got[2:])
	}
}

// A grandchild that keeps the output pipe open after the leader exits holds
// Wait until the deadline, then the group is killed (leader still unreaped).
func TestJobCommandPipeHolderKilledAtDeadline(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	cmd := jobCommand(ctx, "sh", "-c", "sleep 60 &")
	out := &capWriter{max: outputCap}
	cmd.Stdout = out
	start := time.Now()
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	pgid := cmd.Process.Pid
	_ = cmd.Wait()
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("took %s", d)
	}
	waitGroupEmpty(t, pgid, time.Second)
}
