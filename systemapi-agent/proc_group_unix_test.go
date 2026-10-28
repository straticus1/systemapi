//go:build linux || darwin

package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestJobCommandOutputAndExit(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out, err := jobCommand(ctx, "sh", "-c", "echo out; echo err >&2").CombinedOutput()
	if err != nil || !strings.Contains(string(out), "out") || !strings.Contains(string(out), "err") {
		t.Fatalf("out=%q err=%v", out, err)
	}
	out, err = jobCommand(ctx, "sh", "-c", "echo out; echo err >&2").Output()
	if err != nil || strings.TrimSpace(string(out)) != "out" {
		t.Fatalf("out=%q err=%v", out, err)
	}
	if err := jobCommand(ctx, "sh", "-c", "exit 3").Run(); err == nil {
		t.Fatal("exit 3 reported success")
	}
}

func TestJobCommandRefusesEndedContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := jobCommand(ctx, "true").Run(); err == nil {
		t.Fatal("started on an ended context")
	}
}

func TestJobCommandDeadlineReturnsPromptly(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	start := time.Now()
	if err := jobCommand(ctx, "sh", "-c", "sleep 60 & sleep 60").Run(); err == nil {
		t.Fatal("killed command reported success")
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("took %s", d)
	}
}

func TestExecRunCapsOutput(t *testing.T) {
	engine := newTestEngine(&Entitlements{AllowExec: true})
	out, err := engine.Execute(`r = sys.exec.run("sh", "-c", "head -c 200000 /dev/zero | tr '\\0' a")` + "\n" + `print(len(r["output"]), r["truncated"])` + "\n")
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(out) != "65536 True" {
		t.Fatalf("out=%q", out)
	}
	out, err = engine.Execute(`r = sys.exec.run("echo", "hi")` + "\n" + `print(r["output"].strip(), r["truncated"], r["error"])` + "\n")
	if err != nil || strings.TrimSpace(out) != "hi False None" {
		t.Fatalf("out=%q err=%v", out, err)
	}
}

// waitGroupGone waits until no process of group pgid is left to signal
// (kill(-pgid, 0) answers ESRCH). Call it after Wait has reaped the leader;
// a grandchild may need its reaper (init, launchd, tini) for a moment.
func waitGroupGone(t *testing.T, pgid int, within time.Duration) {
	t.Helper()
	end := time.Now().Add(within)
	for {
		err := syscall.Kill(-pgid, 0)
		if errors.Is(err, syscall.ESRCH) {
			return
		}
		if time.Now().After(end) {
			t.Fatalf("group %d still present: kill(-pgid, 0) = %v", pgid, err)
		}
		time.Sleep(20 * time.Millisecond)
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
	d := time.Since(start)
	if d > jobKillGrace+time.Second {
		t.Fatalf("took %s", d)
	}
	if d < jobKillGrace {
		t.Fatalf("SIGKILL came before the grace: %s", d)
	}
	waitGroupGone(t, pgid, time.Second)
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
	waitGroupGone(t, pgid, time.Second)
}

// The leader dies on TERM at once, but a grandchild needs about 2 s to
// clean up. SIGKILL waits for it (its output pipe stays open until it is
// done) instead of following the leader's exit.
func TestJobCommandGraceOutlivesLeader(t *testing.T) {
	f := filepath.Join(t.TempDir(), "cleaned")
	ctx, cancel := context.WithCancel(context.Background())
	cmd := jobCommand(ctx, "sh", "-c", `(trap 'sleep 2; echo cleaned >> "$F"; exit 0' TERM; sleep 600 & wait) & wait`)
	cmd.Env = append(os.Environ(), "F="+f)
	out := &capWriter{max: outputCap}
	cmd.Stdout = out
	cmd.Stderr = out
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	pgid := cmd.Process.Pid
	time.Sleep(300 * time.Millisecond) // the subshell is now in wait
	start := time.Now()
	cancel()
	_ = cmd.Wait()
	d := time.Since(start)
	raw, _ := os.ReadFile(f)
	if strings.TrimSpace(string(raw)) != "cleaned" {
		t.Fatalf("grandchild cleanup was cut short after %s (file=%q)", d, raw)
	}
	if d < 2*time.Second || d > 5*time.Second {
		t.Fatalf("took %s", d)
	}
	waitGroupGone(t, pgid, time.Second)
}

func TestJobCommandRefusesSetsid(t *testing.T) {
	cmd := jobCommand(context.Background(), "true")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Run(); err == nil || !strings.Contains(err.Error(), "Setsid") {
		t.Fatalf("err=%v", err)
	}
}
