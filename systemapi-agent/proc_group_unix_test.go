//go:build linux || darwin || freebsd || netbsd || openbsd || dragonfly

package main

import (
	"context"
	"strings"
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
