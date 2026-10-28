package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// busyLoop never ends on its own (this dialect has no while loop).
const busyLoop = "def spin():\n  for i in range(1 << 30):\n    for j in range(1 << 30):\n      pass\nspin()\n"

func TestExecuteDeadlineCancelsThread(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	engine := newTestEngine(&Entitlements{})
	engine.ctx = ctx
	start := time.Now()
	_, err := engine.Execute(busyLoop)
	if !errors.Is(err, errScriptTimedOut) {
		t.Fatalf("err=%v", err)
	}
	if d := time.Since(start); d > 500*time.Millisecond {
		t.Fatalf("took %s", d)
	}
}

func TestExecuteCancelsLoadedModule(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "spin.star"), []byte(busyLoop), 0o644); err != nil {
		t.Fatal(err)
	}
	orig := sysscriptLoadBase
	sysscriptLoadBase = dir
	t.Cleanup(func() { sysscriptLoadBase = orig })
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	engine := newTestEngine(&Entitlements{})
	engine.ctx = ctx
	start := time.Now()
	_, err := engine.Execute(`load("spin.star", "spin")` + "\n")
	if !errors.Is(err, errScriptTimedOut) {
		t.Fatalf("err=%v", err)
	}
	if d := time.Since(start); d > 500*time.Millisecond {
		t.Fatalf("took %s", d)
	}
}

func TestExecuteCancelCause(t *testing.T) {
	ctx, cancel := context.WithCancelCause(context.Background())
	engine := newTestEngine(&Entitlements{})
	engine.ctx = ctx
	time.AfterFunc(100*time.Millisecond, func() { cancel(errors.New("agent_stopped")) })
	_, err := engine.Execute(busyLoop)
	if !errors.Is(err, errScriptCancelled) || !strings.Contains(err.Error(), "agent_stopped") {
		t.Fatalf("err=%v", err)
	}
}

func TestExecuteRefusesWithoutContext(t *testing.T) {
	engine := newTestEngine(&Entitlements{})
	engine.ctx = nil
	if _, err := engine.Execute("print(1)\n"); err == nil {
		t.Fatal("ran without a script context")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	engine.ctx = ctx
	if _, err := engine.Execute("print(1)\n"); !errors.Is(err, errScriptCancelled) {
		t.Fatalf("err=%v", err)
	}
}

func TestHTTPGetBodyCapAndContext(t *testing.T) {
	big := strings.Repeat("x", hostFileCap+1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/big":
			_, _ = w.Write([]byte(big))
		case "/slow":
			select {
			case <-r.Context().Done():
			case <-time.After(5 * time.Second):
			}
		default:
			_, _ = w.Write([]byte("ok"))
		}
	}))
	defer srv.Close()
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	engine := newTestEngine(&Entitlements{AllowNetOutbound: []string{u.Hostname()}})
	out, err := engine.Execute(`print(sys.net.http_get("` + srv.URL + `/")["body"])` + "\n")
	if err != nil || strings.TrimSpace(out) != "ok" {
		t.Fatalf("out=%q err=%v", out, err)
	}
	if _, err := engine.Execute(`sys.net.http_get("` + srv.URL + `/big")` + "\n"); err == nil || !strings.Contains(err.Error(), "exceeds cap") {
		t.Fatalf("err=%v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	engine.ctx = ctx
	start := time.Now()
	if _, err := engine.Execute(`sys.net.http_get("` + srv.URL + `/slow")` + "\n"); !errors.Is(err, errScriptTimedOut) {
		t.Fatalf("err=%v", err)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("took %s", d)
	}
}
