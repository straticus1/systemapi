package main

// sys frames run off the connection's read goroutine (sys.go goSys) and every
// service call is bounded. Threats: a hung systemctl stop/restart/reload or a
// long package operation wedging the single read goroutine, so PTY, TCP, file
// and job frames stop being served; an unbounded service call.

import (
	"context"
	"encoding/json"
	"sync"
	"testing"
	"time"
)

// hungServiceMgr blocks every Action until release closes or ctx ends.
type hungServiceMgr struct {
	release chan struct{}
	started chan struct{}
	once    sync.Once
}

func (h *hungServiceMgr) Name() string    { return "hung" }
func (h *hungServiceMgr) Available() bool { return true }
func (h *hungServiceMgr) Action(ctx context.Context, verb, service string) (string, error) {
	h.once.Do(func() { close(h.started) })
	select {
	case <-h.release:
		return "done", nil
	case <-ctx.Done():
		return "", ctx.Err()
	}
}
func (h *hungServiceMgr) Status(ctx context.Context, service string) (ServiceStatus, error) {
	return ServiceStatus{State: "active", Active: true}, nil
}
func (h *hungServiceMgr) IsEnabled(context.Context, string) (bool, error) { return false, nil }

func withHungService(t *testing.T) *hungServiceMgr {
	t.Helper()
	hung := &hungServiceMgr{release: make(chan struct{}), started: make(chan struct{})}
	prev := sysServices
	sysServices = func() ServiceManager { return hung }
	t.Cleanup(func() { sysServices = prev })
	return hung
}

// handleOnly feeds a frame through the dispatcher without waiting for sys
// frames, the way the connection's read loop does, and fails if it blocks.
func handleOnly(t *testing.T, ch *channelConn, typ string, frame map[string]interface{}) {
	t.Helper()
	raw, err := json.Marshal(frame)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		if handled, err := ch.handle(typ, raw); !handled || err != nil {
			t.Errorf("%s: handled=%v err=%v", typ, handled, err)
		}
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatalf("%s blocked the read goroutine", typ)
	}
}

func waitSysResult(t *testing.T, out *fakeOut, rid string) map[string]interface{} {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		out.mu.Lock()
		for _, m := range out.jsons {
			if got, _ := m["request_id"].(string); m["type"] == "sys_result" && got == rid {
				p, _ := m["payload"].(map[string]interface{})
				out.mu.Unlock()
				return p
			}
		}
		out.mu.Unlock()
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("no sys_result for %s", rid)
	return nil
}

func TestSysHungServiceDoesNotBlockOtherFrames(t *testing.T) {
	h := newSysHarness(t, true)
	hung := withHungService(t)
	rid := newSysRequestID(t)
	handleOnly(t, h.ch, "sys_service", h.frame(t, rid, "nginx.service", "restart", "", "", inFuture(time.Minute)))
	<-hung.started
	// While the restart hangs, a TCP frame on the same connection is served.
	handleOnly(t, h.ch, "tcp_open", map[string]interface{}{"type": "tcp_open", "session_id": "bad"})
	h.out.mu.Lock()
	served := false
	for _, m := range h.out.jsons {
		if m["type"] == "tcp_status" {
			served = true
		}
	}
	h.out.mu.Unlock()
	if !served {
		t.Fatal("tcp_open was not answered while a sys_service hung")
	}
	// A second sys frame also runs concurrently and answers.
	rid2 := newSysRequestID(t)
	handleOnly(t, h.ch, "sys_service", h.frame(t, rid2, "nginx.service", "stop", "", "restart", inFuture(time.Minute)))
	if p := waitSysResult(t, h.out, rid2); p["error"] != "lease_required" {
		t.Fatalf("second frame: %v", p)
	}
	close(hung.release)
	if p := waitSysResult(t, h.out, rid); p["ok"] != true {
		t.Fatalf("released restart: %v", p)
	}
	h.ch.sysWait()
}

func TestSysServiceTimeoutReportsTimeout(t *testing.T) {
	h := newSysHarness(t, true)
	withHungService(t)
	prev := sysOpTimeout
	sysOpTimeout = 50 * time.Millisecond
	t.Cleanup(func() { sysOpTimeout = prev })
	rid := newSysRequestID(t)
	h.send(t, h.frame(t, rid, "nginx.service", "restart", "", "", inFuture(time.Minute)))
	p := h.result(t, rid)
	if p["ok"] != false || p["error"] != "timeout" {
		t.Fatalf("want timeout, got %v", p)
	}
	// The confirm read still ran on its own deadline.
	if p["state"] != "active" {
		t.Fatalf("status not read after the timeout: %v", p)
	}
}

func TestSysFramesPastTheLimitAreRefusedBusy(t *testing.T) {
	h := newSysHarness(t, true)
	hung := withHungService(t)
	var rids []string
	for i := 0; i < sysMaxInFlight; i++ {
		rid := newSysRequestID(t)
		rids = append(rids, rid)
		handleOnly(t, h.ch, "sys_service", h.frame(t, rid, "nginx.service", "restart", "", "", inFuture(time.Minute)))
	}
	<-hung.started
	extra := newSysRequestID(t)
	handleOnly(t, h.ch, "sys_service", h.frame(t, extra, "nginx.service", "restart", "", "", inFuture(time.Minute)))
	if p := waitSysResult(t, h.out, extra); p["ok"] != false || p["error"] != "busy" {
		t.Fatalf("want busy, got %v", p)
	}
	close(hung.release)
	for _, rid := range rids {
		if p := waitSysResult(t, h.out, rid); p["ok"] != true {
			t.Fatalf("%s: %v", rid, p)
		}
	}
}

// Closing the connection cancels a running sys frame instead of leaving it
// hung for the full timeout.
func TestSysCloseCancelsRunningFrames(t *testing.T) {
	h := newSysHarness(t, true)
	hung := withHungService(t)
	rid := newSysRequestID(t)
	handleOnly(t, h.ch, "sys_service", h.frame(t, rid, "nginx.service", "restart", "", "", inFuture(time.Minute)))
	<-hung.started
	h.ch.close("stopped")
	done := make(chan struct{})
	go func() { h.ch.sysWait(); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("close did not cancel the running sys frame")
	}
	if p := waitSysResult(t, h.out, rid); p["ok"] != false || p["error"] != "action_failed" {
		t.Fatalf("cancelled frame: %v", p)
	}
}

// The agent never stops or disables its own unit over the channel.
func TestSysServiceRefusesStoppingTheAgent(t *testing.T) {
	h := newSysHarness(t, true)
	for _, unit := range []string{"systemapi-agent.service", "systemapi-agent"} {
		for _, action := range []string{"stop", "disable"} {
			rid := newSysRequestID(t)
			h.send(t, h.frame(t, rid, unit, action, "", "", inFuture(time.Minute)))
			if p := h.result(t, rid); p["ok"] != false || p["error"] != "unit_denied" {
				t.Fatalf("%s %s: %v", action, unit, p)
			}
		}
	}
	if len(h.svc.actions) != 0 {
		t.Fatalf("no action should have run, got %v", h.svc.actions)
	}
	rid := newSysRequestID(t)
	h.send(t, h.frame(t, rid, "systemapi-agent.service", "restart", "", "", inFuture(time.Minute)))
	if p := h.result(t, rid); p["ok"] != true {
		t.Fatalf("restart of the agent unit: %v", p)
	}
}
