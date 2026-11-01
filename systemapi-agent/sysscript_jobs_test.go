package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// useTestJobManager installs a fresh job manager for one test.
func useTestJobManager(t *testing.T, workers, queue int) *jobManager {
	t.Helper()
	m := newJobManager(workers, queue)
	jobMgrMu.Lock()
	prev := jobMgrInst
	jobMgrInst = m
	jobMgrMu.Unlock()
	t.Cleanup(func() {
		m.stopAll(jobKillGrace + jobStopMargin)
		jobMgrMu.Lock()
		jobMgrInst = prev
		jobMgrMu.Unlock()
	})
	return m
}

func commandResult(out *fakeOut, requestID string) map[string]interface{} {
	out.mu.Lock()
	defer out.mu.Unlock()
	for _, m := range out.jsons {
		if m["type"] == "command_result" && m["request_id"] == requestID {
			p, _ := m["payload"].(map[string]interface{})
			return p
		}
	}
	return nil
}

func waitResult(t *testing.T, out *fakeOut, requestID string, within time.Duration) map[string]interface{} {
	t.Helper()
	var p map[string]interface{}
	waitFor(t, "command_result "+requestID, within, func() bool {
		p = commandResult(out, requestID)
		return p != nil
	})
	return p
}

func TestJobPoolBusyAndStop(t *testing.T) {
	m := newJobManager(1, 1)
	out := newFakeOut()
	ents := &Entitlements{}
	m.submitLegacy(out, "r1", busyLoop, ents, time.Minute)
	waitFor(t, "r1 picked up", 2*time.Second, func() bool { return len(m.pending) == 0 })
	m.submitLegacy(out, "r2", busyLoop, ents, time.Minute)
	start := time.Now()
	m.submitLegacy(out, "r3", busyLoop, ents, time.Minute)
	m.flush(time.Second)
	p := commandResult(out, "r3")
	if p == nil || p["error"] != "agent_busy" || time.Since(start) > 750*time.Millisecond {
		t.Fatalf("r3=%v after %s", p, time.Since(start))
	}
	if !m.stopAll(5 * time.Second) {
		t.Fatal("workers did not stop")
	}
	for _, id := range []string{"r1", "r2"} {
		if p := commandResult(out, id); p == nil || p["error"] != "agent_stopped" {
			t.Fatalf("%s=%v", id, p)
		}
	}
	m.submitLegacy(out, "r4", "print(1)\n", ents, time.Minute)
	m.flush(time.Second)
	if p := commandResult(out, "r4"); p == nil || p["error"] != "agent_stopped" {
		t.Fatalf("after stop r4=%v", p)
	}
}

func TestJobLegacyDeadlineAndOutput(t *testing.T) {
	m := newJobManager(2, 2)
	defer m.stopAll(5 * time.Second)
	out := newFakeOut()
	m.submitLegacy(out, "ok", "print('hi')\n", &Entitlements{}, time.Minute)
	m.submitLegacy(out, "slow", busyLoop, &Entitlements{}, 200*time.Millisecond)
	if p := waitResult(t, out, "ok", 2*time.Second); p["error"] != "" || p["output"] != "hi\n" {
		t.Fatalf("ok=%v", p)
	}
	p := waitResult(t, out, "slow", 2*time.Second)
	if e, _ := p["error"].(string); !strings.HasPrefix(e, "timed_out") {
		t.Fatalf("slow=%v", p)
	}
}

func TestJobPanicEndsOnlyThatJob(t *testing.T) {
	m := newJobManager(1, 2)
	defer m.stopAll(5 * time.Second)
	var mu sync.Mutex
	var got []error
	submit := func(id, script string, alerts func(interface{}) error) {
		ctx, cancel := context.WithCancelCause(context.Background())
		j := &sysscriptJob{id: id, script: script, ents: &Entitlements{}, ctx: ctx, cancel: cancel, alerts: alerts, started: time.Now()}
		j.finish = func(_ string, _ bool, err error) {
			mu.Lock()
			got = append(got, err)
			mu.Unlock()
		}
		if err := m.submit(j); err != nil {
			t.Fatal(err)
		}
	}
	submit("boom", `sys.alerts.push("info", "x")`+"\n", func(interface{}) error { panic("builtin bug") })
	submit("after", "print(1)\n", func(interface{}) error { return nil })
	waitFor(t, "both jobs", 2*time.Second, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(got) == 2
	})
	if got[0] == nil || got[0].Error() != "internal" || got[1] != nil {
		t.Fatalf("got=%v", got)
	}
}

func TestParseJobFlags(t *testing.T) {
	for _, c := range [][3]int{{0, 300, 3600}, {17, 300, 3600}, {4, 0, 3600}, {4, 3601, 3600}, {4, 300, 0}, {4, 300, 3601}} {
		if _, err := parseJobFlags(c[0], c[1], c[2]); err == nil {
			t.Fatalf("accepted %v", c)
		}
	}
	jc, err := parseJobFlags(4, 900, 600)
	if err != nil || jc.Legacy != 600*time.Second || jc.Max != 600*time.Second || jc.Workers != 4 {
		t.Fatalf("jc=%+v err=%v", jc, err)
	}
}

// liveServer is a fake control plane for one enrolled agent connection: it
// records the agent's text frames and pong times and serializes its writes.
type liveServer struct {
	mu     sync.Mutex
	conn   *websocket.Conn
	ready  chan struct{}
	frames chan map[string]interface{}
	pongs  chan time.Time
}

func (s *liveServer) write(t *testing.T, v interface{}) {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.conn.WriteJSON(v); err != nil {
		t.Errorf("server write: %v", err) // also called from the handler goroutine
	}
}

func (s *liveServer) next(t *testing.T, typ string, within time.Duration) map[string]interface{} {
	t.Helper()
	end := time.After(within)
	for {
		select {
		case m := <-s.frames:
			if m["type"] == typ {
				return m
			}
		case <-end:
			t.Fatalf("no %s frame within %s", typ, within)
		}
	}
}

func startLiveAgent(t *testing.T) (*liveServer, *agentConn, ed25519.PrivateKey) {
	t.Helper()
	pubKey, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub := base64.StdEncoding.EncodeToString(pubKey)
	s := &liveServer{ready: make(chan struct{}), frames: make(chan map[string]interface{}, 256), pongs: make(chan time.Time, 8)}
	var a *agentConn
	srv, _ := fakeControlPlane(t, func(n int64, c *websocket.Conn) {
		if n != 1 {
			return
		}
		s.conn = c
		c.SetPongHandler(func(string) error { s.pongs <- time.Now(); return nil })
		s.write(t, map[string]string{"type": "enrolled", "host_id": a.st.HostID, "control_pubkey": pub})
		close(s.ready)
		for {
			_, raw, err := c.ReadMessage()
			if err != nil {
				return
			}
			var m map[string]interface{}
			if json.Unmarshal(raw, &m) == nil && m["type"] != "telemetry" {
				s.frames <- m
			}
		}
	})
	a = testConn(t, srv, "good")
	a.telemetryEvery = time.Hour
	stop := make(chan struct{})
	done := make(chan error, 1)
	go func() { done <- a.run(stop) }()
	t.Cleanup(func() {
		close(stop)
		select {
		case <-done:
		case <-time.After(20 * time.Second):
			t.Error("agent did not stop")
		}
	})
	select {
	case <-s.ready:
	case <-time.After(5 * time.Second):
		t.Fatal("agent did not connect")
	}
	waitFor(t, "enrolled", 5*time.Second, func() bool {
		identityMu.Lock()
		defer identityMu.Unlock()
		return enrolledHostID == a.st.HostID
	})
	return s, a, priv
}

func sysscriptFrame(t *testing.T, priv ed25519.PrivateKey, host, id, script string, ents map[string]interface{}) map[string]interface{} {
	return map[string]interface{}{
		"type": "sysscript", "request_id": id, "script": script, "entitlements": ents,
		"lease": signLease(t, priv, host, "sysscript", script, time.Now().Add(time.Minute).Unix()),
	}
}

// A legacy script that runs for 5 s no longer stalls the read loop: a ping
// is answered and a pty frame is dispatched while it runs.
func TestLegacySysscriptLeavesReadLoopLive(t *testing.T) {
	useTestJobManager(t, jobWorkersDefault, jobPendingMax)
	s, a, priv := startLiveAgent(t)
	script := `r = sys.exec.run("sleep", "5")` + "\n" + `print(r["error"])` + "\n"
	sent := time.Now()
	s.write(t, sysscriptFrame(t, priv, a.st.HostID, "slow-1", script, map[string]interface{}{"allow_exec": true}))
	time.Sleep(300 * time.Millisecond) // the script is now inside sleep

	pingAt := time.Now()
	s.mu.Lock()
	err := s.conn.WriteControl(websocket.PingMessage, []byte("p"), time.Now().Add(time.Second))
	s.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	select {
	case at := <-s.pongs:
		if d := at.Sub(pingAt); d > 750*time.Millisecond {
			t.Fatalf("pong after %s", d)
		}
	case <-time.After(time.Second):
		t.Fatal("no pong while the script runs")
	}

	// pty_input for a session gives no reply, so a pty_renew (answered
	// pty_renew_rejected for an unknown session) shows pty frames are
	// dispatched.
	renewAt := time.Now()
	s.write(t, map[string]interface{}{"type": "pty_renew", "session_id": "pts_0123456789abcdef0123456789abcdef"})
	s.write(t, map[string]interface{}{"type": "pty_input", "session_id": "pts_0123456789abcdef0123456789abcdef", "data_b64": "aGk="})
	rej := s.next(t, "pty_renew_rejected", time.Second)
	if d := time.Since(renewAt); d > 750*time.Millisecond {
		t.Fatalf("pty frame dispatched after %s", d)
	}
	if p, _ := rej["payload"].(map[string]interface{}); p["error"] != "unknown_session" {
		t.Fatalf("rej=%v", rej)
	}

	res := s.next(t, "command_result", 10*time.Second)
	p, _ := res["payload"].(map[string]interface{})
	if res["request_id"] != "slow-1" || p["error"] != "" || strings.TrimSpace(p["output"].(string)) != "None" {
		t.Fatalf("result=%v", res)
	}
	if d := time.Since(sent); d < 5*time.Second {
		t.Fatalf("script ended after only %s", d)
	}
}

func TestLegacySysscriptBusyOverConnection(t *testing.T) {
	useTestJobManager(t, 1, 1)
	s, a, priv := startLiveAgent(t)
	ents := map[string]interface{}{}
	s.write(t, sysscriptFrame(t, priv, a.st.HostID, "b1", busyLoop, ents))
	waitFor(t, "b1 running", 2*time.Second, func() bool {
		m := jobMgr()
		m.mu.Lock()
		defer m.mu.Unlock()
		return len(m.pending) == 0 && len(m.live) == 1
	})
	s.write(t, sysscriptFrame(t, priv, a.st.HostID, "b2", busyLoop, ents))
	sent := time.Now()
	s.write(t, sysscriptFrame(t, priv, a.st.HostID, "b3", busyLoop, ents))
	res := s.next(t, "command_result", time.Second)
	if d := time.Since(sent); d > 750*time.Millisecond {
		t.Fatalf("agent_busy after %s", d)
	}
	p, _ := res["payload"].(map[string]interface{})
	if res["request_id"] != "b3" || p["error"] != "agent_busy" {
		t.Fatalf("result=%v", res)
	}
	// A forged frame is still refused by the lease check before the pool.
	forged := sysscriptFrame(t, priv, a.st.HostID, "b4", busyLoop, ents)
	forged["script"] = "print(2)\n"
	s.write(t, forged)
	res = s.next(t, "command_result", time.Second)
	if p, _ := res["payload"].(map[string]interface{}); res["request_id"] != "b4" || p["error"] != "payload_mismatch" {
		t.Fatalf("forged=%v", res)
	}
}

func TestSysscriptRequestIDCapped(t *testing.T) {
	out := newFakeOut()
	raw, err := json.Marshal(map[string]interface{}{"type": "sysscript", "request_id": strings.Repeat("r", requestIDMaxBytes+1), "script": "print(1)\n"})
	if err != nil {
		t.Fatal(err)
	}
	processIncomingMessage(out, "host", t.TempDir(), raw)
	if len(out.jsons) != 1 {
		t.Fatalf("frames=%v", out.jsons)
	}
	m := out.jsons[0]
	p, _ := m["payload"].(map[string]interface{})
	if _, echoed := m["request_id"]; echoed || m["type"] != "command_result" || p["error"] != "bad_request" {
		t.Fatalf("frame=%v", m)
	}
}
