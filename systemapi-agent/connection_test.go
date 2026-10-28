package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// fakeControlPlane enrolls each connection with handle(n, conn), n counting
// from 1.
func fakeControlPlane(t *testing.T, handle func(n int64, c *websocket.Conn)) (*httptest.Server, *int64) {
	t.Helper()
	var count int64
	up := websocket.Upgrader{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer good" {
			http.Error(w, "no", http.StatusUnauthorized)
			return
		}
		c, err := up.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer c.Close()
		handle(atomic.AddInt64(&count, 1), c)
	}))
	t.Cleanup(srv.Close)
	return srv, &count
}

func testConn(t *testing.T, srv *httptest.Server, key string) *agentConn {
	t.Helper()
	clearIdentity()
	t.Cleanup(clearIdentity)
	dir := t.TempDir()
	statePath := filepath.Join(dir, "agent.json")
	st, err := loadOrCreateState(statePath, "acme")
	if err != nil {
		t.Fatal(err)
	}
	header := http.Header{}
	header.Set("Authorization", "Bearer "+key)
	return &agentConn{
		url:            "ws" + strings.TrimPrefix(srv.URL, "http"),
		header:         header,
		dialer:         *websocket.DefaultDialer,
		st:             st,
		statePath:      statePath,
		hostname:       "qa-e2e-mac",
		telemetryEvery: 20 * time.Millisecond,
		enrollTimeout:  2 * time.Second,
		minBackoff:     10 * time.Millisecond,
		maxBackoff:     40 * time.Millisecond,
		telemetry: func(h string) (TelemetryPayload, error) {
			return TelemetryPayload{Host: HostInfo{Hostname: h}}, nil
		},
	}
}

func controlKeyB64(t *testing.T) string {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(pub)
}

func TestAgentReconnectsAfterDisconnect(t *testing.T) {
	pub := controlKeyB64(t)
	var a *agentConn
	gotTelemetryHost := make(chan string, 4)
	srv, count := fakeControlPlane(t, func(n int64, c *websocket.Conn) {
		_ = c.WriteJSON(map[string]string{"type": "enrolled", "host_id": a.st.HostID, "control_pubkey": pub})
		var msg struct {
			Type    string `json:"type"`
			Payload struct {
				Host HostInfo `json:"host"`
			} `json:"payload"`
		}
		// The first frame after enroll is sysscript_job_sync; read on to
		// the telemetry.
		for c.ReadJSON(&msg) == nil {
			if msg.Type == "telemetry" {
				gotTelemetryHost <- msg.Payload.Host.Hostname
				break
			}
		}
		if n < 3 {
			return // drop the connection
		}
		for {
			if _, _, err := c.ReadMessage(); err != nil {
				return
			}
		}
	})
	a = testConn(t, srv, "good")
	stop := make(chan struct{})
	result := make(chan error, 1)
	go func() { result <- a.run(stop) }()
	waitFor(t, "third connection", 5*time.Second, func() bool { return atomic.LoadInt64(count) >= 3 })
	if h := <-gotTelemetryHost; h != "qa-e2e-mac" {
		t.Fatalf("telemetry hostname %q", h)
	}
	close(stop)
	select {
	case err := <-result:
		if err != nil {
			t.Fatalf("clean stop returned %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("run did not stop")
	}
}

func TestAgentRetriesWhileControlPlaneIsDown(t *testing.T) {
	pub := controlKeyB64(t)
	var a *agentConn
	var down int32 = 1
	var refused int64
	var count int64
	up := websocket.Upgrader{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.LoadInt32(&down) == 1 {
			atomic.AddInt64(&refused, 1)
			http.Error(w, "down", http.StatusServiceUnavailable)
			return
		}
		c, err := up.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer c.Close()
		if atomic.AddInt64(&count, 1) == 1 {
			_ = c.WriteJSON(map[string]string{"type": "enroll_error", "error": "signer_unavailable"})
			return
		}
		_ = c.WriteJSON(map[string]string{"type": "enrolled", "host_id": a.st.HostID, "control_pubkey": pub})
		for {
			if _, _, err := c.ReadMessage(); err != nil {
				return
			}
		}
	}))
	t.Cleanup(srv.Close)
	a = testConn(t, srv, "good")
	stop := make(chan struct{})
	result := make(chan error, 1)
	go func() { result <- a.run(stop) }()
	waitFor(t, "several refused dials", 5*time.Second, func() bool { return atomic.LoadInt64(&refused) >= 3 })
	select {
	case err := <-result:
		t.Fatalf("gave up while the control plane was down: %v", err)
	default:
	}
	atomic.StoreInt32(&down, 0)
	waitFor(t, "enrolled after a transient refusal", 5*time.Second, func() bool { return atomic.LoadInt64(&count) >= 2 })
	close(stop)
	if err := <-result; err != nil {
		t.Fatal(err)
	}
}

func TestAgentStopsOnFatalErrors(t *testing.T) {
	srv, _ := fakeControlPlane(t, func(n int64, c *websocket.Conn) {
		_ = c.WriteJSON(map[string]string{"type": "enroll_error", "error": "not_a_member"})
	})
	for name, key := range map[string]string{"bad key": "bad", "permanent enroll error": "good"} {
		a := testConn(t, srv, key)
		result := make(chan error, 1)
		go func() { result <- a.run(make(chan struct{})) }()
		select {
		case err := <-result:
			if err == nil || !isFatal(err) {
				t.Fatalf("%s: got %v", name, err)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("%s: kept retrying", name)
		}
	}
}

func TestJitteredBackoffRange(t *testing.T) {
	for i := 0; i < 100; i++ {
		d := jittered(time.Second)
		if d < 500*time.Millisecond || d > time.Second {
			t.Fatalf("out of range: %s", d)
		}
	}
}
