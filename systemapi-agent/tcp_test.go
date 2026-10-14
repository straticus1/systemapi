package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

type tcpHarness struct {
	priv ed25519.PrivateKey
	out  *fakeOut
	ch   *channelConn
}

func newTCPHarness(t *testing.T, allow string) *tcpHarness {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	clearIdentity()
	if err := pinControlPublicKey(base64.StdEncoding.EncodeToString(pub), ptyTestHost); err != nil {
		t.Fatal(err)
	}
	rules, err := parseTCPAllow(allow)
	if err != nil {
		t.Fatal(err)
	}
	prevRules, prevWatch, prevDial, prevTimeout := tcpAllowRules, tcpWatchEvery, tcpDial, tcpDialTimeout
	tcpAllowRules = rules
	tcpWatchEvery = 20 * time.Millisecond
	h := &tcpHarness{priv: priv, out: newFakeOut()}
	h.ch = newChannelConn(h.out, ptyTestHost)
	t.Cleanup(func() {
		h.ch.close("stopped")
		tcpAllowRules, tcpWatchEvery, tcpDial, tcpDialTimeout = prevRules, prevWatch, prevDial, prevTimeout
		clearIdentity()
	})
	return h
}

func newTCPSessionID(t *testing.T) string {
	t.Helper()
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return "tcs_" + hex.EncodeToString(b)
}

type tcpOpenOpts struct {
	leaseHost string // the signed target, when it differs from the opened one
	leasePort int
	leaseExp  int64
	deadline  int64
	idle      int64
	maxBytes  int64
	phase     string
}

func (h *tcpHarness) send(t *testing.T, v interface{}) error {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	var peek struct {
		Type string `json:"type"`
	}
	_ = json.Unmarshal(raw, &peek)
	handled, err := h.ch.handle(peek.Type, raw)
	if !handled {
		t.Fatalf("%s not handled", peek.Type)
	}
	return err
}

func (h *tcpHarness) open(t *testing.T, host string, port int, o tcpOpenOpts) string {
	t.Helper()
	sid := newTCPSessionID(t)
	if o.deadline == 0 {
		o.deadline = inFuture(time.Hour)
	}
	if o.leaseExp == 0 {
		o.leaseExp = inFuture(time.Minute)
	}
	if o.idle == 0 {
		o.idle = 900
	}
	if o.maxBytes == 0 {
		o.maxBytes = 1 << 40
	}
	if o.leaseHost == "" {
		o.leaseHost = host
	}
	if o.leasePort == 0 {
		o.leasePort = port
	}
	if o.phase == "" {
		o.phase = "start"
	}
	payload, err := tcpLeasePayload(sid, o.deadline, o.phase, o.leaseHost, o.leasePort)
	if err != nil {
		t.Fatal(err)
	}
	lease := signLease(t, h.priv, ptyTestHost, "tcp", payload, o.leaseExp)
	_ = h.send(t, map[string]interface{}{
		"type": "tcp_open", "session_id": sid, "target": map[string]interface{}{"host": host, "port": port},
		"deadline_unix": o.deadline, "idle_s": o.idle, "max_bytes": o.maxBytes, "lease": lease,
	})
	return sid
}

func (h *tcpHarness) status(t *testing.T, sid string, timeout time.Duration) map[string]interface{} {
	t.Helper()
	var p map[string]interface{}
	waitFor(t, "tcp_status "+sid, timeout, func() bool {
		m := h.out.find("tcp_status", sid)
		if m == nil {
			return false
		}
		p, _ = m["payload"].(map[string]interface{})
		return true
	})
	return p
}

func (h *tcpHarness) errorOf(t *testing.T, sid string) string {
	t.Helper()
	e, _ := h.status(t, sid, 3*time.Second)["error"].(string)
	return e
}

func (h *tcpHarness) closed(t *testing.T, sid string, timeout time.Duration) map[string]interface{} {
	t.Helper()
	var p map[string]interface{}
	waitFor(t, "tcp_closed "+sid, timeout, func() bool {
		m := h.out.find("tcp_closed", sid)
		if m == nil {
			return false
		}
		p, _ = m["payload"].(map[string]interface{})
		return true
	})
	return p
}

func (h *tcpHarness) toTarget(t *testing.T, sid string, b []byte) error {
	t.Helper()
	frame := append([]byte{byte(len(sid))}, sid...)
	return h.ch.data(append(frame, b...))
}

// listen returns a loopback listener's port and a channel of accepted conns.
func listen(t *testing.T) (int, chan *net.TCPConn) {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	conns := make(chan *net.TCPConn, 70)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			t.Cleanup(func() { _ = c.Close() })
			conns <- c.(*net.TCPConn)
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port, conns
}

func accepted(t *testing.T, conns chan *net.TCPConn) *net.TCPConn {
	t.Helper()
	select {
	case c := <-conns:
		return c
	case <-time.After(3 * time.Second):
		t.Fatal("no connection reached the target")
	}
	return nil
}

func (h *tcpHarness) connect(t *testing.T, o tcpOpenOpts) (string, *net.TCPConn, int) {
	t.Helper()
	port, conns := listen(t)
	tcpAllowRules = append(tcpAllowRules, tcpAllowRule{local: true, lo: port, hi: port})
	sid := h.open(t, "local", port, o)
	target := accepted(t, conns)
	p := h.status(t, sid, 3*time.Second)
	if p["status"] != "connected" {
		t.Fatalf("status %v", p)
	}
	return sid, target, port
}

func TestTCPCapabilityAdvertised(t *testing.T) {
	if !strings.Contains(","+capabilitiesHeaderValue()+",", ",tcp,") {
		t.Fatalf("capabilities %q lack tcp", capabilitiesHeaderValue())
	}
}

func TestTCPEmptyAllowlistIsTargetDeniedAgent(t *testing.T) {
	h := newTCPHarness(t, "")
	port, conns := listen(t)
	sid := h.open(t, "local", port, tcpOpenOpts{})
	if e := h.errorOf(t, sid); e != "target_denied_agent" {
		t.Fatalf("got %q", e)
	}
	select {
	case <-conns:
		t.Fatal("dialed despite an empty allowlist")
	case <-time.After(100 * time.Millisecond):
	}
	// Allowed host, other port.
	h2 := newTCPHarness(t, "local:1")
	sid = h2.open(t, "local", port, tcpOpenOpts{})
	if e := h2.errorOf(t, sid); e != "target_denied_agent" {
		t.Fatalf("got %q", e)
	}
}

func TestTCPRefusedClassesOnTheAgent(t *testing.T) {
	// Even an allowlist that names them cannot open the refused classes.
	h := newTCPHarness(t, "169.254.0.0/16:80,127.0.0.0/8:5432,0.0.0.0/0:80,::/0:80")
	for _, host := range []string{"169.254.169.254", "127.0.0.1", "100.100.100.200", "fd00:ec2::254", "::ffff:10.0.0.1"} {
		sid := h.open(t, host, 80, tcpOpenOpts{})
		if e := h.errorOf(t, sid); e != "target_forbidden" {
			t.Fatalf("%s: got %q", host, e)
		}
	}
}

func TestTCPLeaseBindsTheTarget(t *testing.T) {
	h := newTCPHarness(t, "local:1-65535,10.0.0.0/8:1-65535")
	port, conns := listen(t)
	cases := []tcpOpenOpts{
		{leaseHost: "local", leasePort: port + 1}, // other port
		{leaseHost: "10.0.0.7", leasePort: port},  // other host
		{leaseExp: inFuture(-time.Hour)},          // expired
		{phase: "renew"},                          // a renewal lease cannot start
		{deadline: inFuture(-time.Second)},        // past deadline
		{deadline: inFuture(8 * 24 * time.Hour)},  // too far
	}
	for i, o := range cases {
		sid := h.open(t, "local", port, o)
		if e := h.errorOf(t, sid); e != "lease_required" {
			t.Fatalf("case %d: got %q", i, e)
		}
	}
	// No lease at all.
	sid := newTCPSessionID(t)
	_ = h.send(t, map[string]interface{}{"type": "tcp_open", "session_id": sid, "target": map[string]interface{}{"host": "local", "port": port},
		"deadline_unix": inFuture(time.Hour), "idle_s": 900, "max_bytes": 100})
	if e := h.errorOf(t, sid); e != "lease_required" {
		t.Fatalf("no lease: got %q", e)
	}
	select {
	case <-conns:
		t.Fatal("dialed without a matching lease")
	case <-time.After(100 * time.Millisecond):
	}
	// Bad session id.
	_ = h.send(t, map[string]interface{}{"type": "tcp_open", "session_id": "pts_nope"})
	if m := h.out.find("tcp_status", ""); m == nil {
		t.Fatal("bad session id not refused")
	}
}

func TestTCPDialErrorsMapToCodes(t *testing.T) {
	h := newTCPHarness(t, "local:1-65535,10.0.0.0/8:1-65535")
	// A real refusal.
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	sid := h.open(t, "local", port, tcpOpenOpts{})
	if e := h.errorOf(t, sid); e != "connect_refused" {
		t.Fatalf("got %q", e)
	}
	// Timeout and no route, simulated; the dial is by IP and 10 s by default.
	if tcpDialTimeout != 10*time.Second {
		t.Fatalf("dial timeout %s", tcpDialTimeout)
	}
	var dialed []string
	var mu sync.Mutex
	for _, c := range []struct {
		err  error
		code string
	}{
		{&net.OpError{Op: "dial", Err: timeoutErr{}}, "connect_timeout"},
		{&net.OpError{Op: "dial", Err: os.NewSyscallError("connect", syscall.EHOSTUNREACH)}, "host_unreachable"},
		{&net.OpError{Op: "dial", Err: os.NewSyscallError("connect", syscall.ENETUNREACH)}, "host_unreachable"},
		{errors.New("something else"), "internal"},
	} {
		c := c
		tcpDial = func(ap netip.AddrPort, timeout time.Duration) (net.Conn, error) {
			mu.Lock()
			dialed = append(dialed, ap.String())
			mu.Unlock()
			return nil, c.err
		}
		sid := h.open(t, "10.0.0.7", 3389, tcpOpenOpts{})
		if e := h.errorOf(t, sid); e != c.code {
			t.Fatalf("%v: got %q want %q", c.err, e, c.code)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	for _, d := range dialed {
		if d != "10.0.0.7:3389" {
			t.Fatalf("dialed %q", d)
		}
	}
}

type timeoutErr struct{}

func (timeoutErr) Error() string   { return "i/o timeout" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }

func TestTCPRelayBothWaysAndCreditReturn(t *testing.T) {
	h := newTCPHarness(t, "")
	sid, target, port := h.connect(t, tcpOpenOpts{})
	p := h.status(t, sid, time.Second)
	if p["peer"] != "127.0.0.1:"+strconv.Itoa(port) {
		t.Fatalf("peer %v", p["peer"])
	}
	if err := h.toTarget(t, sid, []byte("hello target")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64)
	_ = target.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, err := io.ReadAtLeast(target, buf, len("hello target"))
	if err != nil || string(buf[:n]) != "hello target" {
		t.Fatalf("target read %q %v", buf[:n], err)
	}
	if _, err := target.Write([]byte("hello client")); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "bytes to the server", 3*time.Second, func() bool { return h.out.text(sid) == "hello client" })

	// A quarter window drained returns credit.
	big := bytes.Repeat([]byte{7}, int(tcpCreditWindow/4))
	go func() { _, _ = io.Copy(io.Discard, target) }()
	if err := h.toTarget(t, sid, big); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "tcp_credit", 3*time.Second, func() bool { return h.out.find("tcp_credit", sid) != nil })
	if b := h.out.find("tcp_credit", sid)["bytes"].(float64); int64(b) < tcpCreditWindow/4 {
		t.Fatalf("credit %v", b)
	}

	_ = h.send(t, map[string]interface{}{"type": "tcp_stop", "session_id": sid})
	c := h.closed(t, sid, 3*time.Second)
	if c["reason"] != "stopped" || c["bytes_in"].(float64) != 12 || c["bytes_out"].(float64) != float64(12+len(big)) {
		t.Fatalf("tcp_closed %v", c)
	}
}

func TestTCPClientFINThenTargetStillSends(t *testing.T) {
	h := newTCPHarness(t, "")
	sid, target, _ := h.connect(t, tcpOpenOpts{})
	if err := h.toTarget(t, sid, []byte("request")); err != nil {
		t.Fatal(err)
	}
	_ = h.send(t, map[string]interface{}{"type": "tcp_eof", "session_id": sid})
	// The target reads the bytes, then EOF (shutdown(SHUT_WR)).
	_ = target.SetReadDeadline(time.Now().Add(3 * time.Second))
	got, err := io.ReadAll(target)
	if err != nil || string(got) != "request" {
		t.Fatalf("target got %q %v", got, err)
	}
	// After one FIN, data still flows the other way.
	if _, err := target.Write([]byte("response")); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "response", 3*time.Second, func() bool { return h.out.text(sid) == "response" })
	if h.out.find("tcp_closed", sid) != nil {
		t.Fatal("closed after one FIN")
	}
	// Target FIN: tcp_eof, then tcp_closed "closed".
	_ = target.CloseWrite()
	c := h.closed(t, sid, 3*time.Second)
	if h.out.find("tcp_eof", sid) == nil || c["reason"] != "closed" || c["bytes_in"].(float64) != 8 || c["bytes_out"].(float64) != 7 {
		t.Fatalf("tcp_closed %v", c)
	}
	assertOrder(t, h.out, sid, "tcp_eof", "tcp_closed")
}

func TestTCPTargetFINThenClientStillSends(t *testing.T) {
	h := newTCPHarness(t, "")
	sid, target, _ := h.connect(t, tcpOpenOpts{})
	if _, err := target.Write([]byte("banner")); err != nil {
		t.Fatal(err)
	}
	_ = target.CloseWrite()
	waitFor(t, "tcp_eof", 3*time.Second, func() bool { return h.out.find("tcp_eof", sid) != nil })
	// The bytes before the FIN reached the server first.
	if h.out.text(sid) != "banner" {
		t.Fatalf("got %q", h.out.text(sid))
	}
	if err := h.toTarget(t, sid, []byte("more from the client")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64)
	_ = target.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, err := io.ReadAtLeast(target, buf, 20)
	if err != nil || string(buf[:n]) != "more from the client" {
		t.Fatalf("target got %q %v", buf[:n], err)
	}
	_ = h.send(t, map[string]interface{}{"type": "tcp_eof", "session_id": sid})
	if c := h.closed(t, sid, 3*time.Second); c["reason"] != "closed" {
		t.Fatalf("tcp_closed %v", c)
	}
	// Bytes after tcp_eof never reach the target.
	_ = h.toTarget(t, sid, []byte("late"))
}

func assertOrder(t *testing.T, f *fakeOut, sid string, first, second string) {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	a, b := -1, -1
	for i, m := range f.jsons {
		if got, _ := m["session_id"].(string); got != sid {
			continue
		}
		if m["type"] == first && a < 0 {
			a = i
		}
		if m["type"] == second && b < 0 {
			b = i
		}
	}
	if a < 0 || b < 0 || a > b {
		t.Fatalf("%s at %d, %s at %d", first, a, second, b)
	}
}

func TestTCPResetFromTarget(t *testing.T) {
	h := newTCPHarness(t, "")
	sid, target, _ := h.connect(t, tcpOpenOpts{})
	_ = target.SetLinger(0)
	_ = target.Close()
	if c := h.closed(t, sid, 3*time.Second); c["reason"] != "reset" && c["reason"] != "closed" {
		t.Fatalf("tcp_closed %v", c)
	} else if c["reason"] == "closed" {
		t.Logf("platform reported RST as EOF")
	}
}

func TestTCPIdleTimeoutFires(t *testing.T) {
	h := newTCPHarness(t, "")
	sid, target, _ := h.connect(t, tcpOpenOpts{idle: 1})
	for i := 0; i < 3; i++ {
		time.Sleep(400 * time.Millisecond)
		_, _ = target.Write([]byte("k"))
	}
	if h.out.find("tcp_closed", sid) != nil {
		t.Fatal("idle fired despite activity")
	}
	if c := h.closed(t, sid, 3*time.Second); c["reason"] != "idle_timeout" {
		t.Fatalf("tcp_closed %v", c)
	}
	// The target is closed.
	_ = target.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.ReadAll(target); err != nil && !errors.Is(err, syscall.ECONNRESET) {
		t.Fatalf("target not closed: %v", err)
	}
}

func TestTCPByteCapFires(t *testing.T) {
	h := newTCPHarness(t, "")
	sid, target, _ := h.connect(t, tcpOpenOpts{maxBytes: 10})
	if err := h.toTarget(t, sid, []byte("123456")); err != nil {
		t.Fatal(err)
	}
	if _, err := target.Write([]byte("1234")); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "4 bytes", 3*time.Second, func() bool { return h.out.text(sid) == "1234" })
	if _, err := target.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	if c := h.closed(t, sid, 3*time.Second); c["reason"] != "byte_cap" {
		t.Fatalf("tcp_closed %v", c)
	}
	if h.out.text(sid) != "1234" {
		t.Fatalf("bytes past the cap forwarded: %q", h.out.text(sid))
	}
	// From the server side too.
	sid2, _, _ := h.connect(t, tcpOpenOpts{maxBytes: 10})
	if err := h.toTarget(t, sid2, []byte("12345678901")); err != nil {
		t.Fatal(err)
	}
	if c := h.closed(t, sid2, 3*time.Second); c["reason"] != "byte_cap" {
		t.Fatalf("tcp_closed %v", c)
	}
}

func TestTCPMaxDurationAndLeaseLapse(t *testing.T) {
	h := newTCPHarness(t, "")
	sid, _, _ := h.connect(t, tcpOpenOpts{deadline: inFuture(time.Second)})
	if c := h.closed(t, sid, 4*time.Second); c["reason"] != "max_duration" {
		t.Fatalf("tcp_closed %v", c)
	}
	// The lease lapses without a renewal: stopped.
	sid2, _, _ := h.connect(t, tcpOpenOpts{leaseExp: inFuture(time.Second)})
	if c := h.closed(t, sid2, 4*time.Second); c["reason"] != "stopped" {
		t.Fatalf("tcp_closed %v", c)
	}
}

func TestTCPRenewalExtendsAndBadRenewalsDoNot(t *testing.T) {
	h := newTCPHarness(t, "")
	deadline := inFuture(time.Hour)
	sid, _, port := h.connect(t, tcpOpenOpts{leaseExp: inFuture(time.Second), deadline: deadline})
	bad := []*Lease{
		signLease(t, h.priv, ptyTestHost, "tcp", mustTCPPayload(t, sid, deadline, "start", "local", port), inFuture(time.Minute)),
		signLease(t, h.priv, ptyTestHost, "tcp", mustTCPPayload(t, sid, deadline, "renew", "local", port+1), inFuture(time.Minute)),
		signLease(t, h.priv, ptyTestHost, "pty", terminalPayload(sid, deadline, "renew"), inFuture(time.Minute)),
	}
	for i, l := range bad {
		if err := h.ch.renewTCP(sid, l, time.Now()); err == nil {
			t.Fatalf("bad renewal %d accepted", i)
		}
	}
	good := signLease(t, h.priv, ptyTestHost, "tcp", mustTCPPayload(t, sid, deadline, "renew", "local", port), inFuture(time.Minute))
	_ = h.send(t, map[string]interface{}{"type": "tcp_renew", "session_id": sid, "lease": good})
	time.Sleep(2500 * time.Millisecond)
	if h.out.find("tcp_closed", sid) != nil {
		t.Fatal("renewed stream ended")
	}
}

func mustTCPPayload(t *testing.T, sid string, deadline int64, phase, host string, port int) string {
	t.Helper()
	p, err := tcpLeasePayload(sid, deadline, phase, host, port)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestTCPStopsReadingTargetWithoutCredit(t *testing.T) {
	h := newTCPHarness(t, "")
	sid, target, _ := h.connect(t, tcpOpenOpts{})
	written := make(chan int64, 1)
	go func() {
		n, _ := io.Copy(target, io.LimitReader(zeroReader{}, 16<<20))
		written <- n
	}()
	waitFor(t, "one window", 3*time.Second, func() bool { return int64(len(h.out.text(sid))) == tcpCreditWindow })
	time.Sleep(200 * time.Millisecond)
	if got := int64(len(h.out.text(sid))); got != tcpCreditWindow {
		t.Fatalf("sent %d bytes without credit", got)
	}
	select {
	case n := <-written:
		t.Fatalf("the target wrote all %d bytes: the agent kept reading", n)
	default:
	}
	// Credit back: more flows.
	_ = h.send(t, map[string]interface{}{"type": "tcp_credit", "session_id": sid, "bytes": 64 * 1024})
	waitFor(t, "more after credit", 3*time.Second, func() bool {
		return int64(len(h.out.text(sid))) == tcpCreditWindow+64*1024
	})
}

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 'z'
	}
	return len(p), nil
}

func TestTCPServerOverrunIsFatal(t *testing.T) {
	h := newTCPHarness(t, "10.0.0.0/8:1-65535")
	// A target that never reads (a pipe has no kernel buffer), so nothing
	// drains and no credit goes back: one window is allowed.
	tcpDial = func(ap netip.AddrPort, timeout time.Duration) (net.Conn, error) {
		a, b := net.Pipe()
		t.Cleanup(func() { _ = b.Close() })
		return a, nil
	}
	sid := h.open(t, "10.0.0.7", 3389, tcpOpenOpts{})
	if p := h.status(t, sid, 3*time.Second); p["status"] != "connected" {
		t.Fatalf("status %v", p)
	}
	chunk := bytes.Repeat([]byte{1}, 64*1024)
	for i := 0; i < 4; i++ {
		if err := h.toTarget(t, sid, chunk); err != nil {
			t.Fatalf("within window: %v", err)
		}
	}
	if err := h.toTarget(t, sid, []byte{1}); !errors.Is(err, errCreditOverrun) {
		t.Fatalf("overrun: %v", err)
	}
	// Credit past what it could owe, or malformed, is fatal too.
	if err := h.send(t, map[string]interface{}{"type": "tcp_credit", "session_id": sid, "bytes": 1}); !errors.Is(err, errCreditOverflow) {
		t.Fatalf("overflow: %v", err)
	}
	if err := h.send(t, map[string]interface{}{"type": "tcp_credit", "session_id": sid, "bytes": -5}); err == nil {
		t.Fatal("malformed credit accepted")
	}
}

func TestTCPStreamCap(t *testing.T) {
	h := newTCPHarness(t, "10.0.0.0/8:1-65535")
	release := make(chan struct{})
	tcpDial = func(ap netip.AddrPort, timeout time.Duration) (net.Conn, error) {
		<-release
		return nil, errors.New("released")
	}
	defer close(release)
	for i := 0; i < tcpMaxStreams; i++ {
		h.open(t, "10.0.0.7", 3389, tcpOpenOpts{})
	}
	sid := h.open(t, "10.0.0.7", 3389, tcpOpenOpts{})
	if e := h.errorOf(t, sid); e != "cap_reached" {
		t.Fatalf("got %q", e)
	}
}

func TestTCPStopWhileDialingReportsClosed(t *testing.T) {
	h := newTCPHarness(t, "10.0.0.0/8:1-65535")
	release := make(chan struct{})
	tcpDial = func(ap netip.AddrPort, timeout time.Duration) (net.Conn, error) {
		<-release
		a, b := net.Pipe()
		_ = b.Close()
		return a, nil
	}
	sid := h.open(t, "10.0.0.7", 3389, tcpOpenOpts{})
	_ = h.send(t, map[string]interface{}{"type": "tcp_stop", "session_id": sid})
	close(release)
	if c := h.closed(t, sid, 3*time.Second); c["reason"] != "stopped" {
		t.Fatalf("tcp_closed %v", c)
	}
	if m := h.out.find("tcp_status", sid); m != nil {
		t.Fatalf("connected after stop: %v", m)
	}
}

// End to end over a real control-plane socket: the agent advertises tcp,
// relays bytes, and a server that overruns the credit window loses the
// connection.
func TestTCPOverTheControlPlaneSocket(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	port, conns := listen(t)
	prevRules := tcpAllowRules
	tcpAllowRules = []tcpAllowRule{{local: true, lo: port, hi: port}}
	t.Cleanup(func() { tcpAllowRules = prevRules })

	var a *agentConn
	dropped := make(chan struct{}, 2)
	srv, _ := fakeControlPlane(t, func(n int64, c *websocket.Conn) {
		_ = c.WriteJSON(map[string]string{"type": "enrolled", "host_id": a.st.HostID, "control_pubkey": base64.StdEncoding.EncodeToString(pub)})
		if n > 1 {
			for {
				if _, _, err := c.ReadMessage(); err != nil {
					return
				}
			}
		}
		time.Sleep(100 * time.Millisecond)
		sid := "tcs_" + strings.Repeat("e", 22)
		deadline := inFuture(time.Hour)
		payload, _ := tcpLeasePayload(sid, deadline, "start", "local", port)
		lease := signLease(t, priv, a.st.HostID, "tcp", payload, inFuture(time.Minute))
		_ = c.WriteJSON(map[string]interface{}{"type": "tcp_open", "session_id": sid, "target": map[string]interface{}{"host": "local", "port": port},
			"deadline_unix": deadline, "idle_s": 900, "max_bytes": 1 << 30, "lease": lease})
		var got bytes.Buffer
		for {
			mt, msg, err := c.ReadMessage()
			if err != nil {
				dropped <- struct{}{}
				return
			}
			if mt == websocket.BinaryMessage {
				got.Write(msg[1+int(msg[0]):])
				if got.String() == "pong" {
					// Overrun: ignore every tcp_credit and keep sending.
					// The target stops reading, so once its kernel
					// buffers are full nothing drains and the window is
					// exceeded.
					frame := append([]byte{byte(len(sid))}, sid...)
					frame = append(frame, bytes.Repeat([]byte{0}, 64*1024)...)
					go func() {
						for i := 0; i < 2048; i++ {
							if c.WriteMessage(websocket.BinaryMessage, frame) != nil {
								return
							}
						}
					}()
				}
				continue
			}
			var m map[string]interface{}
			_ = json.Unmarshal(msg, &m)
			if m["type"] == "tcp_status" {
				p, _ := m["payload"].(map[string]interface{})
				if p["status"] == "connected" {
					frame := append([]byte{byte(len(sid))}, sid...)
					_ = c.WriteMessage(websocket.BinaryMessage, append(frame, "ping"...))
				}
			}
		}
	})
	a = testConn(t, srv, "good")
	a.header.Set(capabilitiesHeader, capabilitiesHeaderValue())
	if !strings.Contains(a.header.Get(capabilitiesHeader), "tcp") {
		t.Fatal("no tcp capability on dial")
	}
	stop := make(chan struct{})
	result := make(chan error, 1)
	go func() { result <- a.run(stop) }()
	target := accepted(t, conns)
	buf := make([]byte, 4)
	_ = target.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.ReadFull(target, buf); err != nil || string(buf) != "ping" {
		t.Fatalf("target got %q %v", buf, err)
	}
	if _, err := target.Write([]byte("pong")); err != nil {
		t.Fatal(err)
	}
	select {
	case <-dropped:
	case <-time.After(20 * time.Second):
		t.Fatal("the agent kept a connection that overran its credit")
	}
	// The stream ended with the connection: the target sees EOF or reset.
	_ = target.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.Copy(io.Discard, target); err != nil && !errors.Is(err, syscall.ECONNRESET) {
		t.Fatalf("target not closed: %v", err)
	}
	close(stop)
	if err := <-result; err != nil {
		t.Fatal(err)
	}
}
