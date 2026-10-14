package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

const ptyTestHost = "33333333-3333-4333-8333-333333333333"

type fakeOut struct {
	mu     sync.Mutex
	jsons  []map[string]interface{}
	output map[string]*strings.Builder
}

func newFakeOut() *fakeOut {
	return &fakeOut{output: map[string]*strings.Builder{}}
}

func (f *fakeOut) WriteJSON(v interface{}) error {
	raw, err := json.Marshal(v)
	if err != nil {
		return err
	}
	var m map[string]interface{}
	if err := json.Unmarshal(raw, &m); err != nil {
		return err
	}
	f.mu.Lock()
	f.jsons = append(f.jsons, m)
	f.mu.Unlock()
	return nil
}

func (f *fakeOut) WriteBinary(b []byte) error {
	n := int(b[0])
	sid := string(b[1 : 1+n])
	f.mu.Lock()
	if f.output[sid] == nil {
		f.output[sid] = &strings.Builder{}
	}
	f.output[sid].Write(b[1+n:])
	f.mu.Unlock()
	return nil
}

func (f *fakeOut) text(sid string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.output[sid] == nil {
		return ""
	}
	return f.output[sid].String()
}

// find returns the first JSON message of type typ for sid.
func (f *fakeOut) find(typ, sid string) map[string]interface{} {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, m := range f.jsons {
		got, _ := m["session_id"].(string)
		if m["type"] == typ && got == sid {
			return m
		}
	}
	return nil
}

func waitFor(t *testing.T, what string, timeout time.Duration, ok func() bool) {
	t.Helper()
	end := time.Now().Add(timeout)
	for time.Now().Before(end) {
		if ok() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

type ptyHarness struct {
	priv ed25519.PrivateKey
	out  *fakeOut
	dir  string
}

func newPTYHarness(t *testing.T) *ptyHarness {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	clearIdentity()
	if err := pinControlPublicKey(base64.StdEncoding.EncodeToString(pub), ptyTestHost); err != nil {
		t.Fatal(err)
	}
	prevCfg, prevEUID := ptyCfg, agentEUID
	ptyCfg = ptySettings{Record: false, Shell: "/bin/sh"}
	t.Cleanup(func() {
		ptyMu.Lock()
		live := make([]*ptySession, 0, len(ptySessions))
		for _, s := range ptySessions {
			live = append(live, s)
		}
		ptyMu.Unlock()
		for _, s := range live {
			s.end("stopped")
		}
		ptyCfg, agentEUID = prevCfg, prevEUID
		clearIdentity()
	})
	return &ptyHarness{priv: priv, out: newFakeOut(), dir: t.TempDir()}
}

func newSessionID(t *testing.T) string {
	t.Helper()
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return "pts_" + hex.EncodeToString(b)
}

func signLease(t *testing.T, priv ed25519.PrivateKey, host, action, payload string, exp int64) *Lease {
	t.Helper()
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	l := &Lease{V: 1, HostID: host, Action: action, ExpiresUnix: exp, NonceHex: hex.EncodeToString(nonce), PayloadSHA: payloadHash(action, payload)}
	msg := canonicalLease(l.HostID, l.Action, l.ExpiresUnix, l.NonceHex, l.PayloadSHA)
	l.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(priv, []byte(msg)))
	return l
}

// start begins a session whose lease expires at leaseExp and whose deadline
// is deadline (both unix seconds).
func (h *ptyHarness) start(t *testing.T, action string, leaseExp, deadline int64) string {
	t.Helper()
	sid := newSessionID(t)
	lease := signLease(t, h.priv, ptyTestHost, action, terminalPayload(sid, deadline), leaseExp)
	startPTYSession(h.out, ptyTestHost, h.dir, ptyStartRequest{
		SessionID: sid, Action: action, Rows: 24, Cols: 80, DeadlineUnix: deadline, Lease: lease,
	}, time.Now())
	return sid
}

func (h *ptyHarness) startErr(t *testing.T, sid string) string {
	t.Helper()
	m := h.out.find("pty_status", sid)
	if m == nil {
		t.Fatalf("no pty_status for %s", sid)
	}
	p, _ := m["payload"].(map[string]interface{})
	e, _ := p["error"].(string)
	return e
}

func (h *ptyHarness) exitOf(t *testing.T, sid string, timeout time.Duration) (int, string) {
	t.Helper()
	var m map[string]interface{}
	waitFor(t, "pty_exit "+sid, timeout, func() bool {
		m = h.out.find("pty_exit", sid)
		return m != nil
	})
	p := m["payload"].(map[string]interface{})
	return int(p["code"].(float64)), p["reason"].(string)
}

func inFuture(d time.Duration) int64 { return time.Now().Add(d).Unix() }

func TestPTYTwoSessionsDoNotCollide(t *testing.T) {
	h := newPTYHarness(t)
	a := h.start(t, "pty", inFuture(60*time.Second), inFuture(time.Hour))
	b := h.start(t, "pty", inFuture(60*time.Second), inFuture(time.Hour))
	if e := h.startErr(t, a); e != "" {
		t.Fatalf("start a: %s", e)
	}
	if e := h.startErr(t, b); e != "" {
		t.Fatalf("start b: %s", e)
	}
	handlePTYInput(a, []byte("echo AAA$((40+2))\n"))
	handlePTYInput(b, []byte("echo BBB$((50+5))\n"))
	waitFor(t, "output a", 5*time.Second, func() bool { return strings.Contains(h.out.text(a), "AAA42") })
	waitFor(t, "output b", 5*time.Second, func() bool { return strings.Contains(h.out.text(b), "BBB55") })
	if strings.Contains(h.out.text(a), "BBB55") || strings.Contains(h.out.text(b), "AAA42") {
		t.Fatal("output crossed sessions")
	}
	handlePTYInput(a, []byte("exit 4\n"))
	if code, reason := h.exitOf(t, a, 5*time.Second); code != 4 || reason != "exited" {
		t.Fatalf("a exit %d %s", code, reason)
	}
	if lookupSession(b) == nil {
		t.Fatal("ending a ended b")
	}
	handlePTYEOF(b)
	if code, reason := h.exitOf(t, b, 5*time.Second); code != 0 || reason != "exited" {
		t.Fatalf("b exit after eof %d %s", code, reason)
	}
}

func TestPTYExitCodePassedThrough(t *testing.T) {
	h := newPTYHarness(t)
	sid := h.start(t, "pty", inFuture(60*time.Second), inFuture(time.Hour))
	handlePTYInput(sid, []byte("exit 3\n"))
	if code, reason := h.exitOf(t, sid, 5*time.Second); code != 3 || reason != "exited" {
		t.Fatalf("exit %d %s", code, reason)
	}
	if lookupSession(sid) != nil {
		t.Fatal("session not removed")
	}
}

func TestPTYStopEndsOnlyThatSession(t *testing.T) {
	h := newPTYHarness(t)
	sid := h.start(t, "pty", inFuture(60*time.Second), inFuture(time.Hour))
	handlePTYStop(sid)
	if code, reason := h.exitOf(t, sid, 5*time.Second); code != -1 || reason != "stopped" {
		t.Fatalf("exit %d %s", code, reason)
	}
}

func TestPTYRenewalExtendsSession(t *testing.T) {
	h := newPTYHarness(t)
	deadline := inFuture(time.Hour)
	sid := h.start(t, "pty", inFuture(3*time.Second), deadline)
	time.Sleep(time.Second)
	renew := signLease(t, h.priv, ptyTestHost, "pty", terminalPayload(sid, deadline), inFuture(5*time.Second))
	if err := renewPTYSession(ptyTestHost, sid, renew, time.Now()); err != nil {
		t.Fatalf("renew: %v", err)
	}
	// The start lease has lapsed by now; only the renewal keeps it alive.
	time.Sleep(2500 * time.Millisecond)
	if lookupSession(sid) == nil || h.out.find("pty_exit", sid) != nil {
		t.Fatal("session ended despite renewal")
	}
	// No further renewal: the session ends when the last lease lapses.
	if code, reason := h.exitOf(t, sid, 5*time.Second); code != -1 || reason != "stopped" {
		t.Fatalf("exit %d %s", code, reason)
	}
}

func TestPTYRenewalRejectsBadLeases(t *testing.T) {
	h := newPTYHarness(t)
	deadline := inFuture(time.Hour)
	sid := h.start(t, "pty", inFuture(30*time.Second), deadline)
	s := lookupSession(sid)
	if s == nil {
		t.Fatal("not started")
	}
	s.mu.Lock()
	before := s.leaseExp
	s.mu.Unlock()
	payload := terminalPayload(sid, deadline)

	_, otherPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name  string
		sid   string
		lease *Lease
		want  string
	}{
		{"forged", sid, signLease(t, otherPriv, ptyTestHost, "pty", payload, inFuture(200*time.Second)), "bad_signature"},
		{"expired", sid, signLease(t, h.priv, ptyTestHost, "pty", payload, inFuture(-2*time.Minute)), "expired"},
		{"other host", sid, signLease(t, h.priv, "44444444-4444-4444-8444-444444444444", "pty", payload, inFuture(200*time.Second)), "bad_host"},
		{"other action", sid, signLease(t, h.priv, ptyTestHost, "pty_root", payload, inFuture(200*time.Second)), "bad_action"},
		{"other session", sid, signLease(t, h.priv, ptyTestHost, "pty", terminalPayload(newSessionID(t), deadline), inFuture(200*time.Second)), "payload_mismatch"},
		{"moved deadline", sid, signLease(t, h.priv, ptyTestHost, "pty", terminalPayload(sid, deadline+3600), inFuture(200*time.Second)), "payload_mismatch"},
		{"unknown session", newSessionID(t), signLease(t, h.priv, ptyTestHost, "pty", payload, inFuture(200*time.Second)), "unknown_session"},
		{"missing lease", sid, nil, "malformed"},
	}
	for _, c := range cases {
		err := renewPTYSession(ptyTestHost, c.sid, c.lease, time.Now())
		if err == nil || err.Error() != c.want {
			t.Fatalf("%s: got %v want %s", c.name, err, c.want)
		}
	}
	good := signLease(t, h.priv, ptyTestHost, "pty", payload, inFuture(200*time.Second))
	if err := renewPTYSession(ptyTestHost, sid, good, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := renewPTYSession(ptyTestHost, sid, good, time.Now()); err == nil || err.Error() != "replay" {
		t.Fatalf("replayed renewal: %v", err)
	}
	s.mu.Lock()
	after := s.leaseExp
	s.mu.Unlock()
	if !after.After(before) || after.Unix() != good.ExpiresUnix {
		t.Fatalf("lease not extended by the good renewal only: %v -> %v", before, after)
	}
}

func TestPTYMaxDurationEndsSession(t *testing.T) {
	h := newPTYHarness(t)
	sid := h.start(t, "pty", inFuture(120*time.Second), inFuture(2*time.Second))
	if e := h.startErr(t, sid); e != "" {
		t.Fatalf("start: %s", e)
	}
	if code, reason := h.exitOf(t, sid, 6*time.Second); code != -1 || reason != "max_duration" {
		t.Fatalf("exit %d %s", code, reason)
	}
}

func TestPTYUserUnsetWhenRoot(t *testing.T) {
	h := newPTYHarness(t)
	agentEUID = func() int { return 0 }
	sid := h.start(t, "pty", inFuture(60*time.Second), inFuture(time.Hour))
	if e := h.startErr(t, sid); e != "pty_user_unset" {
		t.Fatalf("got %q", e)
	}
	if lookupSession(sid) != nil {
		t.Fatal("session started")
	}
}

func TestPTYRootNeedsItsOwnLeaseAndRoot(t *testing.T) {
	h := newPTYHarness(t)
	// A terminal:open lease cannot start a root shell.
	sid := newSessionID(t)
	deadline := inFuture(time.Hour)
	lease := signLease(t, h.priv, ptyTestHost, "pty", terminalPayload(sid, deadline), inFuture(60*time.Second))
	startPTYSession(h.out, ptyTestHost, h.dir, ptyStartRequest{SessionID: sid, Action: "pty_root", DeadlineUnix: deadline, Lease: lease}, time.Now())
	if e := h.startErr(t, sid); e != "lease_required" {
		t.Fatalf("pty lease for pty_root: %q", e)
	}
	// A non-root agent refuses pty_root even with a valid lease.
	agentEUID = func() int { return 1000 }
	sid = h.start(t, "pty_root", inFuture(60*time.Second), inFuture(time.Hour))
	if e := h.startErr(t, sid); e != "pty_start_failed" {
		t.Fatalf("pty_root on non-root: %q", e)
	}
}

func TestPTYRecordingUnavailableWithoutAdssh(t *testing.T) {
	h := newPTYHarness(t)
	ptyCfg.Record = true
	ptyCfg.RecordDir = filepath.Join(h.dir, "rec")
	t.Setenv("PATH", t.TempDir())
	sid := h.start(t, "pty", inFuture(60*time.Second), inFuture(time.Hour))
	if e := h.startErr(t, sid); e != "recording_unavailable" {
		t.Fatalf("got %q", e)
	}
	if lookupSession(sid) != nil {
		t.Fatal("ran unrecorded")
	}
}

func TestPTYRecordingRunsUnderAdssh(t *testing.T) {
	h := newPTYHarness(t)
	bin := t.TempDir()
	if err := os.WriteFile(filepath.Join(bin, "adssh"), []byte("#!/bin/sh\necho \"policy=$ADSSH_POLICY\"\nexit 7\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+":/usr/bin:/bin")
	ptyCfg.Record = true
	ptyCfg.RecordDir = filepath.Join(h.dir, "rec")
	sid := h.start(t, "pty", inFuture(60*time.Second), inFuture(time.Hour))
	m := h.out.find("pty_status", sid)
	if m == nil {
		t.Fatal("no status")
	}
	p := m["payload"].(map[string]interface{})
	if p["status"] != "started" || p["recording"] != true {
		t.Fatalf("status %v", p)
	}
	if code, reason := h.exitOf(t, sid, 5*time.Second); code != 7 || reason != "exited" {
		t.Fatalf("exit %d %s", code, reason)
	}
	if !strings.Contains(h.out.text(sid), "policy="+filepath.Join(ptyCfg.RecordDir, "terminal.rego")) {
		t.Fatalf("adssh did not get the policy: %q", h.out.text(sid))
	}
	st, err := os.Stat(filepath.Join(ptyCfg.RecordDir, p["pty_user"].(string)))
	if err != nil || st.Mode().Perm() != 0o700 {
		t.Fatalf("user audit dir: %v %v", err, st)
	}
}

func TestPTYStartRejectsBadRequests(t *testing.T) {
	h := newPTYHarness(t)
	deadline := inFuture(time.Hour)
	startPTYSession(h.out, ptyTestHost, h.dir, ptyStartRequest{SessionID: "bad id", Action: "pty", DeadlineUnix: deadline}, time.Now())
	if m := h.out.find("pty_status", ""); m == nil {
		t.Fatal("bad session id accepted")
	}
	sid := newSessionID(t)
	startPTYSession(h.out, ptyTestHost, h.dir, ptyStartRequest{SessionID: sid, Action: "pty", DeadlineUnix: deadline}, time.Now())
	if e := h.startErr(t, sid); e != "lease_required" {
		t.Fatalf("no lease: %q", e)
	}
	// Reusing a running session id is refused.
	live := h.start(t, "pty", inFuture(60*time.Second), deadline)
	again := signLease(t, h.priv, ptyTestHost, "pty", terminalPayload(live, deadline), inFuture(60*time.Second))
	h.out.mu.Lock()
	before := len(h.out.jsons)
	h.out.mu.Unlock()
	startPTYSession(h.out, ptyTestHost, h.dir, ptyStartRequest{SessionID: live, Action: "pty", DeadlineUnix: deadline, Lease: again}, time.Now())
	h.out.mu.Lock()
	last := h.out.jsons[len(h.out.jsons)-1]
	grew := len(h.out.jsons) > before
	h.out.mu.Unlock()
	if !grew || last["payload"].(map[string]interface{})["error"] != "pty_start_failed" {
		t.Fatalf("duplicate session id: %v", last)
	}
}

func TestPTYIdentityDropsToConfiguredUser(t *testing.T) {
	me, err := user.Current()
	if err != nil {
		t.Fatalf("current user: %v", err)
	}
	id, code := resolvePTYIdentity("pty", ptySettings{User: me.Username}, 0)
	if code != "" {
		t.Fatalf("code %s", code)
	}
	if !id.drop || strconv.FormatUint(uint64(id.uid), 10) != me.Uid || strconv.FormatUint(uint64(id.gid), 10) != me.Gid || id.home != me.HomeDir {
		t.Fatalf("identity %+v", id)
	}
	if _, code := resolvePTYIdentity("pty", ptySettings{User: "root"}, 0); code != "pty_start_failed" {
		t.Fatalf("root as pty user: %q", code)
	}
	if _, code := resolvePTYIdentity("pty", ptySettings{User: "no-such-user-systemapi"}, 0); code != "pty_start_failed" {
		t.Fatalf("unknown pty user: %q", code)
	}
	if _, code := resolvePTYIdentity("pty", ptySettings{User: "no-such-user-systemapi"}, 1000); code != "pty_start_failed" {
		t.Fatalf("non-root agent switching user: %q", code)
	}
	t.Setenv("SYSTEMAPI_API_KEY", "secret")
	t.Setenv("HOME", "/root-home-should-not-leak")
	env := strings.Join(sessionEnv(id, nil), "\n")
	if strings.Contains(env, "secret") || strings.Contains(env, "root-home-should-not-leak") {
		t.Fatalf("agent env leaked: %s", env)
	}
	for _, want := range []string{"HOME=" + me.HomeDir, "USER=" + me.Username, "LOGNAME=" + me.Username, "SHELL=" + id.shell} {
		if !strings.Contains(env, want) {
			t.Fatalf("missing %s in %s", want, env)
		}
	}
}
