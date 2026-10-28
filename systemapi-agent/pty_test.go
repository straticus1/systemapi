package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
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

func (f *fakeOut) WriteText(b []byte) error {
	var m map[string]interface{}
	if err := json.Unmarshal(b, &m); err != nil {
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
	prevIn, prevRec := inputQueueMax, recordQueueMax
	ptyCfg = ptySettings{Record: false, Shell: "/bin/sh", AllowAgentUser: true, RecordMinFree: 1}
	// Tests run as an ordinary agent unless they say otherwise, even when
	// the test process is root (the Linux container run).
	agentEUID = func() int { return 1000 }
	resetRecordingKeyCache()
	t.Cleanup(func() {
		stopAllSessions("stopped", 5*time.Second)
		ptyCfg, agentEUID = prevCfg, prevEUID
		inputQueueMax, recordQueueMax = prevIn, prevRec
		resetRecordingKeyCache()
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
	lease := signLease(t, h.priv, ptyTestHost, action, terminalPayload(sid, deadline, "start"), leaseExp)
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
	renew := signLease(t, h.priv, ptyTestHost, "pty", terminalPayload(sid, deadline, "renew"), inFuture(5*time.Second))
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
	payload := terminalPayload(sid, deadline, "renew")

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
		{"other session", sid, signLease(t, h.priv, ptyTestHost, "pty", terminalPayload(newSessionID(t), deadline, "renew"), inFuture(200*time.Second)), "payload_mismatch"},
		{"start lease as renewal", sid, signLease(t, h.priv, ptyTestHost, "pty", terminalPayload(sid, deadline, "start"), inFuture(200*time.Second)), "payload_mismatch"},
		{"moved deadline", sid, signLease(t, h.priv, ptyTestHost, "pty", terminalPayload(sid, deadline+3600, "renew"), inFuture(200*time.Second)), "payload_mismatch"},
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
	lease := signLease(t, h.priv, ptyTestHost, "pty", terminalPayload(sid, deadline, "start"), inFuture(60*time.Second))
	startPTYSession(h.out, ptyTestHost, h.dir, ptyStartRequest{SessionID: sid, Action: "pty_root", DeadlineUnix: deadline, Lease: lease}, time.Now())
	if e := h.startErr(t, sid); e != "lease_required" {
		t.Fatalf("pty lease for pty_root: %q", e)
	}
	// A non-root agent refuses pty_root even with a valid lease.
	agentEUID = func() int { return 1000 }
	sid = h.start(t, "pty_root", inFuture(60*time.Second), inFuture(time.Hour))
	if e := h.startErr(t, sid); e != "root_unavailable" {
		t.Fatalf("pty_root on non-root: %q", e)
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
	again := signLease(t, h.priv, ptyTestHost, "pty", terminalPayload(live, deadline, "start"), inFuture(60*time.Second))
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
	if me.Uid == "0" {
		// Running as root: drop to nobody instead of ourselves.
		if me, err = user.Lookup("nobody"); err != nil {
			t.Fatalf("nobody: %v", err)
		}
	}
	id, code := resolvePTYIdentity("pty", "", ptySettings{User: me.Username}, 0)
	if code != "" {
		t.Fatalf("code %s", code)
	}
	if !id.drop || strconv.FormatUint(uint64(id.uid), 10) != me.Uid || strconv.FormatUint(uint64(id.gid), 10) != me.Gid || id.home != me.HomeDir {
		t.Fatalf("identity %+v", id)
	}
	if _, code := resolvePTYIdentity("pty", "", ptySettings{User: "root"}, 0); code != "pty_start_failed" {
		t.Fatalf("root as pty user: %q", code)
	}
	if _, code := resolvePTYIdentity("pty", "", ptySettings{User: "no-such-user-systemapi"}, 0); code != "pty_start_failed" {
		t.Fatalf("unknown pty user: %q", code)
	}
	if _, code := resolvePTYIdentity("pty", "", ptySettings{User: "no-such-user-systemapi"}, 1000); code != "pty_start_failed" {
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

func writeScript(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "shell.sh")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+body), 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}

func exitPayload(t *testing.T, h *ptyHarness, sid string, timeout time.Duration) map[string]interface{} {
	t.Helper()
	h.exitOf(t, sid, timeout)
	return h.out.find("pty_exit", sid)["payload"].(map[string]interface{})
}

func startedPayload(t *testing.T, h *ptyHarness, sid string) map[string]interface{} {
	t.Helper()
	m := h.out.find("pty_status", sid)
	if m == nil {
		t.Fatalf("no status for %s", sid)
	}
	p := m["payload"].(map[string]interface{})
	if p["status"] != "started" {
		t.Fatalf("not started: %v", p)
	}
	return p
}

func TestPTYRenewLeaseCannotStart(t *testing.T) {
	h := newPTYHarness(t)
	sid := newSessionID(t)
	deadline := inFuture(time.Hour)
	lease := signLease(t, h.priv, ptyTestHost, "pty", terminalPayload(sid, deadline, "renew"), inFuture(60*time.Second))
	startPTYSession(h.out, ptyTestHost, h.dir, ptyStartRequest{SessionID: sid, Action: "pty", DeadlineUnix: deadline, Lease: lease}, time.Now())
	if e := h.startErr(t, sid); e != "lease_required" {
		t.Fatalf("renew lease used as start: %q", e)
	}
}

func TestPTYRefusesAgentUserWithoutFlag(t *testing.T) {
	h := newPTYHarness(t)
	ptyCfg.AllowAgentUser = false
	agentEUID = func() int { return 1000 }
	sid := h.start(t, "pty", inFuture(60*time.Second), inFuture(time.Hour))
	if e := h.startErr(t, sid); e != "pty_start_failed" {
		t.Fatalf("got %q", e)
	}
	if lookupSession(sid) != nil {
		t.Fatal("shell started as the agent user")
	}
}

func TestPTYRecordingModes(t *testing.T) {
	if m := recordingMode(ptySettings{Record: true}, 0); m != "agent" {
		t.Fatal(m)
	}
	if m := recordingMode(ptySettings{Record: true}, 1000); m != "user_owned" {
		t.Fatal(m)
	}
	if m := recordingMode(ptySettings{Record: false}, 0); m != "off" {
		t.Fatal(m)
	}
}

func TestPTYAgentRecordingIsChainedAndVerifiable(t *testing.T) {
	h := newPTYHarness(t)
	ptyCfg.Record = true
	ptyCfg.RecordDir = filepath.Join(h.dir, "rec")
	t.Setenv("PATH", t.TempDir()+":/usr/bin:/bin") // no adssh: ordinary pty does not need it
	sid := h.start(t, "pty", inFuture(60*time.Second), inFuture(time.Hour))
	if p := startedPayload(t, h, sid); p["recording"] != "user_owned" {
		t.Fatalf("recording %v", p["recording"])
	}
	handlePTYInput(sid, []byte("echo REC$((2+3))\n"))
	waitFor(t, "output", 5*time.Second, func() bool { return strings.Contains(h.out.text(sid), "REC5") })
	handlePTYInput(sid, []byte("exit 0\n"))
	p := exitPayload(t, h, sid, 5*time.Second)
	rec := p["record"].(map[string]interface{})
	if _, bad := p["record_error"]; bad {
		t.Fatalf("record error %v", p)
	}
	path := rec["path"].(string)
	if rec["bytes_in"].(float64) < float64(len("echo REC$((2+3))\nexit 0\n")) || rec["bytes_out"].(float64) == 0 {
		t.Fatalf("counts %v", rec)
	}
	key, err := loadRecordingKey(h.dir)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := verifyRecording(path, key, sid)
	if err != nil || digest != rec["digest"] {
		t.Fatalf("verify: %v %s vs %v", err, digest, rec["digest"])
	}
	for _, f := range []struct {
		path string
		mode os.FileMode
	}{{path, 0o600}, {ptyCfg.RecordDir, 0o700}, {filepath.Join(h.dir, recordingKeyFile), 0o600}} {
		st, err := os.Stat(f.path)
		if err != nil || st.Mode().Perm() != f.mode {
			t.Fatalf("%s mode %v %v", f.path, st.Mode().Perm(), err)
		}
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), base64.StdEncoding.EncodeToString([]byte("echo REC$((2+3))\n"))) {
		t.Fatal("input not recorded")
	}
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	tampered := filepath.Join(h.dir, "tampered.rec")
	edited := strings.Replace(string(raw), base64.StdEncoding.EncodeToString([]byte("echo REC$((2+3))\n")), base64.StdEncoding.EncodeToString([]byte("echo XYZ$((2+3))\n")), 1)
	if err := os.WriteFile(tampered, []byte(edited), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := verifyRecording(tampered, key, sid); err == nil {
		t.Fatal("edited recording verified")
	}
	dropped := strings.Join(append(append([]string{}, lines[:1]...), lines[2:]...), "\n") + "\n"
	if err := os.WriteFile(tampered, []byte(dropped), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := verifyRecording(tampered, key, sid); err == nil {
		t.Fatal("recording with a deleted line verified")
	}
	if _, err := verifyRecording(path, []byte(strings.Repeat("k", 32)), sid); err == nil {
		t.Fatal("wrong key verified")
	}
}

func TestPTYRecordingKeyRefusesLooseMode(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, recordingKeyFile), []byte(strings.Repeat("ab", 32)+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	resetRecordingKeyCache()
	t.Cleanup(resetRecordingKeyCache)
	if _, err := loadRecordingKey(dir); err == nil {
		t.Fatal("accepted a 0644 recording key")
	}
}

func TestPTYRecordingUnavailableWhenRecordCannotOpen(t *testing.T) {
	h := newPTYHarness(t)
	ptyCfg.Record = true
	target := t.TempDir()
	link := filepath.Join(h.dir, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	notDir := filepath.Join(h.dir, "file")
	if err := os.WriteFile(notDir, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{link, notDir} {
		ptyCfg.RecordDir = dir
		sid := h.start(t, "pty", inFuture(60*time.Second), inFuture(time.Hour))
		if e := h.startErr(t, sid); e != "recording_unavailable" {
			t.Fatalf("%s: got %q", dir, e)
		}
		if lookupSession(sid) != nil {
			t.Fatal("ran unrecorded")
		}
	}
}

func TestPTYRecorderOverflowEndsSession(t *testing.T) {
	h := newPTYHarness(t)
	ptyCfg.Record = true
	ptyCfg.RecordDir = filepath.Join(h.dir, "rec")
	sid := h.start(t, "pty", inFuture(60*time.Second), inFuture(time.Hour))
	startedPayload(t, h, sid)
	recordQueueMax = 64
	handlePTYInput(sid, []byte(strings.Repeat("x", 200)))
	p := exitPayload(t, h, sid, 5*time.Second)
	if p["reason"] != "stopped" || p["record_error"] != "recording_failed" {
		t.Fatalf("exit %v", p)
	}
}

func TestPTYBreakglassKeepsAdsshAndIsRecorded(t *testing.T) {
	h := newPTYHarness(t)
	bin := t.TempDir()
	if err := os.WriteFile(filepath.Join(bin, "adssh"), []byte("#!/bin/sh\necho \"policy=$ADSSH_POLICY key=$SYSTEMAPI_API_KEY\"\nexit 7\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+":/usr/bin:/bin")
	t.Setenv("SYSTEMAPI_API_KEY", "leak-me")
	ptyCfg.Record = true
	ptyCfg.RecordDir = filepath.Join(h.dir, "rec")
	sid := h.start(t, "breakglass", inFuture(60*time.Second), inFuture(time.Hour))
	startedPayload(t, h, sid)
	p := exitPayload(t, h, sid, 5*time.Second)
	if p["code"].(float64) != 7 {
		t.Fatalf("exit %v", p)
	}
	out := h.out.text(sid)
	if !strings.Contains(out, "policy="+filepath.Join(h.dir, "breakglass.rego")) || strings.Contains(out, "leak-me") {
		t.Fatalf("adssh env: %q", out)
	}
	key, err := loadRecordingKey(h.dir)
	if err != nil {
		t.Fatal(err)
	}
	rec := p["record"].(map[string]interface{})
	if d, err := verifyRecording(rec["path"].(string), key, sid); err != nil || d != rec["digest"] {
		t.Fatalf("verify %v", err)
	}
	// Without adssh, break-glass is still refused.
	t.Setenv("PATH", t.TempDir())
	sid = h.start(t, "breakglass", inFuture(60*time.Second), inFuture(time.Hour))
	if e := h.startErr(t, sid); e != "recording_unavailable" {
		t.Fatalf("got %q", e)
	}
}

func TestPTYInputQueueNeverBlocksAndOverflowEndsOnlyThatSession(t *testing.T) {
	inputQueueMax = 64 * 1024
	t.Cleanup(func() { inputQueueMax = 1024 * 1024 })
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close(); _ = w.Close() })
	// Nobody reads r, so the writer goroutine blocks once the pipe fills.
	s := &ptySession{id: "pts_blockedblockedblocked", ptmx: w, inCh: make(chan []byte, 4096)}
	go s.inputLoop()
	chunk := make([]byte, 1024)
	start := time.Now()
	for i := 0; i < 400; i++ {
		s.queueInput(chunk)
	}
	if time.Since(start) > 2*time.Second {
		t.Fatal("queueInput blocked")
	}
	s.mu.Lock()
	reason, ending := s.reason, s.ending
	s.mu.Unlock()
	if !ending || reason != "stopped" {
		t.Fatalf("overflow did not end the session: %v %q", ending, reason)
	}
	_ = r.Close()
	s.mu.Lock()
	s.inClosed = true
	close(s.inCh)
	s.mu.Unlock()
}

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

func TestStopAllSessionsEndsEverySession(t *testing.T) {
	h := newPTYHarness(t)
	a := h.start(t, "pty", inFuture(60*time.Second), inFuture(time.Hour))
	b := h.start(t, "pty", inFuture(60*time.Second), inFuture(time.Hour))
	startedPayload(t, h, a)
	startedPayload(t, h, b)
	stopAllSessions("stopped", 5*time.Second)
	for _, sid := range []string{a, b} {
		if _, reason := h.exitOf(t, sid, time.Second); reason != "stopped" {
			t.Fatalf("%s %s", sid, reason)
		}
	}
	ptyMu.Lock()
	n := len(ptySessions)
	ptyMu.Unlock()
	if n != 0 {
		t.Fatalf("%d sessions left", n)
	}
}

func TestPTYReservedSlotsForBreakglassAndRoot(t *testing.T) {
	h := newPTYHarness(t)
	bin := t.TempDir()
	if err := os.WriteFile(filepath.Join(bin, "adssh"), []byte("#!/bin/sh\nsleep 5\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+":/usr/bin:/bin")
	var dummies []string
	ptyMu.Lock()
	for i := 0; i < ptyMaxSessions-ptyReservedSlots; i++ {
		id := fmt.Sprintf("pts_dummy%020d", i)
		ptySessions[id] = &ptySession{id: id}
		dummies = append(dummies, id)
	}
	ptyMu.Unlock()
	t.Cleanup(func() {
		ptyMu.Lock()
		for _, id := range dummies {
			delete(ptySessions, id)
		}
		ptyMu.Unlock()
	})
	sid := h.start(t, "pty", inFuture(60*time.Second), inFuture(time.Hour))
	if e := h.startErr(t, sid); e != "pty_start_failed" {
		t.Fatalf("operator pty took a reserved slot: %q", e)
	}
	sid = h.start(t, "breakglass", inFuture(60*time.Second), inFuture(time.Hour))
	startedPayload(t, h, sid)
}

func TestPrivilegedGroupsFlagged(t *testing.T) {
	got := privilegedGroups([]string{"users", "docker", "staff", "sudo", "adm", "wheel"})
	if strings.Join(got, ",") != "docker,sudo,adm,wheel" {
		t.Fatalf("%v", got)
	}
	if len(privilegedGroups([]string{"users"})) != 0 {
		t.Fatal("flagged an ordinary group")
	}
}

func TestResolveAPIKey(t *testing.T) {
	t.Setenv("SYSTEMAPI_API_KEY", "from-env")
	key, warn, err := resolveAPIKey("", "")
	if err != nil || key != "from-env" || warn != "" {
		t.Fatalf("%q %q %v", key, warn, err)
	}
	if _, ok := os.LookupEnv("SYSTEMAPI_API_KEY"); ok {
		t.Fatal("SYSTEMAPI_API_KEY left in the environment")
	}
	key, warn, err = resolveAPIKey("from-argv", "")
	if err != nil || key != "from-argv" || !strings.Contains(warn, "process list") {
		t.Fatalf("%q %q %v", key, warn, err)
	}
	dir := t.TempDir()
	loose := filepath.Join(dir, "loose")
	if err := os.WriteFile(loose, []byte("k\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := resolveAPIKey("", loose); err == nil {
		t.Fatal("accepted a 0644 key file")
	}
	tight := filepath.Join(dir, "tight")
	if err := os.WriteFile(tight, []byte("from-file\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if key, _, err := resolveAPIKey("", tight); err != nil || key != "from-file" {
		t.Fatalf("%q %v", key, err)
	}
	if _, _, err := resolveAPIKey("", ""); err == nil {
		t.Fatal("no key accepted")
	}
}

// TestPTYSetuidDropsToPTYUser runs only as root (the Linux CI run). It
// starts a real shell as nobody and checks uid, gid and groups.
func TestPTYSetuidDropsToPTYUser(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	h := newPTYHarness(t)
	agentEUID = os.Geteuid
	nobody, err := user.Lookup("nobody")
	if err != nil {
		t.Skip("no nobody user")
	}
	ptyCfg.User = "nobody"
	ptyCfg.Record = true
	ptyCfg.RecordDir = filepath.Join(h.dir, "rec")
	sid := h.start(t, "pty", inFuture(60*time.Second), inFuture(time.Hour))
	if p := startedPayload(t, h, sid); p["pty_user"] != "nobody" || p["recording"] != "agent" {
		t.Fatalf("%v", p)
	}
	handlePTYInput(sid, []byte("echo ID=$(id -u):$(id -g):$(id -G | tr ' ' ,):$HOME:$USER\n"))
	want := "ID=" + nobody.Uid + ":" + nobody.Gid + ":"
	waitFor(t, "id output", 5*time.Second, func() bool { return strings.Contains(h.out.text(sid), want) })
	text := h.out.text(sid)
	line := text[strings.Index(text, want):]
	if strings.Contains(strings.SplitN(line, "\n", 2)[0], ":0,") || strings.Contains(strings.SplitN(line, "\n", 2)[0], ",0:") {
		t.Fatalf("root group kept: %q", line)
	}
	if !strings.Contains(line, ":"+nobody.HomeDir+":nobody") {
		t.Fatalf("HOME/USER not set: %q", line)
	}
	handlePTYInput(sid, []byte("exit 0\n"))
	h.exitOf(t, sid, 5*time.Second)
}

func TestPTYRootRefusedWithoutAgentRecording(t *testing.T) {
	h := newPTYHarness(t)
	agentEUID = func() int { return 0 }
	ptyCfg.Record = false
	sid := h.start(t, "pty_root", inFuture(60*time.Second), inFuture(time.Hour))
	if e := h.startErr(t, sid); e != "root_unavailable" {
		t.Fatalf("got %q", e)
	}
	if lookupSession(sid) != nil {
		t.Fatal("root shell started unrecorded")
	}
}

func TestPTYRecordingSizeCapEndsSession(t *testing.T) {
	h := newPTYHarness(t)
	ptyCfg.Record = true
	ptyCfg.RecordDir = filepath.Join(h.dir, "rec")
	ptyCfg.RecordMaxBytes = 100
	sid := h.start(t, "pty", inFuture(60*time.Second), inFuture(time.Hour))
	startedPayload(t, h, sid)
	handlePTYInput(sid, []byte(strings.Repeat("x", 200)))
	p := exitPayload(t, h, sid, 5*time.Second)
	if p["reason"] != "stopped" || p["record_error"] != "recording_size_limit" {
		t.Fatalf("exit %v", p)
	}
	rec := p["record"].(map[string]interface{})
	if rec["bytes_in"].(float64)+rec["bytes_out"].(float64) > 100 {
		t.Fatalf("recorded past the cap: %v", rec)
	}
}

func TestPTYRecordingRefusedWhenDiskLow(t *testing.T) {
	h := newPTYHarness(t)
	ptyCfg.Record = true
	ptyCfg.RecordDir = filepath.Join(h.dir, "rec")
	ptyCfg.RecordMinFree = 1 << 62
	sid := h.start(t, "pty", inFuture(60*time.Second), inFuture(time.Hour))
	if e := h.startErr(t, sid); e != "recording_unavailable" {
		t.Fatalf("got %q", e)
	}
	if lookupSession(sid) != nil {
		t.Fatal("session started")
	}
}

func TestVerifyRecordingCommand(t *testing.T) {
	h := newPTYHarness(t)
	ptyCfg.Record = true
	ptyCfg.RecordDir = filepath.Join(h.dir, "rec")
	sid := h.start(t, "pty", inFuture(60*time.Second), inFuture(time.Hour))
	startedPayload(t, h, sid)
	handlePTYInput(sid, []byte("echo VR$((1+1))\nexit 0\n"))
	p := exitPayload(t, h, sid, 5*time.Second)
	rec := p["record"].(map[string]interface{})
	path, digest := rec["path"].(string), rec["digest"].(string)
	keyPath := filepath.Join(h.dir, recordingKeyFile)

	run := func(args ...string) (int, string) {
		var stdout, stderr strings.Builder
		code := runVerifyRecording(args, &stdout, &stderr)
		return code, stdout.String() + stderr.String()
	}
	if code, out := run(path, "--key", keyPath); code != 0 || !strings.Contains(out, "digest="+digest) {
		t.Fatalf("valid: %d %s", code, out)
	}
	if code, out := run(path, "--digest", digest, "--key", keyPath); code != 0 {
		t.Fatalf("matching digest: %d %s", code, out)
	}
	if code, out := run("--key", keyPath, path, "--digest", strings.ToUpper(digest)); code != 0 {
		t.Fatalf("flags before file, upper-case digest: %d %s", code, out)
	}
	if code, out := run(path, "--digest", strings.Repeat("0", 64), "--key", keyPath); code != 1 || !strings.Contains(out, "digest mismatch") {
		t.Fatalf("wrong digest: %d %s", code, out)
	}
	// --state finds the key beside the agent's state file, as the agent keeps it.
	if code, out := run(path, "--digest", digest, "--state", filepath.Join(h.dir, "agent.json")); code != 0 {
		t.Fatalf("--state: %d %s", code, out)
	}
	if code, out := run(path, "--key", keyPath, "--state", filepath.Join(h.dir, "agent.json")); code != 2 {
		t.Fatalf("--key with --state must be refused: %d %s", code, out)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	copyAs := func(body string) string {
		p := filepath.Join(t.TempDir(), filepath.Base(path))
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	truncated := copyAs(strings.Join(lines[:len(lines)-1], "\n") + "\n")
	if code, out := run(truncated, "--key", keyPath); code != 1 || !strings.Contains(out, "recording_truncated") {
		t.Fatalf("truncated: %d %s", code, out)
	}
	tamperedLine := strings.Replace(lines[1], `"b64":"`, `"b64":"QQ`, 1)
	tampered := copyAs(strings.Join(append([]string{lines[0], tamperedLine}, lines[2:]...), "\n") + "\n")
	if code, out := run(tampered, "--key", keyPath); code != 1 || !strings.Contains(out, "recording_mac_mismatch") {
		t.Fatalf("tampered: %d %s", code, out)
	}
	otherKey := filepath.Join(t.TempDir(), "k")
	if err := os.WriteFile(otherKey, []byte(strings.Repeat("cd", 32)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, _ := run(path, "--key", otherKey); code != 1 {
		t.Fatal("wrong key verified")
	}
	renamed := filepath.Join(t.TempDir(), "pts_"+strings.Repeat("a", 32)+".rec")
	if err := os.WriteFile(renamed, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if code, _ := run(renamed, "--key", keyPath); code != 1 {
		t.Fatal("recording verified under another session id")
	}
	if code, _ := run("--key", keyPath); code != 2 {
		t.Fatal("missing file not a usage error")
	}
	if code, _ := run(path, path, "--key", keyPath); code != 2 {
		t.Fatal("two files not a usage error")
	}
}

func TestPTYNoSignalAfterReap(t *testing.T) {
	h := newPTYHarness(t)
	sid := h.start(t, "pty", inFuture(60*time.Second), inFuture(time.Hour))
	s := lookupSession(sid)
	if s == nil {
		t.Fatal("not started")
	}
	handlePTYInput(sid, []byte("exit 0\n"))
	h.exitOf(t, sid, 5*time.Second)
	s.reapMu.Lock()
	reaped := s.reaped
	s.reapMu.Unlock()
	if !reaped {
		t.Fatal("not marked reaped")
	}
	if s.signalUnreaped(syscall.SIGKILL) {
		t.Fatal("signalled a reaped process group")
	}
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
