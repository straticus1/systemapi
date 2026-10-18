package main

import (
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// echoShell turns terminal echo off and prints every line it reads, so a
// byte reaches the shell exactly when a GOT[...] line shows it.
const echoShell = "stty -echo\necho READY\nwhile IFS= read -r l; do echo \"GOT[$l]\"; done\n"

func newWatchID(t *testing.T) string {
	t.Helper()
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return "wch_" + hex.EncodeToString(b)
}

func (h *ptyHarness) startEcho(t *testing.T) string {
	t.Helper()
	ptyCfg.Shell = writeScript(t, echoShell)
	sid := h.start(t, "pty", inFuture(time.Minute), inFuture(time.Hour))
	startedPayload(t, h, sid)
	waitFor(t, "shell ready", 5*time.Second, func() bool { return strings.Contains(h.out.text(sid), "READY") })
	return sid
}

// watch sends one watch_request signed for exactly these fields.
func (h *ptyHarness) watch(t *testing.T, sid, mode, actor, reason string, override bool) string {
	t.Helper()
	wid := newWatchID(t)
	s := lookupSession(sid)
	if s == nil {
		t.Fatal("no session")
	}
	lease := signLease(t, h.priv, ptyTestHost, s.action, watchPayload(sid, s.deadline.Unix(), wid, mode, override, reason), inFuture(time.Minute))
	handleWatchRequest(h.out, ptyTestHost, watchRequest{
		SessionID: sid, WatchID: wid, Mode: mode, Actor: actor, Reason: reason, Override: override, Lease: lease,
	}, time.Now())
	return wid
}

// consentOf waits for the watch_consent answer for wid that matches result
// (any answer when result is empty).
func (h *ptyHarness) consentOf(t *testing.T, sid, wid string, timeout time.Duration) map[string]interface{} {
	t.Helper()
	var got map[string]interface{}
	waitFor(t, "watch_consent "+wid, timeout, func() bool {
		h.out.mu.Lock()
		defer h.out.mu.Unlock()
		for _, m := range h.out.jsons {
			p, _ := m["payload"].(map[string]interface{})
			if m["type"] == "watch_consent" && m["session_id"] == sid && p["watch_id"] == wid && p["result"] != "stopped" {
				got = p
				return true
			}
		}
		return false
	})
	return got
}

func waitPrompt(t *testing.T, h *ptyHarness, sid string) {
	t.Helper()
	waitFor(t, "consent prompt", 5*time.Second, func() bool { return strings.Contains(h.out.text(sid), "Allow? [y/N]") })
}

func TestPTYNoticeShownFirst(t *testing.T) {
	h := newPTYHarness(t)
	ptyCfg.Tenant = "acme"
	sid := h.startEcho(t)
	text := h.out.text(sid)
	notice := strings.Index(text, "This session is recorded and may be viewed by an administrator.")
	if notice < 0 || !strings.Contains(text, "Tenant: acme") {
		t.Fatalf("no notice: %q", text)
	}
	if ready := strings.Index(text, "READY"); ready < notice {
		t.Fatalf("shell output before the notice: %q", text)
	}
}

func TestPTYNoticeConfigurableNotRemovable(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "notice")
	if err := os.WriteFile(path, []byte("Monitored by ACME SecOps.\x1b[2J\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	text, err := loadPTYNotice(path, os.Geteuid())
	if err != nil || text != "Monitored by ACME SecOps.[2J" {
		t.Fatalf("got %q %v", text, err)
	}
	for _, body := range []string{"", "  \n\t\n", "\x1b\x07"} {
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := loadPTYNotice(path, os.Geteuid()); err == nil {
			t.Fatalf("empty notice %q accepted", body)
		}
	}
	if err := os.WriteFile(path, []byte("x"), 0o666); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o666); err != nil {
		t.Fatal(err)
	}
	if _, err := loadPTYNotice(path, os.Geteuid()); err == nil {
		t.Fatal("world-writable notice accepted")
	}

	h := newPTYHarness(t)
	ptyCfg.Notice = "Monitored by ACME SecOps."
	ptyCfg.Tenant = "acme"
	sid := h.startEcho(t)
	out := h.out.text(sid)
	if !strings.Contains(out, "Monitored by ACME SecOps.") || !strings.Contains(out, "Tenant: acme") {
		t.Fatalf("custom notice missing: %q", out)
	}
}

// The y/n answer goes to the prompt, never to the shell, and is not echoed.
func TestWatchConsentGrantedKeystrokesNeverReachShell(t *testing.T) {
	h := newPTYHarness(t)
	sid := h.startEcho(t)
	wid := h.watch(t, sid, watchModeView, "support-7", "ticket 123", false)
	waitPrompt(t, h, sid)
	handlePTYInput(sid, []byte("zz\n"))
	handlePTYInput(sid, []byte("yes please\n"))
	time.Sleep(100 * time.Millisecond)
	if s := lookupSession(sid); func() bool { s.mu.Lock(); defer s.mu.Unlock(); return s.watchers[wid] != nil }() {
		t.Fatal("text that is not a lone y consented")
	}
	handlePTYInput(sid, []byte("y"))
	p := h.consentOf(t, sid, wid, 5*time.Second)
	if p["granted"] != true || p["consent"] != true || p["result"] != "granted" || p["actor"] != "support-7" || p["reason"] != "ticket 123" {
		t.Fatalf("%v", p)
	}
	handlePTYInput(sid, []byte("after\n"))
	waitFor(t, "input after the prompt", 5*time.Second, func() bool { return strings.Contains(h.out.text(sid), "GOT[after]") })
	out := h.out.text(sid)
	if strings.Contains(out, "zz") || strings.Contains(out, "GOT[y") || strings.Contains(out, "please") {
		t.Fatalf("prompt keystrokes reached the shell or were echoed: %q", out)
	}
	if !strings.Contains(out, "You allowed support-7 to watch this session, view only.") {
		t.Fatalf("no start line: %q", out)
	}
	handleWatchStop(sid, wid)
	waitFor(t, "stop line", 5*time.Second, func() bool {
		return strings.Contains(h.out.text(sid), "support-7 stopped watching this session.")
	})
}

func TestWatchConsentDenied(t *testing.T) {
	h := newPTYHarness(t)
	sid := h.startEcho(t)
	wid := h.watch(t, sid, watchModeView, "support-7", "", false)
	waitPrompt(t, h, sid)
	handlePTYInput(sid, []byte("N"))
	if p := h.consentOf(t, sid, wid, 5*time.Second); p["granted"] != false || p["consent"] != false || p["result"] != "denied" {
		t.Fatalf("%v", p)
	}
	if s := lookupSession(sid); func() bool { s.mu.Lock(); defer s.mu.Unlock(); return len(s.watchers) != 0 }() {
		t.Fatal("watcher registered after a refusal")
	}
	handlePTYInput(sid, []byte("next\n"))
	waitFor(t, "input after refusal", 5*time.Second, func() bool { return strings.Contains(h.out.text(sid), "GOT[next]") })
	if strings.Contains(h.out.text(sid), "GOT[N") {
		t.Fatal("answer reached the shell")
	}
}

func TestWatchConsentTimeoutRefuses(t *testing.T) {
	h := newPTYHarness(t)
	prev := watchConsentTimeout
	watchConsentTimeout = 300 * time.Millisecond
	t.Cleanup(func() { watchConsentTimeout = prev })
	sid := h.startEcho(t)
	wid := h.watch(t, sid, watchModeView, "support-7", "", false)
	waitPrompt(t, h, sid)
	handlePTYInput(sid, []byte("maybe"))
	if p := h.consentOf(t, sid, wid, 5*time.Second); p["granted"] != false || p["result"] != "timeout" {
		t.Fatalf("%v", p)
	}
	if !strings.Contains(h.out.text(sid), "watching refused") {
		t.Fatal("user not told of the timeout")
	}
	handlePTYInput(sid, []byte("later\n"))
	waitFor(t, "input after timeout", 5*time.Second, func() bool { return strings.Contains(h.out.text(sid), "GOT[later]") })
	if strings.Contains(h.out.text(sid), "maybe") {
		t.Fatal("bytes typed during the prompt reached the shell")
	}
}

func TestWatchConsentDefaultTimeoutIs30s(t *testing.T) {
	if watchConsentTimeout != 30*time.Second {
		t.Fatalf("got %v", watchConsentTimeout)
	}
}

func TestWatchAdminOverrideViewOnlyWithReason(t *testing.T) {
	h := newPTYHarness(t)
	sid := h.startEcho(t)
	wid := h.watch(t, sid, watchModeView, "admin-1", "incident 42", true)
	p := h.consentOf(t, sid, wid, 5*time.Second)
	if p["granted"] != true || p["consent"] != false || p["result"] != "override" || p["reason"] != "incident 42" {
		t.Fatalf("%v", p)
	}
	out := h.out.text(sid)
	if strings.Contains(out, "Allow?") || !strings.Contains(out, "An administrator (admin-1) started watching this session, view only. Reason: incident 42") {
		t.Fatalf("%q", out)
	}
	handleWatchStop(sid, wid)
	waitFor(t, "stop line", 5*time.Second, func() bool { return strings.Contains(h.out.text(sid), "admin-1 stopped watching this session.") })
}

func TestWatchOverrideNeedsReason(t *testing.T) {
	h := newPTYHarness(t)
	sid := h.startEcho(t)
	wid := h.watch(t, sid, watchModeView, "admin-1", "", true)
	waitFor(t, "refusal", 5*time.Second, func() bool {
		m := h.out.find("watch_consent", sid)
		return m != nil
	})
	p := h.out.find("watch_consent", sid)["payload"].(map[string]interface{})
	if p["watch_id"] != wid || p["error"] != "reason_required" || p["granted"] != false {
		t.Fatalf("%v", p)
	}
}

// Read-write always asks, even with the override flag and a reason.
func TestWatchReadWriteAlwaysAsks(t *testing.T) {
	h := newPTYHarness(t)
	sid := h.startEcho(t)
	wid := h.watch(t, sid, watchModeControl, "admin-1", "incident 42", true)
	waitPrompt(t, h, sid)
	if !strings.Contains(h.out.text(sid), "with control") {
		t.Fatal("prompt does not say read-write")
	}
	handlePTYInput(sid, []byte("n"))
	if p := h.consentOf(t, sid, wid, 5*time.Second); p["granted"] != false || p["result"] != "denied" {
		t.Fatalf("%v", p)
	}
	handleWatcherInput(sid, wid, []byte("hijack\n"))
	handlePTYInput(sid, []byte("mine\n"))
	waitFor(t, "user input", 5*time.Second, func() bool { return strings.Contains(h.out.text(sid), "GOT[mine]") })
	if strings.Contains(h.out.text(sid), "hijack") {
		t.Fatal("watcher input without read-write consent reached the shell")
	}
}

func TestWatcherInputNeedsReadWriteConsent(t *testing.T) {
	h := newPTYHarness(t)
	sid := h.startEcho(t)
	ro := h.watch(t, sid, watchModeView, "admin-1", "incident 42", true)
	h.consentOf(t, sid, ro, 5*time.Second)
	handleWatcherInput(sid, ro, []byte("viewonly\n"))
	rw := h.watch(t, sid, watchModeControl, "support-7", "", false)
	waitPrompt(t, h, sid)
	handlePTYInput(sid, []byte("y"))
	if p := h.consentOf(t, sid, rw, 5*time.Second); p["granted"] != true {
		t.Fatalf("%v", p)
	}
	handleWatcherInput(sid, rw, []byte("helper\n"))
	waitFor(t, "watcher input", 5*time.Second, func() bool { return strings.Contains(h.out.text(sid), "GOT[helper]") })
	if strings.Contains(h.out.text(sid), "viewonly") {
		t.Fatal("view-only watcher typed into the shell")
	}
}

func TestWatchRefusals(t *testing.T) {
	h := newPTYHarness(t)
	sid := h.startEcho(t)
	s := lookupSession(sid)
	refusal := func(wid string) string {
		var code string
		waitFor(t, "refusal "+wid, 5*time.Second, func() bool {
			h.out.mu.Lock()
			defer h.out.mu.Unlock()
			for _, m := range h.out.jsons {
				p, _ := m["payload"].(map[string]interface{})
				if m["type"] == "watch_consent" && p["watch_id"] == wid {
					code, _ = p["error"].(string)
					return true
				}
			}
			return false
		})
		return code
	}
	// A lease for view-only does not authorize read-write, nor an override.
	wid := newWatchID(t)
	lease := signLease(t, h.priv, ptyTestHost, "pty", watchPayload(sid, s.deadline.Unix(), wid, watchModeView, false, ""), inFuture(time.Minute))
	handleWatchRequest(h.out, ptyTestHost, watchRequest{SessionID: sid, WatchID: wid, Mode: watchModeView, Actor: "a", Override: true, Reason: "", Lease: lease}, time.Now())
	if c := refusal(wid); c != "lease_required" {
		t.Fatalf("forged override: %q", c)
	}
	// A start lease is not a watch lease.
	wid = newWatchID(t)
	lease = signLease(t, h.priv, ptyTestHost, "pty", terminalPayload(sid, s.deadline.Unix(), "start"), inFuture(time.Minute))
	handleWatchRequest(h.out, ptyTestHost, watchRequest{SessionID: sid, WatchID: wid, Mode: watchModeView, Actor: "a", Lease: lease}, time.Now())
	if c := refusal(wid); c != "lease_required" {
		t.Fatalf("start lease: %q", c)
	}
	// An escape sequence in the reason never reaches the terminal.
	wid = h.watch(t, sid, watchModeView, "a", "x\x1b[2J", false)
	if c := refusal(wid); c != "bad_request" {
		t.Fatalf("escape in reason: %q", c)
	}
	// One prompt at a time.
	first := h.watch(t, sid, watchModeView, "a", "", false)
	waitPrompt(t, h, sid)
	second := h.watch(t, sid, watchModeView, "b", "", false)
	if c := refusal(second); c != "busy" {
		t.Fatalf("second prompt: %q", c)
	}
	// Ending the session answers the open prompt.
	handlePTYStop(sid)
	if p := h.consentOf(t, sid, first, 5*time.Second); p["granted"] != false || p["result"] != "session_ended" {
		t.Fatalf("%v", p)
	}
}
