package main

// Intent-bound terminal sessions end to end through startPTYSession and
// renewPTYSession (contract 1.5; N20-N25 at the real sites).

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// intentPTY starts a long-running break-glass shell (a fake adssh) and pins
// the harness key for intent leases.
func intentPTY(t *testing.T) (*ptyHarness, *intentHarness) {
	t.Helper()
	h := newPTYHarness(t)
	bin := t.TempDir()
	if err := os.WriteFile(filepath.Join(bin, "adssh"), []byte("#!/bin/sh\nsleep 30\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+":/usr/bin:/bin")
	ih := &intentHarness{priv: h.priv, now: time.Now()}
	withRequireIntent(t, "")
	return h, ih
}

func TestPTYIntentStartAndRenew(t *testing.T) {
	h, ih := intentPTY(t)
	sid := newSessionID(t)
	dl := ih.now.Unix() + 3600
	start := terminalPayload(sid, dl, "start")
	text := ih.intent(t, "breakglass", start, dl, func(f *intentFields) { f.Requester = "member:alice" })
	sha := sha256Hex(text)
	withRequireIntent(t, "breakglass\n")

	// N25: a v1 start for a pinned class is refused.
	v1sid := newSessionID(t)
	startPTYSession(h.out, ptyTestHost, h.dir, ptyStartRequest{SessionID: v1sid, Action: "breakglass", DeadlineUnix: dl, Actor: "alice",
		Lease: signLease(t, h.priv, ptyTestHost, "breakglass", terminalPayload(v1sid, dl, "start"), inFuture(time.Minute))}, time.Now())
	if e := h.startErr(t, v1sid); e != "lease_required" || lookupSession(v1sid) != nil {
		t.Fatalf("N25 v1 under pin: %q", e)
	}
	// Another actor than the intent's requester.
	bob := newSessionID(t)
	bobStart := terminalPayload(bob, dl, "start")
	bobText := ih.intent(t, "breakglass", bobStart, dl, nil)
	startPTYSession(h.out, ptyTestHost, h.dir, ptyStartRequest{SessionID: bob, Action: "breakglass", DeadlineUnix: dl, Actor: "bob", Intent: bobText,
		Lease: signLeaseV2(t, h.priv, ptyTestHost, "breakglass", bobStart, sha256Hex(bobText), inFuture(time.Minute))}, time.Now())
	if e := h.startErr(t, bob); e != "lease_required" || lookupSession(bob) != nil {
		t.Fatalf("requester mismatch started: %q", e)
	}

	// The approved v2 start.
	startPTYSession(h.out, ptyTestHost, h.dir, ptyStartRequest{SessionID: sid, Action: "breakglass", DeadlineUnix: dl, Actor: "alice", Intent: text,
		Lease: signLeaseV2(t, h.priv, ptyTestHost, "breakglass", start, sha, inFuture(time.Minute))}, time.Now())
	startedPayload(t, h, sid)
	s := lookupSession(sid)
	if s == nil || s.intentSHA != sha {
		t.Fatal("session does not hold the intent hash")
	}
	renew := terminalPayload(sid, dl, "renew")
	// N22: v1 renew on the intent session.
	wantErr(t, "N22", renewPTYSession(ptyTestHost, sid, signLease(t, h.priv, ptyTestHost, "breakglass", renew, inFuture(time.Minute)), time.Now()), "intent_required")
	// N21: v2 renew with another intent hash.
	wantErr(t, "N21", renewPTYSession(ptyTestHost, sid, signLeaseV2(t, h.priv, ptyTestHost, "breakglass", renew, sha256Hex("x"), inFuture(time.Minute)), time.Now()), "intent_mismatch")
	// N20: a renew past use_by (the agent's clock moved 20 minutes on).
	later := time.Now().Add(20 * time.Minute)
	if err := renewPTYSession(ptyTestHost, sid, signLeaseV2(t, h.priv, ptyTestHost, "breakglass", renew, sha, later.Unix()+60), later); err != nil {
		t.Fatalf("N20: %v", err)
	}
}

func TestPTYV2RenewOnSessionWithoutIntent(t *testing.T) {
	h, ih := intentPTY(t)
	sid := h.start(t, "breakglass", inFuture(time.Minute), ih.now.Unix()+3600)
	startedPayload(t, h, sid)
	s := lookupSession(sid)
	if s == nil || s.intentSHA != "" {
		t.Fatal("v1 session holds an intent hash")
	}
	renew := terminalPayload(sid, s.deadline.Unix(), "renew")
	// N23.
	wantErr(t, "N23", renewPTYSession(ptyTestHost, sid, signLeaseV2(t, h.priv, ptyTestHost, "breakglass", renew, sha256Hex("x"), inFuture(time.Minute)), time.Now()), "intent_unexpected")
	if err := renewPTYSession(ptyTestHost, sid, signLease(t, h.priv, ptyTestHost, "breakglass", renew, inFuture(time.Minute)), time.Now()); err != nil {
		t.Fatalf("v1 renew: %v", err)
	}
	// A pin added while a v1 session runs: its next v1 renew is refused.
	withRequireIntent(t, "breakglass\n")
	wantErr(t, "pin after start", renewPTYSession(ptyTestHost, sid, signLease(t, h.priv, ptyTestHost, "breakglass", renew, inFuture(time.Minute)), time.Now()), "intent_required")
}
