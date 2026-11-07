package main

// file_root and xfer_root through the intent gate (contract 1.5: "file_root
// and xfer_root renewals follow the same split at their renew sites").

import (
	"strings"
	"testing"
	"time"
)

func TestFileRootIntentStartAndRenew(t *testing.T) {
	h := newFileHarness(t)
	withRequireIntent(t, "root-session\n")
	ih := &intentHarness{priv: h.priv, now: time.Now()}
	sid := newFileSessionID(t)
	dl := ih.now.Unix() + 3600
	start, err := fileLeasePayload(sid, dl, "start", "write", "/")
	if err != nil {
		t.Fatal(err)
	}
	// N25 for root-session: a v1 file_root open under the pin.
	h.ch.openFile(fileMsg{SessionID: sid, Action: "file_root", Mode: "write", Root: "/", DeadlineUnix: dl, IdleS: 60, Actor: "alice",
		Lease: signLease(t, h.priv, ptyTestHost, "file_root", start, inFuture(time.Minute))}, time.Now())
	if h.ch.lookupFile(sid) != nil || !strings.Contains(h.out.text(sid)+fileStatusOf(h, sid), "lease_required") {
		t.Fatalf("v1 file_root opened under the pin: %q", fileStatusOf(h, sid))
	}
	// A v2 open whose intent names another requester.
	text := ih.intent(t, "file_root", start, dl, nil)
	h.ch.openFile(fileMsg{SessionID: sid, Action: "file_root", Mode: "write", Root: "/", DeadlineUnix: dl, IdleS: 60, Actor: "mallory", Intent: text,
		Lease: signLeaseV2(t, h.priv, ptyTestHost, "file_root", start, sha256Hex(text), inFuture(time.Minute))}, time.Now())
	if h.ch.lookupFile(sid) != nil {
		t.Fatal("file_root opened for another requester")
	}

	// Renew split on a session that holds an intent hash.
	sha := sha256Hex(text)
	s := &fileSession{c: h.ch, id: sid, action: "file_root", mode: "write", root: "/", deadline: time.Unix(dl, 0), intentSHA: sha}
	h.ch.mu.Lock()
	h.ch.files[sid] = s
	h.ch.mu.Unlock()
	t.Cleanup(func() {
		h.ch.mu.Lock()
		delete(h.ch.files, sid)
		h.ch.mu.Unlock()
	})
	renew, _ := fileLeasePayload(sid, dl, "renew", "write", "/")
	wantErr(t, "file N22", h.ch.renewFile(sid, signLease(t, h.priv, ptyTestHost, "file_root", renew, inFuture(time.Minute)), time.Now()), "intent_required")
	wantErr(t, "file N21", h.ch.renewFile(sid, signLeaseV2(t, h.priv, ptyTestHost, "file_root", renew, sha256Hex("x"), inFuture(time.Minute)), time.Now()), "intent_mismatch")
	later := time.Now().Add(20 * time.Minute)
	if err := h.ch.renewFile(sid, signLeaseV2(t, h.priv, ptyTestHost, "file_root", renew, sha, later.Unix()+60), later); err != nil {
		t.Fatalf("file N20: %v", err)
	}
	s.intentSHA = ""
	wantErr(t, "file N23", h.ch.renewFile(sid, signLeaseV2(t, h.priv, ptyTestHost, "file_root", renew, sha, inFuture(time.Minute)), time.Now()), "intent_unexpected")
}

func fileStatusOf(h *fileHarness, sid string) string {
	m := h.out.find("file_status", sid)
	if m == nil {
		return ""
	}
	p, _ := m["payload"].(map[string]interface{})
	e, _ := p["error"].(string)
	return e
}

func TestXferRootIntentRenew(t *testing.T) {
	ih := newIntentHarness(t)
	withRequireIntent(t, "root-session\n")
	m := newXferManager(t.TempDir())
	dl := ih.now.Unix() + 60
	fields := xferLeaseFields{
		GrantID: "xfr_AAAAAAAAAAAA", DeadlineUnix: dl, Phase: "start", Dir: "put", Root: "/", Path: "a",
		Size: 1, SHA256: strings.Repeat("a", 64), TransferID: "0123456789abcdef", ExpiresUnix: dl,
		IdleS: 10, MaxS: 60, ByteCap: 1, Profile: "internet", Transport: "udp", Peer: "listen", Material: strings.Repeat("b", 64),
	}
	sha := sha256Hex("intent")
	x := &xferChild{m: m, hostID: ptyTestHost, grantID: fields.GrantID, action: "xfer_root", intentSHA: sha, lease: fields,
		deadline: dl, ctlq: make(chan []byte, 8), ctlStop: make(chan struct{}), done: make(chan struct{})}
	m.mu.Lock()
	m.live[x.grantID] = x
	m.mu.Unlock()
	next := dl + 30
	rf := fields
	rf.Phase, rf.DeadlineUnix = "renew", next
	renew, err := xferLeasePayload(rf)
	if err != nil {
		t.Fatal(err)
	}
	msg := func(l *Lease) xferMsg { return xferMsg{GrantID: x.grantID, DeadlineUnix: next, Lease: l} }
	wantErr(t, "xfer N22", m.renew(msg(signLease(t, ih.priv, ptyTestHost, "xfer_root", renew, inFuture(time.Minute))), time.Now()), "intent_required")
	wantErr(t, "xfer N21", m.renew(msg(signLeaseV2(t, ih.priv, ptyTestHost, "xfer_root", renew, sha256Hex("x"), inFuture(time.Minute))), time.Now()), "intent_mismatch")
	if err := m.renew(msg(signLeaseV2(t, ih.priv, ptyTestHost, "xfer_root", renew, sha, inFuture(time.Minute))), time.Now()); err != nil {
		t.Fatalf("xfer v2 renew: %v", err)
	}
	x.intentSHA = ""
	wantErr(t, "xfer N23", m.renew(msg(signLeaseV2(t, ih.priv, ptyTestHost, "xfer_root", renew, sha, inFuture(time.Minute))), time.Now()), "intent_unexpected")
	// The pin refuses a v1 renew of a root transfer with no intent.
	wantErr(t, "xfer pinned v1", m.renew(msg(signLease(t, ih.priv, ptyTestHost, "xfer_root", renew, inFuture(time.Minute))), time.Now()), "intent_required")
}
