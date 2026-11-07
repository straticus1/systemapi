package main

// systemapi-intent-v1 and systemapi-lease-v2, agent half
// (.omc/plans/sah-signed-intent-contract.md 1.1-1.5, 2.4, 2.5; tests
// N20-N27). controlplane/testdata/intent-lease-vectors.json is signed by the
// control plane's builders (controlplane/intent.js) and checked here, so the
// two sides agree byte for byte.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type intentVectorLease struct {
	Payload string `json:"payload"`
	Message string `json:"message"`
	Lease   Lease  `json:"lease"`
}

type intentVectors struct {
	PublicRawB64 string `json:"public_raw_b64"`
	HostID       string `json:"host_id"`
	NowMS        int64  `json:"now_ms"`
	Vectors      []struct {
		Name   string `json:"name"`
		Fields struct {
			RequestID          string `json:"request_id"`
			TenantID           string `json:"tenant_id"`
			HostID             string `json:"host_id"`
			Requester          string `json:"requester"`
			Action             string `json:"action"`
			PayloadSHA         string `json:"payload_sha256"`
			NotBefore          int64  `json:"not_before_unix"`
			UseBy              int64  `json:"use_by_unix"`
			MaxSessionDeadline int64  `json:"max_session_deadline_unix"`
			ReasonSHA          string `json:"reason_sha256"`
			ApproverSetVersion int64  `json:"approver_set_version"`
			ThresholdK         int64  `json:"threshold_k"`
		} `json:"fields"`
		Intent    string             `json:"intent"`
		IntentSHA string             `json:"intent_sha256"`
		Action    string             `json:"action"`
		Payload   string             `json:"payload"`
		Start     *intentVectorLease `json:"start"`
		Renew     *intentVectorLease `json:"renew"`
	} `json:"vectors"`
	Invalid []struct {
		Name   string `json:"name"`
		Intent string `json:"intent"`
	} `json:"invalid"`
}

func loadIntentVectors(t *testing.T) intentVectors {
	t.Helper()
	blob, err := os.ReadFile(filepath.Join("..", "controlplane", "testdata", "intent-lease-vectors.json"))
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}
	var v intentVectors
	if err := json.Unmarshal(blob, &v); err != nil {
		t.Fatalf("parse vectors: %v", err)
	}
	return v
}

// intentTestKey is keys.js TEST_SEED, the key that signed the vectors.
func intentTestKey() ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x11}, 32))
}

func TestIntentVectorsAgreeWithControlPlane(t *testing.T) {
	v := loadIntentVectors(t)
	priv := intentTestKey()
	if base64.StdEncoding.EncodeToString(priv.Public().(ed25519.PublicKey)) != v.PublicRawB64 {
		t.Fatal("vector key is not TEST_SEED")
	}
	pub := priv.Public().(ed25519.PublicKey)
	now := time.UnixMilli(v.NowMS)
	if len(v.Vectors) < 5 {
		t.Fatalf("%d vectors", len(v.Vectors))
	}
	for _, c := range v.Vectors {
		fv := c.Fields
		f := intentFields{fv.RequestID, fv.TenantID, fv.HostID, fv.Requester, fv.Action, fv.PayloadSHA,
			fv.NotBefore, fv.UseBy, fv.MaxSessionDeadline, fv.ReasonSHA, fv.ApproverSetVersion, fv.ThresholdK}
		text, err := canonicalIntent(f)
		if err != nil || text != c.Intent {
			t.Fatalf("%s: Go canonical %q (%v), server built %q", c.Name, text, err, c.Intent)
		}
		got, err := parseIntent(c.Intent)
		if err != nil || got != f {
			t.Fatalf("%s: parse %+v (%v)", c.Name, got, err)
		}
		if sha256Hex(c.Intent) != c.IntentSHA {
			t.Fatalf("%s: intent hash", c.Name)
		}
		if c.Start == nil {
			continue
		}
		if payloadHash(c.Action, c.Payload) != fv.PayloadSHA {
			t.Fatalf("%s: payload hash differs from the intent", c.Name)
		}
		for phase, l := range map[string]*intentVectorLease{"start": c.Start, "renew": c.Renew} {
			if l == nil {
				continue
			}
			payload := c.Payload
			if phase == "renew" {
				payload = l.Payload
			}
			msg := canonicalLeaseV2(l.Lease.HostID, l.Lease.Action, l.Lease.ExpiresUnix, l.Lease.NonceHex, l.Lease.PayloadSHA, l.Lease.IntentSHA)
			if msg != l.Message {
				t.Fatalf("%s %s: canonical v2 message mismatch", c.Name, phase)
			}
			sha, err := verifyLeaseV2(pub, &l.Lease, v.HostID, c.Action, payload, now)
			if err != nil || sha != c.IntentSHA {
				t.Fatalf("%s %s: verifyLeaseV2 %q %v", c.Name, phase, sha, err)
			}
			// An old verifier (v1 only, lease.go verifyLease) refuses v2 as
			// malformed, so an old agent fails closed.
			if err := verifyLease(pub, &l.Lease, v.HostID, c.Action, payload, now); err == nil || err.Error() != "malformed" {
				t.Fatalf("%s %s: v1 verifier on a v2 lease: %v", c.Name, phase, err)
			}
			v1 := l.Lease
			v1.V, v1.IntentSHA = 1, ""
			if err := verifyLease(pub, &v1, v.HostID, c.Action, payload, now); err == nil || err.Error() != "bad_signature" {
				t.Fatalf("%s %s: v2 relabelled v1: %v", c.Name, phase, err)
			}
		}
		ctx := intentCtx{}
		if intentSessionAction(c.Action) {
			ctx = intentCtx{Requester: fv.Requester, DeadlineUnix: fv.MaxSessionDeadline, Session: true}
		}
		if _, err := checkIntentStart(c.Intent, &c.Start.Lease, ctx, now); err != nil {
			t.Fatalf("%s: checkIntentStart %v", c.Name, err)
		}
	}
}

func TestIntentInvalidVectorsRefused(t *testing.T) {
	v := loadIntentVectors(t)
	if len(v.Invalid) < 30 {
		t.Fatalf("%d invalid vectors", len(v.Invalid))
	}
	for _, c := range v.Invalid {
		if _, err := parseIntent(c.Intent); err == nil || err.Error() != "intent_malformed" {
			t.Fatalf("%s: parse %v, want intent_malformed", c.Name, err)
		}
	}
}

func TestCanonicalIntentRefusesNeverEscapes(t *testing.T) {
	base, err := parseIntent(loadIntentVectors(t).Vectors[0].Intent)
	if err != nil {
		t.Fatal(err)
	}
	for name, mut := range map[string]func(f *intentFields){
		"newline":       func(f *intentFields) { f.Requester = "member:a\nmember:b" },
		"space":         func(f *intentFields) { f.TenantID = "ac me" },
		"nul":           func(f *intentFields) { f.RequestID = "apr_AAAAAAAAAAAAAAAAAAAAA\x00" },
		"negative":      func(f *intentFields) { f.NotBefore = -1 },
		"above_safe":    func(f *intentFields) { f.ApproverSetVersion = intentMaxInt + 1 },
		"unknown":       func(f *intentFields) { f.Action = "pty" },
		"empty_reason":  func(f *intentFields) { f.ReasonSHA = "" },
		"k_zero":        func(f *intentFields) { f.ThresholdK = 0 },
		"utf8":          func(f *intentFields) { f.TenantID = "acmé" },
		"key_principal": func(f *intentFields) { f.Requester = "key:abc" },
	} {
		f := base
		mut(&f)
		if _, err := canonicalIntent(f); err == nil {
			t.Fatalf("%s: built", name)
		}
	}
}

// intentHarness pins TEST_SEED for ptyTestHost and builds intents and v2
// leases signed by it.
type intentHarness struct {
	priv ed25519.PrivateKey
	now  time.Time
}

func newIntentHarness(t *testing.T) *intentHarness {
	t.Helper()
	priv := intentTestKey()
	clearIdentity()
	t.Cleanup(clearIdentity)
	if err := pinControlPublicKey(base64.StdEncoding.EncodeToString(priv.Public().(ed25519.PublicKey)), ptyTestHost); err != nil {
		t.Fatal(err)
	}
	withRequireIntent(t, "")
	return &intentHarness{priv: priv, now: time.Now()}
}

// intent builds an intent for action+payload on ptyTestHost whose window is
// [now-60, now+840].
func (h *intentHarness) intent(t *testing.T, action, payload string, msd int64, mut func(*intentFields)) string {
	t.Helper()
	n := h.now.Unix()
	f := intentFields{
		RequestID: "apr_AAAAAAAAAAAAAAAAAAAAAA", TenantID: "acme", HostID: ptyTestHost, Requester: "member:alice",
		Action: action, PayloadSHA: payloadHash(action, payload), NotBefore: n - 60, UseBy: n + 840,
		MaxSessionDeadline: msd, ReasonSHA: sha256Hex("why"), ApproverSetVersion: 1, ThresholdK: 1,
	}
	if mut != nil {
		mut(&f)
	}
	text, err := canonicalIntent(f)
	if err != nil {
		t.Fatalf("intent: %v", err)
	}
	return text
}

func signLeaseV2(t *testing.T, priv ed25519.PrivateKey, host, action, payload, intentSHA string, exp int64) *Lease {
	t.Helper()
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	l := &Lease{V: 2, HostID: host, Action: action, ExpiresUnix: exp, NonceHex: hex.EncodeToString(nonce), PayloadSHA: payloadHash(action, payload), IntentSHA: intentSHA}
	msg := canonicalLeaseV2(l.HostID, l.Action, l.ExpiresUnix, l.NonceHex, l.PayloadSHA, l.IntentSHA)
	l.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(priv, []byte(msg)))
	return l
}

// withRequireIntent points requireIntentPath at a trusted temp file holding
// body; "" removes it (no pin).
func withRequireIntent(t *testing.T, body string) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "etc-systemapi-agent")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "require-intent")
	if body != "" {
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	prevPath, prevUID := requireIntentPath, helperTrustOwnerUID
	requireIntentPath = path
	helperTrustOwnerUID = uint32(os.Getuid())
	t.Cleanup(func() { requireIntentPath, helperTrustOwnerUID = prevPath, prevUID })
	return path
}

// captureReceipts collects intent_receipt lines.
func captureReceipts(t *testing.T) func() []string {
	t.Helper()
	var mu sync.Mutex
	var lines []string
	prev := intentReceiptSink
	intentReceiptSink = func(l string) {
		mu.Lock()
		lines = append(lines, l)
		mu.Unlock()
	}
	t.Cleanup(func() { intentReceiptSink = prev })
	return func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), lines...)
	}
}

func wantErr(t *testing.T, name string, err error, code string) {
	t.Helper()
	if err == nil || err.Error() != code {
		t.Fatalf("%s: %v, want %s", name, err, code)
	}
}

func TestIntentStartChecksRefuse(t *testing.T) {
	h := newIntentHarness(t)
	sid := "pts_AAAAAAAAAAAAAAAAAAAAAA"
	dl := h.now.Unix() + 3600
	payload := terminalPayload(sid, dl, "start")
	exp := h.now.Unix() + 60
	ctx := intentCtx{Requester: "member:alice", DeadlineUnix: dl, Session: true}
	start := func(text string, l *Lease, c intentCtx, now time.Time) error {
		_, err := authorizeIntentStart(ptyTestHost, "breakglass", payload, l, text, c, now)
		return err
	}
	good := h.intent(t, "breakglass", payload, dl, nil)
	if err := start(good, signLeaseV2(t, h.priv, ptyTestHost, "breakglass", payload, sha256Hex(good), exp), ctx, h.now); err != nil {
		t.Fatalf("positive control: %v", err)
	}
	lease := func(text string) *Lease {
		return signLeaseV2(t, h.priv, ptyTestHost, "breakglass", payload, sha256Hex(text), exp)
	}
	// 1: the text is not the one the lease signed.
	other := h.intent(t, "breakglass", payload, dl, func(f *intentFields) { f.ReasonSHA = sha256Hex("other") })
	wantErr(t, "hash", start(other, lease(good), ctx, h.now), "intent_mismatch")
	// 2: a lease signed over a non-canonical text (wrong domain prefix).
	bad := strings.Replace(good, "systemapi-intent-v1", "systemapi-intent-v0", 1)
	wantErr(t, "prefix", start(bad, lease(bad), ctx, h.now), "intent_malformed")
	// 3: intent names another host, action or payload than the lease.
	for name, mut := range map[string]func(*intentFields){
		"host":    func(f *intentFields) { f.HostID = "44444444-4444-4444-8444-444444444444" },
		"action":  func(f *intentFields) { f.Action = "pty_root" },
		"payload": func(f *intentFields) { f.PayloadSHA = payloadHash("breakglass", terminalPayload(sid, dl+1, "start")) },
	} {
		text := h.intent(t, "breakglass", payload, dl, mut)
		wantErr(t, name, start(text, lease(text), ctx, h.now), "intent_mismatch")
	}
	// 4: requester; 5: request id.
	wantErr(t, "requester", start(good, lease(good), intentCtx{Requester: "member:bob", DeadlineUnix: dl, Session: true}, h.now), "intent_requester")
	wantErr(t, "no actor", start(good, lease(good), intentCtx{Requester: "", DeadlineUnix: dl, Session: true}, h.now), "intent_requester")
	wantErr(t, "request", start(good, lease(good), intentCtx{Requester: "member:alice", RequestID: "apr_BBBBBBBBBBBBBBBBBBBBBB", DeadlineUnix: dl, Session: true}, h.now), "intent_request")
	// 6 (N24): the agent's own clock is past use_by + skew or before
	// not_before - skew. The lease itself is fresh for that clock.
	late := h.now.Add(840*time.Second + leaseSkew + 2*time.Second)
	wantErr(t, "after use_by", start(good, signLeaseV2(t, h.priv, ptyTestHost, "breakglass", payload, sha256Hex(good), late.Unix()+60), ctx, late), "intent_window")
	early := h.now.Add(-60*time.Second - leaseSkew - 2*time.Second)
	wantErr(t, "before not_before", start(good, signLeaseV2(t, h.priv, ptyTestHost, "breakglass", payload, sha256Hex(good), early.Unix()+60), ctx, early), "intent_window")
	// 7 (N24): start frame deadline != max_session_deadline.
	short := h.intent(t, "breakglass", payload, dl-60, nil)
	wantErr(t, "deadline", start(short, lease(short), ctx, h.now), "intent_deadline")
	// A v2 lease for an action that never carries an intent.
	pty := signLeaseV2(t, h.priv, ptyTestHost, "pty", payload, sha256Hex(good), exp)
	_, err := authorizeIntentStart(ptyTestHost, "pty", payload, pty, good, ctx, h.now)
	wantErr(t, "pty v2", err, "bad_action")
	// Replay of the same v2 lease nonce.
	l := lease(good)
	if err := start(good, l, ctx, h.now); err != nil {
		t.Fatal(err)
	}
	wantErr(t, "replay", start(good, l, ctx, h.now), "replay")
}

func TestIntentRenewSplit(t *testing.T) {
	h := newIntentHarness(t)
	sid := "pts_AAAAAAAAAAAAAAAAAAAAAA"
	dl := h.now.Unix() + 7200
	renew := terminalPayload(sid, dl, "renew")
	text := h.intent(t, "breakglass", terminalPayload(sid, dl, "start"), dl, nil)
	stored := sha256Hex(text)
	// N20: a renew after use_by on an intent session succeeds.
	afterUseBy := h.now.Add(900 * time.Second)
	if err := authorizeRenew(ptyTestHost, "breakglass", renew, signLeaseV2(t, h.priv, ptyTestHost, "breakglass", renew, stored, afterUseBy.Unix()+60), stored, []string{"breakglass"}, sid, afterUseBy); err != nil {
		t.Fatalf("N20: %v", err)
	}
	// N21: a renew lease with a different intent hash.
	wantErr(t, "N21", authorizeRenew(ptyTestHost, "breakglass", renew, signLeaseV2(t, h.priv, ptyTestHost, "breakglass", renew, sha256Hex("other"), h.now.Unix()+60), stored, []string{"breakglass"}, sid, h.now), "intent_mismatch")
	// N22: a v1 renew on an intent session (downgrade).
	wantErr(t, "N22", authorizeRenew(ptyTestHost, "breakglass", renew, signLease(t, h.priv, ptyTestHost, "breakglass", renew, h.now.Unix()+60), stored, []string{"breakglass"}, sid, h.now), "intent_required")
	wantErr(t, "N22 nil", authorizeRenew(ptyTestHost, "breakglass", renew, nil, stored, []string{"breakglass"}, sid, h.now), "intent_required")
	// N23: a v2 renew on a session started without an intent.
	wantErr(t, "N23", authorizeRenew(ptyTestHost, "breakglass", renew, signLeaseV2(t, h.priv, ptyTestHost, "breakglass", renew, stored, h.now.Unix()+60), "", []string{"breakglass"}, sid, h.now), "intent_unexpected")
	// A start payload cannot renew.
	start := terminalPayload(sid, dl, "start")
	wantErr(t, "start as renew", authorizeRenew(ptyTestHost, "breakglass", renew, signLeaseV2(t, h.priv, ptyTestHost, "breakglass", start, stored, h.now.Unix()+60), stored, []string{"breakglass"}, sid, h.now), "payload_mismatch")
	// v1 renew of a v1 session keeps working.
	if err := authorizeRenew(ptyTestHost, "breakglass", renew, signLease(t, h.priv, ptyTestHost, "breakglass", renew, h.now.Unix()+60), "", []string{"breakglass"}, sid, h.now); err != nil {
		t.Fatalf("v1 renew: %v", err)
	}
}

func TestRequireIntentPin(t *testing.T) {
	h := newIntentHarness(t)
	sid := "pts_AAAAAAAAAAAAAAAAAAAAAA"
	dl := h.now.Unix() + 3600
	payload := terminalPayload(sid, dl, "start")
	ctx := intentCtx{Requester: "member:alice", DeadlineUnix: dl, Session: true}
	v1 := func(action string) error {
		_, err := authorizeStart(ptyTestHost, action, payload, signLease(t, h.priv, ptyTestHost, action, payload, h.now.Unix()+60), "", ctx, intentClasses(action, payload, nil), sid, h.now)
		return err
	}
	v2 := func() error {
		text := h.intent(t, "breakglass", payload, dl, nil)
		_, err := authorizeStart(ptyTestHost, "breakglass", payload, signLeaseV2(t, h.priv, ptyTestHost, "breakglass", payload, sha256Hex(text), h.now.Unix()+60), text, ctx, []string{"breakglass"}, sid, h.now)
		return err
	}
	// No pin: v1 as today.
	if err := v1("breakglass"); err != nil {
		t.Fatalf("no pin: %v", err)
	}
	// N25: pin lists breakglass, a v1 breakglass start is refused; v2 works;
	// root-session is not pinned so v1 pty_root still works.
	withRequireIntent(t, "breakglass\n")
	wantErr(t, "N25", v1("breakglass"), "intent_required")
	if err := v2(); err != nil {
		t.Fatalf("v2 under pin: %v", err)
	}
	if err := v1("pty_root"); err != nil {
		t.Fatalf("unpinned class: %v", err)
	}
	if got := requireIntentHeader(); got != "breakglass" {
		t.Fatalf("header %q", got)
	}
	withRequireIntent(t, "sys-write\nroot-session\nbreakglass\nsash-config\n")
	if got := requireIntentHeader(); got != "breakglass,root-session,sash-config,sys-write" {
		t.Fatalf("header %q", got)
	}
	wantErr(t, "root pinned", v1("pty_root"), "intent_required")
	// An intent text beside a v1 lease is never ignored.
	_, err := authorizeStart(ptyTestHost, "pty_root", payload, signLease(t, h.priv, ptyTestHost, "pty_root", payload, h.now.Unix()+60), "x", ctx, []string{"root-session"}, sid, h.now)
	wantErr(t, "v1 with intent", err, "intent_unexpected")
	// N26: a damaged pin refuses every approval-class action, v1 and v2,
	// and leaves ordinary actions alone.
	for name, body := range map[string]string{
		"unknown class":    "breakglass\nroot\n",
		"crlf":             "breakglass\r\n",
		"no final newline": "breakglass",
		"blank line":       "breakglass\n\n",
		"space":            "breakglass \n",
		"too large":        strings.Repeat("breakglass\n", 200),
	} {
		withRequireIntent(t, body)
		wantErr(t, "N26 "+name+" v1", v1("pty_root"), "intent_pin_unavailable")
		wantErr(t, "N26 "+name+" v2", v2(), "intent_pin_unavailable")
		if err := v1("pty"); err != nil {
			t.Fatalf("N26 %s: plain pty refused: %v", name, err)
		}
		if requireIntentHeader() != "invalid" {
			t.Fatalf("N26 %s: header", name)
		}
	}
	path := withRequireIntent(t, "breakglass\n")
	if err := os.Chmod(path, 0o666); err != nil {
		t.Fatal(err)
	}
	wantErr(t, "N26 writable", v1("breakglass"), "intent_pin_unavailable")
	link := withRequireIntent(t, "")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	wantErr(t, "N26 symlink", v1("breakglass"), "intent_pin_unavailable")
	// An empty pin file pins nothing.
	empty := withRequireIntent(t, "")
	if err := os.WriteFile(empty, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := v1("breakglass"); err != nil {
		t.Fatalf("empty pin: %v", err)
	}
}

func TestIntentReceipts(t *testing.T) {
	h := newIntentHarness(t)
	got := captureReceipts(t)
	sid := "pts_AAAAAAAAAAAAAAAAAAAAAA"
	dl := h.now.Unix() + 3600
	payload := terminalPayload(sid, dl, "start")
	ctx := intentCtx{Requester: "member:alice", DeadlineUnix: dl, Session: true}
	text := h.intent(t, "breakglass", payload, dl, nil)
	l2 := signLeaseV2(t, h.priv, ptyTestHost, "breakglass", payload, sha256Hex(text), h.now.Unix()+60)
	sha, err := authorizeStart(ptyTestHost, "breakglass", payload, l2, text, ctx, []string{"breakglass"}, sid, h.now)
	if err != nil {
		t.Fatal(err)
	}
	renew := terminalPayload(sid, dl, "renew")
	lr := signLeaseV2(t, h.priv, ptyTestHost, "breakglass", renew, sha, h.now.Unix()+60)
	if err := authorizeRenew(ptyTestHost, "breakglass", renew, lr, sha, []string{"breakglass"}, sid, h.now); err != nil {
		t.Fatal(err)
	}
	// N27: a v1 approval-class one-shot (sys_config write) gets a receipt
	// with intent=none and no path; an ordinary pty start gets none.
	cfg, _ := sysConfigLeasePayload("write", "/etc/nginx/secret-name.conf", sha256Hex("x"))
	if _, err := authorizeStart(ptyTestHost, "sys_config", cfg, signLease(t, h.priv, ptyTestHost, "sys_config", cfg, h.now.Unix()+60), "", intentCtx{}, intentClasses("sys_config", cfg, nil), "", h.now); err != nil {
		t.Fatal(err)
	}
	pp := terminalPayload("pts_CCCCCCCCCCCCCCCCCCCCCC", dl, "start")
	if _, err := authorizeStart(ptyTestHost, "pty", pp, signLease(t, h.priv, ptyTestHost, "pty", pp, h.now.Unix()+60), "", ctx, intentClasses("pty", pp, nil), sid, h.now); err != nil {
		t.Fatal(err)
	}
	lines := got()
	want := []string{
		"intent_receipt phase=start action=breakglass nonce=" + l2.NonceHex + " intent=" + sha + " request=apr_AAAAAAAAAAAAAAAAAAAAAA session=" + sid,
		"intent_receipt phase=renew action=breakglass nonce=" + lr.NonceHex + " intent=" + sha + " request=none session=" + sid,
	}
	if len(lines) != 3 || lines[0] != want[0] || lines[1] != want[1] {
		t.Fatalf("receipts %q", lines)
	}
	if !strings.HasPrefix(lines[2], "intent_receipt phase=start action=sys_config nonce=") || !strings.Contains(lines[2], " intent=none request=none session=-") {
		t.Fatalf("v1 receipt %q", lines[2])
	}
	for _, l := range lines {
		if strings.Contains(l, "/etc") || strings.Contains(l, "alice") || strings.Contains(l, "secret") {
			t.Fatalf("receipt leaks a path or actor: %q", l)
		}
	}
	// A refused lease writes no receipt.
	n := len(got())
	_, _ = authorizeStart(ptyTestHost, "breakglass", payload, l2, text, ctx, []string{"breakglass"}, sid, h.now)
	if len(got()) != n {
		t.Fatal("receipt for a refused (replayed) lease")
	}
}
