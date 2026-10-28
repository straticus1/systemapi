package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type jobLeaseVector struct {
	Name                  string          `json:"name"`
	JobID                 string          `json:"job_id"`
	DeadlineUnix          int64           `json:"deadline_unix"`
	TimeoutS              int             `json:"timeout_s"`
	Script                string          `json:"script"`
	Entitlements          json.RawMessage `json:"entitlements"`
	CanonicalEntitlements string          `json:"canonical_entitlements"`
	EntitlementsSHA256    string          `json:"entitlements_sha256"`
	ScriptSHA256          string          `json:"script_sha256"`
	Payload               string          `json:"payload"`
	Message               string          `json:"message"`
	Lease                 Lease           `json:"lease"`
}

type jobLeaseVectors struct {
	PublicRawB64 string           `json:"public_raw_b64"`
	HostID       string           `json:"host_id"`
	NowMS        int64            `json:"now_ms"`
	Vectors      []jobLeaseVector `json:"vectors"`
}

func loadJobLeaseVectors(t *testing.T) (jobLeaseVectors, ed25519.PublicKey) {
	t.Helper()
	blob, err := os.ReadFile(filepath.Join("..", "controlplane", "testdata", "sysscript-job-lease-vectors.json"))
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}
	var v jobLeaseVectors
	if err := json.Unmarshal(blob, &v); err != nil {
		t.Fatalf("parse vectors: %v", err)
	}
	raw, err := base64.StdEncoding.DecodeString(v.PublicRawB64)
	if err != nil || len(raw) != ed25519.PublicKeySize {
		t.Fatalf("public key: %v", err)
	}
	return v, ed25519.PublicKey(raw)
}

// jobPayloadOf builds the payload the agent would verify for a frame with
// these fields, parsing the entitlements as the frame decoder does.
func jobPayloadOf(t *testing.T, jobID string, deadline int64, timeoutS int, script string, ents json.RawMessage) string {
	t.Helper()
	var e *Entitlements
	if err := json.Unmarshal(ents, &e); err != nil {
		t.Fatalf("entitlements: %v", err)
	}
	canon, err := canonicalEntitlements(e)
	if err != nil {
		t.Fatalf("canonical: %v", err)
	}
	p, err := sysscriptJobLeasePayload(jobID, deadline, timeoutS, sha256Hex(script), sha256Hex(canon))
	if err != nil {
		t.Fatalf("payload: %v", err)
	}
	return p
}

func TestSysscriptJobLeaseVectors(t *testing.T) {
	v, pub := loadJobLeaseVectors(t)
	now := time.UnixMilli(v.NowMS)
	if len(v.Vectors) < 3 {
		t.Fatalf("expected 3 vectors, got %d", len(v.Vectors))
	}
	for _, c := range v.Vectors {
		var e *Entitlements
		if err := json.Unmarshal(c.Entitlements, &e); err != nil {
			t.Fatalf("%s: entitlements: %v", c.Name, err)
		}
		canon, err := canonicalEntitlements(e)
		if err != nil {
			t.Fatalf("%s: canonical: %v", c.Name, err)
		}
		if canon != c.CanonicalEntitlements {
			t.Fatalf("%s: canonical text differs:\ngo:   %q\nnode: %q", c.Name, canon, c.CanonicalEntitlements)
		}
		if sha256Hex(canon) != c.EntitlementsSHA256 || sha256Hex(c.Script) != c.ScriptSHA256 {
			t.Fatalf("%s: hash differs", c.Name)
		}
		if p := jobPayloadOf(t, c.JobID, c.DeadlineUnix, c.TimeoutS, c.Script, c.Entitlements); p != c.Payload {
			t.Fatalf("%s: payload %q, want %q", c.Name, p, c.Payload)
		}
		msg := canonicalLease(c.Lease.HostID, c.Lease.Action, c.Lease.ExpiresUnix, c.Lease.NonceHex, c.Lease.PayloadSHA)
		if msg != c.Message {
			t.Fatalf("%s: canonical message mismatch", c.Name)
		}
		if err := verifyLease(pub, &c.Lease, v.HostID, "sysscript_job", c.Payload, now); err != nil {
			t.Fatalf("%s: verifyLease: %v", c.Name, err)
		}
	}
}

// editEnts returns the vector's entitlements with one key replaced.
func editEnts(t *testing.T, raw json.RawMessage, key string, val interface{}) json.RawMessage {
	t.Helper()
	var m map[string]interface{}
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	m[key] = val
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestSysscriptJobLeaseRejectsTamper(t *testing.T) {
	v, pub := loadJobLeaseVectors(t)
	now := time.UnixMilli(v.NowMS)
	c := v.Vectors[0]
	mustFail := func(name string, l Lease, action, payload string, at time.Time, want string) {
		t.Helper()
		err := verifyLease(pub, &l, v.HostID, action, payload, at)
		if err == nil || err.Error() != want {
			t.Fatalf("%s: got %v, want %s", name, err, want)
		}
	}
	p := func(id string, dl int64, to int, script string, ents json.RawMessage) string {
		return jobPayloadOf(t, id, dl, to, script, ents)
	}
	mustFail("deadline", c.Lease, "sysscript_job", p(c.JobID, c.DeadlineUnix+1, c.TimeoutS, c.Script, c.Entitlements), now, "payload_mismatch")
	mustFail("timeout", c.Lease, "sysscript_job", p(c.JobID, c.DeadlineUnix, c.TimeoutS-1, c.Script, c.Entitlements), now, "payload_mismatch")
	script := []byte(c.Script)
	script[0] ^= 1
	mustFail("script byte", c.Lease, "sysscript_job", p(c.JobID, c.DeadlineUnix, c.TimeoutS, string(script), c.Entitlements), now, "payload_mismatch")
	mustFail("job id", c.Lease, "sysscript_job", p("sjb_Q2xhdWRlLXRlc3QtMTIzNQ", c.DeadlineUnix, c.TimeoutS, c.Script, c.Entitlements), now, "payload_mismatch")
	// Only the entitlements change: one list item added, one boolean flipped.
	added := editEnts(t, c.Entitlements, "allow_packages", []string{"nginx", "curl", "nginx", "openssh-server"})
	mustFail("ents item added", c.Lease, "sysscript_job", p(c.JobID, c.DeadlineUnix, c.TimeoutS, c.Script, added), now, "payload_mismatch")
	flipped := editEnts(t, c.Entitlements, "allow_k3s", true)
	mustFail("ents bool flipped", c.Lease, "sysscript_job", p(c.JobID, c.DeadlineUnix, c.TimeoutS, c.Script, flipped), now, "payload_mismatch")
	// The same entitlements in another order or with a dropped item still
	// verify: the canonical form is what is signed.
	same := editEnts(t, c.Entitlements, "allow_packages", []string{"curl", "nginx", "*"})
	if err := verifyLease(pub, &c.Lease, v.HostID, "sysscript_job", p(c.JobID, c.DeadlineUnix, c.TimeoutS, c.Script, same), now); err != nil {
		t.Fatalf("reordered entitlements: %v", err)
	}
	// Action sysscript: a job lease is not a sysscript lease, and relabeling
	// breaks the hash.
	mustFail("as sysscript", c.Lease, "sysscript", c.Payload, now, "bad_action")
	relabeled := c.Lease
	relabeled.Action = "sysscript"
	mustFail("relabeled", relabeled, "sysscript", c.Payload, now, "payload_mismatch")
	// Expired, wrong host, bad signature.
	mustFail("expired", c.Lease, "sysscript_job", c.Payload, now.Add(200*time.Second), "expired")
	other := c.Lease
	other.HostID = "22222222-2222-4222-8222-222222222222"
	mustFail("host", other, "sysscript_job", c.Payload, now, "bad_host")
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	if err := verifyLease(otherPub, &c.Lease, v.HostID, "sysscript_job", c.Payload, now); err == nil || err.Error() != "bad_signature" {
		t.Fatalf("wrong key: %v", err)
	}
	// Replayed nonce.
	clearIdentity()
	t.Cleanup(clearIdentity)
	if err := pinControlPublicKey(v.PublicRawB64, v.HostID); err != nil {
		t.Fatal(err)
	}
	if err := authorizeCommand(v.HostID, "sysscript_job", c.Payload, &c.Lease, now); err != nil {
		t.Fatalf("first use: %v", err)
	}
	if err := authorizeCommand(v.HostID, "sysscript_job", c.Payload, &c.Lease, now); err == nil || err.Error() != "replay" {
		t.Fatalf("replay: %v", err)
	}
}

// The existing sysscript lease is unchanged: its payload is the raw script.
func TestSysscriptLeaseUnchangedBySysscriptJob(t *testing.T) {
	if payloadFor("sysscript", "print(1)\n") != "print(1)\n" {
		t.Fatal("sysscript payload changed")
	}
	if payloadFor("sysscript_job", "x") != "sysscript_job\nx" {
		t.Fatal("sysscript_job payload is not action-bound")
	}
}

func TestCanonicalEntitlementsRefuses(t *testing.T) {
	if _, err := canonicalEntitlements(&Entitlements{AllowFSRead: []string{"/a\n/b"}}); err == nil || err.Error() != "bad_entitlements" {
		t.Fatalf("newline item: %v", err)
	}
	if _, err := canonicalEntitlements(&Entitlements{AllowConfigWrite: []string{"/a\r"}}); err == nil {
		t.Fatal("carriage return item accepted")
	}
	long := make([]string, canonicalListMax+1)
	for i := range long {
		long[i] = "/p" + strings.Repeat("x", i)
	}
	if _, err := canonicalEntitlements(&Entitlements{AllowFSWrite: long}); err == nil {
		t.Fatal("65 items accepted")
	}
	if _, err := canonicalEntitlements(&Entitlements{AllowFSWrite: long[:canonicalListMax]}); err != nil {
		t.Fatalf("64 items refused: %v", err)
	}
	nilText, err := canonicalEntitlements(nil)
	if err != nil {
		t.Fatal(err)
	}
	zeroText, _ := canonicalEntitlements(&Entitlements{})
	if nilText != zeroText || !strings.HasPrefix(nilText, entitlementsPrefix) {
		t.Fatalf("nil entitlements %q", nilText)
	}
}

func TestSysscriptJobLeasePayloadRefusesBadFields(t *testing.T) {
	h := strings.Repeat("a", 64)
	id := "sjb_AAAAAAAAAAAAAAAAAAAAAA"
	for _, c := range []struct {
		name     string
		id       string
		deadline int64
		timeout  int
		s, e     string
		want     string
	}{
		{"short id", "sjb_AAAA", 1, 1, h, h, "bad_job_id"},
		{"newline id", id + "\n", 1, 1, h, h, "bad_job_id"},
		{"zero deadline", id, 0, 1, h, h, "bad_deadline"},
		{"zero timeout", id, 1, 0, h, h, "bad_deadline"},
		{"timeout over cap", id, 1, sysscriptJobTimeoutMax + 1, h, h, "bad_deadline"},
		{"script hash", id, 1, 1, "A" + h[1:], h, "bad_payload"},
		{"ents hash", id, 1, 1, h, h[1:], "bad_payload"},
	} {
		if _, err := sysscriptJobLeasePayload(c.id, c.deadline, c.timeout, c.s, c.e); err == nil || err.Error() != c.want {
			t.Fatalf("%s: %v, want %s", c.name, err, c.want)
		}
	}
}
