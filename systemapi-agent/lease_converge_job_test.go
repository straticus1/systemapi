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

type convergeLeaseVector struct {
	Name                  string          `json:"name"`
	JobID                 string          `json:"job_id"`
	DeadlineUnix          int64           `json:"deadline_unix"`
	TimeoutS              int             `json:"timeout_s"`
	BundleJSON            string          `json:"bundle_json"`
	Entitlements          json.RawMessage `json:"entitlements"`
	Mode                  string          `json:"mode"`
	ExpectPlan            string          `json:"expect_plan_sha256"`
	CanonicalEntitlements string          `json:"canonical_entitlements"`
	EntitlementsSHA256    string          `json:"entitlements_sha256"`
	BundleSHA256          string          `json:"bundle_sha256"`
	Payload               string          `json:"payload"`
	Message               string          `json:"message"`
	Lease                 Lease           `json:"lease"`
}

type convergeLeaseVectors struct {
	PublicRawB64 string                `json:"public_raw_b64"`
	HostID       string                `json:"host_id"`
	NowMS        int64                 `json:"now_ms"`
	Vectors      []convergeLeaseVector `json:"vectors"`
}

func loadConvergeLeaseVectors(t *testing.T) (convergeLeaseVectors, ed25519.PublicKey) {
	t.Helper()
	blob, err := os.ReadFile(filepath.Join("..", "controlplane", "testdata", "converge-job-lease-vectors.json"))
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}
	var v convergeLeaseVectors
	if err := json.Unmarshal(blob, &v); err != nil {
		t.Fatalf("parse vectors: %v", err)
	}
	raw, err := base64.StdEncoding.DecodeString(v.PublicRawB64)
	if err != nil || len(raw) != ed25519.PublicKeySize {
		t.Fatalf("public key: %v", err)
	}
	return v, ed25519.PublicKey(raw)
}

// convergePayloadOf builds the payload the agent would verify for a frame
// with these fields, parsing the entitlements as the frame decoder does.
func convergePayloadOf(t *testing.T, c convergeLeaseVector) string {
	t.Helper()
	var e *Entitlements
	if err := json.Unmarshal(c.Entitlements, &e); err != nil {
		t.Fatalf("entitlements: %v", err)
	}
	canon, err := canonicalEntitlements(e)
	if err != nil {
		t.Fatalf("canonical: %v", err)
	}
	p, err := convergeJobLeasePayload(c.JobID, c.DeadlineUnix, c.TimeoutS, sha256Hex(c.BundleJSON), sha256Hex(canon), c.Mode, c.ExpectPlan)
	if err != nil {
		t.Fatalf("payload: %v", err)
	}
	return p
}

// Go and Node agree on every converge_job vector: canonical entitlements,
// hashes, the 7-line payload, the canonical message and the signature.
func TestConvergeJobLeaseVectors(t *testing.T) {
	v, pub := loadConvergeLeaseVectors(t)
	now := time.UnixMilli(v.NowMS)
	if len(v.Vectors) < 3 {
		t.Fatalf("expected 3 vectors, got %d", len(v.Vectors))
	}
	modes := map[string]bool{}
	for _, c := range v.Vectors {
		modes[c.Mode] = true
		var e *Entitlements
		if err := json.Unmarshal(c.Entitlements, &e); err != nil {
			t.Fatalf("%s: entitlements: %v", c.Name, err)
		}
		canon, err := canonicalEntitlements(e)
		if err != nil {
			t.Fatalf("%s: canonical: %v", c.Name, err)
		}
		if canon != c.CanonicalEntitlements || sha256Hex(canon) != c.EntitlementsSHA256 || sha256Hex(c.BundleJSON) != c.BundleSHA256 {
			t.Fatalf("%s: canonical text or hash differs", c.Name)
		}
		p := convergePayloadOf(t, c)
		if p != c.Payload || strings.Count(p, "\n") != 6 || strings.HasSuffix(p, "\n") {
			t.Fatalf("%s: payload %q, want %q", c.Name, p, c.Payload)
		}
		if msg := canonicalLease(c.Lease.HostID, c.Lease.Action, c.Lease.ExpiresUnix, c.Lease.NonceHex, c.Lease.PayloadSHA); msg != c.Message {
			t.Fatalf("%s: canonical message mismatch", c.Name)
		}
		if err := verifyLease(pub, &c.Lease, v.HostID, "converge_job", c.Payload, now); err != nil {
			t.Fatalf("%s: verifyLease: %v", c.Name, err)
		}
	}
	if !modes["check"] || !modes["apply"] {
		t.Fatalf("vectors must cover check and apply: %v", modes)
	}
}

// AC 2: any single changed field of a converge_job payload is
// payload_mismatch, and the lease is bound to its action both ways.
func TestConvergeJobLeaseRejectsSingleFieldSwap(t *testing.T) {
	v, pub := loadConvergeLeaseVectors(t)
	now := time.UnixMilli(v.NowMS)
	var check, apply convergeLeaseVector
	for _, c := range v.Vectors {
		if c.Mode == "check" && check.Name == "" {
			check = c
		}
		if c.Mode == "apply" && apply.Name == "" {
			apply = c
		}
	}
	mustFail := func(name string, l Lease, action, payload, want string) {
		t.Helper()
		err := verifyLease(pub, &l, v.HostID, action, payload, now)
		if err == nil || err.Error() != want {
			t.Fatalf("%s: got %v, want %s", name, err, want)
		}
	}
	for _, base := range []convergeLeaseVector{check, apply} {
		swap := func(name string, edit func(c *convergeLeaseVector)) {
			t.Helper()
			c := base
			edit(&c)
			mustFail(base.Name+": "+name, base.Lease, "converge_job", convergePayloadOf(t, c), "payload_mismatch")
		}
		swap("job id", func(c *convergeLeaseVector) { c.JobID = "sjb_Q29udmVyZ2UtY2hlY2stMg" })
		swap("deadline", func(c *convergeLeaseVector) { c.DeadlineUnix++ })
		swap("timeout", func(c *convergeLeaseVector) { c.TimeoutS-- })
		swap("bundle byte", func(c *convergeLeaseVector) { c.BundleJSON = strings.Replace(c.BundleJSON, "web", "wec", 1) })
		swap("entitlements", func(c *convergeLeaseVector) {
			c.Entitlements = editEnts(t, c.Entitlements, "allow_k3s", true)
		})
		if base.Mode == "check" {
			swap("mode check->apply", func(c *convergeLeaseVector) { c.Mode, c.ExpectPlan = "apply", strings.Repeat("a", 64) })
		} else {
			swap("plan hash", func(c *convergeLeaseVector) { c.ExpectPlan = strings.Repeat("0", 64) })
			swap("mode apply->check", func(c *convergeLeaseVector) { c.Mode, c.ExpectPlan = "check", "-" })
		}
	}
	// A converge_job lease is not a sysscript_job lease, and relabeling the
	// action breaks the hash.
	mustFail("as sysscript_job", check.Lease, "sysscript_job", check.Payload, "bad_action")
	relabeled := check.Lease
	relabeled.Action = "sysscript_job"
	mustFail("relabeled as sysscript_job", relabeled, "sysscript_job", check.Payload, "payload_mismatch")
	// A sysscript_job lease cannot start a converge job.
	jv, jpub := loadJobLeaseVectors(t)
	j := jv.Vectors[0]
	if err := verifyLease(jpub, &j.Lease, jv.HostID, "converge_job", j.Payload, now); err == nil || err.Error() != "bad_action" {
		t.Fatalf("sysscript_job lease as converge_job: %v", err)
	}
	jr := j.Lease
	jr.Action = "converge_job"
	if err := verifyLease(jpub, &jr, jv.HostID, "converge_job", j.Payload, now); err == nil || err.Error() != "payload_mismatch" {
		t.Fatalf("sysscript_job lease relabeled converge_job: %v", err)
	}
	// Expired, wrong host, wrong key.
	if err := verifyLease(pub, &check.Lease, v.HostID, "converge_job", check.Payload, now.Add(200*time.Second)); err == nil || err.Error() != "expired" {
		t.Fatalf("expired: %v", err)
	}
	other := check.Lease
	other.HostID = "22222222-2222-4222-8222-222222222222"
	mustFail("host", other, "converge_job", check.Payload, "bad_host")
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	if err := verifyLease(otherPub, &check.Lease, v.HostID, "converge_job", check.Payload, now); err == nil || err.Error() != "bad_signature" {
		t.Fatalf("wrong key: %v", err)
	}
}

func TestConvergeJobLeasePayloadRefusesBadFields(t *testing.T) {
	h := strings.Repeat("a", 64)
	id := "sjb_AAAAAAAAAAAAAAAAAAAAAA"
	for _, c := range []struct {
		name, id, b, e, mode, plan, want string
	}{
		{"bad id", "sjb_x", h, h, "check", "-", "bad_job_id"},
		{"bundle hash", id, h[1:], h, "check", "-", "bad_payload"},
		{"check with plan", id, h, h, "check", h, "bad_mode"},
		{"apply without plan", id, h, h, "apply", "-", "bad_mode"},
		{"apply upper hex", id, h, h, "apply", strings.ToUpper(h), "bad_mode"},
		{"unknown mode", id, h, h, "verify", "-", "bad_mode"},
		{"newline mode", id, h, h, "check\n", "-", "bad_mode"},
		{"empty plan", id, h, h, "check", "", "bad_mode"},
	} {
		if _, err := convergeJobLeasePayload(c.id, 1, 1, c.b, c.e, c.mode, c.plan); err == nil || err.Error() != c.want {
			t.Fatalf("%s: %v, want %s", c.name, err, c.want)
		}
	}
	if payloadFor("converge_job", "x") != "converge_job\nx" || !knownAction("converge_job") {
		t.Fatal("converge_job payload is not action-bound")
	}
}
