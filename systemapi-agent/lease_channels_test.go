package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type channelVectors struct {
	PublicRawB64 string `json:"public_raw_b64"`
	HostID       string `json:"host_id"`
	NowMS        int64  `json:"now_ms"`
	Vectors      []struct {
		Action  string `json:"action"`
		Payload string `json:"payload"`
		Message string `json:"message"`
		Lease   Lease  `json:"lease"`
	} `json:"vectors"`
}

func loadChannelVectors(t *testing.T) (channelVectors, ed25519.PublicKey) {
	t.Helper()
	blob, err := os.ReadFile(filepath.Join("..", "controlplane", "testdata", "channel-lease-vectors.json"))
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}
	var v channelVectors
	if err := json.Unmarshal(blob, &v); err != nil {
		t.Fatalf("parse vectors: %v", err)
	}
	raw, err := base64.StdEncoding.DecodeString(v.PublicRawB64)
	if err != nil || len(raw) != ed25519.PublicKeySize {
		t.Fatalf("public key: %v", err)
	}
	return v, ed25519.PublicKey(raw)
}

func TestChannelLeaseVectorsVerify(t *testing.T) {
	v, pub := loadChannelVectors(t)
	now := time.UnixMilli(v.NowMS)
	if len(v.Vectors) < 5 {
		t.Fatalf("expected 5 vectors, got %d", len(v.Vectors))
	}
	for _, c := range v.Vectors {
		msg := canonicalLease(c.Lease.HostID, c.Lease.Action, c.Lease.ExpiresUnix, c.Lease.NonceHex, c.Lease.PayloadSHA)
		if msg != c.Message {
			t.Fatalf("%s: canonical message mismatch", c.Action)
		}
		if err := verifyLease(pub, &c.Lease, v.HostID, c.Action, c.Payload, now); err != nil {
			t.Fatalf("%s: verifyLease: %v", c.Action, err)
		}
	}
	// The Go builders produce the exact payload strings the server signed.
	tcp, err := tcpLeasePayload("tcs_AAAAAAAAAAAAAAAA_-", 1700028800, "start", "10.0.0.7", 3389)
	if err != nil || tcp != v.Vectors[0].Payload {
		t.Fatalf("tcp payload %q %v", tcp, err)
	}
	f, err := fileLeasePayload("fls_BBBBBBBBBBBBBBBB", 1700028800, "start", "read", "/srv/app")
	if err != nil || f != v.Vectors[2].Payload {
		t.Fatalf("file payload %q %v", f, err)
	}
}

func TestChannelLeaseRejectsTamper(t *testing.T) {
	v, pub := loadChannelVectors(t)
	now := time.UnixMilli(v.NowMS)
	tcp := v.Vectors[0]
	file := v.Vectors[2]
	root := v.Vectors[4]
	mustFail := func(name string, l Lease, action, payload string, at time.Time, key ed25519.PublicKey, want string) {
		t.Helper()
		err := verifyLease(key, &l, v.HostID, action, payload, at)
		if err == nil || err.Error() != want {
			t.Fatalf("%s: got %v, want %s", name, err, want)
		}
	}
	p := func(s string, err error) string {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	// Tampered target, port, phase.
	mustFail("target", tcp.Lease, "tcp", p(tcpLeasePayload("tcs_AAAAAAAAAAAAAAAA_-", 1700028800, "start", "10.0.0.8", 3389)), now, pub, "payload_mismatch")
	mustFail("port", tcp.Lease, "tcp", p(tcpLeasePayload("tcs_AAAAAAAAAAAAAAAA_-", 1700028800, "start", "10.0.0.7", 3390)), now, pub, "payload_mismatch")
	mustFail("phase", tcp.Lease, "tcp", p(tcpLeasePayload("tcs_AAAAAAAAAAAAAAAA_-", 1700028800, "renew", "10.0.0.7", 3389)), now, pub, "payload_mismatch")
	// Tampered root and mode.
	mustFail("root", file.Lease, "file", p(fileLeasePayload("fls_BBBBBBBBBBBBBBBB", 1700028800, "start", "read", "/srv/other")), now, pub, "payload_mismatch")
	mustFail("mode", file.Lease, "file", p(fileLeasePayload("fls_BBBBBBBBBBBBBBBB", 1700028800, "start", "write", "/srv/app")), now, pub, "payload_mismatch")
	// Wrong action: a file lease is not a file_root lease, a tcp lease not a pty lease.
	mustFail("file as file_root", file.Lease, "file_root", file.Payload, now, pub, "bad_action")
	mustFail("file_root as file", root.Lease, "file", root.Payload, now, pub, "bad_action")
	relabeled := file.Lease
	relabeled.Action = "file_root"
	mustFail("relabeled", relabeled, "file_root", file.Payload, now, pub, "payload_mismatch")
	mustFail("tcp as pty", tcp.Lease, "pty", tcp.Payload, now, pub, "bad_action")
	// Expired.
	mustFail("expired", tcp.Lease, "tcp", tcp.Payload, now.Add(200*time.Second), pub, "expired")
	// Wrong key.
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	mustFail("wrong key", tcp.Lease, "tcp", tcp.Payload, now, otherPub, "bad_signature")
	// Tampered signature.
	bad := tcp.Lease
	bad.Signature = base64.StdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))
	mustFail("signature", bad, "tcp", tcp.Payload, now, pub, "bad_signature")
}

func TestChannelLeasePayloadBuildersRefuseBadFields(t *testing.T) {
	sid := "tcs_AAAAAAAAAAAAAAAA"
	fid := "fls_AAAAAAAAAAAAAAAA"
	for _, c := range []struct {
		name string
		err  error
	}{
		{"short id", second(tcpLeasePayload("tcs_short", 1, "start", "local", 22))},
		{"pty id", second(tcpLeasePayload("pty_AAAAAAAAAAAAAAAA", 1, "start", "local", 22))},
		{"file id on tcp", second(tcpLeasePayload(fid, 1, "start", "local", 22))},
		{"newline host", second(tcpLeasePayload(sid, 1, "start", "local\n9", 22))},
		{"dns host", second(tcpLeasePayload(sid, 1, "start", "db.internal", 22))},
		{"port 0", second(tcpLeasePayload(sid, 1, "start", "local", 0))},
		{"port high", second(tcpLeasePayload(sid, 1, "start", "local", 65536))},
		{"phase", second(tcpLeasePayload(sid, 1, "begin", "local", 22))},
		{"deadline", second(tcpLeasePayload(sid, 0, "start", "local", 22))},
		{"tcp id on file", second(fileLeasePayload(sid, 1, "start", "read", "/srv"))},
		{"mode", second(fileLeasePayload(fid, 1, "start", "root", "/srv"))},
		{"relative root", second(fileLeasePayload(fid, 1, "start", "read", "srv"))},
		{"newline root", second(fileLeasePayload(fid, 1, "start", "read", "/srv\nwrite"))},
		{"empty root", second(fileLeasePayload(fid, 1, "start", "read", ""))},
	} {
		if c.err == nil {
			t.Fatalf("%s: accepted", c.name)
		}
	}
}

func second(_ string, err error) error { return err }
