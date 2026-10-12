package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type leaseVector struct {
	PublicRawB64 string `json:"public_raw_b64"`
	HostID       string `json:"host_id"`
	Action       string `json:"action"`
	Payload      string `json:"payload"`
	NowMS        int64  `json:"now_ms"`
	Message      string `json:"message"`
	Lease        Lease  `json:"lease"`
}

func loadVector(t *testing.T) leaseVector {
	t.Helper()
	blob, err := os.ReadFile(filepath.Join("..", "controlplane", "testdata", "lease-vector.json"))
	if err != nil {
		t.Fatalf("read vector: %v", err)
	}
	var v leaseVector
	if err := json.Unmarshal(blob, &v); err != nil {
		t.Fatalf("parse vector: %v", err)
	}
	return v
}

func vectorPub(t *testing.T, v leaseVector) ed25519.PublicKey {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(v.PublicRawB64)
	if err != nil || len(raw) != ed25519.PublicKeySize {
		t.Fatalf("public key: %v len=%d", err, len(raw))
	}
	return ed25519.PublicKey(raw)
}

func TestLeaseVectorVerifies(t *testing.T) {
	v := loadVector(t)
	pub := vectorPub(t, v)
	sig, err := base64.StdEncoding.DecodeString(v.Lease.Signature)
	if err != nil || len(sig) != ed25519.SignatureSize {
		t.Fatalf("signature: %v", err)
	}
	msg := canonicalLease(v.Lease.HostID, v.Lease.Action, v.Lease.ExpiresUnix, v.Lease.NonceHex, v.Lease.PayloadSHA)
	if msg != v.Message {
		t.Fatalf("canonical message mismatch")
	}
	if !ed25519.Verify(pub, []byte(msg), sig) {
		t.Fatal("vector signature rejected")
	}
	now := time.UnixMilli(v.NowMS)
	if err := verifyLease(pub, &v.Lease, v.HostID, v.Action, v.Payload, now); err != nil {
		t.Fatalf("verifyLease: %v", err)
	}
}

func TestLeaseRejectsTamper(t *testing.T) {
	v := loadVector(t)
	pub := vectorPub(t, v)
	now := time.UnixMilli(v.NowMS)

	tampered := v.Lease
	tampered.Signature = base64.StdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))
	if err := verifyLease(pub, &tampered, v.HostID, v.Action, v.Payload, now); err == nil || err.Error() != "bad_signature" {
		t.Fatalf("tampered signature: %v", err)
	}

	otherHost := v.Lease
	otherHost.HostID = "22222222-2222-4222-8222-222222222222"
	if err := verifyLease(pub, &otherHost, v.HostID, v.Action, v.Payload, now); err == nil || err.Error() != "bad_host" {
		t.Fatalf("wrong host: %v", err)
	}

	mismatch := v.Lease
	if err := verifyLease(pub, &mismatch, v.HostID, v.Action, "print(2)\n", now); err == nil || err.Error() != "payload_mismatch" {
		t.Fatalf("payload: %v", err)
	}

	expired := v.Lease
	late := time.Unix(v.Lease.ExpiresUnix, 0).Add(31 * time.Second)
	if err := verifyLease(pub, &expired, v.HostID, v.Action, v.Payload, late); err == nil || err.Error() != "expired" {
		t.Fatalf("expired: %v", err)
	}

	far := v.Lease
	early := time.Unix(v.Lease.ExpiresUnix, 0).Add(-301 * time.Second)
	if err := verifyLease(pub, &far, v.HostID, v.Action, v.Payload, early); err == nil || err.Error() != "expiry_too_far" {
		t.Fatalf("far: %v", err)
	}

	if err := verifyLease(pub, nil, v.HostID, v.Action, v.Payload, now); err == nil || err.Error() != "malformed" {
		t.Fatalf("nil lease: %v", err)
	}
}

func TestLeaseNonceReplay(t *testing.T) {
	v := loadVector(t)
	now := time.UnixMilli(v.NowMS)
	clearIdentity()
	t.Cleanup(clearIdentity)
	if err := pinControlPublicKey(v.PublicRawB64, v.HostID); err != nil {
		t.Fatal(err)
	}
	if err := authorizeCommand(v.HostID, v.Action, v.Payload, &v.Lease, now); err != nil {
		t.Fatal(err)
	}
	if err := authorizeCommand(v.HostID, v.Action, v.Payload, &v.Lease, now); err == nil || err.Error() != "replay" {
		t.Fatalf("replay: %v", err)
	}
}

func TestAuthorizeBeforeEnroll(t *testing.T) {
	clearIdentity()
	t.Cleanup(clearIdentity)
	v := loadVector(t)
	err := authorizeCommand(v.HostID, v.Action, v.Payload, &v.Lease, time.UnixMilli(v.NowMS))
	if err == nil || err.Error() != "not_enrolled" {
		t.Fatalf("got %v", err)
	}
}

func TestControlKeyIsPinnedOnce(t *testing.T) {
	clearIdentity()
	t.Cleanup(clearIdentity)
	v := loadVector(t)
	if err := pinControlPublicKey(v.PublicRawB64, v.HostID); err != nil {
		t.Fatal(err)
	}
	if err := pinControlPublicKey(v.PublicRawB64, v.HostID); err != nil {
		t.Fatal(err)
	}
	other := base64.StdEncoding.EncodeToString(make([]byte, ed25519.PublicKeySize))
	if err := pinControlPublicKey(other, v.HostID); err == nil || err.Error() != "control_pubkey_changed" {
		t.Fatalf("got %v", err)
	}
}

func TestSSHPublicKeyWire(t *testing.T) {
	seed := strings.Repeat("11", 32)
	line, err := sshEd25519PublicLine(seed)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(line, "ssh-ed25519 ") {
		t.Fatalf("prefix: %s", line)
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(line, "ssh-ed25519 "))
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) != 51 {
		t.Fatalf("wire len %d", len(raw))
	}
	if string(raw[4:15]) != "ssh-ed25519" {
		t.Fatal("name")
	}
}

func TestStateFileModeAndTenant(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agent.json")
	st, err := loadOrCreateState(path, "acme")
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode %o", info.Mode().Perm())
	}
	if err := validateHostID(st.HostID); err != nil {
		t.Fatal(err)
	}
	if _, err := loadOrCreateState(path, "other"); err == nil {
		t.Fatal("expected tenant mismatch")
	}
	again, err := loadOrCreateState(path, "acme")
	if err != nil {
		t.Fatal(err)
	}
	if again.HostID != st.HostID || again.Ed25519Seed != st.Ed25519Seed {
		t.Fatal("identity was not persisted")
	}
}

func TestStripChildEnv(t *testing.T) {
	out := stripChildEnv([]string{
		"PATH=/bin",
		"SYSTEMAPI_API_KEY=secret",
		"ADSTELCO_KEY=secret",
		"OTHER_API_KEY=secret",
		"HOME=/tmp",
	}, []string{"TERM=xterm-256color"})
	joined := strings.Join(out, "\n")
	if strings.Contains(joined, "secret") || strings.Contains(joined, "SYSTEMAPI") || strings.Contains(joined, "ADSTELCO") || strings.Contains(joined, "API_KEY") {
		t.Fatalf("leaked: %s", joined)
	}
	if !strings.Contains(joined, "PATH=/bin") || !strings.Contains(joined, "TERM=xterm-256color") {
		t.Fatalf("dropped safe env: %s", joined)
	}
}

func TestRefuseAPIKeyURL(t *testing.T) {
	if err := refuseAPIKeyURL("ws://127.0.0.1:3003/api/v1/systems/stream"); err != nil {
		t.Fatal(err)
	}
	if err := refuseAPIKeyURL("ws://127.0.0.1:3003/api/v1/systems/stream?api_key=abc"); err == nil {
		t.Fatal("accepted api_key url")
	}
}

func TestEntitlementsBoolGrantsNoPaths(t *testing.T) {
	var cmd CommandMessage
	raw := []byte(`{"type":"sysscript","script":"print(1)\n","request_id":"r","entitlements":{"allow_exec":true,"allow_fs_write":true,"allow_fs_read":false,"allow_net_outbound":false,"allow_containers":false,"allow_k3s":false}}`)
	if err := json.Unmarshal(raw, &cmd); err != nil {
		t.Fatal(err)
	}
	if cmd.Entitlements == nil || !cmd.Entitlements.AllowExec {
		t.Fatal("allow_exec")
	}
	if cmd.Entitlements.AllowFSWrite != nil || cmd.Entitlements.AllowFSRead != nil {
		t.Fatal("bool must not grant paths")
	}
	var listed Entitlements
	if err := json.Unmarshal([]byte(`{"allow_fs_read":["/etc"],"allow_exec":false}`), &listed); err != nil {
		t.Fatal(err)
	}
	if len(listed.AllowFSRead) != 1 || listed.AllowFSRead[0] != "/etc" || listed.AllowExec {
		t.Fatalf("%+v", listed)
	}
}

func TestBreakglassDoesNotPassRestricted(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "adssh")
	if err := os.WriteFile(path, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	name, args, err := breakglassCommand()
	if err != nil {
		t.Fatal(err)
	}
	if name != path {
		t.Fatalf("name %s", name)
	}
	for _, a := range args {
		if a == "-r" {
			t.Fatal("restricted flag must not be passed")
		}
	}
}

func TestBreakglassMissingRefuses(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	if _, _, err := breakglassCommand(); err == nil || !strings.Contains(err.Error(), "adssh_missing") {
		t.Fatalf("got %v", err)
	}
}
