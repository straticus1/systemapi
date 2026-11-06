package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func sashTestKeys(fill byte) (ed25519.PrivateKey, ed25519.PublicKey) {
	priv := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{fill}, ed25519.SeedSize))
	return priv, priv.Public().(ed25519.PublicKey)
}

func sashSample(purpose string, exp int64) sashGrant {
	return sashGrant{
		V:            "sash/1",
		Actor:        "alice",
		Host:         "host-1",
		Purpose:      purpose,
		Exp:          exp,
		LeaseID:      "lease-1",
		Entitlements: []string{"ps"},
		FileRead:     []string{"/var/log"},
		FileWrite:    []string{},
	}
}

func sashSign(t *testing.T, g sashGrant, priv ed25519.PrivateKey) []byte {
	t.Helper()
	doc, err := signSashGrant(g, priv)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return doc
}

func TestSashGrantRejectsTamperAndLifetime(t *testing.T) {
	fleet, fleetPub := sashTestKeys(0x22)
	_, emerPub := sashTestKeys(0x33)
	now := time.Unix(1_700_000_000, 0)

	doc := sashSign(t, sashSample(sashPurposeOpen, now.Unix()+3600), fleet)
	tampered := append([]byte(nil), doc...)
	needle := []byte(`"actor":"alice"`)
	at := bytes.Index(tampered, needle)
	if at < 0 {
		t.Fatal("actor field missing")
	}
	tampered[at+len(`"actor":"`)] = 'b'
	if _, err := verifySashGrant(tampered, fleetPub, emerPub, now); sashStatusCode(err) != "grant_bad_sig" {
		t.Fatalf("tamper: %v", err)
	}

	expired := sashSign(t, sashSample(sashPurposeOpen, now.Unix()-1), fleet)
	if _, err := verifySashGrant(expired, fleetPub, emerPub, now); sashStatusCode(err) != "grant_expired" {
		t.Fatalf("expired: %v", err)
	}
	edge := sashSign(t, sashSample(sashPurposeOpen, now.Unix()), fleet)
	if _, err := verifySashGrant(edge, fleetPub, emerPub, now); err != nil {
		t.Fatalf("exp == now: %v", err)
	}

	star := sashSample(sashPurposeOpen, now.Unix()+3600)
	star.Entitlements = []string{"*"}
	starDoc := sashSign(t, star, fleet)
	if _, err := verifySashGrant(starDoc, fleetPub, emerPub, now); sashStatusCode(err) != "grant_star" {
		t.Fatalf("star: %v", err)
	}

	if _, err := verifySashGrant(doc, fleetPub, fleetPub, now); sashStatusCode(err) != "grant_bad_sig" {
		t.Fatalf("identical pubs: %v", err)
	}
	if _, err := verifySashGrant(nil, fleetPub, emerPub, now); sashStatusCode(err) != "grant_missing" {
		t.Fatalf("empty: %v", err)
	}
	if _, err := verifySashGrant(bytes.Repeat([]byte{'a'}, sashMaxDocument+1), fleetPub, emerPub, now); sashStatusCode(err) != "grant_bad_shape" {
		t.Fatalf("oversize: %v", err)
	}
}

func TestSashGrantRejectsLeaseDomainAndEmergencyKey(t *testing.T) {
	fleet, fleetPub := sashTestKeys(0x22)
	emer, emerPub := sashTestKeys(0x33)
	now := time.Unix(1_700_000_000, 0)
	g := sashSample(sashPurposeOpen, now.Unix()+3600)

	msg, err := sashMessage(g)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(msg, []byte(sashDomain)) {
		t.Fatal("domain")
	}
	leaseMsg := append([]byte("systemapi-lease-v1\n"), msg[len(sashDomain):]...)
	raw := sashSign(t, g, fleet)
	var wire sashGrantWire
	if err := json.Unmarshal(raw, &wire); err != nil {
		t.Fatal(err)
	}
	wire.Sig = base64.StdEncoding.EncodeToString(ed25519.Sign(fleet, leaseMsg))
	swapped, err := json.Marshal(wire)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifySashGrant(swapped, fleetPub, emerPub, now); sashStatusCode(err) != "grant_bad_sig" {
		t.Fatalf("lease prefix: %v", err)
	}

	em := sashSample(sashPurposeEmergency, now.Unix()+3600)
	good := sashSign(t, em, emer)
	if _, err := verifySashGrant(good, fleetPub, emerPub, now); err != nil {
		t.Fatalf("emergency key: %v", err)
	}
	wrong := sashSign(t, em, fleet)
	if _, err := verifySashGrant(wrong, fleetPub, emerPub, now); sashStatusCode(err) != "grant_bad_sig" {
		t.Fatalf("fleet key on emergency: %v", err)
	}
}

func TestSashGrantBindPurposeBeforeBinding(t *testing.T) {
	fleet, fleetPub := sashTestKeys(0x22)
	emer, emerPub := sashTestKeys(0x33)
	now := time.Unix(1_700_000_000, 0)
	open := sashSign(t, sashSample(sashPurposeOpen, now.Unix()+3600), fleet)
	em := sashSign(t, sashSample(sashPurposeEmergency, now.Unix()+3600), emer)

	bind := func(doc []byte, action, host, actor, lease string) error {
		_, err := bindSashGrant(doc, fleetPub, emerPub, sashBind{
			Action: action, Host: host, Actor: actor, LeaseID: lease, Now: now,
		})
		return err
	}
	if err := bind(em, "pty", "host-1", "alice", "lease-1"); sashStatusCode(err) != "grant_purpose" {
		t.Fatalf("emergency purpose: %v", err)
	}
	if err := bind(em, "pty", "other-host", "other-actor", "lease-1"); sashStatusCode(err) != "grant_purpose" {
		t.Fatalf("purpose and host: %v", err)
	}
	if err := bind(open, "pty", "other-host", "alice", "lease-1"); sashStatusCode(err) != "grant_binding" {
		t.Fatalf("host: %v", err)
	}
	if err := bind(open, "pty", "host-1", "bob", "lease-1"); sashStatusCode(err) != "grant_binding" {
		t.Fatalf("actor: %v", err)
	}
	if err := bind(open, "pty", "", "alice", "lease-1"); sashStatusCode(err) != "grant_binding" {
		t.Fatalf("empty host: %v", err)
	}
	if err := bind(open, "pty", "host-1", "alice", "lease-1"); err != nil {
		t.Fatalf("match: %v", err)
	}
}

func TestReadSashPubRejectsShortFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "pub")
	if err := os.WriteFile(path, bytes.Repeat([]byte{1}, ed25519.PublicKeySize-1), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readSashPub(path); sashStatusCode(err) != "grant_bad_sig" {
		t.Fatalf("short: %v", err)
	}
	if _, err := readSashPub(""); sashStatusCode(err) != "grant_bad_sig" {
		t.Fatalf("empty path: %v", err)
	}
}

func TestSashGrantNodeInterop(t *testing.T) {
	if _, err := exec.LookPath("node"); err != nil {
		t.Skip("node missing")
	}
	exp := time.Now().Add(time.Hour).Unix()
	input := map[string]any{
		"seed":     strings.Repeat("22", 32),
		"actor":    "alice",
		"host":     "host-1",
		"purpose":  "terminal:open",
		"exp":      exp,
		"lease_id": "lease-1",
		"policies": map[string]any{
			"service": map[string]any{"units": []any{"nginx", "*"}},
			"package": map[string]any{"names": []any{"curl"}},
			"config":  map[string]any{"paths": []any{"/etc/ssh/sshd_config", "/"}},
			"tweak":   map[string]any{"sysctls": []any{"net.ipv4.ip_forward", "kernel.core_pattern"}},
			"file": map[string]any{"roots": []any{
				map[string]any{"path": "/var/log", "read": true},
				map[string]any{"path": "/tmp", "read": false, "write": true},
				map[string]any{"path": "~", "read": true},
				map[string]any{"path": "/var/log/../log", "read": true},
			}},
		},
	}
	raw, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("node", "../controlplane/sashgrant.js")
	cmd.Stdin = bytes.NewReader(raw)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("node: %v stderr=%s", err, stderr.String())
	}
	if bytes.Contains(stdout.Bytes(), []byte("\n")) {
		t.Fatal("trailing newline")
	}
	_, fleetPub := sashTestKeys(0x22)
	_, emerPub := sashTestKeys(0x33)
	g, err := verifySashGrant(stdout.Bytes(), fleetPub, emerPub, time.Now())
	if err != nil {
		t.Fatalf("verify node grant: %v", err)
	}
	wantEnt := []string{"ps", "unit.status", "package.query", "sysctl.get", "config.read", "file.read"}
	if strings.Join(g.Entitlements, ",") != strings.Join(wantEnt, ",") {
		t.Fatalf("entitlements %v", g.Entitlements)
	}
	if strings.Join(g.FileRead, ",") != "/var/log" {
		t.Fatalf("file_read %v", g.FileRead)
	}
	if len(g.FileWrite) != 0 || g.AllowPrivate {
		t.Fatalf("writes %v private %v", g.FileWrite, g.AllowPrivate)
	}
	if g.Exp != exp || g.LeaseID != "lease-1" || g.Actor != "alice" || g.Host != "host-1" {
		t.Fatalf("binding %+v", g)
	}
}
