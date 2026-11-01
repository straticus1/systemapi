package main

// Go/Node agreement on the sys channel leases: controlplane/testdata/
// sys-lease-vectors.json is signed by the server's builders (controlplane/
// lease.js sysServicePayload, sysPackagePayload, sysConfigPayload,
// sysTweakPayload); the agent's builders must rebuild the exact payload from
// the same inputs and the lease must verify. Threats: a drift between the two
// builders, which would make a lease for one resource match another on one
// side, or refuse every valid lease.

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type sysLeaseVectors struct {
	PublicRawB64 string `json:"public_raw_b64"`
	HostID       string `json:"host_id"`
	NowMS        int64  `json:"now_ms"`
	Vectors      []struct {
		Name    string            `json:"name"`
		Action  string            `json:"action"`
		Inputs  map[string]string `json:"inputs"`
		Payload string            `json:"payload"`
		Message string            `json:"message"`
		Lease   Lease             `json:"lease"`
	} `json:"vectors"`
}

func TestSysLeaseVectors(t *testing.T) {
	blob, err := os.ReadFile(filepath.Join("..", "controlplane", "testdata", "sys-lease-vectors.json"))
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}
	var v sysLeaseVectors
	if err := json.Unmarshal(blob, &v); err != nil {
		t.Fatalf("parse vectors: %v", err)
	}
	raw, err := base64.StdEncoding.DecodeString(v.PublicRawB64)
	if err != nil || len(raw) != ed25519.PublicKeySize {
		t.Fatalf("public key: %v", err)
	}
	pub := ed25519.PublicKey(raw)
	now := time.UnixMilli(v.NowMS)
	seen := map[string]bool{}
	for _, c := range v.Vectors {
		in := c.Inputs
		var got string
		switch c.Action {
		case "sys_service":
			got, err = sysServiceLeasePayload(in["unit"], in["action"])
		case "sys_package":
			got, err = sysPackageLeasePayload(in["name"], in["action"])
		case "sys_config":
			sha := ""
			if in["action"] == "write" {
				sha = sysSHA256Hex(in["content"])
			}
			got, err = sysConfigLeasePayload(in["action"], in["target"], sha)
		case "sys_tweak":
			sha := ""
			if in["verb"] == "unit-override-set" {
				sha = sysSHA256Hex(in["content"])
			}
			got, err = sysTweakLeasePayload(in["verb"], in["key"], in["value"], in["unit"], in["limit"], in["name"], sha)
		default:
			t.Fatalf("%s: unknown action %s", c.Name, c.Action)
		}
		if err != nil || got != c.Payload {
			t.Fatalf("%s: Go payload %q (%v), server signed %q", c.Name, got, err, c.Payload)
		}
		msg := canonicalLease(c.Lease.HostID, c.Lease.Action, c.Lease.ExpiresUnix, c.Lease.NonceHex, c.Lease.PayloadSHA)
		if msg != c.Message {
			t.Fatalf("%s: canonical message mismatch", c.Name)
		}
		if err := verifyLease(pub, &c.Lease, v.HostID, c.Action, got, now); err != nil {
			t.Fatalf("%s: verifyLease: %v", c.Name, err)
		}
		// The lease binds the action: the same payload under another sys
		// action is refused.
		for _, other := range []string{"sys_service", "sys_package", "sys_config", "sys_tweak"} {
			if other == c.Action {
				continue
			}
			if err := verifyLease(pub, &c.Lease, v.HostID, other, got, now); err == nil {
				t.Fatalf("%s: lease verified as %s", c.Name, other)
			}
		}
		// A one-byte change to the payload is refused.
		if err := verifyLease(pub, &c.Lease, v.HostID, c.Action, got+"x", now); err == nil {
			t.Fatalf("%s: tampered payload verified", c.Name)
		}
		seen[c.Action] = true
	}
	for _, a := range []string{"sys_service", "sys_package", "sys_config", "sys_tweak"} {
		if !seen[a] {
			t.Fatalf("vectors must cover %s", a)
		}
	}
}
