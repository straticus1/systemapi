//go:build linux

package main

import (
	"crypto/ed25519"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

var (
	sashTestFleetPriv    ed25519.PrivateKey
	sashTestEmerPriv     ed25519.PrivateKey
	sashTestFleetPubPath string
	sashTestEmerPubPath  string
	sashTestLook         func(string) (string, error)
)

func init() {
	dir, err := os.MkdirTemp("", "sash-session-")
	if err != nil {
		panic(err)
	}
	fleetPriv, fleetPub := sashTestKeys(0x22)
	emerPriv, emerPub := sashTestKeys(0x33)
	sashTestFleetPriv = fleetPriv
	sashTestEmerPriv = emerPriv
	sashTestFleetPubPath = filepath.Join(dir, "fleet.pub")
	sashTestEmerPubPath = filepath.Join(dir, "emer.pub")
	if err := os.WriteFile(sashTestFleetPubPath, fleetPub, 0o600); err != nil {
		panic(err)
	}
	if err := os.WriteFile(sashTestEmerPubPath, emerPub, 0o600); err != nil {
		panic(err)
	}
	wrap := filepath.Join(dir, "sash")
	if err := os.WriteFile(wrap, []byte("#!/bin/sh\nexec /bin/sh\n"), 0o644); err != nil {
		panic(err)
	}
	if err := os.Chmod(wrap, 0o755); err != nil {
		panic(err)
	}
	sashTestLook = func(name string) (string, error) {
		if name != "sash" {
			return "", exec.ErrNotFound
		}
		return wrap, nil
	}
	sashLookPath = sashTestLook
	attachSashTestGrant = func(t *testing.T, req *ptyStartRequest) {
		t.Helper()
		if req.Action != "pty" && req.Action != "pty_root" {
			return
		}
		if req.Actor == "" {
			req.Actor = "pty-test"
		}
		purpose := sashPurposeOpen
		if req.Action == "pty_root" {
			purpose = sashPurposeRoot
		}
		leaseID := ""
		if req.Lease != nil {
			leaseID = req.Lease.NonceHex
		}
		doc, err := signSashGrant(sashGrant{
			V:            "sash/1",
			Actor:        req.Actor,
			Host:         ptyTestHost,
			Purpose:      purpose,
			Exp:          time.Now().Add(24 * time.Hour).Unix(),
			LeaseID:      leaseID,
			Entitlements: []string{"ps"},
			FileRead:     []string{},
			FileWrite:    []string{},
		}, sashTestFleetPriv)
		if err != nil {
			t.Fatal(err)
		}
		req.Grant = doc
		req.SashTargets = &sashTargets{}
		ptyCfg.SashFleetPub = sashTestFleetPubPath
		ptyCfg.SashEmerPub = sashTestEmerPubPath
	}
}

func TestPrepareSashEmptyGrantDoesNotLook(t *testing.T) {
	calls := 0
	prev := sashLookPath
	sashLookPath = func(string) (string, error) {
		calls++
		return "", exec.ErrNotFound
	}
	t.Cleanup(func() { sashLookPath = prev })
	_, _, extra, stop, err := prepareSash(nil, sashTestFleetPubPath, sashTestEmerPubPath, sashBind{}, sashTargets{}, nil, nil)
	if sashStatusCode(err) != "grant_missing" || calls != 0 || extra != nil || stop != nil {
		t.Fatalf("err %v calls %d", err, calls)
	}
}

func TestPrepareSashLookPathMissIsSashMissing(t *testing.T) {
	prev := sashLookPath
	sashLookPath = func(string) (string, error) { return "", exec.ErrNotFound }
	t.Cleanup(func() { sashLookPath = prev })
	_, _, extra, stop, err := prepareSash([]byte("{"), sashTestFleetPubPath, sashTestEmerPubPath, sashBind{}, sashTargets{}, nil, nil)
	if sashStatusCode(err) != "sash_missing" || extra != nil || stop != nil {
		t.Fatalf("err %v", err)
	}
}

func TestPrepareSashGarbageGrant(t *testing.T) {
	_, _, extra, stop, err := prepareSash([]byte("{"), sashTestFleetPubPath, sashTestEmerPubPath, sashBind{
		Action: "pty", Host: ptyTestHost, Actor: "alice", LeaseID: "lease-1", Now: time.Now(),
	}, sashTargets{}, func() time.Time { return time.Now().Add(time.Hour) }, &ptyIdentity{})
	if sashStatusCode(err) != "grant_bad_shape" || extra != nil || stop != nil {
		t.Fatalf("err %v", err)
	}
}

func TestPrepareSashSessionPipes(t *testing.T) {
	const actor = "alice"
	const leaseID = "lease-1"
	doc, err := signSashGrant(sashGrant{
		V:            "sash/1",
		Actor:        actor,
		Host:         ptyTestHost,
		Purpose:      sashPurposeOpen,
		Exp:          time.Now().Add(time.Hour).Unix(),
		LeaseID:      leaseID,
		Entitlements: []string{"ps"},
		FileRead:     []string{},
		FileWrite:    []string{},
	}, sashTestFleetPriv)
	if err != nil {
		t.Fatal(err)
	}
	bin, args, extra, stop, err := prepareSash(doc, sashTestFleetPubPath, sashTestEmerPubPath, sashBind{
		Action: "pty", Host: ptyTestHost, Actor: actor, LeaseID: leaseID, Now: time.Now(),
	}, sashTargets{}, func() time.Time { return time.Now().Add(time.Hour) }, &ptyIdentity{shell: "/bin/sh"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		for _, f := range extra {
			f.Close()
		}
		stop()
		stop()
	})
	if bin == "" || len(args) != 1 || args[0] != "--session" || len(extra) != 4 || stop == nil {
		t.Fatalf("bin %q args %v extra %d", bin, args, len(extra))
	}
	_ = sashTestEmerPriv
}
