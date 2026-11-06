package main

import (
	"errors"
	"testing"
	"time"
)

func sashLiveLease() func() time.Time {
	return func() time.Time { return time.Now().Add(time.Hour) }
}

func sashDeadLease() func() time.Time {
	return func() time.Time { return time.Now().Add(-time.Hour) }
}

func TestSashDispatchDeadLeaseSkipsHelper(t *testing.T) {
	calls := 0
	prev := sashProcs
	sashProcs = func() ([]sashProc, error) {
		calls++
		return []sashProc{{User: "root", Pid: 1, Cmd: "init"}}, nil
	}
	t.Cleanup(func() { sashProcs = prev })
	_, err := sashDispatch(sashGrant{Entitlements: []string{"ps"}}, sashTargets{}, sashDeadLease(), nil, sashCall{Key: "ps"})
	if !errors.Is(err, errSashDenied) {
		t.Fatalf("err %v", err)
	}
	if calls != 0 {
		t.Fatalf("helper calls %d", calls)
	}
}

func TestSashDispatchWriteClassDeniesBeforeHelper(t *testing.T) {
	unitCalls := 0
	prevUnit := sashUnitStatus
	sashUnitStatus = func(name string) (bool, string, error) {
		unitCalls++
		return true, "active", nil
	}
	t.Cleanup(func() { sashUnitStatus = prevUnit })
	g := sashGrant{Entitlements: []string{"unit.restart", "journal", "unit.status"}}
	_, err := sashDispatch(g, sashTargets{Units: []string{"nginx"}}, sashLiveLease(), nil, sashCall{
		Key: "unit.restart", Argv: []string{"unit", "restart", "nginx"},
	})
	if !errors.Is(err, errSashDenied) || unitCalls != 0 {
		t.Fatalf("restart err %v calls %d", err, unitCalls)
	}
	_, err = sashDispatch(g, sashTargets{}, sashLiveLease(), nil, sashCall{Key: "journal", Argv: []string{"journal"}})
	if !errors.Is(err, errSashDenied) || unitCalls != 0 {
		t.Fatalf("journal err %v calls %d", err, unitCalls)
	}
	_, err = sashDispatch(g, sashTargets{Units: []string{"nginx"}}, sashLiveLease(), nil, sashCall{
		Key: "unit.status", Argv: []string{"unit", "status"},
	})
	if !errors.Is(err, errSashDenied) || unitCalls != 0 {
		t.Fatalf("bad argv err %v calls %d", err, unitCalls)
	}
}

func TestSashDispatchFileAndSysctlDenyBeforeHelper(t *testing.T) {
	fileCalls := 0
	prevFile := sashFile
	sashFile = func(id *ptyIdentity, op, root, rel string) (sashResult, error) {
		fileCalls++
		return sashResult{Bytes: []byte("SECRET")}, nil
	}
	t.Cleanup(func() { sashFile = prevFile })
	sysCalls := 0
	prevSys := sashSysctlGet
	sashSysctlGet = func(key string, allow []string) (string, error) {
		sysCalls++
		return "1", nil
	}
	t.Cleanup(func() { sashSysctlGet = prevSys })

	g := sashGrant{
		Entitlements: []string{"file.read", "sysctl.get"},
		FileRead:     []string{"/var/log"},
	}
	outside := []string{"/etc/passwd", "/var/logbook"}
	for _, p := range outside {
		_, err := sashDispatch(g, sashTargets{Files: []string{"/var/log"}}, sashLiveLease(), &ptyIdentity{}, sashCall{
			Key: "file.read", Argv: []string{"cat"}, Path: p,
		})
		if !errors.Is(err, errSashDenied) {
			t.Fatalf("%s: %v", p, err)
		}
	}
	_, err := sashDispatch(g, sashTargets{}, sashLiveLease(), &ptyIdentity{}, sashCall{
		Key: "file.read", Argv: []string{"cat"}, Path: "/var/log/auth.log",
	})
	if !errors.Is(err, errSashDenied) {
		t.Fatalf("empty files: %v", err)
	}
	if fileCalls != 0 {
		t.Fatalf("file helper calls %d", fileCalls)
	}
	_, err = sashDispatch(g, sashTargets{Sysctls: []string{"kernel.core_pattern"}}, sashLiveLease(), nil, sashCall{
		Key: "sysctl.get", Argv: []string{"sysctl", "get", "kernel.core_pattern"},
	})
	if !errors.Is(err, errSashDenied) || sysCalls != 0 {
		t.Fatalf("sysctl err %v calls %d", err, sysCalls)
	}
}

func TestSashDispatchPS(t *testing.T) {
	prev := sashProcs
	sashProcs = func() ([]sashProc, error) {
		return []sashProc{{User: "root", Pid: 7, Cmd: "sshd"}}, nil
	}
	t.Cleanup(func() { sashProcs = prev })
	res, err := sashDispatch(sashGrant{Entitlements: []string{"ps"}}, sashTargets{}, sashLiveLease(), nil, sashCall{Key: "ps"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Exit != 0 || len(res.Rows) != 1 || res.Rows[0]["cmd"] != "sshd" || res.Rows[0]["pid"] != "7" {
		t.Fatalf("%+v", res)
	}
}
