package main

import (
	"bytes"
	"errors"
	"runtime"
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
	statusCalls := 0
	prevStatus := sashUnitStatus
	sashUnitStatus = func(name string) (bool, string, error) {
		statusCalls++
		return true, "active", nil
	}
	t.Cleanup(func() { sashUnitStatus = prevStatus })
	restartCalls := 0
	prevRestart := sashUnitRestart
	sashUnitRestart = func(name string) (string, error) {
		restartCalls++
		return "restarted", nil
	}
	t.Cleanup(func() { sashUnitRestart = prevRestart })
	g := sashGrant{Entitlements: []string{"unit.restart", "journal", "unit.status"}}
	_, err := sashDispatch(g, sashTargets{}, sashLiveLease(), nil, sashCall{
		Key: "unit.restart", Argv: []string{"unit", "restart", "nginx"},
	})
	if !errors.Is(err, errSashDenied) || restartCalls != 0 {
		t.Fatalf("empty units err %v calls %d", err, restartCalls)
	}
	_, err = sashDispatch(g, sashTargets{Units: []string{"*"}}, sashLiveLease(), nil, sashCall{
		Key: "unit.restart", Argv: []string{"unit", "restart", "nginx"},
	})
	if !errors.Is(err, errSashDenied) || restartCalls != 0 {
		t.Fatalf("star unit err %v calls %d", err, restartCalls)
	}
	_, err = sashDispatch(g, sashTargets{Units: []string{"nginx"}}, sashDeadLease(), nil, sashCall{
		Key: "unit.restart", Argv: []string{"unit", "restart", "nginx"},
	})
	if !errors.Is(err, errSashDenied) || restartCalls != 0 {
		t.Fatalf("dead lease err %v calls %d", err, restartCalls)
	}
	_, err = sashDispatch(sashGrant{Entitlements: []string{"unit.status"}}, sashTargets{Units: []string{"nginx"}}, sashLiveLease(), nil, sashCall{
		Key: "unit.restart", Argv: []string{"unit", "restart", "nginx"},
	})
	if !errors.Is(err, errSashDenied) || restartCalls != 0 {
		t.Fatalf("missing entitlement err %v calls %d", err, restartCalls)
	}
	_, err = sashDispatch(g, sashTargets{}, sashLiveLease(), nil, sashCall{Key: "journal", Argv: []string{"journal"}})
	if !errors.Is(err, errSashDenied) || restartCalls != 0 || statusCalls != 0 {
		t.Fatalf("journal err %v restart %d status %d", err, restartCalls, statusCalls)
	}
	_, err = sashDispatch(g, sashTargets{Units: []string{"nginx"}}, sashLiveLease(), nil, sashCall{
		Key: "unit.status", Argv: []string{"unit", "status"},
	})
	if !errors.Is(err, errSashDenied) || statusCalls != 0 || restartCalls != 0 {
		t.Fatalf("bad argv err %v status %d restart %d", err, statusCalls, restartCalls)
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

func TestSashDispatchWritesCallTheHelperOnce(t *testing.T) {
	restarts := 0
	prevRestart := sashUnitRestart
	sashUnitRestart = func(name string) (string, error) {
		restarts++
		if name != "nginx" {
			t.Fatalf("unit %s", name)
		}
		return "restarted", nil
	}
	t.Cleanup(func() { sashUnitRestart = prevRestart })
	g := sashGrant{Entitlements: []string{"unit.restart"}}
	res, err := sashDispatch(g, sashTargets{Units: []string{"nginx"}}, sashLiveLease(), nil, sashCall{
		Key: "unit.restart", Argv: []string{"unit", "restart", "nginx"},
	})
	if err != nil || res.Exit != 0 || string(res.Bytes) != "restarted" || restarts != 1 {
		t.Fatalf("restart %+v err %v calls %d", res, err, restarts)
	}

	installs := 0
	prevInstall := sashPackageInstall
	sashPackageInstall = func(name string, allow []string) error {
		installs++
		if name != "curl" || len(allow) != 1 || allow[0] != "curl" {
			t.Fatalf("package %s %v", name, allow)
		}
		return errors.New("manager failed")
	}
	t.Cleanup(func() { sashPackageInstall = prevInstall })
	res, err = sashDispatch(sashGrant{Entitlements: []string{"package.install"}}, sashTargets{Packages: []string{"curl"}}, sashLiveLease(), nil, sashCall{
		Key: "package.install", Argv: []string{"package", "install", "curl"},
	})
	if err != nil || res.Exit != 1 || installs != 1 {
		t.Fatalf("install %+v err %v calls %d", res, err, installs)
	}
	_, err = sashDispatch(sashGrant{Entitlements: []string{"package.install"}}, sashTargets{}, sashLiveLease(), nil, sashCall{
		Key: "package.install", Argv: []string{"package", "install", "curl"},
	})
	if !errors.Is(err, errSashDenied) || installs != 1 {
		t.Fatalf("missing package err %v calls %d", err, installs)
	}

	sets := 0
	prevSet := sashSysctlSet
	sashSysctlSet = func(key, value string, allow []string) error {
		sets++
		if key != "net.ipv4.ip_forward" || value != "1" {
			t.Fatalf("sysctl %s=%s", key, value)
		}
		return nil
	}
	t.Cleanup(func() { sashSysctlSet = prevSet })
	sys := sashGrant{Entitlements: []string{"sysctl.set"}}
	targets := sashTargets{Sysctls: []string{"net.ipv4.ip_forward"}}
	res, err = sashDispatch(sys, targets, sashLiveLease(), nil, sashCall{
		Key: "sysctl.set", Argv: []string{"sysctl", "set", "net.ipv4.ip_forward", "1"},
	})
	if err != nil || res.Exit != 0 || len(res.Bytes) != 0 || sets != 1 {
		t.Fatalf("sysctl %+v err %v calls %d", res, err, sets)
	}
	for _, value := range []string{"", "1\n0", "a\x00b"} {
		_, err = sashDispatch(sys, targets, sashLiveLease(), nil, sashCall{
			Key: "sysctl.set", Argv: []string{"sysctl", "set", "net.ipv4.ip_forward", value},
		})
		if !errors.Is(err, errSashDenied) || sets != 1 {
			t.Fatalf("value %q err %v calls %d", value, err, sets)
		}
	}
}

func TestSashDispatchFileWriteUsesWriteRoots(t *testing.T) {
	writes := 0
	var gotRoot, gotRel string
	var gotBody []byte
	prev := sashFileWrite
	sashFileWrite = func(id *ptyIdentity, root, rel string, body []byte) (sashResult, error) {
		writes++
		gotRoot, gotRel = root, rel
		gotBody = append([]byte(nil), body...)
		return sashResult{Kind: "bytes", Exit: 0}, nil
	}
	t.Cleanup(func() { sashFileWrite = prev })
	g := sashGrant{
		Entitlements: []string{"file.write", "file.read"},
		FileRead:     []string{"/var/log"},
		FileWrite:    []string{"/tmp"},
	}
	readOnly := sashTargets{Files: []string{"/var/log"}}
	_, err := sashDispatch(g, readOnly, sashLiveLease(), &ptyIdentity{}, sashCall{
		Key: "file.write", Argv: []string{">", "/var/log/a"}, Path: "/var/log/a", Body: []byte("no"),
	})
	if !errors.Is(err, errSashDenied) || writes != 0 {
		t.Fatalf("read root err %v calls %d", err, writes)
	}
	_, err = sashDispatch(g, sashTargets{}, sashLiveLease(), &ptyIdentity{}, sashCall{
		Key: "file.write", Argv: []string{">", "/tmp/a"}, Path: "/tmp/a", Body: []byte("no"),
	})
	if !errors.Is(err, errSashDenied) || writes != 0 {
		t.Fatalf("empty files_write err %v calls %d", err, writes)
	}
	targets := sashTargets{FilesWrite: []string{"/tmp"}}
	for _, p := range []string{"/tmp", "/tmpbook/a", "/var/log/a"} {
		_, err = sashDispatch(g, targets, sashLiveLease(), &ptyIdentity{}, sashCall{
			Key: "file.write", Argv: []string{">", p}, Path: p, Body: []byte("no"),
		})
		if !errors.Is(err, errSashDenied) || writes != 0 {
			t.Fatalf("%s err %v calls %d", p, err, writes)
		}
	}
	_, err = sashDispatch(g, targets, sashLiveLease(), &ptyIdentity{}, sashCall{
		Key: "file.write", Argv: []string{">", "/tmp/a"}, Path: "/tmp/a", Body: make([]byte, fileReadMax+1),
	})
	if !errors.Is(err, errSashDenied) || writes != 0 {
		t.Fatalf("oversize err %v calls %d", err, writes)
	}
	body := []byte("hello")
	res, err := sashDispatch(g, targets, sashLiveLease(), &ptyIdentity{}, sashCall{
		Key: "file.write", Argv: []string{">", "/tmp/a"}, Path: "/tmp/a", Body: body,
	})
	body[0] = 'H'
	if err != nil || res.Exit != 0 || len(res.Bytes) != 0 || writes != 1 {
		t.Fatalf("write %+v err %v calls %d", res, err, writes)
	}
	if gotRoot != "/tmp" || gotRel != "a" || !bytes.Equal(gotBody, []byte("hello")) {
		t.Fatalf("helper root %s rel %s body %q", gotRoot, gotRel, gotBody)
	}
	res, err = sashDispatch(g, targets, sashLiveLease(), &ptyIdentity{}, sashCall{
		Key: "file.write", Argv: []string{">", "/tmp/empty"}, Path: "/tmp/empty",
	})
	if err != nil || res.Exit != 0 || writes != 2 || len(gotBody) != 0 || gotRel != "empty" {
		t.Fatalf("empty %+v err %v calls %d rel %s", res, err, writes, gotRel)
	}
}

func TestSashFileWriteDefaultDeniesOffLinux(t *testing.T) {
	if runtime.GOOS == "linux" {
		t.Skip("the linux default spawns the helper for a well-formed write")
	}
	_, err := sashFileWriteDefault(&ptyIdentity{}, "/tmp", "a", []byte("x"))
	if !errors.Is(err, errSashDenied) {
		t.Fatalf("%v", err)
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
