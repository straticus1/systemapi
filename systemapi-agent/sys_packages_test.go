package main

import (
	"context"
	"strings"
	"testing"
)

func restorePackageHooks(t *testing.T) {
	t.Helper()
	lookup := lookupPackageManager
	run := runPackageInstall
	t.Cleanup(func() {
		lookupPackageManager = lookup
		runPackageInstall = run
	})
}

func TestInstallPackageDeniesStarAndEmpty(t *testing.T) {
	restorePackageHooks(t)
	called := false
	lookupPackageManager = func() (string, error) {
		called = true
		return "apt-get", nil
	}
	runPackageInstall = func(context.Context, []string) error {
		called = true
		return nil
	}
	for _, allow := range [][]string{{"*"}, nil, {}} {
		err := installPackage("nginx", allow)
		if err == nil || !strings.Contains(err.Error(), "package not allowed") {
			t.Fatalf("%v: %v", allow, err)
		}
		if called {
			t.Fatal("lookup ran")
		}
	}
}

func TestInstallPackageHostGate(t *testing.T) {
	restorePackageHooks(t)
	called := false
	var got []string
	lookupPackageManager = func() (string, error) {
		called = true
		return "apt-get", nil
	}
	runPackageInstall = func(_ context.Context, argv []string) error {
		called = true
		got = append([]string(nil), argv...)
		return nil
	}
	err := installPackage("nginx", []string{"nginx"})
	if hostLinux() {
		if err != nil {
			t.Fatal(err)
		}
		if !called || strings.Join(got, " ") != "apt-get install -y --no-install-recommends -- nginx" {
			t.Fatalf("called=%v argv=%v", called, got)
		}
		return
	}
	if err == nil || !strings.Contains(err.Error(), "requires linux") || called {
		t.Fatalf("err=%v called=%v", err, called)
	}
}

func TestPackageArgv(t *testing.T) {
	apt, err := packageArgv("apt-get", "nginx")
	if err != nil || strings.Join(apt, " ") != "apt-get install -y --no-install-recommends -- nginx" {
		t.Fatalf("%v %v", apt, err)
	}
	dnf, err := packageArgv("dnf", "nginx")
	if err != nil || strings.Join(dnf, " ") != "dnf install -y -- nginx" {
		t.Fatalf("%v %v", dnf, err)
	}
	if _, err := packageArgv("apt-get", "nginx;rm"); err == nil || !strings.Contains(err.Error(), "package not allowed") {
		t.Fatal(err)
	}
	if _, err := packageArgv("apt-get", "*"); err == nil || !strings.Contains(err.Error(), "package not allowed") {
		t.Fatal(err)
	}
	if _, err := packageArgv("yum", "nginx"); err == nil || !strings.Contains(err.Error(), "package manager unavailable") {
		t.Fatal(err)
	}
}

func TestPackagesInstallStarDoesNotRun(t *testing.T) {
	restorePackageHooks(t)
	called := false
	lookupPackageManager = func() (string, error) {
		called = true
		return "apt-get", nil
	}
	runPackageInstall = func(context.Context, []string) error {
		called = true
		return nil
	}
	engine := newTestEngine(&Entitlements{AllowPackages: []string{"*"}})
	_, err := engine.Execute("sys.packages.install(\"nginx\")\n")
	if err == nil || !strings.Contains(err.Error(), "package not allowed") || called {
		t.Fatalf("err=%v called=%v", err, called)
	}
}
