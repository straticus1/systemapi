package main

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

func restorePackageQueryHook(t *testing.T) {
	t.Helper()
	restorePackageHooks(t)
	q := runPackageQuery
	t.Cleanup(func() { runPackageQuery = q })
}

func TestPackageListArgv(t *testing.T) {
	cases := []struct {
		mgr  string
		want []string
	}{
		{"apt-get", []string{"dpkg-query", "-W", "-f", "${Package}\t${Version}\t${db:Status-Abbrev}\n"}},
		{"dnf", []string{"rpm", "-qa", "--qf", "%{NAME}\t%{VERSION}-%{RELEASE}\n"}},
		{"yum", []string{"rpm", "-qa", "--qf", "%{NAME}\t%{VERSION}-%{RELEASE}\n"}},
		{"zypper", []string{"rpm", "-qa", "--qf", "%{NAME}\t%{VERSION}-%{RELEASE}\n"}},
		{"brew", []string{"brew", "list", "--versions"}},
	}
	for _, c := range cases {
		got, err := packageManagerByName(c.mgr).ListArgv()
		if err != nil || !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: argv=%q err=%v want %q", c.mgr, got, err, c.want)
		}
		// The returned slice is a copy; mutating it must not touch the template.
		got[0] = "x"
		if again, _ := packageManagerByName(c.mgr).ListArgv(); again[0] == "x" {
			t.Errorf("%s: ListArgv returned the template slice", c.mgr)
		}
	}
	if _, err := (nonePackageManager{}).ListArgv(); err == nil {
		t.Fatal("none manager ListArgv must fail closed")
	}
}

func TestPackageVerbArgvRejectsBadNames(t *testing.T) {
	for _, mgr := range []string{"apt-get", "dnf", "yum", "zypper", "brew"} {
		m := packageManagerByName(mgr)
		for _, name := range []string{"-rf", "nginx;rm", "*", "", "a b", "../x", "--purge"} {
			for _, fn := range []func(string) ([]string, error){m.RemoveArgv, m.UpgradeArgv, m.QueryArgv} {
				if argv, err := fn(name); err == nil {
					t.Errorf("%s %q: accepted, argv=%q", mgr, name, argv)
				}
			}
		}
	}
}

func TestParsePackageList(t *testing.T) {
	cases := []struct {
		mgr, out string
		want     []pkgEntry
	}{
		{"apt-get", "nginx\t1.18.0-6ubuntu14\tii \nold\t\trc \nlibc6\t2.35-0ubuntu3\tii \nhalf\t1.0\tiU \nheld\t2.0\thi \ngone\t3.0\trc \n",
			[]pkgEntry{{"nginx", "1.18.0-6ubuntu14"}, {"libc6", "2.35-0ubuntu3"}, {"held", "2.0"}}},
		{"dnf", "nginx\t1.20.1-14.el9\nbash\t5.1.8-6.el9\n\n", []pkgEntry{{"nginx", "1.20.1-14.el9"}, {"bash", "5.1.8-6.el9"}}},
		{"yum", "openssl\t1.0.2k-26.el7\n", []pkgEntry{{"openssl", "1.0.2k-26.el7"}}},
		{"zypper", "zypper\t1.14.59-150400.3.20.1\r\n", []pkgEntry{{"zypper", "1.14.59-150400.3.20.1"}}},
		{"brew", "git 2.42.0 2.43.0\nwget 1.21.4\nbroken\n", []pkgEntry{{"git", "2.43.0"}, {"wget", "1.21.4"}}},
		{"pacman", "bash 5.2.015-1\nlinux 6.5.9.arch2-1\n", []pkgEntry{{"bash", "5.2.015-1"}, {"linux", "6.5.9.arch2-1"}}},
		{"unknown", "a 1\n", nil},
		{"dnf", "", nil},
	}
	for _, c := range cases {
		got := parsePackageList(c.mgr, c.out, packageListMax)
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: got %v want %v", c.mgr, got, c.want)
		}
	}
	if got := parsePackageList("dnf", "a\t1\nb\t2\nc\t3\n", 2); len(got) != 2 {
		t.Fatalf("cap not applied: %v", got)
	}
}

func TestParsePackageQuery(t *testing.T) {
	cases := []struct {
		mgr, name, out string
		installed      bool
		version        string
	}{
		{"apt-get", "nginx", "nginx\t1.18.0-6ubuntu14\tii \n", true, "1.18.0-6ubuntu14"},
		{"apt-get", "libc6", "libc6:amd64\t2.35-0ubuntu3\tii \n", true, "2.35-0ubuntu3"},
		{"apt-get", "nginx", "nginx\t1.18.0-6ubuntu14\thi \n", true, "1.18.0-6ubuntu14"},
		// Removed with config left: dpkg-query -W still prints a version.
		{"apt-get", "nginx", "nginx\t1.18.0-6ubuntu14\trc \n", false, ""},
		{"apt-get", "nginx", "nginx\t1.18.0-6ubuntu14\tiU \n", false, ""},
		{"apt-get", "nginx", "nginx\t1.18.0-6ubuntu14\tpn \n", false, ""},
		// The old two-field format (no status) is never installed.
		{"apt-get", "nginx", "nginx\t1.18.0-6ubuntu14\n", false, ""},
		{"apt-get", "nginx", "nginx\t\n", false, ""},
		{"apt-get", "nginx", "", false, ""},
		{"dnf", "nginx", "nginx-1.20.1-14.el9.x86_64\n", true, "1.20.1-14.el9"},
		{"yum", "tzdata", "tzdata-2023c-1.el9.noarch\n", true, "2023c-1.el9"},
		{"zypper", "nginx", "package nginx is not installed\n", false, ""},
		{"dnf", "nginx", "nginx-mod-stream-1.20.1-14.el9.x86_64\n", false, ""},
		{"brew", "wget", "wget 1.21.4\n", true, "1.21.4"},
		{"brew", "wget", "", false, ""},
		{"pacman", "bash", "bash 5.2.015-1\n", true, "5.2.015-1"},
		{"pacman", "bash", "error: package 'bash' was not found\n", false, ""},
	}
	for _, c := range cases {
		inst, ver := parsePackageQuery(c.mgr, c.name, c.out)
		if inst != c.installed || ver != c.version {
			t.Errorf("%s %s %q: got (%v,%q) want (%v,%q)", c.mgr, c.name, c.out, inst, ver, c.installed, c.version)
		}
	}
}

func TestPackageVerbsDenyBeforeLookup(t *testing.T) {
	restorePackageQueryHook(t)
	called := false
	lookupPackageManager = func() (string, error) { called = true; return "apt-get", nil }
	runPackageInstall = func(context.Context, []string) error { called = true; return nil }
	runPackageQuery = func(context.Context, []string) (string, int, error) { called = true; return "", 0, nil }
	for _, allow := range [][]string{{"*"}, nil, {}, {"curl"}} {
		for _, verb := range []string{"remove", "upgrade"} {
			if err := changePackage(context.Background(), verb, "nginx", allow); err == nil || !strings.Contains(err.Error(), "package not allowed") {
				t.Fatalf("%s %v: %v", verb, allow, err)
			}
		}
		if _, _, err := queryPackage(context.Background(), "nginx", allow); err == nil || !strings.Contains(err.Error(), "package not allowed") {
			t.Fatalf("query %v: %v", allow, err)
		}
	}
	for _, allow := range [][]string{{"*"}, nil, {}, {"bad name"}} {
		if _, err := listPackages(context.Background(), allow); err == nil || !strings.Contains(err.Error(), "package not allowed") {
			t.Fatalf("list %v: %v", allow, err)
		}
	}
	if called {
		t.Fatal("a hook ran for a denied request")
	}
}

func TestPackageVerbsHostGate(t *testing.T) {
	restorePackageQueryHook(t)
	var ran [][]string
	lookupPackageManager = func() (string, error) { return "dnf", nil }
	runPackageInstall = func(_ context.Context, argv []string) error {
		ran = append(ran, argv)
		return nil
	}
	runPackageQuery = func(_ context.Context, argv []string) (string, int, error) {
		ran = append(ran, argv)
		if argv[1] == "-qa" {
			return "nginx\t1.20.1-14.el9\n", 0, nil
		}
		if argv[0] == "dnf" {
			return dnfRemoveOnlyNginx, 1, nil
		}
		return "nginx-1.20.1-14.el9.x86_64\n", 0, nil
	}
	allow := []string{"nginx"}
	errRemove := changePackage(context.Background(), "remove", "nginx", allow)
	errUpgrade := changePackage(context.Background(), "upgrade", "nginx", allow)
	inst, ver, errQuery := queryPackage(context.Background(), "nginx", allow)
	list, errList := listPackages(context.Background(), allow)
	if !hostLinux() {
		for _, err := range []error{errRemove, errUpgrade, errQuery, errList} {
			if err == nil || !strings.Contains(err.Error(), "requires linux") {
				t.Fatalf("non-linux must refuse: %v", err)
			}
		}
		if len(ran) != 0 {
			t.Fatalf("ran on non-linux: %v", ran)
		}
		return
	}
	if errRemove != nil || errUpgrade != nil || errQuery != nil || errList != nil {
		t.Fatal(errRemove, errUpgrade, errQuery, errList)
	}
	want := []string{"dnf remove --assumeno -- nginx", "dnf remove -y -- nginx", "dnf upgrade -y -- nginx", "rpm -q nginx"}
	for i, w := range want {
		if strings.Join(ran[i], " ") != w {
			t.Errorf("argv %d = %q want %q", i, strings.Join(ran[i], " "), w)
		}
	}
	if !inst || ver != "1.20.1-14.el9" || len(list) != 1 || list[0].Name != "nginx" {
		t.Fatalf("inst=%v ver=%q list=%v", inst, ver, list)
	}
}

func TestPackageQueryExitCodes(t *testing.T) {
	if !hostLinux() {
		t.Skip("query runs only on linux")
	}
	restorePackageQueryHook(t)
	lookupPackageManager = func() (string, error) { return "dnf", nil }
	runPackageQuery = func(context.Context, []string) (string, int, error) {
		return "package nginx is not installed\n", 1, nil
	}
	if inst, _, err := queryPackage(context.Background(), "nginx", []string{"nginx"}); err != nil || inst {
		t.Fatalf("exit 1 must be not installed: %v %v", inst, err)
	}
	runPackageQuery = func(context.Context, []string) (string, int, error) { return "", 2, nil }
	if _, _, err := queryPackage(context.Background(), "nginx", []string{"nginx"}); err == nil {
		t.Fatal("exit 2 must be an error")
	}
	if _, err := listPackages(context.Background(), []string{"nginx"}); err == nil {
		t.Fatal("list with non-zero exit must be an error")
	}
}

func TestPackagesStarlarkStarDenied(t *testing.T) {
	restorePackageQueryHook(t)
	called := false
	lookupPackageManager = func() (string, error) { called = true; return "apt-get", nil }
	engine := newTestEngine(&Entitlements{AllowPackages: []string{"*"}})
	for _, src := range []string{
		`sys.packages.remove("nginx")`,
		`sys.packages.upgrade("nginx")`,
		`sys.packages.query("nginx")`,
		`sys.packages.list()`,
	} {
		if _, err := engine.Execute(src + "\n"); err == nil || !strings.Contains(err.Error(), "package not allowed") {
			t.Fatalf("%s: %v", src, err)
		}
	}
	if called {
		t.Fatal("lookup ran")
	}
}

// Dry-run fixtures, trimmed from real output.
const dnfRemoveOnlyNginx = `Dependencies resolved.
================================================================================
 Package         Arch        Version                   Repository        Size
================================================================================
Removing:
 nginx           x86_64      1:1.20.1-14.el9           @appstream       1.1 M

Transaction Summary
================================================================================
Remove  1 Package

Freed space: 1.1 M
Operation aborted.
`

const dnfRemoveWithDeps = `Dependencies resolved.
================================================================================
 Package               Arch      Version              Repository        Size
================================================================================
Removing:
 nginx                 x86_64    1:1.20.1-14.el9      @appstream       1.1 M
Removing dependent packages:
 nginx-mod-stream      x86_64    1:1.20.1-14.el9      @appstream        80 k
Removing unused dependencies:
 nginx-filesystem      noarch    1:1.20.1-14.el9      @appstream       0

Transaction Summary
================================================================================
Remove  3 Packages

Operation aborted.
`

const dnf5RemoveOnly = `Package                Arch    Version              Repository      Size
Removing:
 nginx                 x86_64  1:1.24.0-1.fc39      updates       1.1 MiB

Transaction Summary:
 Removing:           1 package
Operation aborted by the user.
`

const yumRemoveWithDeps = `Resolving Dependencies
Dependencies Resolved

================================================================================
 Package           Arch         Version               Repository          Size
================================================================================
Removing:
 nginx             x86_64       1:1.20.1-10.el7       @epel              1.7 M
Removing for dependencies:
 nginx-all-modules noarch       1:1.20.1-10.el7       @epel              0.0

Transaction Summary
================================================================================
Remove  1 Package (+1 Dependent package)

Exiting on user command
`

const aptRemoveOnly = `Reading package lists...
Building dependency tree...
The following packages will be REMOVED:
  nginx
0 upgraded, 0 newly installed, 1 to remove and 0 not upgraded.
Remv nginx [1.18.0-6ubuntu14]
`

const aptRemoveWithDeps = `The following packages will be REMOVED:
  libnginx-mod-http-geoip2 nginx nginx-core
0 upgraded, 0 newly installed, 3 to remove and 0 not upgraded.
Remv nginx [1.18.0-6ubuntu14]
Remv nginx-core [1.18.0-6ubuntu14]
Remv libnginx-mod-http-geoip2:amd64 [1.18.0-6ubuntu14]
`

const zypperRemoveOnly = `Loading repository data...
Reading installed packages...
Resolving package dependencies...

The following package is going to be REMOVED:
  nginx

1 package to remove.
`

const zypperRemoveWithDeps = `Resolving package dependencies...

The following 2 packages are going to be REMOVED:
  nginx nginx-module-x

2 packages to remove.
`

func TestParseRemoveSim(t *testing.T) {
	cases := []struct {
		name, mgr, out string
		code           int
		ok             bool
		want           []string
	}{
		{"apt only", "apt-get", aptRemoveOnly, 0, true, []string{"nginx"}},
		{"apt deps", "apt-get", aptRemoveWithDeps, 0, true, []string{"nginx", "nginx-core", "libnginx-mod-http-geoip2"}},
		{"apt not installed", "apt-get", "Package 'nginx' is not installed, so not removed\n", 0, true, nil},
		{"apt failed", "apt-get", aptRemoveOnly, 100, false, nil},
		{"dnf only", "dnf", dnfRemoveOnlyNginx, 1, true, []string{"nginx"}},
		{"dnf deps", "dnf", dnfRemoveWithDeps, 1, true, []string{"nginx", "nginx-mod-stream", "nginx-filesystem"}},
		{"dnf5 only", "dnf", dnf5RemoveOnly, 1, true, []string{"nginx"}},
		{"dnf nothing", "dnf", "No match for argument: nginx\nNo packages marked for removal.\n", 1, false, nil},
		{"dnf error exit", "dnf", dnfRemoveOnlyNginx, 2, false, nil},
		// The summary counts 1 but a dependency row is listed: refuse.
		{"yum deps", "yum", yumRemoveWithDeps, 1, false, nil},
		{"zypper only", "zypper", zypperRemoveOnly, 0, true, []string{"nginx"}},
		{"zypper deps", "zypper", zypperRemoveWithDeps, 0, true, []string{"nginx", "nginx-module-x"}},
		{"zypper failed", "zypper", "Package 'nginx' not found.\n", 104, false, nil},
		{"brew no users", "brew", "", 0, true, nil},
		{"brew users", "brew", "certbot\nnginx-full\n", 0, true, []string{"certbot", "nginx-full"}},
		{"unknown manager", "pacman", "", 0, false, nil},
	}
	for _, c := range cases {
		got, ok := parseRemoveSim(c.mgr, c.out, c.code)
		if ok != c.ok {
			t.Errorf("%s: ok=%v want %v", c.name, ok, c.ok)
			continue
		}
		want := map[string]bool{}
		for _, n := range c.want {
			want[n] = true
		}
		if ok && !reflect.DeepEqual(got, want) {
			t.Errorf("%s: got %v want %v", c.name, got, want)
		}
	}
}

func TestPackageRemoveRefusesExtraRemovals(t *testing.T) {
	if !hostLinux() {
		t.Skip("remove runs only on linux")
	}
	restorePackageQueryHook(t)
	cases := []struct {
		name, mgr, out string
		code           int
		wantErr        string
	}{
		{"dnf only", "dnf", dnfRemoveOnlyNginx, 1, ""},
		{"apt only", "apt-get", aptRemoveOnly, 0, ""},
		{"zypper only", "zypper", zypperRemoveOnly, 0, ""},
		{"brew unused", "brew", "", 0, ""},
		{"dnf deps", "dnf", dnfRemoveWithDeps, 1, "would remove 3 packages"},
		{"apt deps", "apt-get", aptRemoveWithDeps, 0, "would remove 3 packages"},
		{"apt not installed", "apt-get", "Package 'nginx' is not installed\n", 0, "would remove 0 packages"},
		{"zypper deps", "zypper", zypperRemoveWithDeps, 0, "would remove 2 packages"},
		{"yum deps", "yum", yumRemoveWithDeps, 1, "not understood"},
		{"brew used", "brew", "certbot\n", 0, "depend on nginx"},
		{"garbage", "dnf", "something else\n", 1, "not understood"},
	}
	for _, c := range cases {
		removed := false
		lookupPackageManager = func() (string, error) { return c.mgr, nil }
		runPackageQuery = func(context.Context, []string) (string, int, error) { return c.out, c.code, nil }
		runPackageInstall = func(context.Context, []string) error { removed = true; return nil }
		err := changePackage(context.Background(), "remove", "nginx", []string{"nginx"})
		if c.wantErr == "" {
			if err != nil || !removed {
				t.Errorf("%s: err=%v removed=%v", c.name, err, removed)
			}
			continue
		}
		if err == nil || !strings.Contains(err.Error(), c.wantErr) || removed {
			t.Errorf("%s: err=%v removed=%v, want %q and no remove", c.name, err, removed, c.wantErr)
		}
	}
	// A dry run that cannot run refuses too.
	removed := false
	lookupPackageManager = func() (string, error) { return "dnf", nil }
	runPackageQuery = func(context.Context, []string) (string, int, error) { return "", 0, errors.New("exec failed") }
	runPackageInstall = func(context.Context, []string) error { removed = true; return nil }
	if err := changePackage(context.Background(), "remove", "nginx", []string{"nginx"}); err == nil || removed {
		t.Fatalf("failed dry run: err=%v removed=%v", err, removed)
	}
}

func TestRemoveSimArgv(t *testing.T) {
	want := map[string]string{
		"apt-get": "apt-get -s remove -- nginx",
		"dnf":     "dnf remove --assumeno -- nginx",
		"yum":     "yum remove --assumeno -- nginx",
		"zypper":  "zypper --non-interactive remove --dry-run -- nginx",
		"brew":    "brew uses --installed nginx",
	}
	for mgr, w := range want {
		got, err := packageManagerByName(mgr).RemoveSimArgv("nginx")
		if err != nil || strings.Join(got, " ") != w {
			t.Errorf("%s: %q %v", mgr, got, err)
		}
		if _, err := packageManagerByName(mgr).RemoveSimArgv("-rf"); err == nil {
			t.Errorf("%s: bad name accepted", mgr)
		}
	}
}

// TestPackageVerbsUseScriptContext: the package verbs run under the
// script's own context (no 25 s cap of their own) and report its end; an
// interrupted apt install says how to repair dpkg.
func TestPackageVerbsUseScriptContext(t *testing.T) {
	restorePackageQueryHook(t)
	lookupPackageManager = func() (string, error) { return "apt-get", nil }
	deadline := time.Now().Add(time.Hour)
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()
	var sawDeadline bool
	runPackageInstall = func(c context.Context, argv []string) error {
		d, ok := c.Deadline()
		sawDeadline = ok && d.Equal(deadline)
		cancel()
		<-c.Done()
		return errors.New("signal: terminated")
	}
	err := changePackage(ctx, "install", "nginx", []string{"nginx"})
	if !hostLinux() {
		if err == nil || !strings.Contains(err.Error(), "requires linux") {
			t.Fatalf("non-linux must refuse: %v", err)
		}
		return
	}
	if !sawDeadline {
		t.Fatal("install did not run under the script's context")
	}
	if err == nil || !strings.Contains(err.Error(), "cancelled") || !strings.Contains(err.Error(), "dpkg --configure -a") {
		t.Fatalf("err=%v", err)
	}
	expired, cancel2 := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel2()
	runPackageQuery = func(c context.Context, argv []string) (string, int, error) { return "", -1, c.Err() }
	if _, _, err := queryPackage(expired, "nginx", []string{"nginx"}); err == nil || !strings.Contains(err.Error(), "timed out (script deadline)") || strings.Contains(err.Error(), "dpkg") {
		t.Fatalf("query err=%v", err)
	}
}

// TestPackageVerbsSerialize: scripts run concurrently, but two package
// changes never run the package manager at the same time, and a script
// waiting for the lock gives up at its own deadline.
func TestPackageVerbsSerialize(t *testing.T) {
	restorePackageQueryHook(t)
	lookupPackageManager = func() (string, error) { return "apt-get", nil }
	var mu sync.Mutex
	inside, maxInside := 0, 0
	release := make(chan struct{})
	entered := make(chan struct{}, 4)
	runPackageInstall = func(c context.Context, argv []string) error {
		mu.Lock()
		inside++
		if inside > maxInside {
			maxInside = inside
		}
		mu.Unlock()
		entered <- struct{}{}
		<-release
		mu.Lock()
		inside--
		mu.Unlock()
		return nil
	}
	if !hostLinux() {
		if err := changePackage(context.Background(), "install", "nginx", []string{"nginx"}); err == nil || !strings.Contains(err.Error(), "requires linux") {
			t.Fatalf("non-linux must refuse: %v", err)
		}
		return
	}
	errs := make(chan error, 2)
	for i := 0; i < 2; i++ {
		go func() { errs <- changePackage(context.Background(), "install", "nginx", []string{"nginx"}) }()
	}
	<-entered
	select {
	case <-entered:
		t.Fatal("a second package change ran while the first held the manager")
	case <-time.After(200 * time.Millisecond):
	}
	// A third script with a short deadline gives up waiting for the lock.
	short, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if _, _, err := queryPackage(short, "nginx", []string{"nginx"}); err == nil || !strings.Contains(err.Error(), "waiting for another package operation") {
		t.Fatalf("queued query err=%v", err)
	}
	release <- struct{}{}
	<-entered
	release <- struct{}{}
	for i := 0; i < 2; i++ {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
	if maxInside != 1 {
		t.Fatalf("max concurrent package runs = %d", maxInside)
	}
}
