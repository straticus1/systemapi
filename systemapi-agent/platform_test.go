package main

import (
	"strings"
	"testing"
)

func TestDetectFamily(t *testing.T) {
	cases := []struct {
		name string
		goos string
		osr  map[string]string
		want OSFamily
	}{
		{"rocky id", "linux", map[string]string{"ID": "rocky"}, familyRHEL},
		{"centos id", "linux", map[string]string{"ID": "centos"}, familyRHEL},
		{"amazon id", "linux", map[string]string{"ID": "amzn"}, familyRHEL},
		{"ubuntu id", "linux", map[string]string{"ID": "ubuntu"}, familyDebian},
		{"debian id", "linux", map[string]string{"ID": "debian"}, familyDebian},
		{"opensuse id", "linux", map[string]string{"ID": "opensuse-leap"}, familySUSE},
		{"arch id", "linux", map[string]string{"ID": "arch"}, familyArch},
		{"rhel via id_like", "linux", map[string]string{"ID": "rocky9", "ID_LIKE": "rhel centos fedora"}, familyRHEL},
		{"debian via id_like", "linux", map[string]string{"ID": "pop-os", "ID_LIKE": "ubuntu debian"}, familyDebian},
		{"suse via id_like", "linux", map[string]string{"ID": "sled-weird", "ID_LIKE": "suse"}, familySUSE},
		{"unknown linux", "linux", map[string]string{"ID": "voidlinux"}, familyOther},
		{"no os-release", "linux", nil, familyOther},
		{"darwin", "darwin", nil, familyDarwin},
		{"windows", "windows", nil, familyWindows},
		{"freebsd", "freebsd", nil, familyOther},
	}
	for _, c := range cases {
		if got := detectFamily(c.goos, c.osr); got != c.want {
			t.Errorf("%s: detectFamily=%q want %q", c.name, got, c.want)
		}
	}
}

func TestServiceVerbValidation(t *testing.T) {
	// Only the closed verb set is allowed; a bad verb or an unsafe service
	// name is rejected before it can reach an argument.
	if err := validService("start", "nginx"); err != nil {
		t.Fatalf("start nginx should be allowed: %v", err)
	}
	for _, bad := range []struct{ verb, svc string }{
		{"status", "nginx"}, // status is not a mutating verb here
		{"reload", "nginx"}, // reload is a config op, not a service verb
		{"rm -rf", "nginx"}, // not a verb
		{"start", "a;b"},    // shell metachar in name
		{"start", "a b"},    // space
		{"start", ""},       // empty
		{"start", "a\nb"},   // newline
		{"start", "../etc"}, // traversal-ish
	} {
		if err := validService(bad.verb, bad.svc); err == nil {
			t.Errorf("validService(%q,%q) should fail closed", bad.verb, bad.svc)
		}
	}
}

func TestNoneServiceManagerFailsClosed(t *testing.T) {
	n := selectServiceManager(familyWindows)
	if n.Available() {
		t.Fatal("windows service manager must not be available")
	}
	if _, err := n.Action("start", "nginx"); err == nil {
		t.Fatal("none manager Action must return an error, not a silent success")
	}
	if _, err := n.Status("nginx"); err == nil {
		t.Fatal("none manager Status must return an error")
	}
}

func TestPackageArgvAllManagers(t *testing.T) {
	cases := []struct {
		mgr, verb, want string
	}{
		{"apt-get", "install", "apt-get install -y --no-install-recommends -- nginx"},
		{"apt-get", "remove", "apt-get remove -y -- nginx"},
		{"apt-get", "upgrade", "apt-get install -y --only-upgrade -- nginx"},
		{"apt-get", "query", "dpkg-query -W -f ${Package}\t${Version}\t${db:Status-Abbrev}\n -- nginx"},
		{"dnf", "install", "dnf install -y -- nginx"},
		{"dnf", "remove", "dnf remove -y -- nginx"},
		{"dnf", "upgrade", "dnf upgrade -y -- nginx"},
		{"dnf", "query", "rpm -q nginx"},
		{"yum", "install", "yum install -y -- nginx"},
		{"zypper", "install", "zypper --non-interactive install -- nginx"},
		{"zypper", "upgrade", "zypper --non-interactive update -- nginx"},
		{"brew", "install", "brew install nginx"},
		{"brew", "remove", "brew uninstall nginx"},
		{"brew", "query", "brew list --versions nginx"},
	}
	for _, c := range cases {
		m := packageManagerByName(c.mgr)
		if m == nil {
			t.Fatalf("%s: unknown manager", c.mgr)
		}
		got, err := m.argv(c.verb, "nginx")
		if err != nil {
			t.Fatalf("%s %s: %v", c.mgr, c.verb, err)
		}
		if strings.Join(got, " ") != c.want {
			t.Errorf("%s %s: argv=%q want %q", c.mgr, c.verb, strings.Join(got, " "), c.want)
		}
	}
}

func TestPackageArgvRejectsBadInput(t *testing.T) {
	// A metacharacter name, "*", and an unknown manager are all rejected.
	for _, name := range []string{"nginx;rm", "*", "a b", "", "../x"} {
		if _, err := packageArgv("apt-get", name); err == nil {
			t.Errorf("packageArgv apt-get %q should be rejected", name)
		}
	}
	if _, err := packageArgv("pacman", "nginx"); err == nil || !strings.Contains(err.Error(), "package manager unavailable") {
		t.Fatalf("unknown manager must be unavailable, got %v", err)
	}
	var none PackageManager = nonePackageManager{}
	if none.Available() {
		t.Fatal("none package manager must not be available")
	}
	if _, err := none.InstallArgv("nginx"); err == nil {
		t.Fatal("none package manager must fail closed")
	}
}

func TestPackageManagerOrderPrefersFamily(t *testing.T) {
	cases := []struct {
		fam   OSFamily
		first string
	}{
		{familyDebian, "apt-get"},
		{familyRHEL, "dnf"},
		{familySUSE, "zypper"},
		{familyDarwin, "brew"},
	}
	for _, c := range cases {
		order := packageManagerOrder(c.fam)
		if len(order) == 0 || order[0] != c.first {
			t.Errorf("family %q order[0]=%v want %q", c.fam, order, c.first)
		}
		// every family order lists all five managers exactly once
		if len(order) != 5 {
			t.Errorf("family %q order must list all managers: %v", c.fam, order)
		}
	}
}

func TestConfigStoreValidateAndReload(t *testing.T) {
	cs := newConfigStore(familyDebian)
	out, err := cs.Validate("mystery-service", "/etc/mystery.conf")
	if err != nil || out != "no validator for service" {
		t.Fatalf("unknown validator should be a clean no-op, got out=%q err=%v", out, err)
	}
	// reload rejects an unsafe service name before any exec
	if _, err := cs.Reload("a;b"); err == nil {
		t.Fatal("reload must reject an unsafe service name")
	}
	// windows config reload is unsupported, not a silent success
	if _, err := newConfigStore(familyWindows).Reload("nginx"); err == nil {
		t.Fatal("windows reload must fail closed")
	}
	if !cs.Available() {
		t.Fatal("config store must be available (filesystem write)")
	}
}

func TestConfigWriteAllowed(t *testing.T) {
	if !configWriteAllowed("/etc/nginx/nginx.conf", []string{"/etc/nginx/"}) {
		t.Fatal("prefix match should be allowed")
	}
	if !configWriteAllowed("/anything", []string{"*"}) {
		t.Fatal("* should allow")
	}
	if configWriteAllowed("/etc/passwd", []string{"/etc/nginx/"}) {
		t.Fatal("out-of-prefix path must be denied")
	}
	if configWriteAllowed("/etc/passwd", nil) {
		t.Fatal("empty allow list is not allow-all")
	}
}

func TestTweakSysctlGateFailsClosed(t *testing.T) {
	tw := newTweaks(familyDebian)
	// hard-denied key can never be granted, even if named in the allow list
	if err := tw.SysctlSet("kernel.core_pattern", "|/x", []string{"kernel.core_pattern"}); err == nil {
		t.Fatal("hard-denied sysctl must never be settable")
	}
	// "*" is not allow-all
	if _, err := tw.SysctlGet("net.ipv4.ip_forward", []string{"*"}); err == nil {
		t.Fatal("'*' must not grant a sysctl read")
	}
	// malformed value is rejected even for a granted key
	if err := tw.SysctlSet("net.ipv4.ip_forward", "1\n2", []string{"net.ipv4.ip_forward"}); err == nil {
		t.Fatal("a sysctl value with a newline must be rejected")
	}
	// not granted at all
	if err := tw.SysctlSet("net.ipv4.ip_forward", "1", nil); err == nil {
		t.Fatal("an ungranted sysctl set must fail closed")
	}
}

func TestTweakUnitOverrideFailsClosed(t *testing.T) {
	tw := newTweaks(familyDebian)
	allow := []string{"/etc/systemd/system/"}
	// malformed inputs are rejected on every platform
	if err := tw.SetUnitOverride("bad name", "limit", "[Service]\n", allow); err == nil {
		t.Fatal("bad unit name must be rejected")
	}
	if err := tw.SetUnitOverride("nginx.service", "bad name", "[Service]\n", allow); err == nil {
		t.Fatal("bad override name must be rejected")
	}
	if err := tw.SetUnitOverride("nginx.service", "limit", "", allow); err == nil {
		t.Fatal("empty content must be rejected")
	}
	if err := tw.SetUnitOverride("nginx.service", "limit", strings.Repeat("a", overrideContentCap+1), allow); err == nil {
		t.Fatal("oversized content must be rejected")
	}
	if err := tw.SetUnitOverride("nginx.service", "limit", "a\x00b", allow); err == nil {
		t.Fatal("null byte in content must be rejected")
	}
	// out-of-policy write must fail closed. On Linux the specific gate is the
	// AllowConfigWrite prefix; off Linux it is the unsupported-platform gate.
	if err := tw.SetUnitOverride("nginx.service", "limit", "[Service]\nLimitNOFILE=1024\n", nil); err == nil {
		t.Fatal("an override with no granted path must fail closed")
	}
	if hostLinux() {
		if err := tw.SetUnitOverride("nginx.service", "limit", "[Service]\nLimitNOFILE=1024\n", []string{"/etc/nginx/"}); err == nil || !strings.Contains(err.Error(), "not granted") {
			t.Fatalf("out-of-prefix override must be denied, got %v", err)
		}
	}
	// a non-Linux family never writes a systemd drop-in
	if err := newTweaks(familyDarwin).SetUnitOverride("nginx.service", "limit", "[Service]\nLimitNOFILE=1024\n", []string{"*"}); err == nil {
		t.Fatal("darwin unit override must fail closed in v1")
	}
}

func TestTweakResourceLimitValidation(t *testing.T) {
	tw := newTweaks(familyDebian)
	// an unknown directive is rejected before any write path
	if err := tw.SetResourceLimit("nginx.service", "LimitBOGUS", "1024", []string{"*"}); err == nil {
		t.Fatal("unknown resource limit directive must be rejected")
	}
	// a malformed value is rejected
	if err := tw.SetResourceLimit("nginx.service", "LimitNOFILE", "1024; rm", []string{"*"}); err == nil {
		t.Fatal("malformed resource limit value must be rejected")
	}
}
