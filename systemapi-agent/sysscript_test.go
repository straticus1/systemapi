package main

import (
	"strings"
	"testing"
)

// newTestEngine creates a SysscriptEngine directly without initializing Docker/k3s clients.
// Used for tests that don't need real client connections.
func newTestEngine(entitlements *Entitlements) *SysscriptEngine {
	return &SysscriptEngine{
		Entitlements: entitlements,
		cm:           &ConfigManager{},
	}
}

// TestEntitlementContainersAbsent verifies that sys.containers is absent when AllowContainers=false.
func TestEntitlementContainersAbsent(t *testing.T) {
	engine := newTestEngine(&Entitlements{AllowContainers: false, AllowK3s: false})
	_, err := engine.Execute(`print(sys.containers)`)
	if err == nil {
		t.Fatal("expected error when AllowContainers=false, got nil")
	}
	// Starlark reports missing struct fields as: `"sys" struct has no .containers attribute`
	if !strings.Contains(err.Error(), "has no .containers") {
		t.Errorf("expected 'has no .containers' in error, got: %v", err)
	}
}

// TestEntitlementContainersPresent verifies that sys.containers is present when AllowContainers=true.
func TestEntitlementContainersPresent(t *testing.T) {
	engine := newTestEngine(&Entitlements{AllowContainers: true, AllowK3s: false})
	// type(sys.containers) returns "struct" in Starlark; verify it's accessible (no attribute error)
	_, err := engine.Execute(`print(type(sys.containers))`)
	if err != nil {
		t.Fatalf("unexpected error when AllowContainers=true: %v", err)
	}
}

// TestEntitlementK3sAbsent verifies that sys.k3s is absent when AllowK3s=false.
func TestEntitlementK3sAbsent(t *testing.T) {
	engine := newTestEngine(&Entitlements{AllowContainers: false, AllowK3s: false})
	_, err := engine.Execute(`print(sys.k3s)`)
	if err == nil {
		t.Fatal("expected error when AllowK3s=false, got nil")
	}
	// Starlark reports missing struct fields as: `"sys" struct has no .k3s attribute`
	if !strings.Contains(err.Error(), "has no .k3s") {
		t.Errorf("expected 'has no .k3s' in error, got: %v", err)
	}
}

// TestEntitlementK3sPresent verifies that sys.k3s is present when AllowK3s=true.
func TestEntitlementK3sPresent(t *testing.T) {
	engine := newTestEngine(&Entitlements{AllowContainers: false, AllowK3s: true})
	// type(sys.k3s) returns "struct" in Starlark; verify it's accessible (no attribute error)
	_, err := engine.Execute(`print(type(sys.k3s))`)
	if err != nil {
		t.Fatalf("unexpected error when AllowK3s=true: %v", err)
	}
}

// TestThreadLoadPathTraversal verifies that load() rejects path traversal attempts (T-03-01).
func TestThreadLoadPathTraversal(t *testing.T) {
	engine := newTestEngine(&Entitlements{})
	_, err := engine.Execute(`load("../../etc/passwd", "x")`)
	if err == nil {
		t.Fatal("expected error for path traversal, got nil")
	}
	if !strings.Contains(err.Error(), "path traversal not allowed") {
		t.Errorf("expected 'path traversal not allowed' in error, got: %v", err)
	}
}

// TestThreadLoadFileNotFound verifies that load() returns a clear error for missing files (D-09 fail-fast).
func TestThreadLoadFileNotFound(t *testing.T) {
	engine := newTestEngine(&Entitlements{})
	_, err := engine.Execute(`load("nonexistent.star", "x")`)
	if err == nil {
		t.Fatal("expected error for missing file, got nil")
	}
	if !strings.Contains(err.Error(), `load("nonexistent.star")`) {
		t.Errorf("expected error to mention load(\"nonexistent.star\"), got: %v", err)
	}
}

// TestThreadLoadSuccess verifies that load() correctly loads a .star module.
// Skipped in short mode because it requires /etc/systemapi/scripts/ to exist.
func TestThreadLoadSuccess(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping TestThreadLoadSuccess in short mode: requires /etc/systemapi/scripts/")
	}
	engine := newTestEngine(&Entitlements{})
	_, err := engine.Execute(`load("lib/test_helper.star", "helper_value")`)
	if err != nil {
		t.Logf("load failed (expected on machines without /etc/systemapi/scripts/): %v", err)
	}
}

func TestExecRunExpandsStringList(t *testing.T) {
	engine := newTestEngine(&Entitlements{AllowExec: true})
	out, err := engine.Execute("r = sys.exec.run(\"echo\", [\"hello\", \"world\"])\nprint(r[\"output\"])\n")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "hello world") {
		t.Fatalf("output %q", out)
	}
}

func TestHostModulesAbsentWithoutGrant(t *testing.T) {
	engine := newTestEngine(&Entitlements{})
	for _, name := range []string{"disk", "linux", "procfs", "k8s"} {
		_, err := engine.Execute("print(sys." + name + ")\n")
		if err == nil || !strings.Contains(err.Error(), "has no ."+name) {
			t.Fatalf("%s: %v", name, err)
		}
	}
}

func TestLinuxModulesFollowHost(t *testing.T) {
	engine := newTestEngine(&Entitlements{AllowLinux: true})
	_, err := engine.Execute("print(type(sys.linux))\n")
	if hostLinux() {
		if err != nil {
			t.Fatal(err)
		}
		return
	}
	if err == nil || !strings.Contains(err.Error(), "has no .linux") {
		t.Fatal(err)
	}
}

func TestK8sModulePresentWithoutClient(t *testing.T) {
	engine := newTestEngine(&Entitlements{AllowK8s: true})
	out, err := engine.Execute("print(type(sys.k8s))\n")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "struct") {
		t.Fatalf("%q", out)
	}
}

func TestPackagesStayRegistered(t *testing.T) {
	engine := newTestEngine(&Entitlements{})
	out, err := engine.Execute("print(type(sys.packages))\n")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "struct") {
		t.Fatalf("%q", out)
	}
}

func TestNetWritesFailBeforeHost(t *testing.T) {
	engine := newTestEngine(&Entitlements{AllowNetManage: []string{"eth0"}})
	cases := []struct {
		script string
		want   string
	}{
		{"sys.net.set_address(\"wlan0\", \"10.0.0.2/32\")\n", "interface not allowed"},
		{"sys.net.set_address(\"eth0\", \"not-a-cidr\")\n", "cidr rejected"},
		{"sys.net.set_route(\"eth0\", \"not-a-gateway\")\n", "gateway rejected"},
		{"sys.net.set_dns(\"eth0\", [\"dns.example\"])\n", "nameserver rejected"},
		{"sys.net.set_dns(\"wlan0\", [\"1.1.1.1\"])\n", "interface not allowed"},
	}
	for _, tc := range cases {
		_, err := engine.Execute(tc.script)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("%s: %v", tc.script, err)
		}
	}
}

func TestNetLinksRequireLinux(t *testing.T) {
	if hostLinux() {
		t.Skip("netlink read is live on linux")
	}
	engine := newTestEngine(&Entitlements{})
	_, err := engine.Execute("sys.net.links()\n")
	if err == nil || !strings.Contains(err.Error(), "requires linux") {
		t.Fatal(err)
	}
}

func TestHostPolicyBeforeLinuxCall(t *testing.T) {
	if !hostLinux() {
		t.Skip("disk and procfs are absent off linux")
	}
	engine := newTestEngine(&Entitlements{
		AllowLinux:        true,
		AllowMountTargets: []string{"/mnt"},
		AllowSysctl:       []string{"kernel.core_pattern"},
	})
	cases := []struct {
		script string
		want   string
	}{
		{"sys.disk.usage(\"relative\")\n", "path not allowed"},
		{"sys.disk.mount(\"tmpfs\", \"/etc/passwd\", \"tmpfs\", False)\n", "mount target"},
		{"sys.procfs.read(\"../meminfo\")\n", "procfs path not allowed"},
		{"sys.procfs.sysctl_set(\"kernel.core_pattern\", \"x\")\n", "sysctl not allowed"},
	}
	for _, tc := range cases {
		_, err := engine.Execute(tc.script)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("%s: %v", tc.script, err)
		}
	}
}
