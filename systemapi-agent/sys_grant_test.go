package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseOSRelease(t *testing.T) {
	got := parseOSRelease("NAME=\"Debian GNU/Linux\"\nID=debian\nbad-key=nope\n# comment\n")
	if got["NAME"] != "Debian GNU/Linux" || got["ID"] != "debian" {
		t.Fatalf("%v", got)
	}
	if _, ok := got["bad-key"]; ok {
		t.Fatal("bad key kept")
	}
}

func TestParsePasswdDropsPassword(t *testing.T) {
	rows, err := parsePasswd("root:x:0:0:root:/root:/bin/bash\n")
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("%v", rows)
	}
	row := rows[0]
	for _, key := range []string{"name", "uid", "gid", "home", "shell"} {
		if _, ok := row[key]; !ok {
			t.Fatalf("missing %s in %v", key, row)
		}
	}
	if len(row) != 5 || row["name"] != "root" || row["uid"] != "0" || row["home"] != "/root" || row["shell"] != "/bin/bash" {
		t.Fatalf("%v", row)
	}
	if _, ok := row["password"]; ok || row["uid"] == "x" {
		t.Fatal("password field returned")
	}
	for _, v := range row {
		if v == "x" {
			t.Fatal("password field returned")
		}
	}
}

func TestMountBoundaries(t *testing.T) {
	if !pathWithin("/mnt", "/mnt/data") {
		t.Fatal("/mnt/data should be within /mnt")
	}
	if pathWithin("/mnt", "/mnt-evil") {
		t.Fatal("/mnt-evil matched /mnt")
	}
	if err := mountTargetPolicy("/etc/passwd", []string{"/mnt"}); err == nil || !strings.Contains(err.Error(), "mount target") {
		t.Fatal(err)
	}
	if err := mountTargetPolicy("/", []string{"/mnt"}); err == nil || !strings.Contains(err.Error(), "mount target denied") {
		t.Fatal(err)
	}
	if err := mountTargetPolicy("/mnt/data", []string{"*"}); err == nil || !strings.Contains(err.Error(), "mount target not allowed") {
		t.Fatal(err)
	}
	if err := mountTargetPolicy("/mnt/data", nil); err == nil || !strings.Contains(err.Error(), "mount target not allowed") {
		t.Fatal(err)
	}
	if err := mountTargetPolicy("/mnt/data", []string{"/mnt"}); err != nil {
		t.Fatal(err)
	}
}

func TestResolveMountSymlinkEscape(t *testing.T) {
	// t.TempDir is under /var on macOS, and /var is a hard-denied mount root.
	base, err := os.MkdirTemp("/tmp", "sah-mount-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(base); err != nil {
			t.Error(err)
		}
	})
	real, err := filepath.EvalSymlinks(base)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(real, "in")
	outside := filepath.Join(real, "out")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(outside, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}
	_, err = resolveMountTarget(filepath.Join(link, "file"), []string{dir})
	if err == nil || !strings.Contains(err.Error(), "mount target symlink escape") {
		t.Fatal(err)
	}
	_, err = resolveMountTarget("/etc/foo", []string{"/etc"})
	if err == nil || !strings.Contains(err.Error(), "mount target denied") {
		t.Fatal(err)
	}
}

func TestBlockSourceAndProcfs(t *testing.T) {
	if blockSourcePathOK("/dev") || blockSourcePathOK("/dev-evil/sda") {
		t.Fatal("block source accepted")
	}
	if !blockSourcePathOK("/dev/sda") {
		t.Fatal("/dev/sda rejected")
	}
	if !procfsRelOK("meminfo") || !procfsRelOK("1/status") || !procfsRelOK("net/dev") {
		t.Fatal("fixed procfs path rejected")
	}
	for _, bad := range []string{"../meminfo", "/etc/passwd", "1/maps", "1/mem"} {
		if procfsRelOK(bad) {
			t.Fatalf("accepted %s", bad)
		}
	}
}

func TestSysctlPathAndGrant(t *testing.T) {
	got, err := sysctlProcPath("net.ipv4.ip_forward")
	if err != nil || got != "/proc/sys/net/ipv4/ip_forward" {
		t.Fatalf("%s %v", got, err)
	}
	if _, err := sysctlProcPath("kernel.core_pattern"); err == nil || !strings.Contains(err.Error(), "sysctl not allowed") {
		t.Fatal(err)
	}
	got, err = sysctlProcPath("a..b")
	if err != nil || got != "/proc/sys/a/b" {
		t.Fatalf("%s %v", got, err)
	}
	if exactGrant([]string{"a..b"}, "a..b") || sysctlGranted([]string{"a..b"}, "a..b") {
		t.Fatal("dotdot key granted")
	}
	if sysctlGranted([]string{"kernel.core_pattern"}, "kernel.core_pattern") {
		t.Fatal("hard-denied sysctl granted from a Go list")
	}
	if !sysctlGranted([]string{"kernel.core_pattern", "net.ipv4.ip_forward"}, "net.ipv4.ip_forward") {
		t.Fatal("allowed sysctl rejected")
	}
}

func TestImageAndExactGrant(t *testing.T) {
	if !imageAllowed("nginx:latest") {
		t.Fatal("nginx:latest")
	}
	for _, bad := range []string{"nginx@sha", "../x", "a b"} {
		if imageAllowed(bad) {
			t.Fatalf("accepted %s", bad)
		}
	}
	if exactGrant([]string{"*"}, "nginx") || exactGrant([]string{"curl"}, "nginx") {
		t.Fatal("grant matched")
	}
	if !exactGrant([]string{"nginx"}, "nginx") {
		t.Fatal("exact name rejected")
	}
}

func TestInspectManifest(t *testing.T) {
	priv := "apiVersion: v1\nkind: Pod\nmetadata:\n  name: bad\nspec:\n  containers:\n  - name: c\n    securityContext:\n      privileged: true\n"
	if _, _, _, err := inspectManifest(priv); err == nil || !strings.Contains(err.Error(), "manifest denied") {
		t.Fatal(err)
	}
	host := "apiVersion: v1\nkind: Pod\nmetadata:\n  name: bad\nspec:\n  volumes:\n  - name: h\n    hostPath:\n      path: /etc\n"
	if _, _, _, err := inspectManifest(host); err == nil || !strings.Contains(err.Error(), "manifest denied") {
		t.Fatal(err)
	}
	secret := "apiVersion: v1\nkind: Secret\nmetadata:\n  name: s\n"
	if _, _, _, err := inspectManifest(secret); err == nil || !strings.Contains(err.Error(), "kind not allowed") {
		t.Fatal(err)
	}
	two := "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: a\n---\napiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: b\n"
	if _, _, _, err := inspectManifest(two); err == nil || !strings.Contains(err.Error(), "multiple documents rejected") {
		t.Fatal(err)
	}
	good := "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: my-config\n  namespace: default\ndata:\n  key: value\n"
	kind, name, ns, err := inspectManifest(good)
	if err != nil || kind != "ConfigMap" || name != "my-config" || ns != "default" {
		t.Fatalf("%s %s %s %v", kind, name, ns, err)
	}
	falsePositive := "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: cm\ndata:\n  hostPath: /tmp\n"
	if _, _, _, err := inspectManifest(falsePositive); err == nil || !strings.Contains(err.Error(), "manifest denied") {
		t.Fatal(err)
	}
}

func TestResolvBody(t *testing.T) {
	got, err := resolvBody([]string{"1.1.1.1"})
	if err != nil || got != "nameserver 1.1.1.1\n" {
		t.Fatalf("%q %v", got, err)
	}
	if _, err := resolvBody([]string{"dns.example"}); err == nil || !strings.Contains(err.Error(), "nameserver rejected") {
		t.Fatal(err)
	}
	if _, err := resolvBody([]string{"1.1.1.1\n"}); err == nil || !strings.Contains(err.Error(), "nameserver rejected") {
		t.Fatal(err)
	}
	if _, err := resolvBody([]string{"1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4"}); err == nil || !strings.Contains(err.Error(), "nameserver rejected") {
		t.Fatal(err)
	}
}
