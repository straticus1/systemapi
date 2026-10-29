package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// stateEngine is a test engine with backups under a temp dir.
func stateEngine(t *testing.T, ents *Entitlements) *SysscriptEngine {
	t.Helper()
	old := stateBackupDir
	stateBackupDir = filepath.Join(realTempDir(t), "backups")
	t.Cleanup(func() { stateBackupDir = old })
	return newTestEngine(ents)
}

func TestSysStateEnsureFileChangedThenUnchanged(t *testing.T) {
	dir := realTempDir(t)
	engine := stateEngine(t, &Entitlements{AllowConfigWrite: []string{dir}})
	p := filepath.Join(dir, "app.conf")
	script := `
r1 = sys.state.ensure_file(` + quoteStar(p) + `, "port=8080\n", mode="0640")
print(r1["changed"], r1["status"], r1["error"], r1["after"]["mode"])
r2 = sys.state.ensure_file(` + quoteStar(p) + `, "port=8080\n", mode="0640")
print(r2["changed"], r2["status"], r2["error"], r2["before"]["sha256"] == r2["after"]["sha256"])
`
	out, err := engine.Execute(script)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	want := "True changed  0640\nFalse ok  True\n"
	if out != want {
		t.Fatalf("output %q, want %q", out, want)
	}
	data, err := os.ReadFile(p)
	if err != nil || string(data) != "port=8080\n" {
		t.Fatalf("content %q %v", data, err)
	}
	if got := listDir(t, dir); strings.Join(got, ",") != "app.conf" {
		t.Fatalf("target dir holds %v", got)
	}
}

func TestSysStateEnsureNonIdempotent(t *testing.T) {
	h := newFakeHost()
	h.inert = true
	engine := stateEngine(t, &Entitlements{AllowSysctl: []string{"net.ipv4.ip_forward"}, AllowLinux: true})
	engine.stateBackend = &hostBackend{reads: h, newWrites: func() hostWrites { return h }}
	out, err := engine.Execute(`
r = sys.state.ensure_sysctl("net.ipv4.ip_forward", "1")
print(r["status"], r["changed"], r["error"])
`)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if !strings.HasPrefix(out, "failed False non_idempotent") {
		t.Fatalf("output %q", out)
	}
}

func TestSysStateCheckNeverBuildsWriteHost(t *testing.T) {
	h := newFakeHost()
	h.files["/srv/app/a.conf"] = &fakeFile{content: "old", mode: 0o644}
	built := 0
	engine := stateEngine(t, &Entitlements{
		AllowFSWrite:       []string{"/srv/app"},
		AllowPackages:      []string{"nginx"},
		AllowServiceReload: []string{"nginx"},
		AllowSysctl:        []string{"net.ipv4.ip_forward"},
		AllowLinux:         true,
	})
	engine.stateBackend = &hostBackend{reads: h, newWrites: func() hostWrites { built++; return h }}
	out, err := engine.Execute(`
def main():
    for r in [
        sys.state.check_file("/srv/app/a.conf", "new"),
        sys.state.check_directory("/srv/app/d"),
        sys.state.check_absent("/srv/app/a.conf"),
        sys.state.check_package("nginx"),
        sys.state.check_service("nginx"),
        sys.state.check_sysctl("net.ipv4.ip_forward", "1"),
    ]:
        print(r["status"])
main()
`)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if out != strings.Repeat("drift\n", 6) {
		t.Fatalf("output %q", out)
	}
	if built != 0 || h.writes != 0 {
		t.Fatalf("check built %d write hosts, made %d writes", built, h.writes)
	}
}

func TestSysStateDeniedOutsideGrant(t *testing.T) {
	dir := realTempDir(t)
	other := realTempDir(t)
	engine := stateEngine(t, &Entitlements{AllowFSWrite: []string{dir}})
	p := filepath.Join(other, "x.conf")
	out, err := engine.Execute(`
r1 = sys.state.ensure_file(` + quoteStar(p) + `, "x")
print(r1["status"], r1["changed"])
r2 = sys.state.ensure_service("nginx")
print(r2["status"])
`)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if out != "denied False\ndenied\n" {
		t.Fatalf("output %q", out)
	}
	if _, err := os.Lstat(p); err == nil {
		t.Fatal("denied file was written")
	}
}

func TestSysStateSensitiveResultHasNoHash(t *testing.T) {
	dir := realTempDir(t)
	engine := stateEngine(t, &Entitlements{AllowFSWrite: []string{dir}})
	p := filepath.Join(dir, "token")
	if err := os.WriteFile(p, []byte("old-secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := engine.Execute(`
c = sys.state.check_file(` + quoteStar(p) + `, "new-secret", mode="0600", sensitive=True)
print(c["status"], "sha256" in c["before"], "sha256" in c["desired"], c["diff"] == "", c["before"]["matches"])
r = sys.state.ensure_file(` + quoteStar(p) + `, "new-secret", mode="0600", sensitive=True)
print(r["status"], "sha256" in r["after"], r["after"]["matches"])
print(str(c) + str(r))
`)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	lines := strings.SplitN(out, "\n", 3)
	if lines[0] != "drift False False True False" || lines[1] != "changed False True" {
		t.Fatalf("output %q", out)
	}
	if strings.Contains(out, "secret") || strings.Contains(out, sha256Hex("new-secret")) {
		t.Fatalf("sensitive content leaked: %q", out)
	}
}

func TestSysStateRejectsBadArguments(t *testing.T) {
	engine := stateEngine(t, &Entitlements{AllowFSWrite: []string{"/srv"}})
	for _, src := range []string{
		`sys.state.ensure_file("relative/x", "")`,
		`sys.state.ensure_file("/srv/../etc/x", "")`,
		`sys.state.ensure_file("/srv/x", "", mode="4755")`,
		`sys.state.ensure_file("/srv/x", "", owner="bad name")`,
		`sys.state.ensure_directory("/")`,
		`sys.state.ensure_package("-rf")`,
		`sys.state.ensure_package("nginx", present=False, version="1")`,
		`sys.state.ensure_service("a b")`,
		`sys.state.ensure_service("nginx", restart_on=["file:/x"])`,
		`sys.state.ensure_sysctl("Bad.Key", "1")`,
		`sys.state.ensure_sysctl("net.ipv4.ip_forward", "1\n2")`,
	} {
		if _, err := engine.Execute(src); err == nil {
			t.Errorf("%s: accepted", src)
		}
	}
}

// quoteStar quotes s as a Starlark string literal.
func quoteStar(s string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(s) + `"`
}
