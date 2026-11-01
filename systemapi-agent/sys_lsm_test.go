package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func lsmFixture(t *testing.T, files map[string]string) lsmPaths {
	t.Helper()
	root := t.TempDir()
	for rel, body := range files {
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0644); err != nil {
			t.Fatal(err)
		}
	}
	return lsmPaths{
		selinuxFS:       filepath.Join(root, "sys/fs/selinux"),
		selinuxConfig:   filepath.Join(root, "etc/selinux/config"),
		apparmorFS:      filepath.Join(root, "sys/kernel/security/apparmor"),
		apparmorEnabled: filepath.Join(root, "sys/module/apparmor/parameters/enabled"),
	}
}

func TestReadSELinux(t *testing.T) {
	conf := "# comment\nSELINUX=enforcing\nSELINUXTYPE=targeted\n"
	cases := []struct {
		name  string
		files map[string]string
		want  selinuxStatus
	}{
		{"absent", nil, selinuxStatus{Mode: "disabled"}},
		{"enforcing", map[string]string{"sys/fs/selinux/enforce": "1", "etc/selinux/config": conf},
			selinuxStatus{Enabled: true, Mode: "enforcing", Policy: "targeted"}},
		{"permissive", map[string]string{"sys/fs/selinux/enforce": "0\n", "etc/selinux/config": "SELINUXTYPE=\"mls\"\n"},
			selinuxStatus{Enabled: true, Mode: "permissive", Policy: "mls"}},
		{"config only", map[string]string{"etc/selinux/config": "SELINUX=disabled\nSELINUXTYPE=targeted\n"},
			selinuxStatus{Mode: "disabled", Policy: "targeted"}},
		{"garbage enforce", map[string]string{"sys/fs/selinux/enforce": "maybe"}, selinuxStatus{Mode: "disabled"}},
	}
	for _, c := range cases {
		if got := readSELinux(lsmFixture(t, c.files)); got != c.want {
			t.Errorf("%s: got %+v want %+v", c.name, got, c.want)
		}
	}
}

func TestReadAppArmor(t *testing.T) {
	profiles := "/usr/sbin/cupsd (enforce)\ndocker-default (enforce)\n/usr/bin/man (complain)\nlsb_release (enforce)\nunconfined-thing (unconfined)\n\n"
	cases := []struct {
		name  string
		files map[string]string
		want  apparmorStatus
	}{
		{"absent", nil, apparmorStatus{}},
		{"disabled param", map[string]string{"sys/module/apparmor/parameters/enabled": "N\n",
			"sys/kernel/security/apparmor/profiles": profiles}, apparmorStatus{}},
		{"enabled", map[string]string{"sys/module/apparmor/parameters/enabled": "Y\n",
			"sys/kernel/security/apparmor/profiles": profiles},
			apparmorStatus{Enabled: true, Profiles: 5, Enforce: 3, Complain: 1}},
		{"enabled unreadable profiles", map[string]string{"sys/module/apparmor/parameters/enabled": "Y"},
			apparmorStatus{Enabled: true}},
		{"no param but securityfs dir", map[string]string{"sys/kernel/security/apparmor/profiles": "a (enforce)\n"},
			apparmorStatus{Enabled: true, Profiles: 1, Enforce: 1}},
	}
	for _, c := range cases {
		if got := readAppArmor(lsmFixture(t, c.files)); got != c.want {
			t.Errorf("%s: got %+v want %+v", c.name, got, c.want)
		}
	}
}

// TestLSMBuiltinsAbsent runs the Starlark builtins against an empty root:
// they must succeed with enabled=False rather than fail.
func TestLSMBuiltinsAbsent(t *testing.T) {
	saved := lsmRoots
	t.Cleanup(func() { lsmRoots = saved })
	lsmRoots = lsmFixture(t, nil)
	engine := newTestEngine(&Entitlements{})
	for _, fn := range []func() (interface{}, error){
		func() (interface{}, error) { return engine.linuxSELinux(nil, nil, nil, nil) },
		func() (interface{}, error) { return engine.linuxAppArmor(nil, nil, nil, nil) },
	} {
		v, err := fn()
		if err != nil {
			t.Fatal(err)
		}
		if s := v.(interface{ String() string }).String(); !strings.Contains(s, `"enabled": False`) {
			t.Fatalf("got %s", s)
		}
	}
}
