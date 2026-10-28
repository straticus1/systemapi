package main

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// fsPolicyRig lays out, under one temp dir (not symlink-resolved, so the
// macOS /var -> /private/var case is exercised):
//
//	data/            the granted dir
//	data/ok          a file inside the grant
//	data/link     -> app/        a dir symlink out of the grant
//	data/linkfile -> app/x       a file symlink out of the grant
//	data/dangle   -> app/new     a dangling symlink out of the grant
//	data-secrets/x   a sibling whose name shares the grant's string prefix
//	app/x            a file outside the grant
type fsPolicyRig struct {
	base, data, ok, link, linkfile, dangle, sibling, appX string
}

func newFSPolicyRig(t *testing.T) fsPolicyRig {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("symlink layout needs unix")
	}
	base := t.TempDir()
	r := fsPolicyRig{
		base:     base,
		data:     filepath.Join(base, "data"),
		ok:       filepath.Join(base, "data", "ok"),
		link:     filepath.Join(base, "data", "link"),
		linkfile: filepath.Join(base, "data", "linkfile"),
		dangle:   filepath.Join(base, "data", "dangle"),
		sibling:  filepath.Join(base, "data-secrets", "x"),
		appX:     filepath.Join(base, "app", "x"),
	}
	for _, d := range []string{r.data, filepath.Dir(r.sibling), filepath.Dir(r.appX)} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, f := range []string{r.ok, r.sibling, r.appX} {
		if err := os.WriteFile(f, []byte("secret\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for link, target := range map[string]string{
		r.link:     filepath.Dir(r.appX),
		r.linkfile: r.appX,
		r.dangle:   filepath.Join(base, "app", "new"),
	} {
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
	}
	return r
}

// escapes are paths a grant on data must refuse.
func (r fsPolicyRig) escapes() map[string]string {
	return map[string]string{
		"dotdot":         r.data + "/../app/x",
		"sibling prefix": r.sibling,
		"dir symlink":    filepath.Join(r.link, "x"),
		"file symlink":   r.linkfile,
		"relative":       "data/ok",
	}
}

func TestFsBuiltinsRefuseEscapes(t *testing.T) {
	r := newFSPolicyRig(t)
	grant := []string{r.data}
	ents := &Entitlements{AllowFSRead: grant, AllowFSWrite: grant}
	q := strconvQuote
	builtins := map[string]func(p string) string{
		"read":  func(p string) string { return `sys.fs.read(` + q(p) + `)` },
		"write": func(p string) string { return `sys.fs.write(` + q(p) + `, "pwned")` },
		"mkdir": func(p string) string { return `sys.fs.mkdir(` + q(p+"-dir") + `)` },
		"rm":    func(p string) string { return `sys.fs.rm(` + q(p) + `)` },
		"chmod": func(p string) string { return `sys.fs.chmod(` + q(p) + `, "0777")` },
		"stat":  func(p string) string { return `sys.fs.stat(` + q(p) + `)` },
		"chown": func(p string) string { return `sys.fs.chown(` + q(p) + `, "0", "0")` },
		"diff a": func(p string) string {
			return `sys.fs.diff(` + q(p) + `, ` + q(r.ok) + `)`
		},
		"diff b": func(p string) string {
			return `sys.fs.diff(` + q(r.ok) + `, ` + q(p) + `)`
		},
	}
	for bname, build := range builtins {
		for ename, p := range r.escapes() {
			if bname == "rm" && ename == "file symlink" {
				continue // rm acts on the link itself; covered below
			}
			if bname == "mkdir" && ename == "file symlink" {
				continue // linkfile-dir is a new name inside the grant
			}
			_, err := newTestEngine(ents).Execute(build(p) + "\n")
			if err == nil || !strings.Contains(err.Error(), "not granted") {
				t.Errorf("%s %s (%s): err=%v", bname, ename, p, err)
			}
		}
	}
	// Writes through a dangling symlink would create its target outside.
	for _, src := range []string{
		`sys.fs.write(` + q(r.dangle) + `, "pwned")`,
		`sys.fs.mkdir(` + q(filepath.Join(r.dangle, "sub")) + `)`,
		`sys.fs.chmod(` + q(r.dangle) + `, "0777")`,
	} {
		if _, err := newTestEngine(ents).Execute(src + "\n"); err == nil || !strings.Contains(err.Error(), "not granted") {
			t.Errorf("%s: err=%v", src, err)
		}
	}
	// Nothing outside the grant changed.
	if b, err := os.ReadFile(r.appX); err != nil || string(b) != "secret\n" {
		t.Fatalf("outside file changed: %q %v", b, err)
	}
	if b, err := os.ReadFile(r.sibling); err != nil || string(b) != "secret\n" {
		t.Fatalf("sibling file changed: %q %v", b, err)
	}
	for _, p := range []string{filepath.Join(r.base, "app", "new"), filepath.Join(r.base, "app", "x-dir"), r.data + "/../app/x-dir"} {
		if _, err := os.Lstat(p); !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("%s was created: %v", p, err)
		}
	}
	if fi, err := os.Stat(r.appX); err != nil || fi.Mode().Perm() != 0o644 {
		t.Fatalf("outside mode changed: %v %v", fi, err)
	}
}

func TestFsGlobDropsEscapes(t *testing.T) {
	r := newFSPolicyRig(t)
	engine := newTestEngine(&Entitlements{AllowFSRead: []string{r.data}})
	q := strconvQuote
	for _, pat := range []string{r.base + "/data-secrets/*", r.data + "/../app/*", r.base + "/dat*/x", "data/*"} {
		if _, err := engine.Execute(`sys.fs.glob(` + q(pat) + `)` + "\n"); err == nil || !strings.Contains(err.Error(), "not granted") {
			t.Errorf("%s: err=%v", pat, err)
		}
	}
	// The pattern is inside the grant, but the matches resolve outside it.
	out, err := engine.Execute(`print(sys.fs.glob(` + q(filepath.Join(r.link, "*")) + `))` + "\n")
	if err != nil || strings.TrimSpace(out) != "[]" {
		t.Fatalf("symlinked matches: out=%q err=%v", out, err)
	}
	out, err = engine.Execute(`print(sorted(sys.fs.glob(` + q(r.data+"/*") + `)))` + "\n")
	if err != nil || strings.Contains(out, "linkfile") || strings.Contains(out, "dangle") || !strings.Contains(out, r.ok) {
		t.Fatalf("grant glob: out=%q err=%v", out, err)
	}
}

func TestFsBuiltinsAllowInsideGrant(t *testing.T) {
	r := newFSPolicyRig(t)
	grant := []string{r.data}
	engine := newTestEngine(&Entitlements{AllowFSRead: grant, AllowFSWrite: grant})
	q := strconvQuote
	newFile := filepath.Join(r.data, "sub", "deeper", "f")
	src := strings.Join([]string{
		`sys.fs.mkdir(` + q(filepath.Dir(newFile)) + `)`,
		`sys.fs.write(` + q(newFile) + `, "hello")`,
		`print(sys.fs.read(` + q(r.data+"/sub/../sub/deeper/f") + `))`,
		`sys.fs.chmod(` + q(newFile) + `, "0600")`,
		`print(sys.fs.stat(` + q(newFile) + `)["mode"])`,
		`print(sys.fs.stat(` + q(filepath.Join(r.data, "missing")) + `)["exists"])`,
		`sys.fs.rm(` + q(r.linkfile) + `)`,
		`sys.fs.rm(` + q(filepath.Join(r.data, "sub")) + `, recursive=True)`,
	}, "\n") + "\n"
	out, err := engine.Execute(src)
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(out) != "hello\n0600\nFalse" {
		t.Fatalf("out=%q", out)
	}
	// rm of a symlink removed the link, not its target.
	if _, err := os.Lstat(r.linkfile); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("link still there: %v", err)
	}
	if _, err := os.Stat(r.appX); err != nil {
		t.Fatalf("link target removed: %v", err)
	}
}

func TestFsGrantPathPrefixBoundaries(t *testing.T) {
	cases := []struct {
		allow []string
		path  string
		want  bool
	}{
		{[]string{"/srv/app"}, "/srv/app/x", true},
		{[]string{"/srv/app/"}, "/srv/app/x", true},
		{[]string{"/srv/app"}, "/srv/app", true},
		{[]string{"/srv/app"}, "/srv/app-secrets/x", false},
		{[]string{"/srv/app"}, "/srv/apple", false},
		{[]string{"/srv/data"}, "/srv/data/../app/x", false},
		{[]string{"/srv/data"}, "/srv/data/./x", true},
		{[]string{"srv/data"}, "/srv/data/x", false},
		{[]string{""}, "/srv/data/x", false},
		{nil, "/srv/data/x", false},
		{[]string{"*"}, "relative/x", false},
		{[]string{"*"}, "", false},
		{[]string{"*"}, "/srv/x\x00y", false},
	}
	for _, c := range cases {
		_, err := fsGrantPath(c.allow, c.path, "read", true)
		if (err == nil) != c.want {
			t.Errorf("allow=%q path=%q: err=%v want allowed=%v", c.allow, c.path, err, c.want)
		}
	}
}

func TestConfigBuiltinsRefuseEscapes(t *testing.T) {
	r := newFSPolicyRig(t)
	grant := []string{r.data}
	engine := newTestEngine(&Entitlements{AllowFSRead: grant, AllowFSWrite: grant, AllowConfigWrite: grant})
	q := strconvQuote
	for _, p := range r.escapes() {
		for _, src := range []string{
			`print(sys.config.write(` + q(p) + `, "x")["error"])`,
			`print(sys.config.backup(` + q(p) + `)["error"])`,
			`print(sys.config.restore(` + q(p) + `)["error"])`,
		} {
			out, err := engine.Execute(src + "\n")
			if err != nil || !strings.Contains(out, "not granted") {
				t.Errorf("%s: out=%q err=%v", src, out, err)
			}
		}
		if configWriteAllowed(p, grant) {
			t.Errorf("configWriteAllowed(%q) passed", p)
		}
	}
}
