package main

import (
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// realTempDir resolves symlinks (macOS /var -> /private/var) so the chown
// symlink re-check sees the same prefix that was granted.
func realTempDir(t *testing.T) string {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestFsChownSelfByIDAndName(t *testing.T) {
	dir := realTempDir(t)
	f := filepath.Join(dir, "a.conf")
	if err := os.WriteFile(f, []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	me, err := user.Current()
	if err != nil {
		t.Skip(err)
	}
	engine := newTestEngine(&Entitlements{AllowFSWrite: []string{dir}})
	// Chown to our own uid/gid is permitted without privilege.
	src := `sys.fs.chown("` + f + `", "` + me.Uid + `", "` + me.Gid + `")` + "\n"
	if _, err := engine.Execute(src); err != nil {
		t.Fatalf("numeric: %v", err)
	}
	if ownerNameRE.MatchString(me.Username) {
		if _, err := engine.Execute(`sys.fs.chown("` + f + `", "` + me.Username + `", "")` + "\n"); err != nil {
			t.Fatalf("name: %v", err)
		}
	}
}

func TestFsChownRefusals(t *testing.T) {
	dir := realTempDir(t)
	outside := realTempDir(t)
	secret := filepath.Join(outside, "secret")
	if err := os.WriteFile(secret, []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(secret, link); err != nil {
		t.Fatal(err)
	}
	inside := filepath.Join(dir, "ok")
	if err := os.WriteFile(inside, []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name, src, want string
		ents            *Entitlements
	}{
		{"outside policy", `sys.fs.chown("` + secret + `", "0", "0")`, "not granted", &Entitlements{AllowFSWrite: []string{dir}}},
		{"no write grant", `sys.fs.chown("` + inside + `", "0", "0")`, "not granted", &Entitlements{AllowFSRead: []string{dir}}},
		{"symlink escape", `sys.fs.chown("` + link + `", "0", "0")`, "not granted", &Entitlements{AllowFSWrite: []string{dir}}},
		{"bad user name", `sys.fs.chown("` + inside + `", "-rf", "")`, "invalid name", &Entitlements{AllowFSWrite: []string{dir}}},
		{"unknown user", `sys.fs.chown("` + inside + `", "no_such_user_xq", "")`, "unknown user", &Entitlements{AllowFSWrite: []string{dir}}},
		{"unknown group", `sys.fs.chown("` + inside + `", "", "no_such_grp_xq")`, "unknown group", &Entitlements{AllowFSWrite: []string{dir}}},
		{"both empty", `sys.fs.chown("` + inside + `", "", "")`, "user or group required", &Entitlements{AllowFSWrite: []string{dir}}},
		{"id too large", `sys.fs.chown("` + inside + `", "4294967295", "")`, "invalid id", &Entitlements{AllowFSWrite: []string{dir}}},
	}
	for _, c := range cases {
		_, err := newTestEngine(c.ents).Execute(c.src + "\n")
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err=%v want %q", c.name, err, c.want)
		}
	}
}

func TestResolveOwnerID(t *testing.T) {
	if id, err := resolveOwnerID("", false); err != nil || id != -1 {
		t.Fatalf("empty: %d %v", id, err)
	}
	if id, err := resolveOwnerID("1000", true); err != nil || id != 1000 {
		t.Fatalf("numeric: %d %v", id, err)
	}
	if me, err := user.Current(); err == nil && ownerNameRE.MatchString(me.Username) {
		want, _ := strconv.Atoi(me.Uid)
		if id, err := resolveOwnerID(me.Username, false); err != nil || id != want {
			t.Fatalf("name: %d %v", id, err)
		}
	}
	for _, bad := range []string{"a b", "-1", "x;y", "../root", strings.Repeat("a", 40)} {
		if _, err := resolveOwnerID(bad, false); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestUnifiedDiff(t *testing.T) {
	cases := []struct {
		name, a, b, want string
	}{
		{"equal", "a\nb\n", "a\nb\n", ""},
		{"both empty", "", "", ""},
		{"change middle", "a\nb\nc\n", "a\nB\nc\n",
			"--- A\n+++ B\n@@ -1,3 +1,3 @@\n a\n-b\n+B\n c\n"},
		{"add to empty", "", "x\n", "--- A\n+++ B\n@@ -0,0 +1 @@\n+x\n"},
		{"delete all", "x\ny\n", "", "--- A\n+++ B\n@@ -1,2 +0,0 @@\n-x\n-y\n"},
		{"no newline at eof", "a\n", "a", "--- A\n+++ B\n@@ -1 +1 @@\n-a\n+a\n\\ No newline at end of file\n"},
		{"two hunks",
			"1\n2\n3\n4\n5\n6\n7\n8\n9\n10\n11\n12\n",
			"X\n2\n3\n4\n5\n6\n7\n8\n9\n10\n11\nY\n",
			"--- A\n+++ B\n@@ -1,4 +1,4 @@\n-1\n+X\n 2\n 3\n 4\n@@ -9,4 +9,4 @@\n 9\n 10\n 11\n-12\n+Y\n"},
		{"merged hunk",
			"1\n2\n3\n4\n5\n6\n7\n8\n",
			"X\n2\n3\n4\n5\n6\n7\nY\n",
			"--- A\n+++ B\n@@ -1,8 +1,8 @@\n-1\n+X\n 2\n 3\n 4\n 5\n 6\n 7\n-8\n+Y\n"},
		{"insert middle", "a\nc\n", "a\nb\nc\n", "--- A\n+++ B\n@@ -1,2 +1,3 @@\n a\n+b\n c\n"},
	}
	for _, c := range cases {
		got, err := unifiedDiff("A", "B", c.a, c.b)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if got != c.want {
			t.Errorf("%s:\ngot:\n%s\nwant:\n%s", c.name, got, c.want)
		}
	}
}

// TestMyersDiffApplies checks the edit script rebuilds both sides for
// interleaved changes the prefix/suffix trim does not cover.
func TestMyersDiffApplies(t *testing.T) {
	a := strings.Split("a b c a b b a x y z q", " ")
	b := strings.Split("c b a b a c x z y q r", " ")
	ops, err := myersDiff(a, b, diffMaxEdits, diffMaxWork)
	if err != nil {
		t.Fatal(err)
	}
	var gotA, gotB []string
	edits := 0
	for _, op := range ops {
		if op.kind != '+' {
			gotA = append(gotA, op.line)
		}
		if op.kind != '-' {
			gotB = append(gotB, op.line)
		}
		if op.kind != ' ' {
			edits++
		}
	}
	if strings.Join(gotA, " ") != strings.Join(a, " ") || strings.Join(gotB, " ") != strings.Join(b, " ") {
		t.Fatalf("script does not rebuild inputs: %v / %v", gotA, gotB)
	}
	if edits > len(a)+len(b) {
		t.Fatalf("too many edits: %d", edits)
	}
}

func TestMyersDiffEditCap(t *testing.T) {
	var a, b []string
	for i := 0; i < 50; i++ {
		a = append(a, "a"+strconv.Itoa(i))
		b = append(b, "b"+strconv.Itoa(i))
	}
	if _, err := myersDiff(a, b, 10, diffMaxWork); err == nil || !strings.Contains(err.Error(), "differ by more than") {
		t.Fatalf("cap not enforced: %v", err)
	}
}

func TestDiffLineAndWorkCaps(t *testing.T) {
	big := strings.Repeat("a\n", diffMaxLines/2+1)
	if _, err := unifiedDiff("A", "B", big, big); err == nil || !strings.Contains(err.Error(), "lines in total") {
		t.Fatalf("line cap not enforced: %v", err)
	}
	ok := strings.Repeat("a\n", diffMaxLines/2)
	if _, err := unifiedDiff("A", "B", ok, ok); err != nil {
		t.Fatalf("at the cap: %v", err)
	}
	var a, b []string
	for i := 0; i < 50; i++ {
		a = append(a, "a"+strconv.Itoa(i), "s")
		b = append(b, "b"+strconv.Itoa(i), "s")
	}
	if _, err := myersDiff(a, b, diffMaxEdits, 100); err == nil || !strings.Contains(err.Error(), "search steps") {
		t.Fatalf("work cap not enforced: %v", err)
	}
	if _, err := myersDiff(a, b, diffMaxEdits, diffMaxWork); err != nil {
		t.Fatalf("under the work cap: %v", err)
	}
}

func TestFsDiffPolicyAndCap(t *testing.T) {
	dir := t.TempDir()
	other := t.TempDir()
	a := filepath.Join(dir, "a")
	b := filepath.Join(dir, "b")
	out := filepath.Join(other, "c")
	big := filepath.Join(dir, "big")
	for p, body := range map[string]string{a: "x\ny\n", b: "x\nz\n", out: "q\n"} {
		if err := os.WriteFile(p, []byte(body), 0644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(big, make([]byte, hostFileCap+1), 0644); err != nil {
		t.Fatal(err)
	}
	engine := newTestEngine(&Entitlements{AllowFSRead: []string{dir}})
	got, err := engine.Execute(`print(sys.fs.diff("` + a + `", "` + b + `"))` + "\n")
	if err != nil {
		t.Fatal(err)
	}
	want := "--- " + a + "\n+++ " + b + "\n@@ -1,2 +1,2 @@\n x\n-y\n+z\n"
	if !strings.Contains(got, want) {
		t.Fatalf("got %q want %q", got, want)
	}
	for _, src := range []string{
		`sys.fs.diff("` + a + `", "` + out + `")`,
		`sys.fs.diff("` + out + `", "` + a + `")`,
	} {
		if _, err := engine.Execute(src + "\n"); err == nil || !strings.Contains(err.Error(), "not granted") {
			t.Errorf("%s: %v", src, err)
		}
	}
	if _, err := newTestEngine(&Entitlements{AllowFSWrite: []string{dir}}).Execute(`sys.fs.diff("` + a + `", "` + b + `")` + "\n"); err == nil || !strings.Contains(err.Error(), "not granted") {
		t.Errorf("write grant must not allow diff: %v", err)
	}
	if _, err := engine.Execute(`sys.fs.diff("` + a + `", "` + big + `")` + "\n"); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Errorf("cap not enforced: %v", err)
	}
}
