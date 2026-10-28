//go:build unix

package main

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// configRig: a granted dir holding app.conf, and an outside file a planted
// symlink points at.
func configRig(t *testing.T) (dir, conf, outside string) {
	t.Helper()
	dir = realTempDir(t)
	outside = filepath.Join(realTempDir(t), "shadow")
	if err := os.WriteFile(outside, []byte("root:secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	conf = filepath.Join(dir, "app.conf")
	if err := os.WriteFile(conf, []byte("v1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir, conf, outside
}

func assertUntouched(t *testing.T, outside string) {
	t.Helper()
	b, err := os.ReadFile(outside)
	if err != nil || string(b) != "root:secret\n" {
		t.Fatalf("outside file changed: %q %v", b, err)
	}
}

func TestAtomicWriteIgnoresPlantedTempAndBackupNames(t *testing.T) {
	dir, conf, outside := configRig(t)
	// The old fixed temp name, and backup names for the next few seconds.
	if err := os.Symlink(outside, conf+".systemapi.tmp"); err != nil {
		t.Fatal(err)
	}
	now := time.Now().Unix()
	for i := int64(0); i < 3; i++ {
		_ = os.Symlink(outside, conf+".bak."+strconv.FormatInt(now+i, 10))
	}
	cm := &ConfigManager{}
	if err := cm.AtomicWrite(conf, "v2\n"); err != nil {
		t.Fatal(err)
	}
	assertUntouched(t, outside)
	if b, _ := os.ReadFile(conf); string(b) != "v2\n" {
		t.Fatalf("conf=%q", b)
	}
	// The backup is a new regular 0600 file holding v1.
	backups, _ := filepath.Glob(conf + ".bak.*")
	found := false
	for _, b := range backups {
		fi, err := os.Lstat(b)
		if err != nil || !fi.Mode().IsRegular() {
			continue
		}
		data, _ := os.ReadFile(b)
		if string(data) == "v1\n" && fi.Mode().Perm() == 0o600 {
			found = true
		}
	}
	if !found {
		t.Fatalf("no regular backup of v1 in %v", backups)
	}
	// No temp files are left behind.
	if left, _ := filepath.Glob(filepath.Join(dir, ".app.conf.systemapi-*")); len(left) != 0 {
		t.Fatalf("temp left: %v", left)
	}
}

func TestAtomicWriteReplacesSwappedFinalSymlinkWithoutFollowing(t *testing.T) {
	_, conf, outside := configRig(t)
	if err := os.Remove(conf); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, conf); err != nil {
		t.Fatal(err)
	}
	// Backing up a symlink refuses (it would copy the target out).
	if err := (&ConfigManager{}).AtomicWrite(conf, "pwned\n"); err == nil {
		t.Fatal("write over a symlinked path accepted")
	}
	assertUntouched(t, outside)
	if _, err := (&ConfigManager{}).BackupConfig(conf); err == nil {
		t.Fatal("backup of a symlink accepted")
	}
}

func TestBackupRefusesPlantedName(t *testing.T) {
	_, conf, outside := configRig(t)
	// copyFile must not write through an existing name.
	dst := conf + ".bak.planted"
	if err := os.Symlink(outside, dst); err != nil {
		t.Fatal(err)
	}
	if err := copyFile(conf, dst); err == nil {
		t.Fatal("copy through a planted symlink accepted")
	}
	assertUntouched(t, outside)
}

func TestRestoreRefusesPlantedBackups(t *testing.T) {
	_, conf, outside := configRig(t)
	cm := &ConfigManager{}
	if _, err := cm.BackupConfig(conf); err != nil {
		t.Fatal(err)
	}
	// A newer "backup" that is a symlink to the outside file: restore must
	// refuse, not copy /etc/shadow into the config.
	planted := conf + ".bak.1999999999999999999"
	if err := os.Symlink(outside, planted); err != nil {
		t.Fatal(err)
	}
	if err := cm.RestoreConfig(conf); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("planted backup: %v", err)
	}
	if b, _ := os.ReadFile(conf); string(b) != "v1\n" {
		t.Fatalf("conf changed: %q", b)
	}
	if err := os.Remove(planted); err != nil {
		t.Fatal(err)
	}
	// A FIFO backup is refused without blocking.
	fifo := conf + ".bak.1999999999999999998"
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := cm.RestoreConfig(conf); err == nil {
		t.Fatal("fifo backup accepted")
	}
	_ = os.Remove(fifo)
	// Names that do not match path.bak.<digits> are ignored.
	if err := os.WriteFile(conf+".bak.zzz", []byte("evil\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// The target itself swapped for a symlink: restore replaces the link
	// and never writes through it.
	if err := os.WriteFile(conf, []byte("v2\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(conf); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, conf); err != nil {
		t.Fatal(err)
	}
	if err := cm.RestoreConfig(conf); err != nil {
		t.Fatal(err)
	}
	assertUntouched(t, outside)
	fi, err := os.Lstat(conf)
	if err != nil || !fi.Mode().IsRegular() {
		t.Fatalf("conf is not a regular file after restore: %v %v", fi, err)
	}
	if b, _ := os.ReadFile(conf); string(b) != "v1\n" {
		t.Fatalf("restored %q", b)
	}
}

func TestRestorePicksNewestBackupAcrossFormats(t *testing.T) {
	_, conf, _ := configRig(t)
	for name, body := range map[string]string{
		".bak.1700000000":          "old seconds\n",
		".bak.1800000000000000000": "newest nanos\n",
		".bak.1750000000":          "newer seconds\n",
	} {
		if err := os.WriteFile(conf+name, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := (&ConfigManager{}).RestoreConfig(conf); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(conf); string(b) != "newest nanos\n" {
		t.Fatalf("restored %q", b)
	}
}

func TestConfigValidateGated(t *testing.T) {
	dir, conf, outside := configRig(t)
	engine := newTestEngine(&Entitlements{AllowConfigWrite: []string{dir}, AllowFSRead: []string{"*"}})
	for _, p := range []string{outside, "-v", "relative.conf", dir + "/../" + filepath.Base(filepath.Dir(outside)) + "/shadow"} {
		out, err := engine.Execute(`print(sys.config.validate(` + strconvQuote(p) + `, "nsd")["error"])` + "\n")
		if err != nil || !strings.Contains(out, "not granted") {
			t.Errorf("%q: out=%q err=%v", p, out, err)
		}
	}
	// A read grant alone is not enough: validate needs the config grant.
	out, err := newTestEngine(&Entitlements{AllowFSRead: []string{dir}}).Execute(`print(sys.config.validate(` + strconvQuote(conf) + `, "nsd")["error"])` + "\n")
	if err != nil || !strings.Contains(out, "not granted") {
		t.Errorf("read-only grant: out=%q err=%v", out, err)
	}
	out, err = engine.Execute(`print(sys.config.validate(` + strconvQuote(conf) + `, "no-such-service")["output"])` + "\n")
	if err != nil || !strings.Contains(out, "no validator") {
		t.Errorf("granted: out=%q err=%v", out, err)
	}
}

func TestConfigCheckArgv(t *testing.T) {
	cases := map[string]string{
		"nsd":     "nsd-checkconf -- /etc/nsd/nsd.conf",
		"unbound": "unbound-checkconf -- /etc/nsd/nsd.conf",
		"named":   "named-checkconf -- /etc/nsd/nsd.conf",
		"bind":    "named-checkconf -- /etc/nsd/nsd.conf",
		"postfix": "postfix check",
	}
	for svc, want := range cases {
		argv, err := configCheckArgv(svc, "/etc/nsd/nsd.conf")
		if err != nil || strings.Join(argv, " ") != want {
			t.Errorf("%s: %q %v", svc, argv, err)
		}
	}
	for _, bad := range []string{"-x", "relative", ""} {
		if _, err := configCheckArgv("nsd", bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	if argv, err := configCheckArgv("other", "/x"); argv != nil || err != nil {
		t.Errorf("unknown service: %q %v", argv, err)
	}
}

func TestFsReadRefusesFIFOAndOversize(t *testing.T) {
	dir := realTempDir(t)
	fifo := filepath.Join(dir, "fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skip(err)
	}
	big := filepath.Join(dir, "big")
	if err := os.WriteFile(big, make([]byte, hostFileCap+1), 0o644); err != nil {
		t.Fatal(err)
	}
	engine := newTestEngine(&Entitlements{AllowFSRead: []string{dir}})
	done := make(chan error, 1)
	go func() {
		_, err := engine.Execute(`sys.fs.read(` + strconvQuote(fifo) + `)` + "\n")
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "not a regular file") {
			t.Fatalf("fifo: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("sys.fs.read blocked on a FIFO")
	}
	if _, err := engine.Execute(`sys.fs.read(` + strconvQuote(big) + `)` + "\n"); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("big: %v", err)
	}
}

func TestAtomicReplaceKeepsModeAndOwner(t *testing.T) {
	_, conf, _ := configRig(t)
	if err := os.Chmod(conf, 0o600); err != nil {
		t.Fatal(err)
	}
	wantUID, wantGID := os.Getuid(), os.Getgid()
	if os.Getuid() == 0 {
		wantUID, wantGID = 1234, 2345
		if err := os.Chown(conf, wantUID, wantGID); err != nil {
			t.Fatal(err)
		}
	}
	check := func(step string) {
		t.Helper()
		fi, err := os.Lstat(conf)
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != 0o600 {
			t.Fatalf("%s: mode %v, want 0600", step, fi.Mode().Perm())
		}
		uid, gid, ok := fileOwnerIDs(fi)
		if !ok || uid != wantUID || gid != wantGID {
			t.Fatalf("%s: owner %d:%d, want %d:%d", step, uid, gid, wantUID, wantGID)
		}
	}
	cm := &ConfigManager{}
	if err := cm.AtomicWrite(conf, "v2\n"); err != nil {
		t.Fatal(err)
	}
	check("write")
	if err := cm.RestoreConfig(conf); err != nil {
		t.Fatal(err)
	}
	check("restore")
	if b, _ := os.ReadFile(conf); string(b) != "v1\n" {
		t.Fatalf("restored %q", b)
	}
	// A new file is 0644.
	fresh := conf + ".new"
	if err := cm.AtomicWrite(fresh, "x"); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(fresh); fi.Mode().Perm() != 0o644 {
		t.Fatalf("new file mode %v", fi.Mode().Perm())
	}
}

func TestBackupAndRestoreRefuseHardLinks(t *testing.T) {
	_, conf, outside := configRig(t)
	planted := conf + ".bak.1999999999999999999"
	if err := os.Link(outside, planted); err != nil {
		t.Skip(err)
	}
	cm := &ConfigManager{}
	if err := cm.RestoreConfig(conf); err == nil || !strings.Contains(err.Error(), "hard link") {
		t.Fatalf("restore from a hard link: %v", err)
	}
	if b, _ := os.ReadFile(conf); string(b) != "v1\n" {
		t.Fatalf("conf changed: %q", b)
	}
	// The config itself hard-linked to a secret: backing it up would copy
	// the secret into a new file.
	if err := os.Remove(conf); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(outside, conf); err != nil {
		t.Fatal(err)
	}
	if _, err := cm.BackupConfig(conf); err == nil || !strings.Contains(err.Error(), "hard link") {
		t.Fatalf("backup of a hard link: %v", err)
	}
	if err := cm.AtomicWrite(conf, "x"); err == nil {
		t.Fatal("write over a hard-linked config accepted")
	}
	assertUntouched(t, outside)
}
