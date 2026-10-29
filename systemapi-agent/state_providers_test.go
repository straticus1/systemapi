package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// fakeHost is an in-memory host. It implements hostReads and hostWrites and
// counts every backend call, so a test can prove a denied resource never
// reached the backend and a check never wrote.
type fakeHost struct {
	files    map[string]*fakeFile
	packages map[string]string // name -> version; absent = not installed
	active   map[string]bool
	enabled  map[string]bool
	sysctls  map[string]string
	reads    int
	writes   int
	backups  int
	// inert drops every write, so a verify sees the old state.
	inert bool
}

type fakeFile struct {
	dir      bool
	content  string
	mode     uint32
	uid, gid int
}

func newFakeHost() *fakeHost {
	return &fakeHost{
		files:    map[string]*fakeFile{},
		packages: map[string]string{},
		active:   map[string]bool{},
		enabled:  map[string]bool{},
		sysctls:  map[string]string{},
	}
}

func (h *fakeHost) stat(root, target string) (pathFacts, error) {
	h.reads++
	f, ok := h.files[target]
	if !ok {
		return missingPath, nil
	}
	pf := pathFacts{Exists: true, Type: "file", Mode: f.mode, UID: f.uid, GID: f.gid, Size: int64(len(f.content))}
	if f.dir {
		pf.Type = "dir"
	}
	return pf, nil
}

func (h *fakeHost) readFile(root, target string, max int) ([]byte, error) {
	h.reads++
	f, ok := h.files[target]
	if !ok || f.dir {
		return nil, errors.New("not a regular file")
	}
	return []byte(f.content), nil
}

func (h *fakeHost) packageQuery(ctx context.Context, name string, allow []string) (bool, string, error) {
	h.reads++
	v, ok := h.packages[name]
	return ok, v, nil
}

func (h *fakeHost) serviceState(ctx context.Context, name string) (bool, bool, error) {
	h.reads++
	return h.active[name], h.enabled[name], nil
}

func (h *fakeHost) sysctlGet(key string, allow []string) (string, error) {
	h.reads++
	return h.sysctls[key], nil
}

func (h *fakeHost) backup(root, target string) (string, error) {
	h.writes++
	h.backups++
	return strconv.Itoa(h.backups), nil
}

func (h *fakeHost) replaceFile(root, target string, data []byte, mode os.FileMode, uid, gid int) error {
	h.writes++
	if h.inert {
		return nil
	}
	h.files[target] = &fakeFile{content: string(data), mode: uint32(mode.Perm()), uid: uid, gid: gid}
	return nil
}

func (h *fakeHost) mkdirAll(root, target string, mode os.FileMode) error {
	h.writes++
	if !h.inert {
		h.files[target] = &fakeFile{dir: true, mode: uint32(mode.Perm())}
	}
	return nil
}

func (h *fakeHost) chmod(root, target string, mode os.FileMode) error {
	h.writes++
	if f, ok := h.files[target]; ok && !h.inert {
		f.mode = rawMode(mode)
	}
	return nil
}

func (h *fakeHost) chown(root, target string, uid, gid int) error {
	h.writes++
	if f, ok := h.files[target]; ok && !h.inert {
		if uid >= 0 {
			f.uid = uid
		}
		if gid >= 0 {
			f.gid = gid
		}
	}
	return nil
}

func (h *fakeHost) remove(root, target string) error {
	h.writes++
	if !h.inert {
		delete(h.files, target)
	}
	return nil
}

func (h *fakeHost) packageChange(ctx context.Context, verb, name string, allow []string) error {
	h.writes++
	if h.inert {
		return nil
	}
	if verb == "remove" {
		delete(h.packages, name)
	} else {
		h.packages[name] = "1.0"
	}
	return nil
}

func (h *fakeHost) serviceAction(ctx context.Context, verb, name string) error {
	h.writes++
	if h.inert {
		return nil
	}
	switch verb {
	case "start", "restart":
		h.active[name] = true
	case "stop":
		h.active[name] = false
	case "enable":
		h.enabled[name] = true
	case "disable":
		h.enabled[name] = false
	}
	return nil
}

func (h *fakeHost) sysctlSet(key, value string, allow []string) error {
	h.writes++
	if !h.inert {
		h.sysctls[key] = value
	}
	return nil
}

// stateGrants grants dir for file writes, plus the named package, service
// and sysctl.
func stateGrants(dir string) *Entitlements {
	return &Entitlements{
		AllowFSWrite:       []string{dir},
		AllowPackages:      []string{"nginx"},
		AllowServiceReload: []string{"nginx"},
		AllowSysctl:        []string{"net.ipv4.ip_forward"},
		AllowLinux:         true,
	}
}

// ensureVia runs check, apply and verify against h.
func ensureVia(ctx context.Context, a Applier, ents *Entitlements, h *fakeHost) resourceResult {
	ro := newReadOnlyHost(ents, h)
	res := checkResource(ctx, a, ro)
	return applyChecked(ctx, a, ro, newWriteHost(ents, h), res)
}

func uid() int { return os.Getuid() }

func TestProvidersCheckApplyCheckConverges(t *testing.T) {
	ctx := context.Background()
	dir := realTempDir(t)
	backups := realTempDir(t)
	old := stateBackupDir
	stateBackupDir = backups
	t.Cleanup(func() { stateBackupDir = old })
	ents := stateGrants(dir)
	own := strconv.Itoa(uid())
	resources := []Applier{
		&fileResource{path: filepath.Join(dir, "a.conf"), content: "x=1\n", mode: 0o640, owner: own},
		&dirResource{path: filepath.Join(dir, "d"), mode: 0o750},
		&absentResource{path: filepath.Join(dir, "gone")},
		&packageResource{name: "nginx", present: true},
		&serviceResource{name: "nginx", running: true, enabled: true},
		&sysctlResource{key: "net.ipv4.ip_forward", value: "1"},
	}
	h := newFakeHost()
	h.files[filepath.Join(dir, "a.conf")] = &fakeFile{content: "x=0\n", mode: 0o644, uid: uid()}
	h.files[filepath.Join(dir, "gone")] = &fakeFile{content: "old"}
	h.sysctls["net.ipv4.ip_forward"] = "0"
	for _, r := range resources {
		res := ensureVia(ctx, r, ents, h)
		if res.Status != statusChanged {
			t.Fatalf("%s: status %s error %q", r.Key(), res.Status, res.Error)
		}
		again := checkResource(ctx, r, newReadOnlyHost(ents, h))
		if again.Status != statusOK {
			t.Fatalf("%s: second check %s %v", r.Key(), again.Status, again.diff.Fields)
		}
	}
	if h.backups != 2 {
		t.Fatalf("backups = %d, want 2 (the replaced file and the removed one)", h.backups)
	}
}

func TestProvidersDeniedMakesNoBackendCall(t *testing.T) {
	ctx := context.Background()
	dir := realTempDir(t)
	other := realTempDir(t)
	ents := stateGrants(dir)
	ents.AllowLinux = false
	resources := []Applier{
		&fileResource{path: filepath.Join(other, "a"), content: "x", mode: 0o644},
		&fileResource{path: dir + "/../" + filepath.Base(other) + "/a", content: "x", mode: 0o644},
		&dirResource{path: filepath.Join(other, "d"), mode: 0o755},
		&absentResource{path: filepath.Join(other, "g")},
		&packageResource{name: "curl", present: true},
		&serviceResource{name: "sshd", running: true, enabled: true},
		&sysctlResource{key: "net.ipv4.ip_forward", value: "1"}, // allow_linux off
	}
	// A config_write grant does not cover directory and absent.
	cfgOnly := &Entitlements{AllowConfigWrite: []string{dir}}
	resources2 := []Applier{
		&dirResource{path: filepath.Join(dir, "d"), mode: 0o755},
		&absentResource{path: filepath.Join(dir, "g")},
	}
	h := newFakeHost()
	for _, r := range resources {
		if res := ensureVia(ctx, r, ents, h); res.Status != statusDenied {
			t.Errorf("%s: status %s, want denied", r.Key(), res.Status)
		}
	}
	for _, r := range resources2 {
		if res := ensureVia(ctx, r, cfgOnly, h); res.Status != statusDenied {
			t.Errorf("%s: status %s, want denied under a config_write grant", r.Key(), res.Status)
		}
	}
	// A wildcard is not a package or service grant.
	star := &Entitlements{AllowPackages: []string{"*"}, AllowServiceReload: []string{"*"}}
	for _, r := range []Applier{&packageResource{name: "nginx", present: true}, &serviceResource{name: "nginx", running: true}} {
		if res := ensureVia(ctx, r, star, h); res.Status != statusDenied {
			t.Errorf("%s: wildcard grant accepted (%s)", r.Key(), res.Status)
		}
	}
	if h.reads != 0 || h.writes != 0 {
		t.Fatalf("denied resources reached the backend: %d reads, %d writes", h.reads, h.writes)
	}
	// Apply re-checks the grant too: a WriteHost with no grants refuses.
	rw := newWriteHost(&Entitlements{}, h)
	if err := rw.ReplaceFile(filepath.Join(dir, "a"), grantFileWrite, false, nil, 0o644, -1, -1); !errors.Is(err, errStateDenied) {
		t.Fatalf("apply without grant: %v", err)
	}
	if h.writes != 0 {
		t.Fatal("ungranted apply reached the backend")
	}
}

func TestFileProviderSensitiveDropsHash(t *testing.T) {
	ctx := context.Background()
	dir := realTempDir(t)
	ents := stateGrants(dir)
	p := filepath.Join(dir, "secret")
	h := newFakeHost()
	h.files[p] = &fakeFile{content: "old-password", mode: 0o600}
	r := &fileResource{path: p, content: "new-password", mode: 0o600, sensitive: true}
	res := checkResource(ctx, r, newReadOnlyHost(ents, h))
	if res.Status != statusDrift {
		t.Fatalf("status %s", res.Status)
	}
	for _, f := range []Facts{res.Before, res.Desired} {
		if _, ok := f["sha256"]; ok {
			t.Errorf("sensitive facts carry sha256: %v", f)
		}
		if _, ok := f["size"]; ok {
			t.Errorf("sensitive facts carry size: %v", f)
		}
	}
	if m, ok := res.Before["matches"].(bool); !ok || m {
		t.Errorf("matches = %v, want false", res.Before["matches"])
	}
	if res.Diff != "" || res.diff.Text != "" {
		t.Errorf("sensitive diff: %q", res.Diff)
	}
	// A non-sensitive file reports its hash and a diff.
	r.sensitive = false
	res = checkResource(ctx, r, newReadOnlyHost(ents, h))
	if res.Before["sha256"] != sha256Hex("old-password") || !strings.Contains(res.Diff, "+new-password") {
		t.Errorf("non-sensitive: before %v diff %q", res.Before, res.Diff)
	}
}

func TestPackageVersionIsCheckOnly(t *testing.T) {
	ctx := context.Background()
	ents := stateGrants("/nonexistent")
	h := newFakeHost()
	h.packages["nginx"] = "1.0"
	r := &packageResource{name: "nginx", present: true, version: "2.0"}
	res := ensureVia(ctx, r, ents, h)
	if res.Status != statusFailed || !strings.HasPrefix(res.Error, "version_pin_unsupported") {
		t.Fatalf("status %s error %q", res.Status, res.Error)
	}
	if h.writes != 0 {
		t.Fatal("a version pin reached the package manager")
	}
	r.version = "1.0"
	if res := checkResource(ctx, r, newReadOnlyHost(ents, h)); res.Status != statusOK {
		t.Fatalf("matching version: %s", res.Status)
	}
}

func TestApplyVerifyNonIdempotent(t *testing.T) {
	ctx := context.Background()
	dir := realTempDir(t)
	h := newFakeHost()
	h.inert = true
	res := ensureVia(ctx, &sysctlResource{key: "net.ipv4.ip_forward", value: "1"}, stateGrants(dir), h)
	if res.Status != statusFailed || !strings.HasPrefix(res.Error, "non_idempotent") {
		t.Fatalf("status %s error %q", res.Status, res.Error)
	}
}

func TestCheckSkippedAfterCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	h := newFakeHost()
	res := checkResource(ctx, &sysctlResource{key: "net.ipv4.ip_forward", value: "1"}, newReadOnlyHost(stateGrants("/x"), h))
	if res.Status != statusSkipped || h.reads != 0 {
		t.Fatalf("status %s reads %d", res.Status, h.reads)
	}
}

func TestBackupRefusedInsideWriteGrant(t *testing.T) {
	ctx := context.Background()
	dir := realTempDir(t)
	old := stateBackupDir
	stateBackupDir = filepath.Join(dir, "backups")
	t.Cleanup(func() { stateBackupDir = old })
	h := newFakeHost()
	p := filepath.Join(dir, "a")
	h.files[p] = &fakeFile{content: "old", mode: 0o644}
	res := ensureVia(ctx, &fileResource{path: p, content: "new", mode: 0o644}, stateGrants(dir), h)
	if res.Status != statusFailed || !strings.Contains(res.Error, "overlaps a write grant") {
		t.Fatalf("status %s error %q", res.Status, res.Error)
	}
	if h.writes != 0 {
		t.Fatal("backup inside a grant reached the backend")
	}
}

// listDir returns the sorted names in dir.
func listDir(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	sort.Strings(names)
	return names
}

// TestOSFileProviderConverges runs the real backend: check, apply, check on
// a temp dir; the target dir gains no entry besides the target, and the
// backups land under stateBackupDir, keeping the newest five.
func TestOSFileProviderConverges(t *testing.T) {
	ctx := context.Background()
	dir := realTempDir(t)
	backups := filepath.Join(realTempDir(t), "backups")
	old := stateBackupDir
	stateBackupDir = backups
	t.Cleanup(func() { stateBackupDir = old })
	ents := &Entitlements{AllowConfigWrite: []string{dir}}
	b := osHostBackend()
	target := filepath.Join(dir, "app.conf")
	if err := os.WriteFile(filepath.Join(dir, "other.conf"), []byte("keep"), 0o644); err != nil {
		t.Fatal(err)
	}
	ro := newReadOnlyHost(ents, b.reads)
	for i := 0; i < 7; i++ {
		r := &fileResource{path: target, content: "v=" + strconv.Itoa(i) + "\n", mode: 0o640, owner: strconv.Itoa(uid())}
		res := applyChecked(ctx, r, ro, newWriteHost(ents, b.newWrites()), checkResource(ctx, r, ro))
		if res.Status != statusChanged {
			t.Fatalf("apply %d: %s %q", i, res.Status, res.Error)
		}
		if i > 0 && res.BackupID == "" {
			t.Fatalf("apply %d: no backup id", i)
		}
		if strings.ContainsRune(res.BackupID, filepath.Separator) {
			t.Fatalf("backup id is not a basename: %q", res.BackupID)
		}
		if again := checkResource(ctx, r, ro); again.Status != statusOK {
			t.Fatalf("apply %d: recheck %s %v", i, again.Status, again.diff.Fields)
		}
		if got := listDir(t, dir); strings.Join(got, ",") != "app.conf,other.conf" {
			t.Fatalf("apply %d: target dir holds %v", i, got)
		}
	}
	data, err := os.ReadFile(target)
	if err != nil || string(data) != "v=6\n" {
		t.Fatalf("content %q %v", data, err)
	}
	if fi, _ := os.Stat(target); fi.Mode().Perm() != 0o640 {
		t.Fatalf("mode %v", fi.Mode())
	}
	sum := sha256Hex(target)
	got := listDir(t, filepath.Join(backups, sum))
	if len(got) != stateBackupKeep {
		t.Fatalf("backups kept %d, want %d: %v", len(got), stateBackupKeep, got)
	}
	newest, _ := os.ReadFile(filepath.Join(backups, sum, got[len(got)-1]))
	if string(newest) != "v=5\n" {
		t.Fatalf("newest backup %q", newest)
	}
	if fi, _ := os.Stat(filepath.Join(backups, sum)); fi.Mode().Perm() != 0o700 {
		t.Fatalf("backup dir mode %v", fi.Mode())
	}
	if fi, _ := os.Stat(filepath.Join(backups, sum, got[0])); fi.Mode().Perm() != 0o600 {
		t.Fatalf("backup file mode %v", fi.Mode())
	}
}

// A symlink at the target is replaced by a file; what it pointed at is not
// read, backed up or written.
func TestOSFileProviderReplacesSymlinkNotItsTarget(t *testing.T) {
	ctx := context.Background()
	dir := realTempDir(t)
	outside := realTempDir(t)
	old := stateBackupDir
	stateBackupDir = filepath.Join(realTempDir(t), "b")
	t.Cleanup(func() { stateBackupDir = old })
	secret := filepath.Join(outside, "secret")
	if err := os.WriteFile(secret, []byte("s3cret"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "app.conf")
	if err := os.Symlink(secret, link); err != nil {
		t.Fatal(err)
	}
	ents := &Entitlements{AllowFSWrite: []string{dir}}
	b := osHostBackend()
	ro := newReadOnlyHost(ents, b.reads)
	r := &fileResource{path: link, content: "safe\n", mode: 0o644}
	res := checkResource(ctx, r, ro)
	if res.Status != statusDrift || res.Before["type"] != "symlink" || strings.Contains(res.Diff, "s3cret") {
		t.Fatalf("check: %s %v %q", res.Status, res.Before, res.Diff)
	}
	res = applyChecked(ctx, r, ro, newWriteHost(ents, b.newWrites()), res)
	if res.Status != statusChanged || res.BackupID != "" {
		t.Fatalf("apply: %s %q backup %q", res.Status, res.Error, res.BackupID)
	}
	if fi, err := os.Lstat(link); err != nil || !fi.Mode().IsRegular() {
		t.Fatalf("target is not a regular file now: %v %v", fi, err)
	}
	if data, _ := os.ReadFile(secret); string(data) != "s3cret" {
		t.Fatalf("link target changed: %q", data)
	}
}

func TestOSFileProviderRefusesHardLinkRead(t *testing.T) {
	ctx := context.Background()
	dir := realTempDir(t)
	outside := realTempDir(t)
	secret := filepath.Join(outside, "secret")
	if err := os.WriteFile(secret, []byte("s3cret"), 0o600); err != nil {
		t.Fatal(err)
	}
	hl := filepath.Join(dir, "app.conf")
	if err := os.Link(secret, hl); err != nil {
		t.Fatal(err)
	}
	ents := &Entitlements{AllowFSWrite: []string{dir}}
	res := checkResource(ctx, &fileResource{path: hl, content: "x", mode: 0o600}, newReadOnlyHost(ents, osHostReads{}))
	if res.Status != statusFailed || strings.Contains(res.Diff, "s3cret") || res.Before != nil {
		t.Fatalf("hard link read: %s %v %q", res.Status, res.Before, res.Diff)
	}
}

func TestOSDirAndAbsentProvidersConverge(t *testing.T) {
	ctx := context.Background()
	dir := realTempDir(t)
	old := stateBackupDir
	stateBackupDir = filepath.Join(realTempDir(t), "b")
	t.Cleanup(func() { stateBackupDir = old })
	ents := &Entitlements{AllowFSWrite: []string{dir}}
	b := osHostBackend()
	ro := newReadOnlyHost(ents, b.reads)
	gone := filepath.Join(dir, "gone.conf")
	if err := os.WriteFile(gone, []byte("bye"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, r := range []Applier{
		&dirResource{path: filepath.Join(dir, "a", "b"), mode: 0o750},
		&absentResource{path: gone},
		&absentResource{path: filepath.Join(dir, "never")},
	} {
		res := applyChecked(ctx, r, ro, newWriteHost(ents, b.newWrites()), checkResource(ctx, r, ro))
		if res.Status != statusChanged && res.Status != statusOK {
			t.Fatalf("%s: %s %q", r.Key(), res.Status, res.Error)
		}
		if again := checkResource(ctx, r, ro); again.Status != statusOK {
			t.Fatalf("%s: recheck %s %v", r.Key(), again.Status, again.diff.Fields)
		}
	}
	if fi, err := os.Stat(filepath.Join(dir, "a", "b")); err != nil || fi.Mode().Perm() != 0o750 {
		t.Fatalf("dir: %v %v", fi, err)
	}
	if _, err := os.Lstat(gone); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("absent: %v", err)
	}
	// A non-empty directory is not removed.
	full := filepath.Join(dir, "a")
	r := &absentResource{path: full}
	res := applyChecked(ctx, r, ro, newWriteHost(ents, b.newWrites()), checkResource(ctx, r, ro))
	if res.Status != statusFailed {
		t.Fatalf("non-empty dir removal: %s", res.Status)
	}
	if _, err := os.Stat(filepath.Join(full, "b")); err != nil {
		t.Fatal("non-empty dir was removed")
	}
}

func TestAtomicReplaceModeRefusesSpecialBits(t *testing.T) {
	dir := realTempDir(t)
	if err := atomicReplaceMode(dir, filepath.Join(dir, "x"), []byte("x"), os.ModeSetuid|0o755, -1, -1); err == nil {
		t.Fatal("setuid mode accepted")
	}
	if got := listDir(t, dir); len(got) != 0 {
		t.Fatalf("refused replace left %v", got)
	}
}

func TestReplaceBeneathRefusesSwappedParent(t *testing.T) {
	root := realTempDir(t)
	outside := realTempDir(t)
	if err := os.Symlink(outside, filepath.Join(root, "dir")); err != nil {
		t.Fatal(err)
	}
	err := atomicReplaceMode(root, filepath.Join(root, "dir", "x"), []byte("pwned"), 0o644, -1, -1)
	if err == nil {
		t.Fatal("replace through a swapped parent accepted")
	}
	if got := listDir(t, outside); len(got) != 0 {
		t.Fatalf("written outside: %v", got)
	}
	if runtime.GOOS == "linux" {
		if _, err := statBeneath(root, filepath.Join(root, "dir", "x")); err == nil {
			t.Fatal("stat through a swapped parent accepted")
		}
	}
}

func TestStateParseMode(t *testing.T) {
	for _, ok := range []string{"0644", "755", "0", "0777"} {
		if _, err := parseStateMode(ok, false); err != nil {
			t.Errorf("%q: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "4755", "1777", "2755", "0888", "abc", "-1", "07777"} {
		if _, err := parseStateMode(bad, false); err == nil {
			t.Errorf("file %q accepted", bad)
		}
	}
	for _, ok := range []string{"0755", "1777", "2775", "3777"} {
		if _, err := parseStateMode(ok, true); err != nil {
			t.Errorf("dir %q: %v", ok, err)
		}
	}
	for _, bad := range []string{"4755", "6755", "7777"} {
		if _, err := parseStateMode(bad, true); err == nil {
			t.Errorf("dir %q (setuid) accepted", bad)
		}
	}
	for _, r := range []uint32{0o755, 0o1777, 0o2775, 0o4755} {
		if rawMode(fileModeOf(r)) != r {
			t.Errorf("%o does not round-trip", r)
		}
	}
}

// A directory may carry the sticky bit; check, apply and check converge on
// the real filesystem.
func TestOSDirStickyMode(t *testing.T) {
	ctx := context.Background()
	dir := realTempDir(t)
	ents := &Entitlements{AllowFSWrite: []string{dir}}
	b := osHostBackend()
	ro := newReadOnlyHost(ents, b.reads)
	r := &dirResource{path: filepath.Join(dir, "spool"), mode: 0o1777}
	res := applyChecked(ctx, r, ro, newWriteHost(ents, b.newWrites()), checkResource(ctx, r, ro))
	if res.Status != statusChanged {
		t.Fatalf("%s %q", res.Status, res.Error)
	}
	if again := checkResource(ctx, r, ro); again.Status != statusOK {
		t.Fatalf("recheck %s %v", again.Status, again.diff.Fields)
	}
	if fi, _ := os.Stat(r.path); fi.Mode()&os.ModeSticky == 0 || fi.Mode().Perm() != 0o777 {
		t.Fatalf("mode %v", fi.Mode())
	}
}

func TestSystemdEnabledState(t *testing.T) {
	for state, want := range map[string]bool{"enabled": true, "enabled-runtime": true, "disabled": false, "static": false, "masked": false} {
		got, err := systemdEnabledState(state)
		if err != nil || got != want {
			t.Errorf("%q: %v %v", state, got, err)
		}
	}
	for _, bad := range []string{"", "not-found", "bad", "alias", "Failed to get unit file state"} {
		if _, err := systemdEnabledState(bad); err == nil {
			t.Errorf("%q classified", bad)
		}
	}
}

func TestLaunchdEnabledFrom(t *testing.T) {
	out := "disabled services = {\n\t\"com.a\" => disabled\n\t\"com.b\" => enabled\n\t\"com.c\" => true\n\t\"com.d\" => false\n}\n"
	for label, want := range map[string]bool{"com.a": false, "com.b": true, "com.c": false, "com.d": true, "com.e": true} {
		if got := launchdEnabledFrom(out, label); got != want {
			t.Errorf("%s: %v", label, got)
		}
	}
}

func TestNoneServiceManagerIsEnabledFailsClosed(t *testing.T) {
	if _, err := (noneServiceManager{}).IsEnabled(context.Background(), "nginx"); err == nil {
		t.Fatal("none backend reported an enabled state")
	}
}

func TestCheckStateBackupDir(t *testing.T) {
	for _, bad := range []string{"", "relative", "/", "/var/../tmp"} {
		if _, err := checkStateBackupDir(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	// A group/other-writable directory (or, when not root, one we own) is
	// refused, as is a path through it.
	open := realTempDir(t)
	if err := os.Chmod(open, 0o777); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{open, filepath.Join(open, "backups")} {
		if _, err := checkStateBackupDir(p); err == nil {
			t.Errorf("%s accepted", p)
		}
	}
	// A symlink to an acceptable place is resolved, never kept.
	link := filepath.Join(open, "link")
	if err := os.Symlink("/", link); err != nil {
		t.Fatal(err)
	}
	if _, err := checkStateBackupDir(filepath.Join(link, "var")); err == nil {
		t.Error("a path through a link in an open dir accepted")
	}
	// Root-owned system directories with a missing tail are accepted.
	got, err := checkStateBackupDir("/var/lib/systemapi-test-missing/backups")
	if err != nil {
		t.Fatalf("default-like dir refused: %v", err)
	}
	if !strings.HasSuffix(got, "/lib/systemapi-test-missing/backups") {
		t.Fatalf("resolved to %q", got)
	}
}
