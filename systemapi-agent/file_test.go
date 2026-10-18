package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

// The test binary doubles as the file-helper child, as the agent binary does,
// and as a fake sahxfer recv.
func TestMain(m *testing.M) {
	if len(os.Args) > 1 && os.Args[1] == "file-helper" {
		os.Exit(runFileHelper(os.Stdin, os.Stdout))
	}
	if len(os.Args) > 1 && os.Args[1] == "recv" {
		// A fake sahxfer recv speaking the fd 3 / fd 4 protocol (xfer_test.go).
		os.Exit(runFakeRecv(os.Args[2:]))
	}
	os.Exit(m.Run())
}

// FILE §12: these never reach the disk.
func TestFilePathRules(t *testing.T) {
	bad := []string{
		"../../etc/shadow", "/etc/shadow", "a/../../x", "a//b", "a/./b", "", "a/", "./a", "..", "a/..",
		"a\\b", "a\x00b", "a\x01b", "a\x1fb", "a\x7fb", "\xff\xfe", string(bytes.Repeat([]byte("a"), 256)),
		string(bytes.Repeat([]byte("a/"), 2048)) + "a",
	}
	for _, p := range bad {
		if got := checkFilePath(p); got != "bad_path" {
			t.Errorf("%q: got %q, want bad_path", p, got)
		}
	}
	for _, p := range []string{".sahsync-x.part", "a/.sahsync-upl_1.part", ".sahsync-.part/b"} {
		if got := checkFilePath(p); got != "reserved_name" {
			t.Errorf("%q: got %q, want reserved_name", p, got)
		}
	}
	good := []string{".", "a", "a/b/c", "%2e%2e", ".hidden", "...", "a b", "é", ".sahsync-x", "x.part", string(bytes.Repeat([]byte("a"), 255))}
	for _, p := range good {
		if got := checkFilePath(p); got != "" {
			t.Errorf("%q: got %q, want ok", p, got)
		}
	}
}

func TestFileModeRule(t *testing.T) {
	for _, s := range []string{"0600", "0644", "0755", "0777", "0700"} {
		if _, has, ok := parseFileMode(&s); !ok || !has {
			t.Errorf("%s refused", s)
		}
	}
	for _, s := range []string{"4755", "2755", "1777", "0577", "0000", "755", "06440", "0x1ff", "0788", ""} {
		if _, _, ok := parseFileMode(&s); ok {
			t.Errorf("%s accepted", s)
		}
	}
	if _, has, ok := parseFileMode(nil); has || !ok {
		t.Error("absent mode")
	}
	if formatFileMode(0o644) != "0644" || formatFileMode(0o4755) != "4755" {
		t.Error("format")
	}
}

func TestHelperFraming(t *testing.T) {
	var buf bytes.Buffer
	if err := writeHelperJSON(&buf, map[string]int{"a": 1}); err != nil {
		t.Fatal(err)
	}
	if err := writeHelperFrame(&buf, frameBinary, []byte("xyz")); err != nil {
		t.Fatal(err)
	}
	k, p, err := readHelperFrame(&buf)
	if err != nil || k != frameJSON || string(p) != `{"a":1}` {
		t.Fatalf("%c %s %v", k, p, err)
	}
	k, p, err = readHelperFrame(&buf)
	if err != nil || k != frameBinary || string(p) != "xyz" {
		t.Fatalf("%c %s %v", k, p, err)
	}
	if err := writeHelperFrame(&buf, frameBinary, make([]byte, helperFrameMax+1)); !errors.Is(err, errFrameSize) {
		t.Fatalf("oversized frame written: %v", err)
	}
	// An oversized length or an unknown kind is refused before allocating.
	if _, _, err := readHelperFrame(bytes.NewReader([]byte{'B', 0xff, 0xff, 0xff, 0xff})); !errors.Is(err, errFrameSize) {
		t.Fatalf("got %v", err)
	}
	if _, _, err := readHelperFrame(bytes.NewReader([]byte{'X', 0, 0, 0, 0})); !errors.Is(err, errFrameSize) {
		t.Fatalf("got %v", err)
	}
}

func hexSum(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func testRecord(id string, created time.Time) uploadRecord {
	return uploadRecord{UploadID: id, ActorKey: actorKey("user-1"), Root: "/srv/a", Path: "d/f.bin", Size: 10,
		SHA256: hexSum([]byte("0123456789")), CreatedUnix: created.Unix()}
}

func TestUploadRecordsResumeKeyAndExpiry(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	live := testRecord("upl_aaaaaaaaaaaaaaaaaaaa", now.Add(-time.Hour))
	old := testRecord("upl_bbbbbbbbbbbbbbbbbbbb", now.Add(-25*time.Hour))
	for _, r := range []uploadRecord{live, old} {
		if err := saveUpload(dir, r); err != nil {
			t.Fatal(err)
		}
	}
	st, err := os.Stat(uploadsDir(dir))
	if err != nil || st.Mode().Perm() != 0o700 {
		t.Fatalf("records dir: %v %v", st, err)
	}
	if fi, err := os.Stat(filepath.Join(uploadsDir(dir), live.UploadID+".json")); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("record mode: %v", err)
	}
	// Another actor, root, path, size or hash never matches.
	for _, k := range []struct {
		actor, root, path string
		size              int64
		sha               string
	}{
		{"user-2", "/srv/a", "d/f.bin", 10, live.SHA256},
		{"user-1", "/srv/b", "d/f.bin", 10, live.SHA256},
		{"user-1", "/srv/a", "d/g.bin", 10, live.SHA256},
		{"user-1", "/srv/a", "d/f.bin", 11, live.SHA256},
		{"user-1", "/srv/a", "d/f.bin", 10, hexSum([]byte("x"))},
	} {
		if r := findUpload(dir, k.actor, k.root, k.path, k.size, k.sha, now); r != nil {
			t.Fatalf("matched %+v", k)
		}
	}
	r := findUpload(dir, "user-1", "/srv/a", "d/f.bin", 10, live.SHA256, now)
	if r == nil || r.UploadID != live.UploadID {
		t.Fatalf("live upload not found: %+v", r)
	}
	// Claimed by a live session: not resumable elsewhere.
	if again := findUpload(dir, "user-1", "/srv/a", "d/f.bin", 10, live.SHA256, now); again != nil {
		t.Fatal("a claimed upload was handed out twice")
	}
	unclaimUpload(live.UploadID)
	// The expired one is never resumed, and the sweep removes it.
	var removed []string
	n := sweepUploads(dir, now, func(root, path, id string) error {
		removed = append(removed, id)
		return nil
	})
	if n != 1 || len(removed) != 1 || removed[0] != old.UploadID {
		t.Fatalf("swept %d %v", n, removed)
	}
	recs := loadUploads(dir)
	if len(recs) != 1 || recs[0].UploadID != live.UploadID {
		t.Fatalf("records left: %+v", recs)
	}
	// A crafted record never loads.
	bad := filepath.Join(uploadsDir(dir), "upl_cccccccccccccccccccc.json")
	raw, _ := json.Marshal(uploadRecord{UploadID: "upl_cccccccccccccccccccc", ActorKey: actorKey("x"), Root: "/srv", Path: "../etc/passwd",
		Size: 1, SHA256: live.SHA256, CreatedUnix: 1})
	if err := os.WriteFile(bad, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if len(loadUploads(dir)) != 1 {
		t.Fatal("a record with a traversal path loaded")
	}
}

// Expired uploads are swept on a timer too, not only when a session starts.
func TestUploadSweeperRunsOnATimer(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	old := testRecord("upl_eeeeeeeeeeeeeeeeeeee", now.Add(-25*time.Hour))
	live := testRecord("upl_gggggggggggggggggggg", now.Add(-time.Hour))
	for _, r := range []uploadRecord{old, live} {
		if err := saveUpload(dir, r); err != nil {
			t.Fatal(err)
		}
	}
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		runUploadSweeper(dir, 20*time.Millisecond, stop, func(root, path, id string) error { return nil })
		close(done)
	}()
	waitFor(t, "the timer sweep", 5*time.Second, func() bool { return len(loadUploads(dir)) == 1 })
	close(stop)
	<-done
	if recs := loadUploads(dir); len(recs) != 1 || recs[0].UploadID != live.UploadID {
		t.Fatalf("records left: %+v", recs)
	}
}

func TestCountUploadsPerActorAndRoot(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	recs := []uploadRecord{
		testRecord("upl_aaaaaaaaaaaaaaaaaaa1", now),
		testRecord("upl_aaaaaaaaaaaaaaaaaaa2", now),
		testRecord("upl_aaaaaaaaaaaaaaaaaaa3", now.Add(-25*time.Hour)),
	}
	other := testRecord("upl_aaaaaaaaaaaaaaaaaaa4", now)
	other.ActorKey = actorKey("user-2")
	elsewhere := testRecord("upl_aaaaaaaaaaaaaaaaaaa5", now)
	elsewhere.Root = "/srv/b"
	for _, r := range append(recs, other, elsewhere) {
		if err := saveUpload(dir, r); err != nil {
			t.Fatal(err)
		}
	}
	if n := countUploads(dir, "user-1", "/srv/a", now); n != 2 {
		t.Fatalf("count %d, want 2 (expired, other actor and other root excluded)", n)
	}
}

func TestFileIdentityRules(t *testing.T) {
	if _, code := resolveFileIdentity("file_root", "", ptySettings{AllowAgentUser: true}, 1000); code != "root_unavailable" {
		t.Fatalf("file:root on a non-root agent: %q", code)
	}
	if _, code := resolveFileIdentity("file", "", ptySettings{}, 1000); code != "pty_user_unset" {
		t.Fatalf("non-root agent without --pty-allow-agent-user: %q", code)
	}
	if _, code := resolveFileIdentity("file", "", ptySettings{}, 0); code != "pty_user_unset" {
		t.Fatalf("root agent without --pty-user: %q", code)
	}
	if runtime.GOOS != "windows" {
		if _, code := resolveFileIdentity("file", "", ptySettings{User: "root"}, 0); code != "internal" {
			t.Fatalf("pty_user root: %q", code)
		}
	}
	id, code := resolveFileIdentity("file", "", ptySettings{AllowAgentUser: true}, 1000)
	if code != "" || id.drop {
		t.Fatalf("agent user: %q %+v", code, id)
	}
}

// A non-root session never gets "/" (or a "~" that is "/" or unset) or a
// root holding the agent's state directory; file_root may.
func TestFileSessionRootRefusesHostRootAndStateDir(t *testing.T) {
	base := t.TempDir()
	state := filepath.Join(base, "srv", ".systemapi")
	if err := os.MkdirAll(state, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "link")
	if err := os.Symlink(filepath.Join(base, "srv"), link); err != nil {
		t.Fatal(err)
	}
	real, err := filepath.EvalSymlinks(filepath.Join(base, "srv"))
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct{ root, home, state string }{
		{"/", "/home/u", ""},
		{"~", "/", ""},
		{"~", "", ""},
		{"~", "//", ""},
		{filepath.Join(base, "srv"), "/home/u", state},
		{state, "/home/u", state},
		{"~", filepath.Join(base, "srv"), state},
		{base, "/home/u", state},
		// The state dir is reached through a symlink: its real path still counts.
		{real, "/home/u", filepath.Join(link, ".systemapi")},
	} {
		if got := checkSessionRoot("file", c.root, c.home, c.state); got != "root_denied" {
			t.Errorf("root %q home %q state %q: %q", c.root, c.home, c.state, got)
		}
		if got := checkSessionRoot("file_root", c.root, c.home, c.state); got != "" {
			t.Errorf("file_root %q: %q", c.root, got)
		}
	}
	for _, c := range []struct{ root, home, state string }{
		{filepath.Join(base, "srv", "app"), "/home/u", state},
		{filepath.Join(base, "srv2"), "/home/u", state},
		{"~", "/home/u", state},
		{"/srv/a", "/home/u", ""},
	} {
		if got := checkSessionRoot("file", c.root, c.home, c.state); got != "" {
			t.Errorf("root %q: %q", c.root, got)
		}
	}
}

type fileHarness struct {
	priv ed25519.PrivateKey
	out  *fakeOut
	ch   *channelConn
}

func newFileHarness(t *testing.T) *fileHarness {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	clearIdentity()
	if err := pinControlPublicKey(base64.StdEncoding.EncodeToString(pub), ptyTestHost); err != nil {
		t.Fatal(err)
	}
	prevCfg, prevEUID, prevWatch := ptyCfg, agentEUID, fileWatchEvery
	ptyCfg = ptySettings{AllowAgentUser: true}
	agentEUID = func() int { return 1000 }
	fileWatchEvery = 20 * time.Millisecond
	h := &fileHarness{priv: priv, out: newFakeOut()}
	h.ch = newChannelConn(h.out, ptyTestHost)
	h.ch.stateDir = t.TempDir()
	t.Cleanup(func() {
		h.ch.close("stopped")
		waitFor(t, "file sessions to end", 5*time.Second, func() bool {
			h.ch.mu.Lock()
			defer h.ch.mu.Unlock()
			return len(h.ch.files) == 0
		})
		ptyCfg, agentEUID, fileWatchEvery = prevCfg, prevEUID, prevWatch
		clearIdentity()
	})
	return h
}

func newFileSessionID(t *testing.T) string {
	t.Helper()
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return "fls_" + hex.EncodeToString(b)
}

type fileOpenOpts struct {
	action    string
	mode      string
	leaseMode string
	leaseRoot string
	leaseExp  int64
	deadline  int64
	idle      int64
	actor     string
}

func (h *fileHarness) send(t *testing.T, v interface{}) error {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	var peek struct {
		Type string `json:"type"`
	}
	_ = json.Unmarshal(raw, &peek)
	handled, err := h.ch.handle(peek.Type, raw)
	if !handled {
		t.Fatalf("%s not handled", peek.Type)
	}
	return err
}

func (h *fileHarness) open(t *testing.T, root string, o fileOpenOpts) string {
	t.Helper()
	sid := newFileSessionID(t)
	if o.action == "" {
		o.action = "file"
	}
	if o.mode == "" {
		o.mode = "write"
	}
	if o.leaseMode == "" {
		o.leaseMode = o.mode
	}
	if o.leaseRoot == "" {
		o.leaseRoot = root
	}
	if o.deadline == 0 {
		o.deadline = inFuture(time.Hour)
	}
	if o.leaseExp == 0 {
		o.leaseExp = inFuture(time.Minute)
	}
	if o.idle == 0 {
		o.idle = 900
	}
	if o.actor == "" {
		o.actor = "user-1"
	}
	payload, err := fileLeasePayload(sid, o.deadline, "start", o.leaseMode, o.leaseRoot)
	if err != nil {
		t.Fatal(err)
	}
	lease := signLease(t, h.priv, ptyTestHost, o.action, payload, o.leaseExp)
	_ = h.send(t, map[string]interface{}{
		"type": "file_open", "session_id": sid, "action": o.action, "mode": o.mode, "root": root,
		"deadline_unix": o.deadline, "idle_s": o.idle, "file_max": int64(16 << 30), "actor": o.actor, "lease": lease,
	})
	return sid
}

func (h *fileHarness) status(t *testing.T, sid string) map[string]interface{} {
	t.Helper()
	var p map[string]interface{}
	waitFor(t, "file_status "+sid, 5*time.Second, func() bool {
		m := h.out.find("file_status", sid)
		if m == nil {
			return false
		}
		p, _ = m["payload"].(map[string]interface{})
		return true
	})
	return p
}

func (h *fileHarness) errorOf(t *testing.T, sid string) string {
	t.Helper()
	code, _ := h.status(t, sid)["error"].(string)
	return code
}

// A lease for another root or mode never opens anything (FILE §11 Agent).
func TestFileLeaseBindsRootAndMode(t *testing.T) {
	h := newFileHarness(t)
	root := t.TempDir()
	cases := []fileOpenOpts{
		{leaseRoot: "/srv/b"},
		{mode: "write", leaseMode: "read"},
		{leaseExp: time.Now().Add(-2 * time.Minute).Unix()},
	}
	for i, o := range cases {
		sid := h.open(t, root, o)
		if got := h.errorOf(t, sid); got != "lease_required" {
			t.Fatalf("case %d: got %q", i, got)
		}
	}
	// file_root lease presented as a file lease.
	sid := newFileSessionID(t)
	deadline := inFuture(time.Hour)
	payload, _ := fileLeasePayload(sid, deadline, "start", "write", root)
	lease := signLease(t, h.priv, ptyTestHost, "file_root", payload, inFuture(time.Minute))
	_ = h.send(t, map[string]interface{}{"type": "file_open", "session_id": sid, "action": "file", "mode": "write", "root": root,
		"deadline_unix": deadline, "idle_s": 900, "lease": lease})
	if got := h.errorOf(t, sid); got != "lease_required" {
		t.Fatalf("file_root lease as file: %q", got)
	}
}

func TestFileCapabilityFollowsTheProbe(t *testing.T) {
	has := false
	for _, c := range agentCapabilities() {
		if c == "file" {
			has = true
		}
	}
	if has != (runtime.GOOS == "linux" && openat2Available()) {
		t.Fatalf("file capability %v on %s", has, runtime.GOOS)
	}
	if runtime.GOOS == "linux" {
		t.Skip("the unsupported path is for kernels without openat2")
	}
	h := newFileHarness(t)
	sid := h.open(t, t.TempDir(), fileOpenOpts{})
	if got := h.errorOf(t, sid); got != "agent_unsupported" {
		t.Fatalf("got %q", got)
	}
}
