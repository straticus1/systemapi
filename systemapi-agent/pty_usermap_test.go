package main

import (
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestPTYUserMapParses(t *testing.T) {
	m, err := parsePTYUserMap(strings.NewReader("# who runs as what\n\n alice = sah_alice \nbob@example.com=sah_bob\n42 = u42\n"))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"alice": "sah_alice", "bob@example.com": "sah_bob", "42": "u42"}
	if len(m) != len(want) {
		t.Fatalf("got %v", m)
	}
	for k, v := range want {
		if m[k] != v {
			t.Fatalf("%s: got %q want %q", k, m[k], v)
		}
	}
}

func TestPTYUserMapRefusesBadFiles(t *testing.T) {
	cases := map[string]string{
		"two identities on one account": "alice = shared\nbob = shared\n",
		"wildcard identity":             "* = shared\n",
		"wildcard inside identity":      "team-* = shared\n",
		"repeated identity":             "alice = a1\nalice = a2\n",
		"root account":                  "alice = root\n",
		"no equals":                     "alice shared\n",
		"empty account":                 "alice =\n",
		"bad account":                   "alice = Bad User\n",
		"empty map":                     "# nothing\n",
	}
	for name, body := range cases {
		if _, err := parsePTYUserMap(strings.NewReader(body)); err == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
	_, err := parsePTYUserMap(strings.NewReader("alice = shared\nbob = shared\n"))
	if err == nil || !strings.Contains(err.Error(), "one account per identity") {
		t.Fatalf("duplicate account error: %v", err)
	}
}

func TestPTYUserMapFileChecks(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "map")
	if err := os.WriteFile(path, []byte("alice = sah_alice\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadPTYUserMap(path, os.Geteuid()); err != nil {
		t.Fatalf("0600 own file refused: %v", err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadPTYUserMap(path, os.Geteuid()); err == nil {
		t.Fatal("0644 map accepted")
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if os.Geteuid() != 0 {
		// Owned by neither root nor the claimed agent user.
		if _, err := loadPTYUserMap(path, os.Geteuid()+1); err == nil {
			t.Fatal("map owned by another user accepted")
		}
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := loadPTYUserMap(link, os.Geteuid()); err == nil {
		t.Fatal("symlinked map accepted")
	}
}

// One resolution serves every channel: an unmapped identity is refused,
// a mapped one gets its own account, and --pty-user is not a fallback.
func TestPTYUserMapResolution(t *testing.T) {
	me, err := user.Current()
	if err != nil || me.Uid == "0" {
		t.Skip("needs a non-root current user")
	}
	cfg := ptySettings{User: me.Username, UserMap: map[string]string{"alice": me.Username}}
	id, code := resolvePTYIdentity("pty", "alice", cfg, 0)
	if code != "" || id.name != me.Username || !id.drop {
		t.Fatalf("alice: %v %q", id, code)
	}
	for _, actor := range []string{"bob", "", "*"} {
		if _, code := resolvePTYIdentity("pty", actor, cfg, 0); code != "account_unmapped" {
			t.Fatalf("pty %q: got %q", actor, code)
		}
		if _, code := resolveFileIdentity("file", actor, cfg, 0); code != "account_unmapped" {
			t.Fatalf("file %q: got %q", actor, code)
		}
	}
	if id, code := resolveFileIdentity("file", "alice", cfg, 0); code != "" || id.name != me.Username {
		t.Fatalf("file alice: %v %q", id, code)
	}
	// A non-root agent runs only the identity mapped to its own account.
	cfg.AllowAgentUser = true
	if _, code := resolvePTYIdentity("pty", "alice", cfg, 1000); code != "" {
		t.Fatalf("agent user alice: %q", code)
	}
	if _, code := resolvePTYIdentity("pty", "bob", cfg, 1000); code != "account_unmapped" {
		t.Fatalf("agent user bob: %q", code)
	}
	cfg.UserMap = map[string]string{"alice": "someone_else"}
	if _, code := resolvePTYIdentity("pty", "alice", cfg, 1000); code != "pty_start_failed" {
		t.Fatalf("agent user, other account: %q", code)
	}
	// Without a map, --pty-user still serves every identity.
	if id, code := resolvePTYIdentity("pty", "anyone", ptySettings{User: me.Username}, 0); code != "" || id.name != me.Username {
		t.Fatalf("no map: %v %q", id, code)
	}
}

func (h *ptyHarness) startAs(t *testing.T, actor string) string {
	t.Helper()
	sid := newSessionID(t)
	deadline := inFuture(time.Hour)
	lease := signLease(t, h.priv, ptyTestHost, "pty", terminalPayload(sid, deadline, "start"), inFuture(time.Minute))
	startPTYSession(h.out, ptyTestHost, h.dir, ptyStartRequest{
		SessionID: sid, Action: "pty", Rows: 24, Cols: 80, DeadlineUnix: deadline, Actor: actor, Lease: lease,
	}, time.Now())
	return sid
}

func TestPTYStartResolvesThroughMap(t *testing.T) {
	me, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	h := newPTYHarness(t)
	ptyCfg.UserMap = map[string]string{"alice": me.Username}
	if e := h.startErr(t, h.startAs(t, "bob")); e != "account_unmapped" {
		t.Fatalf("bob: %q", e)
	}
	sid := h.startAs(t, "alice")
	if p := startedPayload(t, h, sid); p["pty_user"] != me.Username {
		t.Fatalf("%v", p)
	}
	handlePTYInput(sid, []byte("exit 0\n"))
	h.exitOf(t, sid, 5*time.Second)
}

func TestXferGrantResolvesThroughMap(t *testing.T) {
	me, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	h := newXferHarness(t)
	root := newXferRoot(t)
	ptyCfg.UserMap = map[string]string{"alice": me.Username}
	msg := h.start(t, root, "ok/blob", func(m *xferMsg) { m.Actor = "bob" })
	if got := h.errorOf(t, msg.GrantID); got != "account_unmapped" {
		t.Fatalf("bob: %q", got)
	}
	h.assertNoSpawn(t, root)
	msg = h.start(t, root, "ok/blob", func(m *xferMsg) { m.Actor = "alice" })
	if res := h.result(t, msg.GrantID); res["status"] != "ok" {
		t.Fatalf("alice: %v", res)
	}
}

// The sweep after a restart resolves the record's own actor.
func TestXferSweepIdentityUsesRecordActor(t *testing.T) {
	me, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	prev, prevEUID := ptyCfg, agentEUID
	t.Cleanup(func() { ptyCfg, agentEUID = prev, prevEUID })
	agentEUID = func() int { return 1000 }
	ptyCfg = ptySettings{AllowAgentUser: true, UserMap: map[string]string{"alice": me.Username}}
	id, code := resolveFileIdentity("file", "alice", ptyCfg, 1000)
	if code != "" {
		t.Fatal(code)
	}
	rec := xferRecord{Action: "xfer", Actor: "alice", Identity: recordIdentity(id)}
	if _, err := sweepIdentity(rec); err != nil {
		t.Fatalf("alice: %v", err)
	}
	rec.Actor = "bob"
	if _, err := sweepIdentity(rec); err == nil {
		t.Fatal("unmapped record actor swept")
	}
}
