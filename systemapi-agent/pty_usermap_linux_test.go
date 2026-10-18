//go:build linux

package main

import (
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestFileOpenResolvesThroughMap(t *testing.T) {
	needOpenat2(t)
	me, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	h := newFileHarness(t)
	ptyCfg.UserMap = map[string]string{"alice": me.Username}
	root := t.TempDir()
	if got := h.errorOf(t, h.open(t, root, fileOpenOpts{actor: "bob"})); got != "account_unmapped" {
		t.Fatalf("bob: %q", got)
	}
	if got := h.errorOf(t, h.open(t, root, fileOpenOpts{actor: "alice"})); got != "" {
		t.Fatalf("alice: %q", got)
	}
}

// Root agent (the Linux container run): two identities mapped to two
// accounts get two uids, and an unmapped one gets no shell.
func TestPTYUserMapSeparatesAccountsAsRoot(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	accts := []*user.User{}
	for _, name := range []string{"nobody", "daemon"} {
		u, err := user.Lookup(name)
		if err != nil {
			t.Skip("no " + name + " user")
		}
		accts = append(accts, u)
	}
	h := newPTYHarness(t)
	agentEUID = os.Geteuid
	ptyCfg.User = "nobody"
	ptyCfg.Record = true
	ptyCfg.RecordDir = filepath.Join(h.dir, "rec")
	ptyCfg.UserMap = map[string]string{"alice": "nobody", "bob": "daemon"}
	if e := h.startErr(t, h.startAs(t, "carol")); e != "account_unmapped" {
		t.Fatalf("carol: %q", e)
	}
	for i, actor := range []string{"alice", "bob"} {
		sid := h.startAs(t, actor)
		if p := startedPayload(t, h, sid); p["pty_user"] != accts[i].Username {
			t.Fatalf("%s: %v", actor, p)
		}
		handlePTYInput(sid, []byte("echo UID=$(id -u)\n"))
		want := "UID=" + accts[i].Uid
		waitFor(t, actor+" id", 5*time.Second, func() bool { return strings.Contains(h.out.text(sid), want) })
		handlePTYInput(sid, []byte("exit 0\n"))
		h.exitOf(t, sid, 5*time.Second)
	}
}
