package main

import (
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

func withHistRoot(t *testing.T, dir string) {
	t.Helper()
	prev := sashHistoryRoot
	sashHistoryRoot = dir
	t.Cleanup(func() { sashHistoryRoot = prev })
}

func histGrant(actor, host string, private bool) sashGrant {
	return sashGrant{Actor: actor, Host: host, AllowPrivate: private}
}

func histAppend(t *testing.T, g sashGrant, line string) {
	t.Helper()
	res, err := sashDispatch(g, sashTargets{}, sashLiveLease(), nil, sashCall{
		Key: "history", Argv: []string{"append"}, Body: []byte(line),
	})
	if err != nil || res.Exit != 0 {
		t.Fatalf("append %q err %v exit %d", line, err, res.Exit)
	}
}

func histGet(t *testing.T, g sashGrant) []string {
	t.Helper()
	res, err := sashDispatch(g, sashTargets{}, sashLiveLease(), nil, sashCall{
		Key: "history", Argv: []string{"get"},
	})
	if err != nil || res.Exit != 0 || res.Kind != "rows" {
		t.Fatalf("get err %v %+v", err, res)
	}
	out := make([]string, len(res.Rows))
	for i, row := range res.Rows {
		out[i] = row["line"]
	}
	return out
}

func histFiles(t *testing.T, root string) []string {
	t.Helper()
	ents, err := os.ReadDir(root)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		t.Fatal(err)
	}
	var names []string
	for _, e := range ents {
		names = append(names, e.Name())
	}
	return names
}

func TestSashHistoryClosed(t *testing.T) {
	root := t.TempDir()
	withHistRoot(t, root)
	g := histGrant("a", "h1", false)

	_, err := sashDispatch(g, sashTargets{}, sashDeadLease(), nil, sashCall{
		Key: "history", Argv: []string{"append"}, Body: []byte("echo dead"),
	})
	if !errors.Is(err, errSashDenied) {
		t.Fatalf("dead %v", err)
	}
	if names := histFiles(t, root); len(names) != 0 {
		t.Fatalf("dead wrote %v", names)
	}

	withHistRoot(t, "")
	_, err = sashDispatch(g, sashTargets{}, sashLiveLease(), nil, sashCall{
		Key: "history", Argv: []string{"append"}, Body: []byte("echo empty"),
	})
	if !errors.Is(err, errSashDenied) {
		t.Fatalf("empty root %v", err)
	}
	res, err := sashDispatch(g, sashTargets{}, sashLiveLease(), nil, sashCall{
		Key: "history", Argv: []string{"get"},
	})
	if err != nil || res.Exit != 0 || len(res.Rows) != 0 {
		t.Fatalf("empty get err %v %+v", err, res)
	}

	withHistRoot(t, root)
	for _, body := range []string{"", "echo\nhi", "echo\rhi", "echo\x00hi", string([]byte{0xff}), strings.Repeat("a", sashHistMaxLine+1)} {
		_, err = sashDispatch(g, sashTargets{}, sashLiveLease(), nil, sashCall{
			Key: "history", Argv: []string{"append"}, Body: []byte(body),
		})
		if !errors.Is(err, errSashDenied) {
			t.Fatalf("body %q err %v", body, err)
		}
	}
	if names := histFiles(t, root); len(names) != 0 {
		t.Fatalf("rejected wrote %v", names)
	}

	_, err = sashDispatch(g, sashTargets{}, sashLiveLease(), nil, sashCall{
		Key: "history", Argv: []string{"append", "other"}, Body: []byte("echo sneak"), Path: "other",
	})
	if !errors.Is(err, errSashDenied) {
		t.Fatalf("argv actor %v", err)
	}
	if names := histFiles(t, root); len(names) != 0 {
		t.Fatalf("argv wrote %v", names)
	}

	calls := 0
	prev := sashProcs
	sashProcs = func() ([]sashProc, error) {
		calls++
		return nil, nil
	}
	t.Cleanup(func() { sashProcs = prev })
	res, err = sashDispatch(sashGrant{}, sashTargets{}, sashLiveLease(), nil, sashCall{
		Key: "history", Argv: []string{"get"},
	})
	if err != nil || len(res.Rows) != 0 || calls != 0 {
		t.Fatalf("empty entitlements err %v rows %d procs %d", err, len(res.Rows), calls)
	}
}

func TestSashHistoryStore(t *testing.T) {
	if openNoFollow == 0 {
		t.Skip("O_NOFOLLOW is required")
	}
	root := t.TempDir()
	withHistRoot(t, root)
	a := histGrant("actor-a", "host-1", false)
	b := histGrant("actor-b", "host-1", false)
	a2 := histGrant("actor-a", "host-2", false)

	histAppend(t, a, "echo a")
	if got := histGet(t, b); len(got) != 0 {
		t.Fatalf("actor b saw %v", got)
	}
	if got := histGet(t, a2); len(got) != 0 {
		t.Fatalf("host 2 saw %v", got)
	}
	if got := histGet(t, a); len(got) != 1 || got[0] != "echo a" {
		t.Fatalf("actor a %v", got)
	}

	res, err := sashDispatch(a, sashTargets{}, sashLiveLease(), nil, sashCall{
		Key: "history", Argv: []string{"append"}, Path: "actor-b", Body: []byte("echo path"),
	})
	if err != nil || res.Exit != 0 {
		t.Fatalf("path ignored %v %+v", err, res)
	}
	if got := histGet(t, b); len(got) != 0 {
		t.Fatalf("path leaked to b %v", got)
	}
	if got := histGet(t, a); len(got) != 2 || got[1] != "echo path" {
		t.Fatalf("path stored %v", got)
	}

	sug, aud, err := sashHistPaths(root, a.Actor, a.Host)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{sug, aud} {
		fi, err := os.Lstat(p)
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode()&os.ModeSymlink != 0 || fi.Mode().Perm() != 0o600 {
			t.Fatalf("mode %s %v", p, fi.Mode())
		}
	}
	di, err := os.Lstat(root)
	if err != nil || di.Mode().Perm() != 0o700 {
		t.Fatalf("dir %v %v", di, err)
	}
	hexName := regexp.MustCompile(`^[0-9a-f]{64}\.(suggest|audit)$`)
	for _, name := range histFiles(t, root) {
		if !hexName.MatchString(name) {
			t.Fatalf("name %s", name)
		}
	}

	priv := histGrant("actor-a", "host-1", true)
	reads := 0
	prevRead := sashHistReadSuggest
	sashHistReadSuggest = func(path string) ([]string, error) {
		reads++
		return prevRead(path)
	}
	t.Cleanup(func() { sashHistReadSuggest = prevRead })
	before, err := os.ReadFile(sug)
	if err != nil {
		t.Fatal(err)
	}
	histAppend(t, priv, "echo secret")
	after, err := os.ReadFile(sug)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Fatal("private append changed suggestions")
	}
	if reads != 0 {
		t.Fatalf("private append reads %d", reads)
	}
	audText, err := os.ReadFile(aud)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(audText), "echo secret") || !strings.Contains(string(audText), "echo a") {
		t.Fatalf("audit %s", audText)
	}
	reads = 0
	if got := histGet(t, priv); len(got) != 0 || reads != 0 {
		t.Fatalf("private get %v reads %d", got, reads)
	}
	if got := histGet(t, a); len(got) != 2 || got[0] != "echo a" || got[1] != "echo path" {
		t.Fatalf("public still %v", got)
	}

	if err := os.WriteFile(sug, []byte("not-json\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := histGet(t, a); len(got) != 0 {
		t.Fatalf("malformed %v", got)
	}
	var big strings.Builder
	for i := 0; i < sashHistMaxKeep+1; i++ {
		if _, err := big.WriteString("{\"line\":\"n\"}\n"); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(sug, []byte(big.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := histGet(t, a); len(got) != 0 {
		t.Fatalf("over count %d", len(got))
	}
}

func TestSashHistoryTrimAndEscape(t *testing.T) {
	if openNoFollow == 0 {
		t.Skip("O_NOFOLLOW is required")
	}
	root := t.TempDir()
	withHistRoot(t, root)
	g := histGrant("actor-a", "host-1", false)
	for i := 0; i <= sashHistMaxKeep; i++ {
		histAppend(t, g, "n"+strconv.Itoa(i))
	}
	got := histGet(t, g)
	if len(got) != sashHistMaxKeep || got[0] != "n1" || got[len(got)-1] != "n"+strconv.Itoa(sashHistMaxKeep) {
		t.Fatalf("len %d first %q last %q", len(got), first(got), last(got))
	}

	parent := t.TempDir()
	escape := filepath.Join(parent, "hist")
	withHistRoot(t, escape)
	histAppend(t, histGrant("../x", "../y", false), "echo z")
	ents, err := os.ReadDir(parent)
	if err != nil {
		t.Fatal(err)
	}
	if len(ents) != 1 || ents[0].Name() != "hist" {
		t.Fatalf("parent %v", ents)
	}
	hexName := regexp.MustCompile(`^[0-9a-f]{64}\.(suggest|audit)$`)
	for _, name := range histFiles(t, escape) {
		if !hexName.MatchString(name) {
			t.Fatalf("escaped name %s", name)
		}
	}
	if _, err := os.Lstat(filepath.Join(parent, "x")); !os.IsNotExist(err) {
		t.Fatal("wrote outside the history dir")
	}
}

func TestSashHistoryPrivateDoesNotDenyPS(t *testing.T) {
	prev := sashProcs
	sashProcs = func() ([]sashProc, error) {
		return []sashProc{{User: "root", Pid: 7, Cmd: "sshd"}}, nil
	}
	t.Cleanup(func() { sashProcs = prev })
	res, err := sashDispatch(sashGrant{Entitlements: []string{"ps"}, AllowPrivate: true}, sashTargets{}, sashLiveLease(), nil, sashCall{Key: "ps"})
	if err != nil || res.Exit != 0 || len(res.Rows) != 1 || res.Rows[0]["cmd"] != "sshd" {
		t.Fatalf("err %v %+v", err, res)
	}
}

func first(s []string) string {
	if len(s) == 0 {
		return ""
	}
	return s[0]
}

func last(s []string) string {
	if len(s) == 0 {
		return ""
	}
	return s[len(s)-1]
}
