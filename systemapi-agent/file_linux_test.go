//go:build linux

package main

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

var fileRID atomic.Int64

func nextRID() string { return "r" + strconv.FormatInt(fileRID.Add(1), 10) }

func needOpenat2(t *testing.T) {
	t.Helper()
	if !openat2Available() {
		t.Skip("kernel without openat2")
	}
}

func (h *fileHarness) ready(t *testing.T, sid string) map[string]interface{} {
	t.Helper()
	p := h.status(t, sid)
	if p["status"] != "ready" {
		t.Fatalf("session not ready: %v", p)
	}
	return p
}

// results returns every file_result for (request_id, op) in sid.
func (h *fileHarness) results(sid, rid, op string) []map[string]interface{} {
	h.out.mu.Lock()
	defer h.out.mu.Unlock()
	var out []map[string]interface{}
	for _, m := range h.out.jsons {
		if m["type"] == "file_result" && m["session_id"] == sid && m["request_id"] == rid && m["op"] == op {
			out = append(out, m)
		}
	}
	return out
}

// waitResult waits for result number n+1 of (request_id, op).
func (h *fileHarness) waitNth(t *testing.T, sid, rid, op string, n int) map[string]interface{} {
	t.Helper()
	var m map[string]interface{}
	waitFor(t, op+" result "+rid, 10*time.Second, func() bool {
		all := h.results(sid, rid, op)
		if len(all) > n {
			m = all[n]
			return true
		}
		return false
	})
	return m
}

func (h *fileHarness) waitResult(t *testing.T, sid, rid, op string) map[string]interface{} {
	t.Helper()
	return h.waitNth(t, sid, rid, op, 0)
}

// do sends one request and waits for its result.
func (h *fileHarness) do(t *testing.T, sid string, req map[string]interface{}) map[string]interface{} {
	t.Helper()
	rid, _ := req["request_id"].(string)
	if rid == "" {
		rid = nextRID()
		req["request_id"] = rid
	}
	op := req["op"].(string)
	n := len(h.results(sid, rid, op))
	h.sendReq(t, sid, req)
	return h.waitNth(t, sid, rid, op, n)
}

func (h *fileHarness) sendReq(t *testing.T, sid string, req map[string]interface{}) {
	t.Helper()
	_ = h.send(t, map[string]interface{}{"type": "file_req", "session_id": sid, "request": req})
}

func errOf(m map[string]interface{}) string {
	if m["status"] == "ok" {
		return ""
	}
	s, _ := m["error"].(string)
	if s == "" {
		return "?"
	}
	return s
}

func (h *fileHarness) code(t *testing.T, sid string, req map[string]interface{}) string {
	t.Helper()
	return errOf(h.do(t, sid, req))
}

func (h *fileHarness) chunk(t *testing.T, sid, rid string, off int64, data []byte) {
	t.Helper()
	_ = h.send(t, map[string]interface{}{"type": "file_chunk", "session_id": sid, "request_id": rid, "offset": off, "length": len(data)})
	frame := append([]byte{byte(len(sid))}, sid...)
	if err := h.ch.data(append(frame, data...)); err != nil {
		t.Fatal(err)
	}
}

func (h *fileHarness) waitAck(t *testing.T, sid, rid string, offset int64) {
	t.Helper()
	waitFor(t, fmt.Sprintf("write_ack %d", offset), 10*time.Second, func() bool {
		h.out.mu.Lock()
		defer h.out.mu.Unlock()
		for _, m := range h.out.jsons {
			if m["type"] == "file_write_ack" && m["session_id"] == sid && m["request_id"] == rid && m["offset"] == float64(offset) {
				return true
			}
		}
		return false
	})
}

func (h *fileHarness) closedOf(t *testing.T, sid string) map[string]interface{} {
	t.Helper()
	var p map[string]interface{}
	waitFor(t, "file_closed "+sid, 10*time.Second, func() bool {
		m := h.out.find("file_closed", sid)
		if m == nil {
			return false
		}
		p, _ = m["payload"].(map[string]interface{})
		return true
	})
	return p
}

func randBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

// upload writes data to path in chunk_max pieces and commits.
func (h *fileHarness) upload(t *testing.T, sid, path string, data []byte, extra map[string]interface{}) (map[string]interface{}, map[string]interface{}) {
	t.Helper()
	rid := nextRID()
	req := map[string]interface{}{"op": "write_open", "request_id": rid, "path": path, "size": len(data), "sha256": hexSum(data), "overwrite": false}
	for k, v := range extra {
		req[k] = v
	}
	open := h.do(t, sid, req)
	if errOf(open) != "" {
		return open, nil
	}
	off := int64(open["offset"].(float64))
	for off < int64(len(data)) {
		end := off + fileChunkMax
		if end > int64(len(data)) {
			end = int64(len(data))
		}
		h.chunk(t, sid, rid, off, data[off:end])
		h.waitAck(t, sid, rid, end)
		off = end
	}
	return open, h.do(t, sid, map[string]interface{}{"op": "write_commit", "request_id": rid})
}

func noTemps(t *testing.T, dir string) {
	t.Helper()
	ents, _ := os.ReadDir(dir)
	for _, e := range ents {
		if strings.HasPrefix(e.Name(), ".sahsync-") {
			t.Fatalf("temp file left: %s", e.Name())
		}
	}
}

// fixture builds a root with a regular file, a subdir, symlinks pointing
// outside and inside, a symlink to /etc/passwd, and a FIFO.
func fixture(t *testing.T) (string, string) {
	t.Helper()
	base := t.TempDir()
	root := filepath.Join(base, "root")
	outside := filepath.Join(base, "outside")
	for _, d := range []string{root, outside, filepath.Join(root, "sub")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	must := func(err error) {
		if err != nil {
			t.Fatal(err)
		}
	}
	must(os.WriteFile(filepath.Join(root, "f.txt"), []byte("hello world"), 0o644))
	must(os.WriteFile(filepath.Join(outside, "secret"), []byte("outside"), 0o644))
	must(os.Symlink(outside, filepath.Join(root, "out")))
	must(os.Symlink("sub", filepath.Join(root, "in")))
	must(os.Symlink("/etc/passwd", filepath.Join(root, "lf")))
	must(syscall.Mkfifo(filepath.Join(root, "p"), 0o644))
	return root, outside
}

func TestFileLinuxPathRulesAndSymlinks(t *testing.T) {
	needOpenat2(t)
	h := newFileHarness(t)
	root, outside := fixture(t)
	sid := h.open(t, root, fileOpenOpts{})
	p := h.ready(t, sid)
	if p["root"] != root {
		t.Fatalf("canonical root %v", p["root"])
	}
	for _, path := range []string{"../../etc/shadow", "/etc/shadow", "a/../../x", "a//b", "a/./b"} {
		for _, op := range []string{"stat", "read", "write_open", "remove"} {
			req := map[string]interface{}{"op": op, "path": path, "offset": 0, "length": 1, "size": 1, "sha256": hexSum([]byte("x")), "overwrite": true}
			if got := h.code(t, sid, req); got != "bad_path" {
				t.Fatalf("%s %q: got %q", op, path, got)
			}
		}
	}
	if got := h.code(t, sid, map[string]interface{}{"op": "stat", "path": "sub/.sahsync-upl_x.part"}); got != "reserved_name" {
		t.Fatalf("reserved: %q", got)
	}
	// stat acts on a final symlink itself; its target is never returned.
	st := h.do(t, sid, map[string]interface{}{"op": "stat", "path": "out"})
	entry := st["entry"].(map[string]interface{})
	if entry["type"] != "symlink" || entry["name"] != "out" || len(entry) != 5 {
		t.Fatalf("stat symlink: %v", st)
	}
	// Reads through or of a symlink, inside or outside, are refused.
	for _, path := range []string{"out/secret", "lf", "in/x", "out"} {
		if got := h.code(t, sid, map[string]interface{}{"op": "read", "path": path, "offset": 0, "length": 10}); got != "symlink_refused" {
			t.Fatalf("read %s: %q", path, got)
		}
		if got := h.code(t, sid, map[string]interface{}{"op": "hash", "path": path}); got != "symlink_refused" {
			t.Fatalf("hash %s: %q", path, got)
		}
	}
	if got := h.code(t, sid, map[string]interface{}{"op": "list", "path": "out"}); got != "symlink_refused" {
		t.Fatalf("list out: %q", got)
	}
	// Writes through a symlink are refused and create nothing outside.
	data := []byte("pwned")
	for _, path := range []string{"out/new", "in/new"} {
		open, _ := h.upload(t, sid, path, data, nil)
		if got := errOf(open); got != "symlink_refused" {
			t.Fatalf("write %s: %q", path, got)
		}
	}
	if _, err := os.Stat(filepath.Join(outside, "new")); !os.IsNotExist(err) {
		t.Fatal("a write escaped through the symlink")
	}
	if got := h.code(t, sid, map[string]interface{}{"op": "mkdir", "path": "out/d", "parents": true}); got != "symlink_refused" {
		t.Fatalf("mkdir through symlink: %q", got)
	}
	// A symlink in the way of a write: exists without overwrite, not_a_file with it.
	if open, _ := h.upload(t, sid, "lf", data, nil); errOf(open) != "exists" {
		t.Fatalf("write onto symlink: %v", open)
	}
	if open, _ := h.upload(t, sid, "lf", data, map[string]interface{}{"overwrite": true}); errOf(open) != "not_a_file" {
		t.Fatalf("overwrite symlink: %v", open)
	}
	// A FIFO never blocks: not_a_file at once.
	start := time.Now()
	if got := h.code(t, sid, map[string]interface{}{"op": "read", "path": "p", "offset": 0, "length": 10}); got != "not_a_file" {
		t.Fatalf("read fifo: %q", got)
	}
	if got := h.code(t, sid, map[string]interface{}{"op": "hash", "path": "p"}); got != "not_a_file" {
		t.Fatalf("hash fifo: %q", got)
	}
	if time.Since(start) > 3*time.Second {
		t.Fatal("fifo blocked")
	}
	// remove deletes the link itself, never its target.
	if got := h.code(t, sid, map[string]interface{}{"op": "remove", "path": "lf"}); got != "" {
		t.Fatalf("remove link: %q", got)
	}
	if _, err := os.Lstat(filepath.Join(root, "lf")); !os.IsNotExist(err) {
		t.Fatal("link still there")
	}
	if _, err := os.Stat("/etc/passwd"); err != nil {
		t.Fatal("link target removed")
	}
	if got := h.code(t, sid, map[string]interface{}{"op": "nope", "path": "x"}); got != "bad_request" {
		t.Fatalf("unknown op: %q", got)
	}
}

func TestFileLinuxRootMustBeARealDirectory(t *testing.T) {
	needOpenat2(t)
	h := newFileHarness(t)
	base := t.TempDir()
	real := filepath.Join(base, "real")
	if err := os.MkdirAll(filepath.Join(real, "d"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, filepath.Join(base, "link")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(base, "file"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, root := range []string{filepath.Join(base, "link"), filepath.Join(base, "link", "d"), filepath.Join(base, "file"), filepath.Join(base, "missing")} {
		sid := h.open(t, root, fileOpenOpts{})
		if got := h.errorOf(t, sid); got != "root_invalid" {
			t.Fatalf("%s: got %q", root, got)
		}
	}
}

func TestFileLinuxReadLeaseCannotWrite(t *testing.T) {
	needOpenat2(t)
	h := newFileHarness(t)
	root, _ := fixture(t)
	sid := h.open(t, root, fileOpenOpts{mode: "read"})
	h.ready(t, sid)
	for _, req := range []map[string]interface{}{
		{"op": "write_open", "path": "n", "size": 1, "sha256": hexSum([]byte("x")), "overwrite": true},
		{"op": "write_commit"},
		{"op": "write_abort"},
		{"op": "mkdir", "path": "d"},
		{"op": "remove", "path": "f.txt"},
	} {
		if got := h.code(t, sid, req); got != "read_only" {
			t.Fatalf("%v: %q", req["op"], got)
		}
	}
	if _, err := os.Stat(filepath.Join(root, "f.txt")); err != nil {
		t.Fatal("removed through a read lease")
	}
	r := h.do(t, sid, map[string]interface{}{"op": "read", "path": "f.txt", "offset": 6, "length": 100})
	if errOf(r) != "" || r["bytes"] != float64(5) || r["eof"] != true || r["size"] != float64(11) {
		t.Fatalf("read: %v", r)
	}
	if got := h.out.text(sid); got != "world" {
		t.Fatalf("data %q", got)
	}
}

func TestFileLinuxReadHashIfMatch(t *testing.T) {
	needOpenat2(t)
	h := newFileHarness(t)
	root, _ := fixture(t)
	sid := h.open(t, root, fileOpenOpts{mode: "read"})
	h.ready(t, sid)
	fi, _ := os.Stat(filepath.Join(root, "f.txt"))
	mt := fi.ModTime().UnixNano()
	good := map[string]interface{}{"size": 11, "mtime_ns": mt}
	r := h.do(t, sid, map[string]interface{}{"op": "hash", "path": "f.txt", "if_match": good})
	if errOf(r) != "" || r["sha256"] != hexSum([]byte("hello world")) {
		t.Fatalf("hash: %v", r)
	}
	for _, m := range []map[string]interface{}{{"size": 12, "mtime_ns": mt}, {"size": 11, "mtime_ns": mt + 1}} {
		if got := h.code(t, sid, map[string]interface{}{"op": "read", "path": "f.txt", "offset": 0, "length": 5, "if_match": m}); got != "changed" {
			t.Fatalf("read if_match: %q", got)
		}
		if got := h.code(t, sid, map[string]interface{}{"op": "hash", "path": "f.txt", "if_match": m}); got != "changed" {
			t.Fatalf("hash if_match: %q", got)
		}
	}
	if got := h.code(t, sid, map[string]interface{}{"op": "read", "path": "f.txt", "offset": 0, "length": fileReadMax + 1}); got != "bad_request" {
		t.Fatalf("read past read_max: %q", got)
	}
	if got := h.code(t, sid, map[string]interface{}{"op": "read", "path": "sub", "offset": 0, "length": 1}); got != "not_a_file" {
		t.Fatalf("read dir: %q", got)
	}
	if got := h.code(t, sid, map[string]interface{}{"op": "read", "path": "nope", "offset": 0, "length": 1}); got != "not_found" {
		t.Fatalf("read missing: %q", got)
	}
	// An mtime_ns that does not fit int64 fails to decode: the request is
	// answered bad_request (never dropped), and the session goes on.
	huge := map[string]interface{}{"size": 11, "mtime_ns": json.Number("99999999999999999999")}
	for _, op := range []string{"read", "hash"} {
		if got := h.code(t, sid, map[string]interface{}{"op": op, "path": "f.txt", "offset": 0, "length": 5, "if_match": huge}); got != "bad_request" {
			t.Fatalf("%s with an mtime_ns past int64: %q", op, got)
		}
	}
	if got := h.code(t, sid, map[string]interface{}{"op": "stat", "path": "f.txt"}); got != "" {
		t.Fatalf("stat after a malformed request: %q", got)
	}
}

func TestFileLinuxWriteCommitIntegrity(t *testing.T) {
	needOpenat2(t)
	h := newFileHarness(t)
	root, _ := fixture(t)
	sid := h.open(t, root, fileOpenOpts{})
	h.ready(t, sid)
	data := randBytes(t, 2*fileChunkMax+fileChunkMax/2)
	open, commit := h.upload(t, sid, "sub/big.bin", data, nil)
	if errOf(open) != "" || !uploadIDRe.MatchString(open["upload_id"].(string)) || open["offset"] != float64(0) {
		t.Fatalf("write_open: %v", open)
	}
	if _, has := open["prefix_sha256"]; has {
		t.Fatal("prefix_sha256 at offset 0")
	}
	if errOf(commit) != "" || commit["sha256"] != hexSum(data) || commit["size"] != float64(len(data)) || commit["path"] != "sub/big.bin" {
		t.Fatalf("commit: %v", commit)
	}
	got, _ := os.ReadFile(filepath.Join(root, "sub", "big.bin"))
	if !bytes.Equal(got, data) {
		t.Fatal("content differs")
	}
	if fi, _ := os.Stat(filepath.Join(root, "sub", "big.bin")); fi.Mode().Perm() != 0o644 {
		t.Fatalf("default mode %v", fi.Mode())
	}
	noTemps(t, filepath.Join(root, "sub"))
	if recs := loadUploads(h.ch.stateDir); len(recs) != 0 {
		t.Fatalf("records left after commit: %v", recs)
	}

	// A sha256 mismatch leaves nothing at the target and no temp file.
	_, commit = h.upload(t, sid, "bad.bin", data[:100], map[string]interface{}{"sha256": hexSum([]byte("other"))})
	if errOf(commit) != "sha256_mismatch" {
		t.Fatalf("mismatch: %v", commit)
	}
	if _, err := os.Lstat(filepath.Join(root, "bad.bin")); !os.IsNotExist(err) {
		t.Fatal("corrupt file visible at the target")
	}
	noTemps(t, root)

	// overwrite:false gives exists, at open and (race) at commit.
	if open, _ := h.upload(t, sid, "f.txt", data[:10], nil); errOf(open) != "exists" {
		t.Fatalf("exists at open: %v", open)
	}
	rid := nextRID()
	small := data[:10]
	if r := h.do(t, sid, map[string]interface{}{"op": "write_open", "request_id": rid, "path": "race.txt", "size": 10, "sha256": hexSum(small), "overwrite": false}); errOf(r) != "" {
		t.Fatal(r)
	}
	// While the write is open, list hides the temp file.
	l := h.do(t, sid, map[string]interface{}{"op": "list", "path": "."})
	for _, e := range l["entries"].([]interface{}) {
		if strings.HasPrefix(e.(map[string]interface{})["name"].(string), ".sahsync-") {
			t.Fatal("list shows a temp file")
		}
	}
	h.chunk(t, sid, rid, 0, small)
	h.waitAck(t, sid, rid, 10)
	if err := os.WriteFile(filepath.Join(root, "race.txt"), []byte("theirs"), 0o644); err != nil {
		t.Fatal(err)
	}
	if r := h.do(t, sid, map[string]interface{}{"op": "write_commit", "request_id": rid}); errOf(r) != "exists" {
		t.Fatalf("commit race: %v", r)
	}
	if b, _ := os.ReadFile(filepath.Join(root, "race.txt")); string(b) != "theirs" {
		t.Fatal("RENAME_NOREPLACE replaced the racing file")
	}

	// overwrite:true replaces a regular file, applies mode; a directory in the way is not_a_file.
	if _, c := h.upload(t, sid, "f.txt", small, map[string]interface{}{"overwrite": true, "mode": "0600"}); errOf(c) != "" {
		t.Fatalf("overwrite: %v", c)
	}
	if fi, _ := os.Stat(filepath.Join(root, "f.txt")); fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", fi.Mode())
	}
	if open, _ := h.upload(t, sid, "sub", small, map[string]interface{}{"overwrite": true}); errOf(open) != "not_a_file" {
		t.Fatalf("dir in the way: %v", open)
	}
	if open, _ := h.upload(t, sid, "m.bin", small, map[string]interface{}{"mode": "4755"}); errOf(open) != "bad_request" {
		t.Fatalf("setuid mode: %v", open)
	}

	// offset_mismatch and too_large end the write; abort deletes the temp file.
	rid = nextRID()
	h.do(t, sid, map[string]interface{}{"op": "write_open", "request_id": rid, "path": "o.bin", "size": 10, "sha256": hexSum(small), "overwrite": false})
	h.chunk(t, sid, rid, 5, small[:5])
	if r := h.waitResult(t, sid, rid, "write_chunk"); errOf(r) != "offset_mismatch" {
		t.Fatalf("offset: %v", r)
	}
	if r := h.do(t, sid, map[string]interface{}{"op": "write_commit", "request_id": rid}); errOf(r) != "upload_not_found" {
		t.Fatalf("commit after failed chunk: %v", r)
	}
	rid = nextRID()
	h.do(t, sid, map[string]interface{}{"op": "write_open", "request_id": rid, "path": "t.bin", "size": 4, "sha256": hexSum(small[:4]), "overwrite": false})
	h.chunk(t, sid, rid, 0, small)
	if r := h.waitResult(t, sid, rid, "write_chunk"); errOf(r) != "too_large" {
		t.Fatalf("too_large: %v", r)
	}
	rid = nextRID()
	ab := h.do(t, sid, map[string]interface{}{"op": "write_open", "request_id": rid, "path": "a.bin", "size": 10, "sha256": hexSum(small), "overwrite": false})
	h.chunk(t, sid, rid, 0, small[:5])
	h.waitAck(t, sid, rid, 5)
	abTmp := filepath.Join(root, tempName(ab["upload_id"].(string)))
	if _, err := os.Stat(abTmp); err != nil {
		t.Fatal("no temp file while writing")
	}
	if r := h.do(t, sid, map[string]interface{}{"op": "write_abort", "request_id": rid}); errOf(r) != "" {
		t.Fatalf("abort: %v", r)
	}
	if _, err := os.Stat(abTmp); !os.IsNotExist(err) {
		t.Fatal("abort left its temp file")
	}
	if r := h.do(t, sid, map[string]interface{}{"op": "write_abort", "request_id": rid}); errOf(r) != "upload_not_found" {
		t.Fatalf("abort again: %v", r)
	}
}

func TestFileLinuxResume(t *testing.T) {
	needOpenat2(t)
	h := newFileHarness(t)
	root, _ := fixture(t)
	data := randBytes(t, 3*fileChunkMax)
	sum := hexSum(data)
	begin := func(sid string, chunks int) string {
		rid := nextRID()
		open := h.do(t, sid, map[string]interface{}{"op": "write_open", "request_id": rid, "path": "sub/r.bin", "size": len(data), "sha256": sum, "overwrite": false, "resume": true})
		if errOf(open) != "" {
			t.Fatal(open)
		}
		for i := 0; i < chunks; i++ {
			off := int64(i * fileChunkMax)
			h.chunk(t, sid, rid, off, data[off:off+fileChunkMax])
			h.waitAck(t, sid, rid, off+fileChunkMax)
		}
		return open["upload_id"].(string)
	}
	// A killed upload: two chunks, then the session is stopped.
	s1 := h.open(t, root, fileOpenOpts{})
	h.ready(t, s1)
	id := begin(s1, 2)
	_ = h.send(t, map[string]interface{}{"type": "file_stop", "session_id": s1})
	if p := h.closedOf(t, s1); p["reason"] != "stopped" || p["bytes_written"] != float64(2*fileChunkMax) {
		t.Fatalf("closed: %v", p)
	}
	tmp := filepath.Join(root, "sub", tempName(id))
	if fi, err := os.Stat(tmp); err != nil || fi.Size() != int64(2*fileChunkMax) || fi.Mode().Perm() != 0o600 {
		t.Fatalf("temp after kill: %v %v", fi, err)
	}
	// Another actor never gets it.
	s2 := h.open(t, root, fileOpenOpts{actor: "user-2"})
	h.ready(t, s2)
	other := h.do(t, s2, map[string]interface{}{"op": "write_open", "path": "sub/r.bin", "size": len(data), "sha256": sum, "overwrite": false, "resume": true})
	if other["upload_id"] == id || other["offset"] != float64(0) {
		t.Fatalf("another actor resumed: %v", other)
	}
	h.do(t, s2, map[string]interface{}{"op": "write_abort", "request_id": other["request_id"]})
	// The same actor resumes at the durable offset with a matching prefix.
	s3 := h.open(t, root, fileOpenOpts{})
	h.ready(t, s3)
	rid := nextRID()
	open := h.do(t, s3, map[string]interface{}{"op": "write_open", "request_id": rid, "path": "sub/r.bin", "size": len(data), "sha256": sum, "overwrite": false, "resume": true})
	if open["upload_id"] != id || open["offset"] != float64(2*fileChunkMax) || open["prefix_sha256"] != hexSum(data[:2*fileChunkMax]) {
		t.Fatalf("resume: %v", open)
	}
	h.chunk(t, s3, rid, int64(2*fileChunkMax), data[2*fileChunkMax:])
	h.waitAck(t, s3, rid, int64(len(data)))
	if c := h.do(t, s3, map[string]interface{}{"op": "write_commit", "request_id": rid}); errOf(c) != "" || c["sha256"] != sum {
		t.Fatalf("commit after resume: %v", c)
	}
	if got, _ := os.ReadFile(filepath.Join(root, "sub", "r.bin")); !bytes.Equal(got, data) {
		t.Fatal("resumed content differs")
	}

	// A wrong prefix is caught: the temp file changed on disk while
	// interrupted, so prefix_sha256 differs from the client's local prefix.
	if err := os.Remove(filepath.Join(root, "sub", "r.bin")); err != nil {
		t.Fatal(err)
	}
	s4 := h.open(t, root, fileOpenOpts{})
	h.ready(t, s4)
	id = begin(s4, 1)
	_ = h.send(t, map[string]interface{}{"type": "file_stop", "session_id": s4})
	h.closedOf(t, s4)
	f, err := os.OpenFile(filepath.Join(root, "sub", tempName(id)), os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.WriteAt([]byte{data[100] ^ 0xff}, 100)
	_ = f.Close()
	s5 := h.open(t, root, fileOpenOpts{})
	h.ready(t, s5)
	rid = nextRID()
	open = h.do(t, s5, map[string]interface{}{"op": "write_open", "request_id": rid, "path": "sub/r.bin", "size": len(data), "sha256": sum, "overwrite": false, "resume": true})
	if open["upload_id"] != id || open["offset"] != float64(fileChunkMax) {
		t.Fatalf("resume 2: %v", open)
	}
	if open["prefix_sha256"] == hexSum(data[:fileChunkMax]) {
		t.Fatal("a corrupted prefix hashed like the client's")
	}
	// The client aborts and restarts.
	if r := h.do(t, s5, map[string]interface{}{"op": "write_abort", "request_id": rid}); errOf(r) != "" {
		t.Fatal(r)
	}
	noTemps(t, filepath.Join(root, "sub"))
}

func TestFileLinuxListMkdirRemove(t *testing.T) {
	needOpenat2(t)
	h := newFileHarness(t)
	root := t.TempDir()
	names := []string{"b", "a", "C", "_", "a.b", "é", "z"}
	for _, n := range names {
		if err := os.WriteFile(filepath.Join(root, n), []byte(n), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(root, ".sahsync-upl_aaaaaaaaaaaaaaaaaaaa.part"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	sid := h.open(t, root, fileOpenOpts{})
	h.ready(t, sid)
	sort.Strings(names)
	var got []string
	var cursor interface{}
	for pages := 0; ; pages++ {
		r := h.do(t, sid, map[string]interface{}{"op": "list", "path": ".", "cursor": cursor, "limit": 3})
		for _, e := range r["entries"].([]interface{}) {
			got = append(got, e.(map[string]interface{})["name"].(string))
		}
		cursor = r["next_cursor"]
		if cursor == nil {
			break
		}
		if pages > 5 {
			t.Fatal("cursor never ended")
		}
	}
	if strings.Join(got, ",") != strings.Join(names, ",") {
		t.Fatalf("list %v, want %v", got, names)
	}
	for _, lim := range []int{0, 1001} {
		if c := h.code(t, sid, map[string]interface{}{"op": "list", "path": ".", "limit": lim}); c != "bad_request" {
			t.Fatalf("limit %d: %q", lim, c)
		}
	}
	if c := h.code(t, sid, map[string]interface{}{"op": "list", "path": "a"}); c != "not_a_dir" {
		t.Fatalf("list file: %q", c)
	}
	mk := h.do(t, sid, map[string]interface{}{"op": "mkdir", "path": "x/y/z", "parents": true, "mode": "0700"})
	if errOf(mk) != "" || mk["entry"].(map[string]interface{})["mode"] != "0700" || mk["entry"].(map[string]interface{})["type"] != "dir" {
		t.Fatalf("mkdir -p: %v", mk)
	}
	if c := h.code(t, sid, map[string]interface{}{"op": "mkdir", "path": "x"}); c != "exists" {
		t.Fatalf("mkdir existing: %q", c)
	}
	if c := h.code(t, sid, map[string]interface{}{"op": "mkdir", "path": "q/r"}); c != "not_found" {
		t.Fatalf("mkdir without parents: %q", c)
	}
	if c := h.code(t, sid, map[string]interface{}{"op": "remove", "path": "x/y"}); c != "not_empty" {
		t.Fatalf("remove non-empty: %q", c)
	}
	for _, p := range []string{"x/y/z", "x/y", "x", "a"} {
		if c := h.code(t, sid, map[string]interface{}{"op": "remove", "path": p}); c != "" {
			t.Fatalf("remove %s: %q", p, c)
		}
	}
	if c := h.code(t, sid, map[string]interface{}{"op": "remove", "path": "."}); c != "bad_path" {
		t.Fatalf("remove root: %q", c)
	}
	if c := h.code(t, sid, map[string]interface{}{"op": "remove", "path": "a"}); c != "not_found" {
		t.Fatalf("remove missing: %q", c)
	}
}

func TestFileLinuxStaleUploadsExpire(t *testing.T) {
	needOpenat2(t)
	h := newFileHarness(t)
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "d"), 0o755); err != nil {
		t.Fatal(err)
	}
	id := "upl_dddddddddddddddddddd"
	tmp := filepath.Join(root, "d", tempName(id))
	if err := os.WriteFile(tmp, []byte("partial"), 0o600); err != nil {
		t.Fatal(err)
	}
	rec := uploadRecord{UploadID: id, ActorKey: actorKey("user-1"), Root: root, Path: "d/f", Size: 100, SHA256: hexSum([]byte("x")),
		CreatedUnix: time.Now().Add(-25 * time.Hour).Unix()}
	if err := saveUpload(h.ch.stateDir, rec); err != nil {
		t.Fatal(err)
	}
	sid := h.open(t, root, fileOpenOpts{})
	h.ready(t, sid)
	if _, err := os.Stat(tmp); !os.IsNotExist(err) {
		t.Fatal("stale temp file not removed")
	}
	if len(loadUploads(h.ch.stateDir)) != 0 {
		t.Fatal("stale record not removed")
	}
}

// Of the 16 agent slots, 2 only take file_root sessions.
func TestFileLinuxRootSlotsReserved(t *testing.T) {
	needOpenat2(t)
	h := newFileHarness(t)
	root := t.TempDir()
	for i := 0; i < fileMaxSessions-fileRootReserved; i++ {
		h.ready(t, h.open(t, root, fileOpenOpts{}))
	}
	if got := h.errorOf(t, h.open(t, root, fileOpenOpts{})); got != "cap_reached" {
		t.Fatalf("non-root session past the unreserved slots: %q", got)
	}
	if got := h.errorOf(t, h.open(t, root, fileOpenOpts{mode: "read"})); got != "cap_reached" {
		t.Fatalf("read session past the unreserved slots: %q", got)
	}
	// A file_root session is not refused for a slot (this agent is not
	// root, so it fails later, at the identity).
	if got := h.errorOf(t, h.open(t, root, fileOpenOpts{action: "file_root"})); got != "root_unavailable" {
		t.Fatalf("file_root session: %q", got)
	}
}

func TestFileLinuxIdleAndDeadline(t *testing.T) {
	needOpenat2(t)
	h := newFileHarness(t)
	root := t.TempDir()
	sid := h.open(t, root, fileOpenOpts{idle: 1})
	h.ready(t, sid)
	if p := h.closedOf(t, sid); p["reason"] != "idle_timeout" {
		t.Fatalf("idle: %v", p)
	}
	sid = h.open(t, root, fileOpenOpts{leaseExp: inFuture(2 * time.Second)})
	h.ready(t, sid)
	if p := h.closedOf(t, sid); p["reason"] != "stopped" {
		t.Fatalf("lease lapse: %v", p)
	}
}

// The helper really runs with the dropped identity: as nobody, files it
// creates belong to nobody and a root-only file is permission_denied;
// file:root runs as root.
func TestFileLinuxHelperRunsAsPtyUser(t *testing.T) {
	needOpenat2(t)
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	nobody, err := user.Lookup("nobody")
	if err != nil {
		t.Skip("no nobody user")
	}
	h := newFileHarness(t)
	agentEUID = os.Geteuid
	ptyCfg = ptySettings{User: "nobody"}
	// A copy of the test binary that nobody can execute.
	bin, err := os.MkdirTemp("/", "sahfile-bin-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(bin) })
	if err := os.Chmod(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	exe := filepath.Join(bin, "agent.test")
	src, err := os.Open(self)
	if err != nil {
		t.Fatal(err)
	}
	dst, err := os.OpenFile(exe, os.O_CREATE|os.O_WRONLY, 0o755)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(dst, src); err != nil {
		t.Fatal(err)
	}
	_ = src.Close()
	_ = dst.Close()
	prevExe := fileHelperExe
	fileHelperExe = func() (string, error) { return exe, nil }
	t.Cleanup(func() { fileHelperExe = prevExe })

	root, err := os.MkdirTemp("/", "sahfile-root-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	if err := os.Chmod(root, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "secret"), []byte("root only"), 0o600); err != nil {
		t.Fatal(err)
	}
	sid := h.open(t, root, fileOpenOpts{})
	p := h.ready(t, sid)
	if p["user"] != "nobody" || strconv.Itoa(int(p["uid"].(float64))) != nobody.Uid {
		t.Fatalf("ready as %v uid %v", p["user"], p["uid"])
	}
	if _, c := h.upload(t, sid, "mine.txt", []byte("hi"), nil); errOf(c) != "" {
		t.Fatalf("upload as nobody: %v", c)
	}
	fi, err := os.Stat(filepath.Join(root, "mine.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if st := fi.Sys().(*syscall.Stat_t); strconv.Itoa(int(st.Uid)) != nobody.Uid || strconv.Itoa(int(st.Gid)) != nobody.Gid {
		t.Fatalf("file owned by %d:%d", st.Uid, st.Gid)
	}
	if c := h.code(t, sid, map[string]interface{}{"op": "read", "path": "secret", "offset": 0, "length": 10}); c != "permission_denied" {
		t.Fatalf("root-only file as nobody: %q", c)
	}
	// file:root runs as root and can read it.
	rs := h.open(t, root, fileOpenOpts{action: "file_root"})
	if p := h.ready(t, rs); p["uid"] != float64(0) || p["user"] != "root" {
		t.Fatalf("file:root as %v", p)
	}
	if r := h.do(t, rs, map[string]interface{}{"op": "read", "path": "secret", "offset": 0, "length": 100}); errOf(r) != "" || r["bytes"] != float64(9) {
		t.Fatalf("file:root read: %v", r)
	}
	// A root agent without --pty-user refuses file:read/write.
	ptyCfg = ptySettings{}
	if got := h.errorOf(t, h.open(t, root, fileOpenOpts{})); got != "pty_user_unset" {
		t.Fatalf("no pty_user: %q", got)
	}
}
