package main

import (
	"bufio"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// ---- fake recv -----------------------------------------------------------

// fakeRecvFields is the exact key set of the fd 3 grant line (plan,
// "Agent to recv, fd 3").
var fakeRecvFields = []string{
	"v", "grant_id", "transfer_id", "purpose", "dir", "root", "path", "size", "sha256", "overwrite",
	"profile", "transport", "aead", "key", "route_token", "expires_unix", "deadline_unix", "idle_s",
	"max_s", "byte_cap", "peer",
}

// runFakeRecv stands in for `sahxfer recv --ctl-fd 3 --event-fd 4` and
// `recv --sweep --ctl-fd 3`. Its behaviour comes from the first component of
// the grant's path, because the agent starts it with an empty environment.
// It appends what it saw on fd 3 to <root>/.fake-ctl.log.
func runFakeRecv(args []string) int {
	// Any fd past 4 must be the child runtime's own (on Linux: netpoll's
	// epoll and eventfd, and the cgroup CPU limit file), never one inherited
	// from the agent (a pipe, a socket, a state or key file).
	var extra []string
	for fd := 5; fd < 64; fd++ {
		if !fdOpen(fd) {
			continue
		}
		target, _ := os.Readlink("/proc/self/fd/" + strconv.Itoa(fd))
		if strings.HasPrefix(target, "anon_inode:") || strings.HasPrefix(target, "/sys/fs/cgroup/") {
			continue
		}
		extra = append(extra, "extra_fd "+strconv.Itoa(fd)+" "+target)
	}
	if len(os.Environ()) != 0 {
		extra = append(extra, "env_nonempty")
	}
	if wd, _ := os.Getwd(); wd != "/" {
		extra = append(extra, "cwd "+wd)
	}
	sweep, report, ctlFD, evFD := false, false, -1, -1
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--sweep":
			sweep = true
		case "--report":
			report = true
		case "--ctl-fd", "--event-fd":
			if i+1 >= len(args) {
				return 2
			}
			n, err := strconv.Atoi(args[i+1])
			if err != nil {
				return 2
			}
			if args[i] == "--ctl-fd" {
				ctlFD = n
			} else {
				evFD = n
			}
			i++
		default:
			return 2
		}
	}
	if ctlFD != 3 {
		return 2
	}
	ctl := bufio.NewReader(os.NewFile(3, "ctl"))
	if sweep {
		if report != (evFD == 4) {
			return 2
		}
		line, err := ctl.ReadBytes('\n')
		if err != nil {
			return 3
		}
		var rec struct {
			Root    string `json:"root"`
			Path    string `json:"path"`
			GrantID string `json:"grant_id"`
		}
		dec := json.NewDecoder(strings.NewReader(string(line)))
		dec.DisallowUnknownFields()
		if dec.Decode(&rec) != nil || !xferGrantRe.MatchString(rec.GrantID) {
			return 3
		}
		_ = os.Remove(fakeTemp(rec.Root, rec.Path, rec.GrantID))
		fakeLog(rec.Root, ".fake-sweep.log", append(extra, "sweep "+rec.GrantID)...)
		if body, err := os.ReadFile(filepath.Join(rec.Root, rec.Path)); err == nil {
			sum := sha256.Sum256(body)
			raw, _ := json.Marshal(map[string]interface{}{"ev": "target", "bytes": len(body), "sha256": hex.EncodeToString(sum[:])})
			_, _ = os.NewFile(4, "events").Write(append(raw, '\n'))
		}
		return 0
	}
	if evFD != 4 {
		return 2
	}
	ev := os.NewFile(4, "events")
	var evMu sync.Mutex
	emit := func(v map[string]interface{}) {
		evMu.Lock()
		defer evMu.Unlock()
		raw, _ := json.Marshal(v)
		_, _ = ev.Write(append(raw, '\n'))
	}
	line, err := ctl.ReadBytes('\n')
	if err != nil || len(line) > xferLineMax {
		return 3
	}
	var keys map[string]json.RawMessage
	if json.Unmarshal(line, &keys) != nil {
		return 3
	}
	var g xferCtlGrant
	dec := json.NewDecoder(strings.NewReader(string(line)))
	dec.DisallowUnknownFields()
	if dec.Decode(&g) != nil {
		return 3
	}
	result := func(status, reason string, committed bool, n int64) {
		r := map[string]interface{}{"ev": "result", "grant_id": g.GrantID, "transfer_id": g.TransferID,
			"status": status, "reason": reason, "bytes": n, "committed": committed}
		if committed {
			r["sha256"] = g.SHA256
		}
		emit(r)
	}
	got := make([]string, 0, len(keys))
	for k := range keys {
		got = append(got, k)
	}
	sort.Strings(got)
	want := append([]string(nil), fakeRecvFields...)
	sort.Strings(want)
	_, kerr := decodeXferSecretOK(g.Key, 32)
	_, terr := decodeXferSecretOK(g.RouteToken, 16)
	if strings.Join(got, ",") != strings.Join(want, ",") || g.V != 1 || kerr != nil || terr != nil {
		fakeLog(g.Root, ".fake-ctl.log", "bad_grant_line")
		result("aborted", "bad_grant", false, 0)
		return 1
	}
	fakeLog(g.Root, ".fake-ctl.log", append(extra, "grant peer="+g.Peer+" overwrite="+strconv.FormatBool(g.Overwrite))...)
	mode, _, _ := strings.Cut(g.Path, "/")
	temp := fakeTemp(g.Root, g.Path, g.GrantID)
	switch mode {
	case "refuse":
		result("aborted", "exists", false, 0)
		return 1
	case "noid": // recv's grant-line decode failure: a result without ids
		emit(map[string]interface{}{"ev": "result", "status": "aborted", "reason": "bad_grant", "committed": false})
		return 1
	case "silent": // exits with a code on stderr and no event
		fmt.Fprintln(os.Stderr, "bad_grant")
		return 1
	case "otherid": // a result naming another grant is not believed
		emit(map[string]interface{}{"ev": "result", "grant_id": "xfr_someoneelse", "transfer_id": g.TransferID,
			"status": "aborted", "reason": "exists", "committed": false})
		return 1
	}
	_ = os.MkdirAll(filepath.Dir(temp), 0o700)
	if err := os.WriteFile(temp, nil, 0o600); err != nil {
		result("aborted", "io", false, 0)
		return 1
	}
	switch mode {
	case "noread": // never reads fd 3 again; runs until killed
		emit(map[string]interface{}{"ev": "ready", "udp": "127.0.0.1:47199"})
		for {
			time.Sleep(time.Second)
		}
	case "nonewline": // the final result line has no newline before EOF
		emit(map[string]interface{}{"ev": "ready", "udp": "127.0.0.1:47198"})
		_ = os.Rename(temp, filepath.Join(g.Root, g.Path))
		raw, _ := json.Marshal(map[string]interface{}{"ev": "result", "grant_id": g.GrantID, "transfer_id": g.TransferID,
			"status": "ok", "bytes": g.Size, "sha256": g.SHA256, "committed": true})
		_, _ = ev.Write(raw)
		return 0
	case "wrongip": // binds one address, reports another
		emit(map[string]interface{}{"ev": "ready", "udp": "127.0.0.2:47197"})
		time.Sleep(10 * time.Second)
		return 0
	case "leak": // leaves a process holding fd 4 and stderr open
		holder := exec.Command("/bin/sleep", "20")
		holder.ExtraFiles = []*os.File{ev}
		holder.Stderr = os.Stderr
		if err := holder.Start(); err == nil {
			fakeLog(g.Root, ".fake-ctl.log", "holder "+strconv.Itoa(holder.Process.Pid))
		}
		emit(map[string]interface{}{"ev": "ready", "udp": "127.0.0.1:47196"})
		_ = os.Rename(temp, filepath.Join(g.Root, g.Path))
		result("ok", "", true, g.Size)
		return 0
	}
	cancel := make(chan string, 1)
	go func() {
		for {
			l, err := ctl.ReadBytes('\n')
			if err != nil {
				fakeLog(g.Root, ".fake-ctl.log", "eof")
				cancel <- "stopped"
				return
			}
			var op struct {
				Op           string `json:"op"`
				DeadlineUnix int64  `json:"deadline_unix"`
				Reason       string `json:"reason"`
			}
			_ = json.Unmarshal(l, &op)
			switch op.Op {
			case "renew":
				fakeLog(g.Root, ".fake-ctl.log", "renew "+strconv.FormatInt(op.DeadlineUnix, 10))
			case "cancel":
				fakeLog(g.Root, ".fake-ctl.log", "cancel "+op.Reason)
				if mode == "expire" {
					// The real recv's lapse path: its own deadline check.
					op.Reason = "expired"
				}
				if mode != "deaf" {
					select {
					case cancel <- op.Reason:
					default:
					}
				}
			}
		}
	}()
	// Ready: a listen address with port 0 is really bound, so the agent
	// sees a kernel-chosen port; a fixed port is reported as given.
	ready := map[string]interface{}{"ev": "ready"}
	if addr, ok := strings.CutPrefix(g.Peer, "listen:"); ok {
		ap, err := netip.ParseAddrPort(addr)
		if err != nil {
			result("aborted", "internal", false, 0)
			return 1
		}
		if ap.Port() == 0 {
			pc, err := net.ListenPacket("udp", addr)
			if err != nil {
				result("aborted", "internal", false, 0)
				return 1
			}
			defer pc.Close()
			addr = pc.LocalAddr().String()
		}
		ready["udp"] = addr
	}
	if mode == "badready" {
		ready["udp"] = "not-an-address"
	}
	emit(ready)
	abort := func(reason string) int {
		_ = os.Remove(temp)
		status := "aborted"
		if reason == "expired" {
			status = "expired"
		}
		result(status, reason, false, 0)
		return 0
	}
	commit := func() int {
		if err := os.Rename(temp, filepath.Join(g.Root, g.Path)); err != nil {
			return abort("io")
		}
		result("ok", "", true, g.Size)
		return 0
	}
	switch mode {
	case "ok":
		emit(map[string]interface{}{"ev": "active", "bytes": g.Size})
		return commit()
	case "wait":
		emit(map[string]interface{}{"ev": "active", "bytes": 0})
		for {
			select {
			case r := <-cancel:
				return abort(r)
			case <-time.After(10 * time.Millisecond):
				if _, err := os.Stat(filepath.Join(g.Root, ".release")); err == nil {
					return commit()
				}
			}
		}
	default: // hold, deaf, badready: progress until cancelled
		var n int64
		for {
			select {
			case r := <-cancel:
				return abort(r)
			case <-time.After(10 * time.Millisecond):
				if n < g.Size {
					n++
				}
				emit(map[string]interface{}{"ev": "active", "bytes": n})
			}
		}
	}
}

func decodeXferSecretOK(s string, n int) ([]byte, error) {
	b, ok := decodeXferSecret(s, n)
	if !ok {
		return nil, errors.New("bad")
	}
	return b, nil
}

func fakeTemp(root, path, gid string) string {
	return filepath.Join(root, filepath.Dir(path), ".sahxfer-"+gid+".part")
}

func fakeLog(root, name string, lines ...string) {
	f, err := os.OpenFile(filepath.Join(root, name), os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return
	}
	defer f.Close()
	for _, l := range lines {
		fmt.Fprintln(f, l)
	}
}

func readFakeLog(root, name string) string {
	b, _ := os.ReadFile(filepath.Join(root, name))
	return string(b)
}

// ---- harness -------------------------------------------------------------

type xferHarness struct {
	priv     ed25519.PrivateKey
	out      *fakeOut
	ch       *channelConn
	m        *xferManager
	stateDir string
}

func testExe(t *testing.T) string {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	exe, err = filepath.EvalSymlinks(exe)
	if err != nil {
		t.Fatal(err)
	}
	return exe
}

func saveXferGlobals(t *testing.T) {
	t.Helper()
	prevCfg, prevEUID, prevX := ptyCfg, agentEUID, xferCfg
	prevWatch, prevProg, prevCancel, prevTerm, prevSweep := xferWatchEvery, xferProgressEvery, xferCancelGrace, xferTermGrace, xferSweepTimeout
	prevMgr := xferMgr()
	t.Cleanup(func() {
		ptyCfg, agentEUID, xferCfg = prevCfg, prevEUID, prevX
		xferWatchEvery, xferProgressEvery, xferCancelGrace, xferTermGrace, xferSweepTimeout = prevWatch, prevProg, prevCancel, prevTerm, prevSweep
		xferMgrPtr.Store(prevMgr)
	})
	ptyCfg = ptySettings{AllowAgentUser: true}
	agentEUID = func() int { return 1000 }
	xferCfg = xferConfig{bin: testExe(t), listen: &xferListen{ip: netip.MustParseAddr("127.0.0.1")}, allowDarwin: true}
	xferWatchEvery = 20 * time.Millisecond
	xferCancelGrace = 300 * time.Millisecond
	xferTermGrace = 300 * time.Millisecond
}

func newXferHarness(t *testing.T) *xferHarness {
	t.Helper()
	if runtime.GOOS == "linux" && !openat2Available() {
		t.Skip("xfer needs openat2 on Linux")
	}
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skip("xfer runs on Linux and Darwin only")
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	clearIdentity()
	if err := pinControlPublicKey(base64.StdEncoding.EncodeToString(pub), ptyTestHost); err != nil {
		t.Fatal(err)
	}
	saveXferGlobals(t)
	h := &xferHarness{priv: priv, out: newFakeOut(), stateDir: t.TempDir()}
	h.m = newXferManager(h.stateDir)
	xferMgrPtr.Store(h.m)
	h.m.attach(h.out)
	h.ch = newChannelConn(h.out, ptyTestHost)
	h.ch.stateDir = h.stateDir
	t.Cleanup(func() {
		h.m.stopAll("stopped", 5*time.Second)
		waitFor(t, "xfer children to end", 5*time.Second, func() bool { return h.m.liveCount() == 0 })
		h.ch.close("stopped")
		clearIdentity()
	})
	return h
}

func randHex(t *testing.T, n int) string {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b)
}

func randB64(t *testing.T, n int) string {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(b)
}

// xferFrame is a valid put grant for root/path, not yet signed.
func xferFrame(t *testing.T, root, path string) xferMsg {
	t.Helper()
	now := time.Now().Unix()
	sum := sha256.Sum256([]byte("hello"))
	return xferMsg{
		Type: "xfer_grant", GrantID: "xfr_" + randHex(t, 8), TransferID: "1" + randHex(t, 8)[:15],
		Action: "xfer", Purpose: "xfer:put", Dir: "put", Root: root, Path: path, Size: 5,
		SHA256: hex.EncodeToString(sum[:]), Profile: "internet", Transport: "udp", Peer: "listen",
		AEAD: xferAEAD, Key: randB64(t, 32), RouteToken: randB64(t, 16), ExpiresUnix: now + 60,
		DeadlineUnix: now + 60, IdleS: 30, MaxS: 600, ByteCap: 5, Actor: "user-1",
	}
}

func signXfer(t *testing.T, priv ed25519.PrivateKey, host string, msg *xferMsg, phase string, leaseExp int64) {
	t.Helper()
	mat, ok := xferMaterialOf(msg.Key, msg.RouteToken)
	if !ok {
		t.Fatal("material")
	}
	payload, err := xferLeasePayload(xferFields(*msg, phase, mat))
	if err != nil {
		t.Fatal(err)
	}
	msg.Lease = signLease(t, priv, host, msg.Action, payload, leaseExp)
}

func (h *xferHarness) sign(t *testing.T, msg *xferMsg) {
	t.Helper()
	signXfer(t, h.priv, ptyTestHost, msg, "start", time.Now().Unix()+60)
}

func (h *xferHarness) send(t *testing.T, v interface{}) {
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
	if !handled || err != nil {
		t.Fatalf("%s: handled=%v err=%v", peek.Type, handled, err)
	}
}

// start sends a signed grant for root/path and returns it.
func (h *xferHarness) start(t *testing.T, root, path string, edit func(*xferMsg)) xferMsg {
	t.Helper()
	msg := xferFrame(t, root, path)
	if edit != nil {
		edit(&msg)
	}
	h.sign(t, &msg)
	h.send(t, msg)
	return msg
}

// xferMsgs returns the payloads of every message of typ for gid, in order.
func xferMsgs(f *fakeOut, typ, gid string) []map[string]interface{} {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []map[string]interface{}
	for _, m := range f.jsons {
		if m["type"] == typ && m["grant_id"] == gid {
			p, _ := m["payload"].(map[string]interface{})
			out = append(out, p)
		}
	}
	return out
}

func waitXfer(t *testing.T, f *fakeOut, typ, gid string, match func(map[string]interface{}) bool) map[string]interface{} {
	t.Helper()
	var got map[string]interface{}
	waitFor(t, typ+" "+gid, 10*time.Second, func() bool {
		for _, p := range xferMsgs(f, typ, gid) {
			if match == nil || match(p) {
				got = p
				return true
			}
		}
		return false
	})
	return got
}

func (h *xferHarness) errorOf(t *testing.T, gid string) string {
	t.Helper()
	p := waitXfer(t, h.out, "xfer_status", gid, func(p map[string]interface{}) bool { return p["error"] != nil })
	code, _ := p["error"].(string)
	return code
}

func (h *xferHarness) ready(t *testing.T, gid string) map[string]interface{} {
	t.Helper()
	return waitXfer(t, h.out, "xfer_status", gid, func(p map[string]interface{}) bool { return p["status"] == "ready" })
}

func (h *xferHarness) result(t *testing.T, gid string) map[string]interface{} {
	t.Helper()
	return waitXfer(t, h.out, "xfer_result", gid, nil)
}

func newXferRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return root
}

// assertNoSpawn checks that a refused grant started nothing and left no record.
func (h *xferHarness) assertNoSpawn(t *testing.T, root string) {
	t.Helper()
	if h.m.liveCount() != 0 {
		t.Fatalf("%d children live", h.m.liveCount())
	}
	if s := readFakeLog(root, ".fake-ctl.log"); s != "" {
		t.Fatalf("recv started: %q", s)
	}
	if recs := loadXferRecords(h.stateDir); len(recs) != 0 {
		t.Fatalf("%d records left", len(recs))
	}
}

// ---- payload -------------------------------------------------------------

func goldenVector(t *testing.T) (payload, hash string) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "golden-xfer-lease-v2.txt"))
	if err != nil {
		t.Fatalf("golden vector: %v", err)
	}
	s := string(raw)
	const begin, end = "-----BEGIN PAYLOAD-----\n", "\n-----END PAYLOAD-----"
	i, j := strings.Index(s, begin), strings.Index(s, end)
	if i < 0 || j < i {
		t.Fatal("golden vector: no payload block")
	}
	payload = s[i+len(begin) : j]
	const marker = "sha256(\"xfer\\n\" + payload) =\n"
	k := strings.Index(s, marker)
	if k < 0 {
		t.Fatal("golden vector: no hash")
	}
	hash = strings.TrimSpace(strings.SplitN(s[k+len(marker):], "\n", 2)[0])
	return payload, hash
}

// The shared golden vector (sahxfer docs/golden-xfer-lease-v2.txt, copied
// byte for byte into testdata): same inputs, same payload, same hash in Go
// and in Node.
func TestXferLeaseGoldenVector(t *testing.T) {
	wantPayload, wantHash := goldenVector(t)
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	token := make([]byte, 16)
	for i := range token {
		token[i] = byte(0xa1 + i)
	}
	if base64.StdEncoding.EncodeToString(key) != "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=" ||
		base64.StdEncoding.EncodeToString(token) != "oaKjpKWmp6ipqqusra6vsA==" {
		t.Fatal("material inputs")
	}
	mat, err := xferMaterial(key, token)
	if err != nil {
		t.Fatal(err)
	}
	mat2, ok := xferMaterialOf("AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=", "oaKjpKWmp6ipqqusra6vsA==")
	if !ok || mat2 != mat {
		t.Fatal("material from base64")
	}
	got, err := xferLeasePayload(xferLeaseFields{
		GrantID: "xfr_GoldenVectorAAAAAAAAAA", DeadlineUnix: 1760745600, Phase: "start", Dir: "put",
		Root: "/srv/app", Path: "releases/app.tar.gz", Size: 1048576,
		SHA256:    "fce1b8bb923aa974c6756658f3e59e5dedfe1ad2f3082a484cd7a2fe593c29e5",
		Overwrite: false, TransferID: "0123456789abcdef", ExpiresUnix: 1760745600, IdleS: 30, MaxS: 3600,
		ByteCap: 1048576, Profile: "internet", Transport: "udp", Peer: "listen", Material: mat,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got != wantPayload {
		t.Fatalf("payload differs from the golden vector:\n%q\n%q", got, wantPayload)
	}
	if strings.Count(got, "\n") != 17 {
		t.Fatalf("payload has %d lines", strings.Count(got, "\n")+1)
	}
	sum := sha256.Sum256([]byte("xfer\n" + got))
	if hex.EncodeToString(sum[:]) != wantHash || payloadHash("xfer", got) != wantHash {
		t.Fatalf("hash %x, want %s", sum, wantHash)
	}
	if wantHash != "234e6abdf170097f94d2c8e3f6dafb006e5d1cf761159b6a4a226f3f6ca32380" {
		t.Fatal("the golden vector copy changed")
	}
	sum2 := sha256.Sum256([]byte("sahxfer golden vector contents.."))
	if hex.EncodeToString(sum2[:]) != "fce1b8bb923aa974c6756658f3e59e5dedfe1ad2f3082a484cd7a2fe593c29e5" {
		t.Fatal("golden sha256 input")
	}
}

func TestXferPayloadBuilderRefusesBadFields(t *testing.T) {
	base := xferLeaseFields{
		GrantID: "xfr_abcdefgh", DeadlineUnix: 100, Phase: "start", Dir: "put", Root: "/srv/app", Path: "a/b",
		Size: 5, SHA256: strings.Repeat("a", 64), TransferID: "0123456789abcdef", ExpiresUnix: 100, IdleS: 30,
		MaxS: 600, ByteCap: 5, Profile: "dc", Transport: "udp", Peer: "dial:relay.example:4000", Material: strings.Repeat("b", 64),
	}
	if _, err := xferLeasePayload(base); err != nil {
		t.Fatalf("base: %v", err)
	}
	for name, edit := range map[string]func(*xferLeaseFields){
		"grant id":            func(f *xferLeaseFields) { f.GrantID = "xfr_short" },
		"grant id newline":    func(f *xferLeaseFields) { f.GrantID = "xfr_abcdefgh\nx" },
		"deadline":            func(f *xferLeaseFields) { f.DeadlineUnix = 0 },
		"phase":               func(f *xferLeaseFields) { f.Phase = "prepare" },
		"dir":                 func(f *xferLeaseFields) { f.Dir = "both" },
		"root relative":       func(f *xferLeaseFields) { f.Root = "srv" },
		"root tilde":          func(f *xferLeaseFields) { f.Root = "~" },
		"root dotdot":         func(f *xferLeaseFields) { f.Root = "/srv/../etc" },
		"root trailing slash": func(f *xferLeaseFields) { f.Root = "/srv/" },
		"root newline":        func(f *xferLeaseFields) { f.Root = "/srv\n/x" },
		"path absolute":       func(f *xferLeaseFields) { f.Path = "/a" },
		"path dotdot":         func(f *xferLeaseFields) { f.Path = "a/../b" },
		"path dot":            func(f *xferLeaseFields) { f.Path = "." },
		"path empty":          func(f *xferLeaseFields) { f.Path = "" },
		"path control":        func(f *xferLeaseFields) { f.Path = "a\x01b" },
		"path newline":        func(f *xferLeaseFields) { f.Path = "a\nb" },
		"path backslash":      func(f *xferLeaseFields) { f.Path = "a\\b" },
		"path long component": func(f *xferLeaseFields) { f.Path = strings.Repeat("x", 256) },
		"size negative":       func(f *xferLeaseFields) { f.Size = -1 },
		"sha256 upper":        func(f *xferLeaseFields) { f.SHA256 = strings.Repeat("A", 64) },
		"transfer zero":       func(f *xferLeaseFields) { f.TransferID = "0000000000000000" },
		"transfer upper":      func(f *xferLeaseFields) { f.TransferID = "0123456789ABCDEF" },
		"expires":             func(f *xferLeaseFields) { f.ExpiresUnix = 0 },
		"idle zero":           func(f *xferLeaseFields) { f.IdleS = 0 },
		"idle over max":       func(f *xferLeaseFields) { f.IdleS = 601 },
		"max over 3600":       func(f *xferLeaseFields) { f.MaxS = 3601; f.IdleS = 30 },
		"byte cap under size": func(f *xferLeaseFields) { f.ByteCap = 4 },
		"byte cap huge":       func(f *xferLeaseFields) { f.ByteCap = xferMaxInt + 1 },
		"profile":             func(f *xferLeaseFields) { f.Profile = "lan" },
		"transport":           func(f *xferLeaseFields) { f.Transport = "quic" },
		"peer":                func(f *xferLeaseFields) { f.Peer = "listen:1.2.3.4:5" },
		"peer no port":        func(f *xferLeaseFields) { f.Peer = "dial:relay.example" },
		"peer port zero":      func(f *xferLeaseFields) { f.Peer = "dial:relay.example:0" },
		"peer port big":       func(f *xferLeaseFields) { f.Peer = "dial:relay.example:65536" },
		"peer newline":        func(f *xferLeaseFields) { f.Peer = "dial:a\n:1" },
		"material":            func(f *xferLeaseFields) { f.Material = "abc" },
	} {
		f := base
		edit(&f)
		if _, err := xferLeasePayload(f); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	for _, peer := range []string{"listen", "dial:127.0.0.1:47000", "dial:[::1]:1", "dial:relay-1.example.net:65535"} {
		f := base
		f.Peer = peer
		if _, err := xferLeasePayload(f); err != nil {
			t.Errorf("%s refused: %v", peer, err)
		}
	}
}

// ---- grant verification --------------------------------------------------

// Each of the 18 fields changed after signing: lease_required, nothing spawned.
func TestXferLeaseEveryFieldTamper(t *testing.T) {
	h := newXferHarness(t)
	root := newXferRoot(t)
	other := newXferRoot(t)
	cases := map[string]func(*xferMsg){
		"01 grant_id":      func(m *xferMsg) { m.GrantID = "xfr_" + randHex(t, 8) },
		"02 deadline_unix": func(m *xferMsg) { m.DeadlineUnix++ },
		"04 dir":           func(m *xferMsg) { m.Dir, m.Purpose = "get", "xfer:get" },
		"05 root":          func(m *xferMsg) { m.Root = other },
		"06 path":          func(m *xferMsg) { m.Path = "ok/other" },
		"07 size":          func(m *xferMsg) { m.Size = 4 },
		"08 sha256":        func(m *xferMsg) { m.SHA256 = strings.Repeat("c", 64) },
		"09 overwrite":     func(m *xferMsg) { m.Overwrite = true },
		"10 transfer_id":   func(m *xferMsg) { m.TransferID = "fedcba9876543210" },
		"11 expires_unix":  func(m *xferMsg) { m.ExpiresUnix++ },
		"12 idle_s":        func(m *xferMsg) { m.IdleS++ },
		"13 max_s":         func(m *xferMsg) { m.MaxS++ },
		"14 byte_cap":      func(m *xferMsg) { m.ByteCap++ },
		"15 profile":       func(m *xferMsg) { m.Profile = "dc" },
		"16 transport":     func(m *xferMsg) { m.Transport = "quic" },
		"17 peer":          func(m *xferMsg) { m.Peer = "dial:127.0.0.1:9" },
		"18 material key":  func(m *xferMsg) { m.Key = randB64(t, 32) },
		"18 material tok":  func(m *xferMsg) { m.RouteToken = randB64(t, 16) },
		"key not base64":   func(m *xferMsg) { m.Key = "!!" },
		"key not canonical": func(m *xferMsg) {
			m.Key = strings.TrimRight(m.Key, "=")
		},
	}
	for name, edit := range cases {
		msg := xferFrame(t, root, "ok/blob")
		h.sign(t, &msg)
		edit(&msg)
		h.send(t, msg)
		if got := h.errorOf(t, msg.GrantID); got != "lease_required" {
			t.Fatalf("%s: got %q", name, got)
		}
		h.assertNoSpawn(t, root)
	}
	// 03 phase: a renew lease presented as a start.
	msg := xferFrame(t, root, "ok/blob")
	signXfer(t, h.priv, ptyTestHost, &msg, "renew", time.Now().Unix()+60)
	h.send(t, msg)
	if got := h.errorOf(t, msg.GrantID); got != "lease_required" {
		t.Fatalf("phase: got %q", got)
	}
	// Another signer, another host, an xfer_root lease as xfer, an expired lease.
	_, otherKey, _ := ed25519.GenerateKey(rand.Reader)
	for name, fn := range map[string]func(*xferMsg){
		"wrong key": func(m *xferMsg) { signXfer(t, otherKey, ptyTestHost, m, "start", time.Now().Unix()+60) },
		"wrong host": func(m *xferMsg) {
			signXfer(t, h.priv, "22222222-2222-4222-8222-222222222222", m, "start", time.Now().Unix()+60)
		},
		"root lease as xfer": func(m *xferMsg) {
			m.Action = "xfer_root"
			signXfer(t, h.priv, ptyTestHost, m, "start", time.Now().Unix()+60)
			m.Action = "xfer"
		},
		"expired":  func(m *xferMsg) { signXfer(t, h.priv, ptyTestHost, m, "start", time.Now().Unix()-60) },
		"no lease": func(m *xferMsg) {},
	} {
		msg := xferFrame(t, root, "ok/blob")
		fn(&msg)
		h.send(t, msg)
		if got := h.errorOf(t, msg.GrantID); got != "lease_required" {
			t.Fatalf("%s: got %q", name, got)
		}
		h.assertNoSpawn(t, root)
	}
	// A replayed frame: the nonce is spent.
	msg = h.start(t, root, "ok/blob", nil)
	h.result(t, msg.GrantID)
	waitFor(t, "slot released", 5*time.Second, func() bool { return h.m.liveCount() == 0 })
	h.out = newFakeOut()
	h.ch.out = h.out
	h.send(t, msg)
	if got := h.errorOf(t, msg.GrantID); got != "lease_required" {
		t.Fatalf("replay: got %q", got)
	}
}

// Sequence step 5: each check refuses before any child starts.
func TestXferStep5RefusalsBeforeSpawn(t *testing.T) {
	h := newXferHarness(t)
	root := newXferRoot(t)
	now := time.Now().Unix()
	cases := []struct {
		name  string
		edit  func(*xferMsg)
		setup func()
		want  string
	}{
		{"get is phase 2", func(m *xferMsg) { m.Dir, m.Purpose = "get", "xfer:get" }, nil, "agent_unsupported"},
		{"aead", func(m *xferMsg) { m.AEAD = "AES-256-GCM" }, nil, "agent_unsupported"},
		{"purpose", func(m *xferMsg) { m.Purpose = "xfer:get" }, nil, "lease_required"},
		{"root purpose on xfer", func(m *xferMsg) { m.Purpose = "xfer:root" }, nil, "lease_required"},
		{"deadline passed", func(m *xferMsg) { m.DeadlineUnix = now - 1 }, nil, "lease_required"},
		{"first packet passed", func(m *xferMsg) { m.ExpiresUnix = now - 1 }, nil, "lease_required"},
		{"no xfer-bin", nil, func() { xferCfg.bin = "" }, "agent_unsupported"},
		{"platform gate", nil, func() {
			if runtime.GOOS == "darwin" {
				xferCfg.allowDarwin = false
			} else {
				xferCfg.bin = ""
			}
		}, "agent_unsupported"},
		{"listen without flag", nil, func() { xferCfg.listen = nil }, "agent_unsupported"},
		{"non-root agent, no allow flag", nil, func() { ptyCfg.AllowAgentUser = false }, "pty_user_unset"},
		{"xfer_root on a non-root agent", func(m *xferMsg) { m.Action, m.Purpose = "xfer_root", "xfer:root" }, nil, "root_unavailable"},
		{"root /", func(m *xferMsg) { m.Root = "/" }, nil, "root_denied"},
		{"root holds the state dir", func(m *xferMsg) { m.Root = filepath.Dir(h.stateDir) }, nil, "root_denied"},
	}
	for _, c := range cases {
		saved, savedPty := xferCfg, ptyCfg
		if c.setup != nil {
			c.setup()
		}
		msg := h.start(t, root, "ok/blob", c.edit)
		got := h.errorOf(t, msg.GrantID)
		xferCfg, ptyCfg = saved, savedPty
		if got != c.want {
			t.Fatalf("%s: got %q, want %q", c.name, got, c.want)
		}
		h.assertNoSpawn(t, root)
	}
}

func TestXferPutListenMode(t *testing.T) {
	h := newXferHarness(t)
	root := newXferRoot(t)
	msg := h.start(t, root, "ok/blob", nil)
	ready := h.ready(t, msg.GrantID)
	udp, _ := ready["udp"].(string)
	ap, err := netip.ParseAddrPort(udp)
	if err != nil || ap.Addr().String() != "127.0.0.1" || ap.Port() == 0 {
		t.Fatalf("ready udp %q", udp)
	}
	res := h.result(t, msg.GrantID)
	if res["status"] != "ok" || res["committed"] != true || res["sha256"] != msg.SHA256 || res["bytes"] != float64(5) {
		t.Fatalf("result %v", res)
	}
	if _, err := os.Stat(filepath.Join(root, "ok", "blob")); err != nil {
		t.Fatalf("target: %v", err)
	}
	active := xferMsgs(h.out, "xfer_status", msg.GrantID)
	if len(active) != 2 || active[1]["status"] != "active" {
		t.Fatalf("statuses %v", active)
	}
	log := readFakeLog(root, ".fake-ctl.log")
	if !strings.Contains(log, "grant peer=listen:127.0.0.1:0 overwrite=false") {
		t.Fatalf("grant line: %q", log)
	}
	// Only fds 0 to 4, an empty environment, and "/" as the directory.
	if strings.Contains(log, "extra_fd") || strings.Contains(log, "env_nonempty") || strings.Contains(log, "cwd ") {
		t.Fatalf("child environment: %q", log)
	}
	waitFor(t, "record removed", 5*time.Second, func() bool { return len(loadXferRecords(h.stateDir)) == 0 })
	// The key never reaches the agent's own messages.
	h.out.mu.Lock()
	raw, _ := json.Marshal(h.out.jsons)
	h.out.mu.Unlock()
	if strings.Contains(string(raw), msg.Key) || strings.Contains(string(raw), msg.RouteToken) {
		t.Fatal("key material in agent output")
	}
}

func TestXferAdvertiseAndDialModes(t *testing.T) {
	h := newXferHarness(t)
	root := newXferRoot(t)
	xferCfg.advertise = netip.MustParseAddr("192.0.2.7")
	msg := h.start(t, root, "ok/a", nil)
	udp, _ := h.ready(t, msg.GrantID)["udp"].(string)
	if !strings.HasPrefix(udp, "192.0.2.7:") || strings.HasSuffix(udp, ":0") {
		t.Fatalf("advertised %q", udp)
	}
	h.result(t, msg.GrantID)

	xferCfg.listen = nil // dial mode needs no listen flags
	msg = h.start(t, root, "ok/b", func(m *xferMsg) { m.Peer = "dial:relay.example:4000" })
	ready := h.ready(t, msg.GrantID)
	if _, has := ready["udp"]; has {
		t.Fatalf("dial ready carries udp: %v", ready)
	}
	if !strings.Contains(readFakeLog(root, ".fake-ctl.log"), "grant peer=dial:relay.example:4000") {
		t.Fatal("dial peer not passed through")
	}
	if res := h.result(t, msg.GrantID); res["status"] != "ok" {
		t.Fatalf("result %v", res)
	}
}

func TestXferPortRange(t *testing.T) {
	h := newXferHarness(t)
	root := newXferRoot(t)
	xferCfg.listen = &xferListen{ip: netip.MustParseAddr("127.0.0.1"), lo: 47100, hi: 47101}
	a := h.start(t, root, "hold/a", nil)
	b := h.start(t, root, "hold/b", nil)
	ports := map[string]bool{}
	for _, gid := range []string{a.GrantID, b.GrantID} {
		udp, _ := h.ready(t, gid)["udp"].(string)
		ports[udp] = true
	}
	if !ports["127.0.0.1:47100"] || !ports["127.0.0.1:47101"] {
		t.Fatalf("ports %v", ports)
	}
	c := h.start(t, root, "hold/c", nil)
	if got := h.errorOf(t, c.GrantID); got != "cap_reached" {
		t.Fatalf("range exhausted: %q", got)
	}
	h.send(t, map[string]interface{}{"type": "xfer_cancel", "grant_id": a.GrantID, "reason": "cancelled"})
	h.result(t, a.GrantID)
	waitFor(t, "slot freed", 5*time.Second, func() bool { return h.m.liveCount() == 1 })
	d := h.start(t, root, "hold/d", nil)
	if udp, _ := h.ready(t, d.GrantID)["udp"].(string); !ports[udp] {
		t.Fatalf("freed port not reused: %q", udp)
	}
}

// A ready without a usable address in listen mode is a refusal, not ready.
func TestXferBadReadyIsRefused(t *testing.T) {
	h := newXferHarness(t)
	root := newXferRoot(t)
	msg := h.start(t, root, "badready/x", nil)
	if got := h.errorOf(t, msg.GrantID); got != "internal" {
		t.Fatalf("got %q", got)
	}
	if len(xferMsgs(h.out, "xfer_result", msg.GrantID)) != 0 {
		t.Fatal("result sent for a grant that never got ready")
	}
}

// A refusal by recv before ready (step 7) is an xfer_status error with its code.
func TestXferRecvRefusalBeforeReady(t *testing.T) {
	h := newXferHarness(t)
	root := newXferRoot(t)
	msg := h.start(t, root, "refuse/x", nil)
	if got := h.errorOf(t, msg.GrantID); got != "exists" {
		t.Fatalf("got %q", got)
	}
	waitFor(t, "child gone", 5*time.Second, func() bool { return h.m.liveCount() == 0 })
	if len(xferMsgs(h.out, "xfer_result", msg.GrantID)) != 0 {
		t.Fatal("xfer_result before ready")
	}
	if len(loadXferRecords(h.stateDir)) != 0 {
		t.Fatal("record left")
	}
	for mode, want := range map[string]string{"noid": "bad_grant", "silent": "internal", "otherid": "internal"} {
		msg := h.start(t, root, mode+"/x", nil)
		if got := h.errorOf(t, msg.GrantID); got != want {
			t.Fatalf("%s: got %q, want %q", mode, got, want)
		}
	}
}

// ---- renew, cancel, EOF, lapse ------------------------------------------

func TestXferRenewCannotChangeAField(t *testing.T) {
	h := newXferHarness(t)
	root := newXferRoot(t)
	msg := h.start(t, root, "hold/x", nil)
	h.ready(t, msg.GrantID)
	renew := func(edit func(*xferMsg), phase string, deadline int64) error {
		m := msg
		if edit != nil {
			edit(&m)
		}
		m.DeadlineUnix = deadline
		signXfer(t, h.priv, ptyTestHost, &m, phase, time.Now().Unix()+60)
		return h.m.renew(xferMsg{GrantID: msg.GrantID, DeadlineUnix: deadline, Lease: m.Lease}, time.Now())
	}
	next := msg.DeadlineUnix + 30
	bad := map[string]func() error{
		"path":         func() error { return renew(func(m *xferMsg) { m.Path = "hold/y" }, "renew", next) },
		"root":         func() error { return renew(func(m *xferMsg) { m.Root = "/srv" }, "renew", next) },
		"size":         func() error { return renew(func(m *xferMsg) { m.Size = 4 }, "renew", next) },
		"overwrite":    func() error { return renew(func(m *xferMsg) { m.Overwrite = true }, "renew", next) },
		"material":     func() error { return renew(func(m *xferMsg) { m.Key = randB64(t, 32) }, "renew", next) },
		"peer":         func() error { return renew(func(m *xferMsg) { m.Peer = "dial:1.2.3.4:5" }, "renew", next) },
		"byte cap":     func() error { return renew(func(m *xferMsg) { m.ByteCap = 9 }, "renew", next) },
		"max":          func() error { return renew(func(m *xferMsg) { m.MaxS = 3600 }, "renew", next) },
		"start phase":  func() error { return renew(nil, "start", next) },
		"root action":  func() error { return renew(func(m *xferMsg) { m.Action = "xfer_root" }, "renew", next) },
		"backwards":    func() error { return renew(nil, "renew", msg.DeadlineUnix-1) },
		"unknown":      func() error { return h.m.renew(xferMsg{GrantID: "xfr_unknown123"}, time.Now()) },
		"lease absent": func() error { return h.m.renew(xferMsg{GrantID: msg.GrantID, DeadlineUnix: next}, time.Now()) },
	}
	for name, fn := range bad {
		if err := fn(); err == nil {
			t.Fatalf("%s: renew accepted", name)
		}
	}
	if strings.Contains(readFakeLog(root, ".fake-ctl.log"), "renew") {
		t.Fatal("a refused renew reached fd 3")
	}
	if err := renew(nil, "renew", next); err != nil {
		t.Fatalf("valid renew: %v", err)
	}
	waitFor(t, "renew on fd 3", 5*time.Second, func() bool {
		return strings.Contains(readFakeLog(root, ".fake-ctl.log"), "renew "+strconv.FormatInt(next, 10))
	})
	// Through the frame path too.
	m := msg
	m.DeadlineUnix = next + 30
	signXfer(t, h.priv, ptyTestHost, &m, "renew", time.Now().Unix()+60)
	h.send(t, map[string]interface{}{"type": "xfer_renew", "grant_id": msg.GrantID, "deadline_unix": next + 30, "lease": m.Lease})
	waitFor(t, "frame renew on fd 3", 5*time.Second, func() bool {
		return strings.Contains(readFakeLog(root, ".fake-ctl.log"), "renew "+strconv.FormatInt(next+30, 10))
	})
}

func TestXferCancelReachesFd3(t *testing.T) {
	h := newXferHarness(t)
	root := newXferRoot(t)
	msg := h.start(t, root, "hold/x", nil)
	h.ready(t, msg.GrantID)
	temp := fakeTemp(root, msg.Path, msg.GrantID)
	if _, err := os.Stat(temp); err != nil {
		t.Fatalf("temp: %v", err)
	}
	h.send(t, map[string]interface{}{"type": "xfer_cancel", "grant_id": msg.GrantID, "reason": "cancelled"})
	res := h.result(t, msg.GrantID)
	if res["status"] != "aborted" || res["reason"] != "cancelled" || res["committed"] != false {
		t.Fatalf("result %v", res)
	}
	if !strings.Contains(readFakeLog(root, ".fake-ctl.log"), "cancel cancelled") {
		t.Fatal("cancel did not reach fd 3")
	}
	if _, err := os.Stat(temp); !os.IsNotExist(err) {
		t.Fatal("temp left")
	}
	// A reason outside the shape is sent as cancelled.
	msg = h.start(t, root, "hold/y", nil)
	h.ready(t, msg.GrantID)
	h.send(t, map[string]interface{}{"type": "xfer_cancel", "grant_id": msg.GrantID, "reason": "Bad Reason\n"})
	if res := h.result(t, msg.GrantID); res["reason"] != "cancelled" {
		t.Fatalf("result %v", res)
	}
}

// EOF on fd 3 is cancel stopped: what recv sees when the agent dies.
func TestXferCtlEOFIsCancel(t *testing.T) {
	h := newXferHarness(t)
	root := newXferRoot(t)
	msg := h.start(t, root, "hold/x", nil)
	h.ready(t, msg.GrantID)
	h.m.lookup(msg.GrantID).closeCtl()
	res := h.result(t, msg.GrantID)
	if res["status"] != "aborted" || res["reason"] != "stopped" {
		t.Fatalf("result %v", res)
	}
	if !strings.Contains(readFakeLog(root, ".fake-ctl.log"), "eof") {
		t.Fatal("recv did not see EOF")
	}
	if _, err := os.Stat(fakeTemp(root, msg.Path, msg.GrantID)); !os.IsNotExist(err) {
		t.Fatal("temp left")
	}
}

// A renew that never comes: cancel stopped at lapse; a recv that ignores it
// is terminated, then killed, and the result is still sent.
func TestXferLeaseLapse(t *testing.T) {
	h := newXferHarness(t)
	root := newXferRoot(t)
	for _, mode := range []string{"hold", "deaf", "expire"} {
		msg := xferFrame(t, root, mode+"/x")
		signXfer(t, h.priv, ptyTestHost, &msg, "start", time.Now().Unix()+2)
		h.send(t, msg)
		h.ready(t, msg.GrantID)
		res := h.result(t, msg.GrantID)
		// A recv killed without a result may have committed: committed is
		// then left out, never claimed false.
		wantCommitted, has := interface{}(false), true
		if mode == "deaf" {
			wantCommitted, has = nil, false
		}
		if c, ok := res["committed"]; res["status"] != "aborted" || res["reason"] != "stopped" || ok != has || c != wantCommitted {
			t.Fatalf("%s: result %v", mode, res)
		}
		if !strings.Contains(readFakeLog(root, ".fake-ctl.log"), "cancel stopped") {
			t.Fatalf("%s: no cancel at lapse", mode)
		}
	}
}

func TestXferProgressThrottle(t *testing.T) {
	h := newXferHarness(t)
	root := newXferRoot(t)
	xferProgressEvery = time.Hour
	msg := h.start(t, root, "hold/x", nil)
	h.ready(t, msg.GrantID)
	time.Sleep(300 * time.Millisecond)
	n := 0
	for _, p := range xferMsgs(h.out, "xfer_status", msg.GrantID) {
		if p["status"] == "active" {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("%d active statuses inside one throttle window", n)
	}
	h.send(t, map[string]interface{}{"type": "xfer_cancel", "grant_id": msg.GrantID, "reason": "cancelled"})
	h.result(t, msg.GrantID)
	waitFor(t, "child gone", 5*time.Second, func() bool { return h.m.liveCount() == 0 })
	xferProgressEvery = 50 * time.Millisecond
	msg2 := h.start(t, root, "hold/y", nil)
	waitFor(t, "more progress", 5*time.Second, func() bool {
		c := 0
		for _, p := range xferMsgs(h.out, "xfer_status", msg2.GrantID) {
			if p["status"] == "active" {
				c++
			}
		}
		return c >= 3
	})
}

func TestXferChildCap(t *testing.T) {
	h := newXferHarness(t)
	root := newXferRoot(t)
	var ids []string
	for i := 0; i < xferMaxChildren; i++ {
		msg := h.start(t, root, fmt.Sprintf("hold/%d", i), nil)
		h.ready(t, msg.GrantID)
		ids = append(ids, msg.GrantID)
	}
	other := newXferRoot(t)
	msg := h.start(t, other, "hold/5", nil)
	if got := h.errorOf(t, msg.GrantID); got != "cap_reached" {
		t.Fatalf("fifth: %q", got)
	}
	if readFakeLog(other, ".fake-ctl.log") != "" || h.m.liveCount() != xferMaxChildren {
		t.Fatal("fifth child started")
	}
	h.send(t, map[string]interface{}{"type": "xfer_cancel", "grant_id": ids[0], "reason": "cancelled"})
	h.result(t, ids[0])
	waitFor(t, "slot freed", 5*time.Second, func() bool { return h.m.liveCount() == xferMaxChildren-1 })
	msg = h.start(t, other, "hold/6", nil)
	h.ready(t, msg.GrantID)
}

// ---- connection drop and restart ----------------------------------------

// The child outlives its connection and the result waits for the next one.
func TestXferResultQueuedAcrossConnectionDrop(t *testing.T) {
	h := newXferHarness(t)
	root := newXferRoot(t)
	msg := h.start(t, root, "wait/x", nil)
	h.ready(t, msg.GrantID)
	h.m.detach(h.out)
	h.ch.close("agent_disconnected")
	if h.m.liveCount() != 1 {
		t.Fatal("connection close ended the transfer")
	}
	if err := os.WriteFile(filepath.Join(root, ".release"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "child done", 5*time.Second, func() bool { return h.m.liveCount() == 0 })
	if len(xferMsgs(h.out, "xfer_result", msg.GrantID)) != 0 {
		t.Fatal("result went to the dropped connection")
	}
	rec, err := loadXferRecord(h.stateDir, msg.GrantID)
	if err != nil || rec.Result["status"] != "ok" {
		t.Fatalf("record with result: %v %v", rec, err)
	}
	out2 := newFakeOut()
	h.m.attach(out2)
	res := waitXfer(t, out2, "xfer_result", msg.GrantID, nil)
	if res["status"] != "ok" || res["committed"] != true {
		t.Fatalf("result %v", res)
	}
	if _, err := loadXferRecord(h.stateDir, msg.GrantID); !os.IsNotExist(err) {
		t.Fatalf("record after delivery: %v", err)
	}
}

// The same through agentConn: the first connection drops after ready, the
// child finishes, and the result is sent on the second enrolled connection.
func TestXferSurvivesAgentReconnect(t *testing.T) {
	if runtime.GOOS == "linux" && !openat2Available() {
		t.Skip("xfer needs openat2 on Linux")
	}
	saveXferGlobals(t)
	m := newXferManager("")
	xferMgrPtr.Store(m)
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pubB64 := base64.StdEncoding.EncodeToString(pub)
	root := newXferRoot(t)
	var frame xferMsg
	var hostID string
	readyCh := make(chan struct{}, 1)
	results := make(chan map[string]interface{}, 1)
	srv, count := fakeControlPlane(t, func(n int64, c *websocket.Conn) {
		_ = c.WriteJSON(map[string]interface{}{"type": "enrolled", "host_id": hostID, "control_pubkey": pubB64})
		if n == 1 {
			_ = c.WriteJSON(frame)
		}
		for {
			_, raw, err := c.ReadMessage()
			if err != nil {
				return
			}
			var msg struct {
				Type    string                 `json:"type"`
				GrantID string                 `json:"grant_id"`
				Payload map[string]interface{} `json:"payload"`
			}
			if json.Unmarshal(raw, &msg) != nil || msg.GrantID != frame.GrantID {
				continue
			}
			if n == 1 && msg.Type == "xfer_status" && msg.Payload["status"] == "ready" {
				readyCh <- struct{}{}
				return // drop the first connection
			}
			if msg.Type == "xfer_result" {
				results <- msg.Payload
			}
		}
	})
	a := testConn(t, srv, "good")
	hostID = a.st.HostID
	frame = xferFrame(t, root, "wait/x")
	signXfer(t, priv, hostID, &frame, "start", time.Now().Unix()+60)
	stop := make(chan struct{})
	done := make(chan error, 1)
	go func() { done <- a.run(stop) }()
	t.Cleanup(func() {
		close(stop)
		<-done
		m.stopAll("stopped", 5*time.Second)
	})
	select {
	case <-readyCh:
	case <-time.After(10 * time.Second):
		t.Fatal("no ready")
	}
	waitFor(t, "second connection", 10*time.Second, func() bool { return atomic.LoadInt64(count) >= 2 })
	if m.liveCount() != 1 {
		t.Fatal("the drop ended the transfer")
	}
	if err := os.WriteFile(filepath.Join(root, ".release"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	select {
	case res := <-results:
		if res["status"] != "ok" || res["committed"] != true {
			t.Fatalf("result %v", res)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("no result on the second connection")
	}
}

func currentIdentity(t *testing.T) xferRecordIdentity {
	t.Helper()
	u, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	id, err := identityFromUser(u, false)
	if err != nil {
		t.Fatal(err)
	}
	return recordIdentity(id)
}

// On start, leftover records are swept as their identity and reported:
// ok when the target holds the grant's hash, aborted committed false when it
// does not, and not at all (unknown on the server) when it cannot be checked.
func TestXferRestartSweep(t *testing.T) {
	if runtime.GOOS == "linux" && !openat2Available() {
		t.Skip("xfer needs openat2 on Linux")
	}
	saveXferGlobals(t)
	stateDir := t.TempDir()
	root := newXferRoot(t)
	if err := os.MkdirAll(filepath.Join(root, "in"), 0o700); err != nil {
		t.Fatal(err)
	}
	body := []byte("hello")
	sum := sha256.Sum256(body)
	mk := func(gid, path string) xferRecord {
		return xferRecord{GrantID: gid, TransferID: "0123456789abcdef", Action: "xfer", Root: root, Path: path,
			Size: int64(len(body)), SHA256: hex.EncodeToString(sum[:]), Identity: currentIdentity(t), CreatedUnix: time.Now().Unix()}
	}
	absent := mk("xfr_interrupted1", "in/absent")
	committed := mk("xfr_committed001", "in/done")
	different := mk("xfr_different001", "in/other")
	finished := mk("xfr_finished0001", "in/fin")
	finished.Result = map[string]interface{}{"status": "ok", "reason": "", "bytes": float64(5), "committed": true}
	noHash := mk("xfr_nohash00001", "in/nohash")
	noHash.SHA256 = ""
	otherUser := mk("xfr_otheruser01", "in/user")
	otherUser.Identity.UID++
	for _, r := range []xferRecord{absent, committed, different, finished, noHash, otherUser} {
		if err := saveXferRecord(stateDir, r); err != nil {
			t.Fatal(err)
		}
	}
	info, err := os.Stat(xferRecordPath(stateDir, absent.GrantID))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("record mode: %v %v", info, err)
	}
	if dinfo, _ := os.Stat(xferRecordsDir(stateDir)); dinfo.Mode().Perm() != 0o700 {
		t.Fatal("records dir mode")
	}
	write := func(p string, b []byte) {
		if err := os.WriteFile(filepath.Join(root, p), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("in/done", body)
	write("in/other", []byte("HELLO"))
	temp := fakeTemp(root, "in/absent", absent.GrantID)
	write("in/.sahxfer-"+absent.GrantID+".part", nil)
	write("in/.sahxfer-xfr_someoneelse.part", nil)
	write("in/.sahxfer-"+otherUser.GrantID+".part", nil)

	m := newXferManager(stateDir)
	xferMgrPtr.Store(m)
	m.sweepXferRecords()
	if _, err := os.Stat(temp); !os.IsNotExist(err) {
		t.Fatal("interrupted temp not swept")
	}
	if _, err := os.Stat(filepath.Join(root, "in", ".sahxfer-xfr_someoneelse.part")); err != nil {
		t.Fatal("sweep removed another grant's temp")
	}
	if _, err := os.Stat(filepath.Join(root, "in", ".sahxfer-"+otherUser.GrantID+".part")); err != nil {
		t.Fatal("swept as an identity that no longer matches the record")
	}
	if s := readFakeLog(root, ".fake-sweep.log"); strings.Contains(s, "extra_fd") || strings.Contains(s, "env_nonempty") {
		t.Fatalf("sweep child environment: %q", s)
	}
	out := newFakeOut()
	m.attach(out)
	if res := waitXfer(t, out, "xfer_result", absent.GrantID, nil); res["status"] != "aborted" || res["reason"] != "agent_restart" || res["committed"] != false {
		t.Fatalf("absent: %v", res)
	}
	if res := waitXfer(t, out, "xfer_result", committed.GrantID, nil); res["status"] != "ok" || res["committed"] != true ||
		res["sha256"] != committed.SHA256 || res["bytes"] != float64(5) {
		t.Fatalf("committed: %v", res)
	}
	if res := waitXfer(t, out, "xfer_result", different.GrantID, nil); res["status"] != "aborted" || res["committed"] != false {
		t.Fatalf("different: %v", res)
	}
	if res := waitXfer(t, out, "xfer_result", finished.GrantID, nil); res["status"] != "ok" || res["committed"] != true {
		t.Fatalf("finished: %v", res)
	}
	for _, gid := range []string{noHash.GrantID, otherUser.GrantID} {
		if len(xferMsgs(out, "xfer_result", gid)) != 0 {
			t.Fatalf("%s: an unchecked record was reported", gid)
		}
	}
	left := map[string]bool{}
	for _, r := range loadXferRecords(stateDir) {
		left[r.GrantID] = true
	}
	if len(left) != 2 || !left[noHash.GrantID] || !left[otherUser.GrantID] {
		t.Fatalf("records left: %v", left)
	}

	// Without a usable --xfer-bin nothing is swept or reported.
	if err := saveXferRecord(stateDir, absent); err != nil {
		t.Fatal(err)
	}
	xferCfg.bin = ""
	m2 := newXferManager(stateDir)
	out2 := newFakeOut()
	m2.attach(out2)
	m2.sweepXferRecords()
	if len(xferMsgs(out2, "xfer_result", absent.GrantID)) != 0 || len(loadXferRecords(stateDir)) != 3 {
		t.Fatal("unchecked record reported or dropped")
	}
}

// ---- flags and capability -------------------------------------------------

func TestXferBinChecks(t *testing.T) {
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	me := os.Geteuid()
	mk := func(name string, mode os.FileMode) string {
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("#!/bin/sh\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, mode); err != nil {
			t.Fatal(err)
		}
		return p
	}
	good := mk("good", 0o755)
	if err := checkXferBin(good, me); err != nil {
		t.Fatalf("good: %v", err)
	}
	if err := checkXferBin(mk("ro", 0o555), me); err != nil {
		t.Fatalf("read-only: %v", err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(good, link); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(dir, filepath.Join(dir, "dirlink")); err != nil {
		t.Fatal(err)
	}
	wp := mk("wparent/bin", 0o755)
	if err := os.Chmod(filepath.Dir(wp), 0o777); err != nil {
		t.Fatal(err)
	}
	gp := mk("gparent/bin", 0o755)
	if err := os.Chmod(filepath.Dir(gp), 0o775); err != nil {
		t.Fatal(err)
	}
	for name, path := range map[string]string{
		"relative":              "sahxfer",
		"unclean":               dir + "/./good",
		"group writable":        mk("gw", 0o775),
		"other writable":        mk("ow", 0o757),
		"not executable":        mk("nx", 0o644),
		"directory":             dir,
		"missing":               filepath.Join(dir, "missing"),
		"empty":                 "",
		"world writable":        mk("ww", 0o777),
		"dotdot":                dir + "/../" + filepath.Base(dir) + "/good",
		"trailing slash":        dir + "/good/",
		"symlink":               link,
		"symlinked parent":      filepath.Join(dir, "dirlink", "good"),
		"other-writable parent": wp,
		"group-writable parent": gp,
		"file as parent":        filepath.Join(good, "x"),
	} {
		if err := checkXferBin(path, me); err == nil || !errors.Is(err, errXferBin) {
			t.Errorf("%s: %v", name, err)
		}
		if _, _, err := openXferBin(path, me); err == nil {
			t.Errorf("%s: openXferBin accepted", name)
		}
	}
	// A sticky world-writable parent (as /tmp) is fine: only an entry's
	// owner may rename it there.
	sp := mk("sticky/bin", 0o755)
	if err := os.Chmod(filepath.Dir(sp), 0o777|os.ModeSticky); err != nil {
		t.Fatal(err)
	}
	if err := checkXferBin(sp, me); err != nil {
		t.Fatalf("sticky parent: %v", err)
	}
	// A parent owned by neither root nor the agent user.
	if me == 0 {
		if err := os.Chown(filepath.Dir(sp), 4242, 4242); err != nil {
			t.Fatal(err)
		}
		if err := checkXferBin(sp, 0); err == nil || !strings.Contains(err.Error(), filepath.Dir(sp)+":") {
			t.Fatalf("foreign parent: %v", err)
		}
		if err := os.Chown(good, 4242, 4242); err != nil {
			t.Fatal(err)
		}
		if err := checkXferBin(good, 0); err == nil {
			t.Fatal("foreign owner accepted")
		}
	} else {
		// The first directory owned by this user fails before the file does.
		err := checkXferBin(good, me+1)
		if err == nil || !strings.Contains(err.Error(), "not owned") || strings.Contains(err.Error(), good+":") {
			t.Fatalf("foreign parent: %v", err)
		}
	}
	exe, release, err := openXferBin(testExe(t), os.Geteuid())
	if err != nil {
		t.Fatal(err)
	}
	release()
	if runtime.GOOS == "linux" && !strings.HasPrefix(exe, "/proc/self/fd/") {
		t.Fatalf("linux exec path %q", exe)
	}
	// The flag refuses the same paths at startup.
	if _, err := parseXferFlags(filepath.Join(dir, "gw"), "", "", false, me); err == nil {
		t.Fatal("parseXferFlags accepted a group-writable binary")
	}
}

func TestXferFlagParsing(t *testing.T) {
	for in, want := range map[string]xferListen{
		"127.0.0.1:0":           {ip: netip.MustParseAddr("127.0.0.1")},
		"0.0.0.0:47000-47003":   {ip: netip.MustParseAddr("0.0.0.0"), lo: 47000, hi: 47003},
		"[::1]:5000":            {ip: netip.MustParseAddr("::1"), lo: 5000, hi: 5000},
		"10.0.0.1:65535-65535":  {ip: netip.MustParseAddr("10.0.0.1"), lo: 65535, hi: 65535},
		"[::ffff:1.2.3.4]:4000": {ip: netip.MustParseAddr("1.2.3.4"), lo: 4000, hi: 4000},
	} {
		got, err := parseXferListen(in)
		if err != nil || *got != want {
			t.Errorf("%s: %+v %v", in, got, err)
		}
	}
	for _, in := range []string{"", "127.0.0.1", "localhost:4000", "127.0.0.1:", "127.0.0.1:65536", "127.0.0.1:5-4",
		"127.0.0.1:0-4", "127.0.0.1:-4", "127.0.0.1:4-", "127.0.0.1:04", "127.0.0.1:+4", "::1:4000", "[fe80::1%en0]:4000", "127.0.0.1:1-2-3"} {
		if _, err := parseXferListen(in); err == nil {
			t.Errorf("%q accepted", in)
		}
	}
	if _, err := parseXferFlags("", "", "192.0.2.1", false, 0); err == nil {
		t.Error("advertise without listen accepted")
	}
	for _, adv := range []string{"host.example", "0.0.0.0", "192.0.2.1:4000", "fe80::1%en0"} {
		if _, err := parseXferFlags("", "127.0.0.1:0", adv, false, 0); err == nil {
			t.Errorf("advertise %q accepted", adv)
		}
	}
	cfg, err := parseXferFlags("", "0.0.0.0:47000-47003", "127.0.0.1", true, 0)
	if err != nil || cfg.advertise.String() != "127.0.0.1" || cfg.listen.hi != 47003 || !cfg.allowDarwin || cfg.bin != "" {
		t.Fatalf("%+v %v", cfg, err)
	}
}

// The Darwin flag gate and the Linux openat2 rule (plan item 20).
func TestXferCapabilityRules(t *testing.T) {
	yes := func() bool { return true }
	no := func() bool { return false }
	for _, c := range []struct {
		goos              string
		bin, darwin, oat2 bool
		want              bool
	}{
		{"linux", true, false, true, true},
		{"linux", true, true, false, false},
		{"linux", false, false, true, false},
		{"darwin", true, false, true, false},
		{"darwin", true, true, true, true},
		{"darwin", false, true, true, false},
		{"windows", true, true, true, false},
		{"freebsd", true, true, true, false},
	} {
		o := no
		if c.oat2 {
			o = yes
		}
		if got := xferSupported(c.goos, c.bin, c.darwin, o); got != c.want {
			t.Errorf("%+v: got %v", c, got)
		}
	}
	saveXferGlobals(t)
	has := func() bool {
		for _, c := range agentCapabilities() {
			if c == "xfer" {
				return true
			}
		}
		return false
	}
	if has() != xferAvailable() {
		t.Fatal("capability does not follow the probe")
	}
	xferCfg.bin = ""
	if has() {
		t.Fatal("xfer advertised without --xfer-bin")
	}
	if runtime.GOOS == "darwin" {
		xferCfg.bin, xferCfg.allowDarwin = testExe(t), false
		if has() {
			t.Fatal("xfer advertised on Darwin without --xfer-allow-darwin")
		}
		xferCfg.allowDarwin = true
		if !has() {
			t.Fatal("xfer not advertised on Darwin with the flag")
		}
	}
}

// ---- review fixes ---------------------------------------------------------

// S2: a process holding recv's fd 4 and stderr open cannot pin the slot.
func TestXferHeldFd4StillReaped(t *testing.T) {
	h := newXferHarness(t)
	root := newXferRoot(t)
	msg := h.start(t, root, "leak/x", nil)
	start := time.Now()
	res := h.result(t, msg.GrantID)
	if res["status"] != "ok" || res["committed"] != true {
		t.Fatalf("result %v", res)
	}
	waitFor(t, "slot released", 5*time.Second, func() bool { return h.m.liveCount() == 0 })
	if d := time.Since(start); d > xferWaitDelay+xferEventDrain+2*time.Second {
		t.Fatalf("took %s", d)
	}
	for _, l := range strings.Split(readFakeLog(root, ".fake-ctl.log"), "\n") {
		if pid, ok := strings.CutPrefix(l, "holder "); ok {
			if n, err := strconv.Atoi(pid); err == nil {
				killPid(n)
			}
		}
	}
}

// S3: a recv that stops reading fd 3 never blocks the connection's read
// loop, and is still terminated.
func TestXferStuckCtlDoesNotBlock(t *testing.T) {
	h := newXferHarness(t)
	root := newXferRoot(t)
	msg := h.start(t, root, "noread/x", nil)
	h.ready(t, msg.GrantID)
	var slowest time.Duration
	for i := 0; i < 4000 && h.m.lookup(msg.GrantID) != nil; i++ {
		m := msg
		signXfer(t, h.priv, ptyTestHost, &m, "renew", time.Now().Unix()+60)
		start := time.Now()
		h.send(t, map[string]interface{}{"type": "xfer_renew", "grant_id": msg.GrantID, "deadline_unix": msg.DeadlineUnix, "lease": m.Lease})
		if d := time.Since(start); d > slowest {
			slowest = d
		}
		x := h.m.lookup(msg.GrantID)
		if x != nil {
			x.mu.Lock()
			stopping := x.stopping
			x.mu.Unlock()
			if stopping {
				break
			}
		}
	}
	start := time.Now()
	h.send(t, map[string]interface{}{"type": "xfer_cancel", "grant_id": msg.GrantID, "reason": "cancelled"})
	if d := time.Since(start); d > slowest {
		slowest = d
	}
	if slowest > 500*time.Millisecond {
		t.Fatalf("a frame blocked the read loop for %s", slowest)
	}
	res := h.result(t, msg.GrantID)
	if res["status"] != "aborted" {
		t.Fatalf("result %v", res)
	}
	waitFor(t, "slot released", 5*time.Second, func() bool { return h.m.liveCount() == 0 })
}

// S1 on Linux: a dropped identity still execs the checked inode through
// /proc/self/fd, without being able to traverse the binary's directory.
func TestXferDroppedIdentityExecsByFd(t *testing.T) {
	if runtime.GOOS != "linux" || os.Geteuid() != 0 {
		t.Skip("needs a root agent on Linux")
	}
	h := newXferHarness(t)
	if _, err := user.Lookup("nobody"); err != nil {
		t.Skip("no nobody account")
	}
	ptyCfg = ptySettings{User: "nobody"}
	agentEUID = os.Geteuid
	root, err := os.MkdirTemp("/", "xferdrop")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(root) })
	if err := os.Chmod(root, 0o777); err != nil {
		t.Fatal(err)
	}
	msg := h.start(t, root, "ok/blob", nil)
	if res := h.result(t, msg.GrantID); res["status"] != "ok" || res["committed"] != true {
		t.Fatalf("result %v", res)
	}
	fi, err := os.Stat(filepath.Join(root, "ok", "blob"))
	if err != nil {
		t.Fatal(err)
	}
	u, _ := user.Lookup("nobody")
	if uid, ok := fileUID(fi); !ok || strconv.FormatUint(uint64(uid), 10) != u.Uid {
		t.Fatalf("target not written as nobody: %v", fi.Sys())
	}
}

// N1: a second frame for a live grant gets no error frame.
func TestXferFrameForLiveGrantIgnored(t *testing.T) {
	h := newXferHarness(t)
	root := newXferRoot(t)
	msg := h.start(t, root, "hold/x", nil)
	h.ready(t, msg.GrantID)
	h.send(t, msg) // the same frame: a replayed nonce
	again := msg
	h.sign(t, &again) // a fresh lease for the same grant
	h.send(t, again)
	h.send(t, map[string]interface{}{"type": "xfer_grant", "grant_id": msg.GrantID, "size": "not a number"})
	time.Sleep(200 * time.Millisecond)
	for _, p := range xferMsgs(h.out, "xfer_status", msg.GrantID) {
		if p["error"] != nil {
			t.Fatalf("error frame for a live grant: %v", p)
		}
	}
	if h.m.liveCount() != 1 {
		t.Fatal("a second child started")
	}
}

// N3: a result line without a newline before EOF still counts.
func TestXferFinalLineWithoutNewline(t *testing.T) {
	h := newXferHarness(t)
	root := newXferRoot(t)
	msg := h.start(t, root, "nonewline/x", nil)
	if res := h.result(t, msg.GrantID); res["status"] != "ok" || res["committed"] != true {
		t.Fatalf("result %v", res)
	}
}

// N4: in listen mode the ready address must be on the --xfer-udp-listen IP.
func TestXferReadyAddressPinnedToListenIP(t *testing.T) {
	h := newXferHarness(t)
	root := newXferRoot(t)
	msg := h.start(t, root, "wrongip/x", nil)
	if got := h.errorOf(t, msg.GrantID); got != "internal" {
		t.Fatalf("got %q", got)
	}
}

// ---- the real recv --------------------------------------------------------

// One real put through the real `sahxfer recv --ctl-fd 3 --event-fd 4` over
// loopback. Runs only when SAHXFER_BIN names the binary.
func TestXferRealRecvLoopback(t *testing.T) {
	bin := os.Getenv("SAHXFER_BIN")
	if bin == "" {
		t.Skip("SAHXFER_BIN not set")
	}
	h := newXferHarness(t)
	xferCfg.bin = bin
	if err := checkXferBin(bin, os.Geteuid()); err != nil {
		t.Fatal(err)
	}
	xferCancelGrace, xferTermGrace = 2*time.Second, 3*time.Second
	root := newXferRoot(t)
	if err := os.MkdirAll(filepath.Join(root, "in"), 0o755); err != nil {
		t.Fatal(err)
	}
	work := t.TempDir()
	src := filepath.Join(work, "blob")
	body := make([]byte, 1153+64*1024)
	if _, err := rand.Read(body); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(src, body, 0o600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(body)
	gpath := filepath.Join(work, "grant.json")
	size := strconv.Itoa(len(body))
	cmd := exec.Command(bin, "grant", "--out", gpath, "--purpose", "xfer:put", "--root", root, "--path", "in/blob",
		"--size", size, "--sha256", hex.EncodeToString(sum[:]), "--profile", "internet", "--transport", "udp",
		"--host-id", "loophost", "--peer-udp", "127.0.0.1:9", "--idle", "30", "--max", "600",
		"--expires", time.Now().Add(60*time.Second).UTC().Format(time.RFC3339))
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("sahxfer grant: %v %s", err, out)
	}
	raw, err := os.ReadFile(gpath)
	if err != nil {
		t.Fatal(err)
	}
	var g map[string]interface{}
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.UseNumber()
	if err := dec.Decode(&g); err != nil {
		t.Fatal(err)
	}
	str := func(k string) string { s, _ := g[k].(string); return s }
	num := func(k string) int64 {
		switch v := g[k].(type) {
		case json.Number:
			n, _ := v.Int64()
			return n
		case string:
			n, _ := strconv.ParseInt(v, 10, 64)
			return n
		}
		return 0
	}
	exp, err := time.Parse(time.RFC3339Nano, str("expires_at"))
	if err != nil {
		t.Fatalf("expires_at %q", str("expires_at"))
	}
	msg := xferMsg{
		Type: "xfer_grant", GrantID: str("grant_id"), TransferID: str("transfer_id"), Action: "xfer",
		Purpose: "xfer:put", Dir: "put", Root: root, Path: "in/blob", Size: int64(len(body)),
		SHA256: hex.EncodeToString(sum[:]), Profile: "internet", Transport: "udp", Peer: "listen", AEAD: xferAEAD,
		Key: str("key"), RouteToken: str("route_token"), ExpiresUnix: exp.Unix(),
		DeadlineUnix: time.Now().Unix() + 60, IdleS: num("idle_seconds"), MaxS: num("max_seconds"),
		ByteCap: num("byte_cap"), Actor: "user-1",
	}
	h.sign(t, &msg)
	h.send(t, msg)
	udp, _ := h.ready(t, msg.GrantID)["udp"].(string)
	if udp == "" {
		t.Fatalf("no ready address: %v", xferMsgs(h.out, "xfer_status", msg.GrantID))
	}
	put := exec.Command(bin, "put", "--grant", gpath, "--to", udp, src)
	if out, err := put.CombinedOutput(); err != nil {
		t.Fatalf("sahxfer put: %v %s", err, out)
	}
	res := h.result(t, msg.GrantID)
	if res["status"] != "ok" || res["committed"] != true || res["sha256"] != msg.SHA256 {
		t.Fatalf("result %v", res)
	}
	got, err := os.ReadFile(filepath.Join(root, "in", "blob"))
	if err != nil || sha256.Sum256(got) != sum {
		t.Fatalf("target: %v", err)
	}
	matches, _ := filepath.Glob(filepath.Join(root, "in", ".sahxfer-*.part"))
	if len(matches) != 0 {
		t.Fatalf("temp left: %v", matches)
	}

	// Cancel before any packet: fd 3 cancel, temp gone, aborted.
	c := msg
	c.GrantID, c.TransferID, c.Path = "xfr_"+randHex(t, 8), "2"+randHex(t, 8)[:15], "in/blob2"
	c.Key, c.RouteToken = randB64(t, 32), randB64(t, 16)
	h.sign(t, &c)
	h.send(t, c)
	h.ready(t, c.GrantID)
	h.send(t, map[string]interface{}{"type": "xfer_cancel", "grant_id": c.GrantID, "reason": "cancelled"})
	res = h.result(t, c.GrantID)
	if res["status"] == "ok" || res["committed"] != false {
		t.Fatalf("cancel result %v", res)
	}
	if m, _ := filepath.Glob(filepath.Join(root, "in", ".sahxfer-*.part")); len(m) != 0 {
		t.Fatalf("temp left after cancel: %v", m)
	}

	// The startup sweep removes exactly the record's temp name.
	u, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	id, err := identityFromUser(u, false)
	if err != nil {
		t.Fatal(err)
	}
	rec := xferRecord{GrantID: "xfr_realsweep01", TransferID: "0123456789abcdef", Action: "xfer", Root: root,
		Path: "in/blob", Identity: recordIdentity(id)}
	temp := filepath.Join(root, "in", ".sahxfer-"+rec.GrantID+".part")
	other := filepath.Join(root, "in", ".sahxfer-xfr_notthisone.part")
	for _, p := range []string{temp, other} {
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	target, err := runXferSweep(rec, bin, id)
	if err != nil {
		t.Fatalf("real sweep: %v", err)
	}
	if target == nil || target.Bytes != int64(len(body)) || target.SHA256 != msg.SHA256 {
		t.Fatalf("real sweep report: %+v", target)
	}
	rec.Path = "in/absent"
	if target, err := runXferSweep(rec, bin, id); err != nil || target != nil {
		t.Fatalf("real sweep, absent target: %+v %v", target, err)
	}
	if _, err := os.Stat(temp); !os.IsNotExist(err) {
		t.Fatal("real sweep left the temp")
	}
	if err := os.WriteFile(temp, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := runXferSweep(rec, bin, id); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(temp); !os.IsNotExist(err) {
		t.Fatal("real sweep left the temp")
	}
	if _, err := os.Stat(other); err != nil {
		t.Fatal("real sweep removed another name")
	}
}
