// sahxfer grants, agent side (sahxfer docs/plans/2026-10-18-end-to-end-wiring.md,
// sequence for put, steps 5 to 15). The agent verifies the lease, then
// starts `sahxfer recv --ctl-fd 3 --event-fd 4` as the identity user and
// talks to it over two pipes: fd 3 carries the grant line, renew and cancel;
// fd 4 carries ready, active and result. The xferManager is agent-level, not
// per connection, so a control-plane drop does not end a transfer: its
// result waits in a queue and goes out on the next enrolled connection.
// Threats: a grant the lease did not sign (the agent rebuilds the 18-line
// payload from every frame field it acts on, the key material included as
// its hash, so any change is payload_mismatch), a renew that changes a field
// (it is rebuilt from the stored grant with only phase and deadline
// changed, and the deadline may only move forward), a transfer outliving
// its lease (a watcher writes cancel at lapse, then SIGTERM, then SIGKILL),
// operations running as the agent (the child runs as the file channel's
// identity: a non-root agent refuses without --pty-allow-agent-user, and
// xfer_root needs a root agent), a root of "/" or one holding the state
// directory, more than four children, a --xfer-bin the identity user could
// replace (checked at startup and before every spawn), and the agent's
// secrets reaching the child (empty environment, Dir "/", only fds 0 to 4;
// the key and route token travel only on fd 3 and are never logged).
// Does NOT verify the actor (it rides the authenticated socket, not the
// lease), does NOT move the UDP socket into the agent (decision 4), and
// does NOT check, after a restart, whether the target already holds the
// grant's hash: the sweep mode has no channel to report it, so a transfer
// interrupted between commit and result is reported aborted agent_restart.
package main

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

const (
	xferMaxChildren = 4
	xferCtlQueue    = 8
	xferLineMax     = 64 * 1024
	xferAEAD        = "ChaCha20-Poly1305"
)

var (
	// Tests shorten these.
	xferWatchEvery    = 200 * time.Millisecond
	xferProgressEvery = 5 * time.Second
	xferCancelGrace   = 2 * time.Second
	xferTermGrace     = 3 * time.Second
	xferSweepTimeout  = 10 * time.Minute // a sweep may hash a large target
	xferCtlTimeout    = time.Second
	xferEventDrain    = time.Second
	xferWaitDelay     = 2 * time.Second
	// xferStopTimeout covers cancel, SIGTERM and SIGKILL on shutdown.
	xferStopTimeout = 6 * time.Second

	xferReasonRe = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`)
	errXferBin   = errors.New("xfer_bin_refused")

	xferResultStatuses = map[string]bool{"ok": true, "hash_mismatch": true, "aborted": true, "expired": true, "io_error": true}
)

// xferListen is --xfer-udp-listen: one ip and a port range (lo == hi == 0
// lets the kernel pick).
type xferListen struct {
	ip     netip.Addr
	lo, hi uint16
}

type xferConfig struct {
	bin         string
	listen      *xferListen
	advertise   netip.Addr
	allowDarwin bool
}

// xferCfg is set once from the flags before the agent connects.
var xferCfg xferConfig

func init() {
	registerCapability("xfer", xferAvailable)
}

func xferAvailable() bool {
	return xferSupported(runtime.GOOS, xferCfg.bin != "", xferCfg.allowDarwin, openat2Available)
}

// xferSupported is the capability rule: Linux needs openat2 and --xfer-bin;
// Darwin, a development target, also needs --xfer-allow-darwin.
func xferSupported(goos string, haveBin, allowDarwin bool, openat2 func() bool) bool {
	if !haveBin {
		return false
	}
	switch goos {
	case "linux":
		return openat2()
	case "darwin":
		return allowDarwin
	}
	return false
}

// parseXferFlags checks the four xfer flags. agentUID owns or may own the binary.
func parseXferFlags(bin, listen, advertise string, allowDarwin bool, agentUID int) (xferConfig, error) {
	cfg := xferConfig{allowDarwin: allowDarwin}
	if bin != "" {
		if err := checkXferBin(bin, agentUID); err != nil {
			return cfg, err
		}
		cfg.bin = bin
	}
	if listen != "" {
		l, err := parseXferListen(listen)
		if err != nil {
			return cfg, err
		}
		cfg.listen = l
	}
	if advertise != "" {
		if cfg.listen == nil {
			return cfg, errors.New("--xfer-udp-advertise needs --xfer-udp-listen")
		}
		ip, err := netip.ParseAddr(advertise)
		if err != nil || ip.Zone() != "" || ip.IsUnspecified() {
			return cfg, errors.New("--xfer-udp-advertise must be an IP literal")
		}
		cfg.advertise = ip.Unmap()
	}
	return cfg, nil
}

// parseXferListen takes "ip:port" or "ip:lo-hi" (IPv6 in brackets).
func parseXferListen(s string) (*xferListen, error) {
	bad := fmt.Errorf("--xfer-udp-listen %q: want ip:port or ip:lo-hi", s)
	host, ports, err := net.SplitHostPort(s)
	if err != nil {
		return nil, bad
	}
	ip, err := netip.ParseAddr(host)
	if err != nil || ip.Zone() != "" {
		return nil, bad
	}
	port := func(p string, min int) (uint16, bool) {
		if p == "" || len(p) > 5 || strings.TrimLeft(p, "0123456789") != "" || (len(p) > 1 && p[0] == '0') {
			return 0, false
		}
		n, err := strconv.Atoi(p)
		if err != nil || n < min || n > 65535 {
			return 0, false
		}
		return uint16(n), true
	}
	l := &xferListen{ip: ip.Unmap()}
	if a, b, ok := strings.Cut(ports, "-"); ok {
		lo, ok1 := port(a, 1)
		hi, ok2 := port(b, 1)
		if !ok1 || !ok2 || lo > hi {
			return nil, bad
		}
		l.lo, l.hi = lo, hi
		return l, nil
	}
	p, ok := port(ports, 0)
	if !ok {
		return nil, bad
	}
	l.lo, l.hi = p, p
	return l, nil
}

// checkXferBin refuses a --xfer-bin the identity user could replace. The
// path must be clean and absolute, and no component may be a symlink. Every
// directory from "/" down must be owned by root or agentUID and must not be
// group or other writable unless it is sticky (as /tmp is: there only an
// entry's owner may rename it, and the next component is checked to be root
// or agentUID). The file must be a regular, executable file, owned by root
// or agentUID, and not group or other writable. On Linux the binary is then
// opened once and executed through its fd (openXferBin), so the inode that
// was checked is the one that runs.
func checkXferBin(path string, agentUID int) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return fmt.Errorf("%w: --xfer-bin must be a clean absolute path", errXferBin)
	}
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	cur := "/"
	for i := -1; i < len(parts); i++ {
		if i >= 0 {
			cur = filepath.Join(cur, parts[i])
		}
		fi, err := os.Lstat(cur)
		if err != nil {
			return fmt.Errorf("%w: --xfer-bin: %v", errXferBin, err)
		}
		if fi.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%w: %s is a symlink", errXferBin, cur)
		}
		if err := checkXferBinOwner(fi, agentUID); err != nil {
			return fmt.Errorf("%w: %s: %v", errXferBin, cur, err)
		}
		if i < len(parts)-1 {
			if !fi.IsDir() {
				return fmt.Errorf("%w: %s is not a directory", errXferBin, cur)
			}
			if fi.Mode().Perm()&0o022 != 0 && fi.Mode()&os.ModeSticky == 0 {
				return fmt.Errorf("%w: parent directory %s is group or other writable", errXferBin, cur)
			}
			continue
		}
		if err := checkXferBinMode(fi.Mode()); err != nil {
			return err
		}
	}
	return nil
}

func checkXferBinMode(mode os.FileMode) error {
	if !mode.IsRegular() {
		return fmt.Errorf("%w: --xfer-bin is not a regular file", errXferBin)
	}
	if mode.Perm()&0o022 != 0 {
		return fmt.Errorf("%w: --xfer-bin is group or other writable", errXferBin)
	}
	if mode.Perm()&0o111 == 0 {
		return fmt.Errorf("%w: --xfer-bin is not executable", errXferBin)
	}
	return nil
}

// xferMsg is a server frame: xfer_grant, xfer_renew or xfer_cancel.
type xferMsg struct {
	Type         string `json:"type"`
	GrantID      string `json:"grant_id"`
	TransferID   string `json:"transfer_id"`
	Action       string `json:"action"`
	Purpose      string `json:"purpose"`
	Dir          string `json:"dir"`
	Root         string `json:"root"`
	Path         string `json:"path"`
	Size         int64  `json:"size"`
	SHA256       string `json:"sha256"`
	Overwrite    bool   `json:"overwrite"`
	Profile      string `json:"profile"`
	Transport    string `json:"transport"`
	Peer         string `json:"peer"`
	AEAD         string `json:"aead"`
	Key          string `json:"key"`
	RouteToken   string `json:"route_token"`
	ExpiresUnix  int64  `json:"expires_unix"`
	DeadlineUnix int64  `json:"deadline_unix"`
	IdleS        int64  `json:"idle_s"`
	MaxS         int64  `json:"max_s"`
	ByteCap      int64  `json:"byte_cap"`
	Actor        string `json:"actor"`
	Reason       string `json:"reason"`
	Lease        *Lease `json:"lease"`
}

// xferCtlGrant is the first fd 3 line (decision 3).
type xferCtlGrant struct {
	V            int    `json:"v"`
	GrantID      string `json:"grant_id"`
	TransferID   string `json:"transfer_id"`
	Purpose      string `json:"purpose"`
	Dir          string `json:"dir"`
	Root         string `json:"root"`
	Path         string `json:"path"`
	Size         int64  `json:"size"`
	SHA256       string `json:"sha256"`
	Overwrite    bool   `json:"overwrite"`
	Profile      string `json:"profile"`
	Transport    string `json:"transport"`
	AEAD         string `json:"aead"`
	Key          string `json:"key"`
	RouteToken   string `json:"route_token"`
	ExpiresUnix  int64  `json:"expires_unix"`
	DeadlineUnix int64  `json:"deadline_unix"`
	IdleS        int64  `json:"idle_s"`
	MaxS         int64  `json:"max_s"`
	ByteCap      int64  `json:"byte_cap"`
	Peer         string `json:"peer"`
}

// xferEvent is one fd 4 line.
type xferEvent struct {
	Ev         string `json:"ev"`
	UDP        string `json:"udp"`
	Bytes      int64  `json:"bytes"`
	GrantID    string `json:"grant_id"`
	TransferID string `json:"transfer_id"`
	Status     string `json:"status"`
	Reason     string `json:"reason"`
	SHA256     string `json:"sha256"`
	Committed  bool   `json:"committed"`
}

type xferQueued struct {
	grantID   string
	payload   map[string]interface{}
	recordDir string
	// keepRecord leaves the state record in place after delivery (a sweep
	// that failed is retried on the next start).
	keepRecord bool
}

// xferManager owns every xfer child of the agent process.
type xferManager struct {
	mu       sync.Mutex
	stateDir string
	out      ptyOut // the enrolled connection; nil while down
	live     map[string]*xferChild
	ports    map[uint16]bool
	queue    []xferQueued
}

func newXferManager(stateDir string) *xferManager {
	return &xferManager{stateDir: stateDir, live: map[string]*xferChild{}, ports: map[uint16]bool{}}
}

var xferMgrPtr atomic.Pointer[xferManager]

func init() {
	xferMgrPtr.Store(newXferManager(""))
}

func xferMgr() *xferManager { return xferMgrPtr.Load() }

func (m *xferManager) setStateDir(dir string) {
	m.mu.Lock()
	m.stateDir = dir
	m.mu.Unlock()
}

func (m *xferManager) recordDir(fallback string) string {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.stateDir != "" {
		return m.stateDir
	}
	return fallback
}

// attach makes out the connection results go to and flushes the queue.
// The agent calls it once a connection has enrolled.
func (m *xferManager) attach(out ptyOut) {
	m.mu.Lock()
	m.out = out
	q := m.queue
	m.queue = nil
	m.mu.Unlock()
	for _, item := range q {
		m.deliver(item)
	}
}

// detach forgets out if it is still the current connection.
func (m *xferManager) detach(out ptyOut) {
	m.mu.Lock()
	if m.out == out {
		m.out = nil
	}
	m.mu.Unlock()
}

// deliver sends an xfer_result now, or queues it for the next connection.
// The state record goes once the frame is written.
func (m *xferManager) deliver(q xferQueued) {
	m.mu.Lock()
	out := m.out
	if out == nil {
		m.queue = append(m.queue, q)
		m.mu.Unlock()
		return
	}
	m.mu.Unlock()
	err := out.WriteJSON(map[string]interface{}{"type": "xfer_result", "grant_id": q.grantID, "payload": q.payload})
	if err != nil {
		m.mu.Lock()
		m.queue = append(m.queue, q)
		m.mu.Unlock()
		return
	}
	if !q.keepRecord {
		removeXferRecord(q.recordDir, q.grantID)
	}
}

func (m *xferManager) lookup(id string) *xferChild {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.live[id]
}

func (m *xferManager) liveCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.live)
}

// reserve takes one of the four slots and, in listen mode with a range, a
// port. It returns "dup" for a grant id already live, "cap" when no slot or
// port is free, and "" on success.
func (m *xferManager) reserve(x *xferChild, listen *xferListen) string {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.live[x.grantID] != nil {
		return "dup"
	}
	if len(m.live) >= xferMaxChildren {
		return "cap"
	}
	if listen != nil && listen.lo != 0 {
		found := false
		for p := uint32(listen.lo); p <= uint32(listen.hi); p++ {
			if !m.ports[uint16(p)] {
				x.port, found = uint16(p), true
				break
			}
		}
		if !found {
			return "cap"
		}
		m.ports[x.port] = true
	}
	m.live[x.grantID] = x
	return ""
}

func (m *xferManager) release(x *xferChild) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.live[x.grantID] == x {
		delete(m.live, x.grantID)
	}
	if x.port != 0 {
		delete(m.ports, x.port)
	}
}

// stopAll cancels every child and waits up to timeout for them to finish.
func (m *xferManager) stopAll(reason string, timeout time.Duration) {
	m.mu.Lock()
	live := make([]*xferChild, 0, len(m.live))
	for _, x := range m.live {
		live = append(live, x)
	}
	m.mu.Unlock()
	end := time.After(timeout)
	for _, x := range live {
		x.stop(reason)
	}
	for _, x := range live {
		select {
		case <-x.done:
		case <-end:
			return
		}
	}
}

func xferStatus(out ptyOut, gid string, payload interface{}) {
	_ = out.WriteJSON(map[string]interface{}{"type": "xfer_status", "grant_id": gid, "payload": payload})
}

func xferStatusError(out ptyOut, gid, code string) {
	xferStatus(out, gid, map[string]string{"error": code})
}

// handleXfer routes xfer frames to the agent-level manager.
func (c *channelConn) handleXfer(typ string, message []byte) bool {
	switch typ {
	case "xfer_grant", "xfer_renew", "xfer_cancel":
	default:
		return false
	}
	var msg xferMsg
	if err := json.Unmarshal(message, &msg); err != nil {
		log.Printf("rejected malformed %s", typ)
		if typ == "xfer_grant" {
			// Recover the grant id so the server is not left waiting.
			var head struct {
				GrantID string `json:"grant_id"`
			}
			if json.Unmarshal(message, &head) == nil && xferGrantRe.MatchString(head.GrantID) && xferMgr().lookup(head.GrantID) == nil {
				xferStatusError(c.out, head.GrantID, "internal")
			}
		}
		return true
	}
	m := xferMgr()
	now := time.Now()
	switch typ {
	case "xfer_grant":
		m.grant(c, msg, now)
	case "xfer_renew":
		if err := m.renew(msg, now); err != nil {
			log.Printf("xfer_renew refused: %s", err.Error())
		}
	case "xfer_cancel":
		if x := m.lookup(msg.GrantID); x != nil {
			reason := msg.Reason
			if !xferReasonRe.MatchString(reason) {
				reason = "cancelled"
			}
			x.stop(reason)
		}
	}
	return true
}

// decodeXferSecret decodes canonical padded base64 of exactly n bytes.
func decodeXferSecret(s string, n int) ([]byte, bool) {
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil || len(raw) != n || base64.StdEncoding.EncodeToString(raw) != s {
		return nil, false
	}
	return raw, true
}

func xferMaterialOf(key, token string) (string, bool) {
	k, ok1 := decodeXferSecret(key, 32)
	t, ok2 := decodeXferSecret(token, 16)
	if !ok1 || !ok2 {
		return "", false
	}
	mat, err := xferMaterial(k, t)
	for i := range k {
		k[i] = 0
	}
	for i := range t {
		t[i] = 0
	}
	return mat, err == nil
}

func xferFields(msg xferMsg, phase, material string) xferLeaseFields {
	return xferLeaseFields{
		GrantID: msg.GrantID, DeadlineUnix: msg.DeadlineUnix, Phase: phase, Dir: msg.Dir, Root: msg.Root,
		Path: msg.Path, Size: msg.Size, SHA256: msg.SHA256, Overwrite: msg.Overwrite, TransferID: msg.TransferID,
		ExpiresUnix: msg.ExpiresUnix, IdleS: msg.IdleS, MaxS: msg.MaxS, ByteCap: msg.ByteCap,
		Profile: msg.Profile, Transport: msg.Transport, Peer: msg.Peer, Material: material,
	}
}

// grant runs sequence steps 5 and 6. Every refusal is an xfer_status error
// sent before any child starts.
func (m *xferManager) grant(c *channelConn, msg xferMsg, now time.Time) {
	gid := msg.GrantID
	if !xferGrantRe.MatchString(gid) {
		log.Printf("xfer_grant refused: bad grant id")
		return
	}
	// A second frame for a live grant (a replay, or a server bug) must not
	// produce an error frame the server would apply to the live transfer.
	if m.lookup(gid) != nil {
		log.Printf("xfer %s: frame for a live grant ignored", gid)
		return
	}
	refuse := func(code, why string) {
		log.Printf("xfer %s refused: %s", gid, why)
		xferStatusError(c.out, gid, code)
	}
	if !xferAction(msg.Action) {
		refuse("lease_required", "bad action")
		return
	}
	material, ok := xferMaterialOf(msg.Key, msg.RouteToken)
	if !ok {
		refuse("lease_required", "bad key material")
		return
	}
	fields := xferFields(msg, "start", material)
	payload, err := xferLeasePayload(fields)
	if err != nil {
		refuse("lease_required", err.Error())
		return
	}
	if err := authorizeCommand(c.hostID, msg.Action, payload, msg.Lease, now); err != nil {
		refuse("lease_required", err.Error())
		return
	}
	// Unsigned fields must agree with the signed ones.
	wantPurpose := "xfer:" + msg.Dir
	if msg.Action == "xfer_root" {
		wantPurpose = "xfer:root"
	}
	if msg.Purpose != wantPurpose {
		refuse("lease_required", "purpose does not match the action and dir")
		return
	}
	nowUnix := now.Unix()
	switch {
	case msg.Dir != "put":
		refuse("agent_unsupported", "get is phase 2")
		return
	case msg.Transport != "udp" || msg.AEAD != xferAEAD:
		refuse("agent_unsupported", "transport or aead")
		return
	case msg.DeadlineUnix <= nowUnix:
		refuse("lease_required", "deadline passed")
		return
	case msg.ExpiresUnix <= nowUnix:
		refuse("lease_required", "first-packet deadline passed")
		return
	case msg.MaxS > xferMaxSeconds || msg.IdleS > msg.MaxS || msg.ByteCap < msg.Size:
		refuse("lease_required", "limits")
		return
	}
	if !xferAvailable() {
		refuse("agent_unsupported", "xfer is not available on this agent")
		return
	}
	cfg := xferCfg
	listenMode := msg.Peer == "listen"
	if listenMode && cfg.listen == nil {
		refuse("agent_unsupported", "listen mode without --xfer-udp-listen")
		return
	}
	leaseExp := time.Unix(msg.Lease.ExpiresUnix, 0)
	if d := time.Unix(msg.DeadlineUnix, 0); d.Before(leaseExp) {
		leaseExp = d
	}
	x := &xferChild{
		m: m, out: c.out, hostID: c.hostID, grantID: gid, transferID: msg.TransferID, action: msg.Action,
		lease: fields, listenMode: listenMode, deadline: msg.DeadlineUnix, leaseExp: leaseExp,
		byteCap: msg.ByteCap, done: make(chan struct{}), advertise: cfg.advertise,
		ctlq: make(chan []byte, xferCtlQueue), ctlStop: make(chan struct{}),
		watchEvery: xferWatchEvery, progressEvery: xferProgressEvery, cancelGrace: xferCancelGrace, termGrace: xferTermGrace,
	}
	var listen *xferListen
	if listenMode {
		listen = cfg.listen
		x.listenIP = cfg.listen.ip
	}
	switch m.reserve(x, listen) {
	case "dup":
		log.Printf("xfer %s: frame for a live grant ignored", gid)
		return
	case "cap":
		refuse("cap_reached", "no free xfer slot or port")
		return
	}
	fileAction := "file"
	if msg.Action == "xfer_root" {
		fileAction = "file_root"
	}
	id, code := resolveFileIdentity(fileAction, ptyCfg, agentEUID())
	if code != "" {
		m.release(x)
		refuse(code, "identity")
		return
	}
	stateDir := m.recordDir(c.stateDir)
	if code := checkSessionRoot(fileAction, msg.Root, id.home, stateDir); code != "" {
		m.release(x)
		refuse(code, "the root is / or holds the agent state directory")
		return
	}
	if stateDir == "" {
		m.release(x)
		refuse("internal", "no state directory for the transfer record")
		return
	}
	x.recordDir = stateDir
	rec := xferRecord{
		GrantID: gid, TransferID: msg.TransferID, Action: msg.Action, Root: msg.Root, Path: msg.Path,
		Size: msg.Size, SHA256: msg.SHA256, Identity: recordIdentity(id), CreatedUnix: nowUnix,
	}
	if err := saveXferRecord(stateDir, rec); err != nil {
		m.release(x)
		refuse("internal", "state record not written")
		return
	}
	peer := msg.Peer
	if listenMode {
		peer = "listen:" + netip.AddrPortFrom(cfg.listen.ip, x.port).String()
	}
	line := xferCtlGrant{
		V: 1, GrantID: gid, TransferID: msg.TransferID, Purpose: msg.Purpose, Dir: msg.Dir, Root: msg.Root,
		Path: msg.Path, Size: msg.Size, SHA256: msg.SHA256, Overwrite: msg.Overwrite, Profile: msg.Profile,
		Transport: msg.Transport, AEAD: msg.AEAD, Key: msg.Key, RouteToken: msg.RouteToken,
		ExpiresUnix: msg.ExpiresUnix, DeadlineUnix: msg.DeadlineUnix, IdleS: msg.IdleS, MaxS: msg.MaxS,
		ByteCap: msg.ByteCap, Peer: peer,
	}
	if err := x.spawn(id, cfg.bin, line); err != nil {
		log.Printf("xfer %s: recv did not start: %v", gid, err)
		removeXferRecord(stateDir, gid)
		m.release(x)
		xferStatusError(c.out, gid, "internal")
		return
	}
	log.Printf("xfer %s started action=%s", gid, msg.Action)
}

// renew runs step 12: the payload is rebuilt from the stored grant with
// only phase and deadline changed.
func (m *xferManager) renew(msg xferMsg, now time.Time) error {
	x := m.lookup(msg.GrantID)
	if x == nil {
		return errors.New("unknown_grant")
	}
	x.mu.Lock()
	fields, cur := x.lease, x.deadline
	x.mu.Unlock()
	if msg.DeadlineUnix < cur {
		return errors.New("deadline_backwards")
	}
	fields.Phase, fields.DeadlineUnix = "renew", msg.DeadlineUnix
	payload, err := xferLeasePayload(fields)
	if err != nil {
		return err
	}
	if err := authorizeCommand(x.hostID, x.action, payload, msg.Lease, now); err != nil {
		return err
	}
	exp := time.Unix(msg.Lease.ExpiresUnix, 0)
	if d := time.Unix(msg.DeadlineUnix, 0); d.Before(exp) {
		exp = d
	}
	x.mu.Lock()
	if x.stopping {
		x.mu.Unlock()
		return errors.New("transfer_ending")
	}
	if msg.DeadlineUnix > x.deadline {
		x.deadline = msg.DeadlineUnix
	}
	if exp.After(x.leaseExp) {
		x.leaseExp = exp
	}
	x.mu.Unlock()
	return x.sendCtl(map[string]interface{}{"op": "renew", "deadline_unix": msg.DeadlineUnix})
}

// xferChild is one running recv.
type xferChild struct {
	m          *xferManager
	out        ptyOut // the socket the grant came on; xfer_status goes there
	hostID     string
	grantID    string
	transferID string
	action     string
	listenMode bool
	port       uint16
	byteCap    int64
	recordDir  string
	done       chan struct{}
	advertise  netip.Addr
	listenIP   netip.Addr
	// Timings, fixed at grant time.
	watchEvery, progressEvery, cancelGrace, termGrace time.Duration

	// fd 3: lines go through ctlq to one writer goroutine, so neither the
	// connection's read loop nor stop ever blocks on a recv that stopped
	// reading; each write has a deadline.
	ctlq    chan []byte
	ctlStop chan struct{}
	ctlOnce sync.Once
	ctlMu   sync.Mutex
	ctl     *os.File

	mu         sync.Mutex
	cmd        *exec.Cmd
	lease      xferLeaseFields // no key: renewals need only the material hash
	deadline   int64
	leaseExp   time.Time
	stopping   bool
	stopReason string
	ready      bool
	result     *xferEvent
	bytes      int64
	lastActive time.Time
	sentActive bool
	stderr     limitedBuffer
}

// limitedBuffer keeps the first 512 bytes of the child's stderr.
type limitedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if room := 512 - b.buf.Len(); room > 0 {
		if len(p) > room {
			b.buf.Write(p[:room])
		} else {
			b.buf.Write(p)
		}
	}
	return len(p), nil
}

func (b *limitedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, strings.TrimSpace(b.buf.String()))
}

// spawn starts recv with fds 3 and 4, writes the grant line, and starts the
// fd 3 writer, the event reader and the lease watcher.
func (x *xferChild) spawn(id *ptyIdentity, bin string, line xferCtlGrant) error {
	exe, release, err := openXferBin(bin, os.Geteuid())
	if err != nil {
		return err
	}
	defer release()
	cmd, err := startXferProc(id, exe, "recv", "--ctl-fd", "3", "--event-fd", "4")
	if err != nil {
		return err
	}
	cmd.Args[0] = "sahxfer"
	// Wait returns this long after recv exits even if something the
	// identity user started still holds recv's stderr.
	cmd.WaitDelay = xferWaitDelay
	ctlR, ctlW, err := os.Pipe()
	if err != nil {
		return err
	}
	evR, evW, err := os.Pipe()
	if err != nil {
		closeAll(ctlR, ctlW)
		return err
	}
	cmd.ExtraFiles = []*os.File{ctlR, evW}
	cmd.Stderr = &x.stderr
	raw, err := json.Marshal(line)
	if err != nil {
		closeAll(ctlR, ctlW, evR, evW)
		return err
	}
	raw = append(raw, '\n')
	defer func() {
		for i := range raw {
			raw[i] = 0
		}
	}()
	// Start and the grant line happen under both locks, so a cancel that
	// races the spawn either stops it here or is queued after the grant.
	x.mu.Lock()
	if x.stopping {
		x.mu.Unlock()
		closeAll(ctlR, ctlW, evR, evW)
		return errors.New("cancelled before start")
	}
	if err := cmd.Start(); err != nil {
		x.mu.Unlock()
		closeAll(ctlR, ctlW, evR, evW)
		return err
	}
	closeAll(ctlR, evW)
	x.cmd = cmd
	x.ctlMu.Lock()
	x.ctl = ctlW
	x.ctlMu.Unlock()
	x.mu.Unlock()
	go x.watch()
	go x.run(evR)
	if err := x.writeCtlNow(raw); err != nil {
		// recv got no grant: it reads EOF, which is cancel, and exits.
		log.Printf("xfer %s: grant line not written", x.grantID)
		x.closeCtl()
		x.stop("internal")
	}
	go x.ctlWriter()
	return nil
}

// sendCtl queues one fd 3 line. A full queue means recv is not reading
// fd 3; it is stopped.
func (x *xferChild) sendCtl(v interface{}) error {
	raw, err := json.Marshal(v)
	if err != nil {
		return err
	}
	select {
	case <-x.ctlStop:
		return errors.New("ctl_closed")
	default:
	}
	select {
	case x.ctlq <- append(raw, '\n'):
		return nil
	default:
		log.Printf("xfer %s: recv is not reading fd 3; stopping it", x.grantID)
		x.closeCtl()
		x.stop("internal")
		return errors.New("ctl_full")
	}
}

func (x *xferChild) ctlWriter() {
	for {
		select {
		case <-x.ctlStop:
			return
		case b := <-x.ctlq:
			if err := x.writeCtlNow(b); err != nil {
				log.Printf("xfer %s: fd 3 write failed; stopping recv", x.grantID)
				x.closeCtl()
				x.stop("internal")
				return
			}
		}
	}
}

// writeCtlNow writes one line with a deadline. ctlMu guards only the
// pointer, never a write, so closeCtl never waits on a blocked write: closing
// the file fails that write at once.
func (x *xferChild) writeCtlNow(b []byte) error {
	x.ctlMu.Lock()
	f := x.ctl
	x.ctlMu.Unlock()
	if f == nil {
		return errors.New("ctl_closed")
	}
	if err := f.SetWriteDeadline(time.Now().Add(xferCtlTimeout)); err != nil {
		return err
	}
	_, err := f.Write(b)
	return err
}

// closeCtl closes fd 3's write end; recv reads EOF, which is cancel stopped.
func (x *xferChild) closeCtl() {
	x.ctlOnce.Do(func() { close(x.ctlStop) })
	x.ctlMu.Lock()
	f := x.ctl
	x.ctl = nil
	x.ctlMu.Unlock()
	if f != nil {
		_ = f.Close()
	}
}

// stop starts the SIGTERM and SIGKILL timers once, then queues cancel:
// SIGTERM after cancelGrace and SIGKILL after a further termGrace if recv
// has not exited, whatever happens to the cancel line.
func (x *xferChild) stop(reason string) {
	x.mu.Lock()
	if x.stopping {
		x.mu.Unlock()
		return
	}
	x.stopping, x.stopReason = true, reason
	x.mu.Unlock()
	signal := func(sig os.Signal) {
		x.mu.Lock()
		cmd := x.cmd
		x.mu.Unlock()
		if cmd != nil && cmd.Process != nil {
			_ = cmd.Process.Signal(sig)
		}
	}
	go func() {
		select {
		case <-x.done:
			return
		case <-time.After(x.cancelGrace):
		}
		signal(syscall.SIGTERM)
		select {
		case <-x.done:
			return
		case <-time.After(x.termGrace):
		}
		signal(os.Kill)
	}()
	_ = x.sendCtl(map[string]interface{}{"op": "cancel", "reason": reason})
}

// watch ends the transfer when its lease lapses without a renew.
func (x *xferChild) watch() {
	t := time.NewTicker(x.watchEvery)
	defer t.Stop()
	for {
		select {
		case <-x.done:
			return
		case now := <-t.C:
			x.mu.Lock()
			lapsed := !now.Before(x.leaseExp)
			x.mu.Unlock()
			if lapsed {
				log.Printf("xfer %s: lease lapsed", x.grantID)
				x.stop("stopped")
				return
			}
		}
	}
}

// run reaps recv and reports. Wait runs here, apart from the event reader:
// once recv has exited the reader gets xferEventDrain to finish, then its
// pipe is cut, so a process holding recv's fd 4 or stderr cannot pin the
// slot or leave a zombie.
func (x *xferChild) run(evR *os.File) {
	evDone := make(chan struct{})
	go func() {
		defer close(evDone)
		x.readEvents(evR)
	}()
	x.mu.Lock()
	cmd := x.cmd
	x.mu.Unlock()
	werr := cmd.Wait()
	select {
	case <-evDone:
	case <-time.After(xferEventDrain):
		log.Printf("xfer %s: fd 4 still open after recv exited; closing it", x.grantID)
		_ = evR.SetReadDeadline(time.Now())
		<-evDone
	}
	evR.Close()
	x.closeCtl()
	if msg := x.stderr.String(); msg != "" {
		log.Printf("xfer %s recv stderr: %s", x.grantID, msg)
	}
	x.finish(werr)
	// The slot is free only once the outcome is recorded or sent.
	close(x.done)
	x.m.release(x)
}

// readEvents reads fd 4 lines until EOF or error. A last line without a
// newline at EOF still counts.
func (x *xferChild) readEvents(evR *os.File) {
	r := bufio.NewReaderSize(evR, xferLineMax+1)
	for {
		line, err := r.ReadSlice('\n')
		if errors.Is(err, bufio.ErrBufferFull) {
			log.Printf("xfer %s: event line over 64 KiB; stopping recv", x.grantID)
			x.stop("internal")
			for {
				if _, err := r.ReadSlice('\n'); err != nil && !errors.Is(err, bufio.ErrBufferFull) {
					return
				}
			}
		}
		if len(line) > 0 && (err == nil || errors.Is(err, io.EOF)) {
			x.onEvent(line)
		}
		if err != nil {
			return
		}
	}
}

func closeAll(fs ...*os.File) {
	for _, f := range fs {
		_ = f.Close()
	}
}

func (x *xferChild) onEvent(line []byte) {
	var ev xferEvent
	if err := json.Unmarshal(bytes.TrimSpace(line), &ev); err != nil {
		log.Printf("xfer %s: malformed event ignored", x.grantID)
		return
	}
	switch ev.Ev {
	case "ready":
		x.onReady(ev.UDP)
	case "active":
		x.onActive(ev.Bytes)
	case "result":
		// A grant line recv could not decode yields a result with no ids,
		// and only before ready; any other result must name this grant.
		x.mu.Lock()
		ok := (ev.GrantID == x.grantID && ev.TransferID == x.transferID) ||
			(!x.ready && ev.GrantID == "" && ev.TransferID == "")
		if ok && x.result == nil {
			r := ev
			x.result = &r
		}
		x.mu.Unlock()
		if !ok {
			log.Printf("xfer %s: result for another grant ignored", x.grantID)
		}
	}
}

// onReady sends xfer_status ready. In listen mode udp is required, and
// --xfer-udp-advertise replaces the IP recv bound.
func (x *xferChild) onReady(udp string) {
	x.mu.Lock()
	if x.ready || x.stopping || x.result != nil {
		x.mu.Unlock()
		return
	}
	x.mu.Unlock()
	payload := map[string]interface{}{"status": "ready"}
	if x.listenMode {
		ap, err := netip.ParseAddrPort(udp)
		pinned := x.listenIP.IsValid() && !x.listenIP.IsUnspecified() && ap.Addr().Unmap() != x.listenIP
		if err != nil || ap.Port() == 0 || (x.port != 0 && ap.Port() != x.port) || pinned {
			log.Printf("xfer %s: recv reported a bad ready address", x.grantID)
			x.stop("internal")
			return
		}
		if adv := x.advertise; adv.IsValid() {
			ap = netip.AddrPortFrom(adv, ap.Port())
		}
		payload["udp"] = ap.String()
	}
	x.mu.Lock()
	x.ready = true
	x.mu.Unlock()
	xferStatus(x.out, x.grantID, payload)
}

// onActive forwards progress: the first report at once, then at most one
// every xferProgressEvery.
func (x *xferChild) onActive(n int64) {
	if n < 0 || n > x.byteCap {
		return
	}
	now := time.Now()
	x.mu.Lock()
	if !x.ready || n < x.bytes {
		x.mu.Unlock()
		return
	}
	x.bytes = n
	send := !x.sentActive || now.Sub(x.lastActive) >= x.progressEvery
	if send {
		x.sentActive, x.lastActive = true, now
	}
	x.mu.Unlock()
	if send {
		xferStatus(x.out, x.grantID, map[string]interface{}{"status": "active", "bytes": n})
	}
}

// finish reports the outcome: a refusal before ready is an xfer_status
// error, anything after ready an xfer_result through the queue.
func (x *xferChild) finish(werr error) {
	x.mu.Lock()
	res, ready, reason, bytesSeen := x.result, x.ready, x.stopReason, x.bytes
	lapsed := reason == "stopped" || !time.Now().Before(x.leaseExp)
	x.mu.Unlock()
	if !ready {
		code := "internal"
		if res != nil && xferReasonRe.MatchString(res.Reason) {
			code = res.Reason
		}
		log.Printf("xfer %s refused by recv: %s", x.grantID, code)
		xferStatusError(x.out, x.grantID, code)
		removeXferRecord(x.recordDir, x.grantID)
		return
	}
	var payload map[string]interface{}
	if res != nil {
		payload = xferResultPayload(res, x.byteCap)
		// recv enforces the lease deadline itself and calls that expired;
		// a lease that lapsed without a renew is reported aborted stopped.
		if lapsed && !res.Committed && res.Reason == "expired" {
			payload["status"], payload["reason"] = "aborted", "stopped"
		}
	} else {
		if reason == "" {
			reason = "internal"
		}
		log.Printf("xfer %s: recv exited without a result (%v)", x.grantID, werr)
		// Whether recv committed before it died is not known, so committed
		// is left out rather than claimed false.
		payload = map[string]interface{}{"status": "aborted", "reason": reason, "bytes": bytesSeen}
	}
	log.Printf("xfer %s finished: %v %v", x.grantID, payload["status"], payload["reason"])
	// A crash between here and delivery still reports this result on restart.
	if err := saveXferResult(x.recordDir, x.grantID, payload); err != nil {
		log.Printf("xfer %s: result not recorded: %v", x.grantID, err)
	}
	x.m.deliver(xferQueued{grantID: x.grantID, payload: payload, recordDir: x.recordDir})
}

// xferResultPayload keeps only well-formed result fields.
func xferResultPayload(res *xferEvent, byteCap int64) map[string]interface{} {
	status := res.Status
	if !xferResultStatuses[status] {
		status = "aborted"
	}
	p := map[string]interface{}{"status": status, "committed": res.Committed}
	if xferReasonRe.MatchString(res.Reason) {
		p["reason"] = res.Reason
	}
	if res.Bytes >= 0 && res.Bytes <= byteCap {
		p["bytes"] = res.Bytes
	}
	if res.Committed && hashHexRe.MatchString(res.SHA256) {
		p["sha256"] = res.SHA256
	}
	return p
}
