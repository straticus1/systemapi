// File channel, agent side (docs/sah-file-protocol.md): the session layer
// between the control-plane socket and one file-helper child per session.
// Threats: an operation outside what the lease signed (the lease payload
// carries the session id, deadline, mode and root; the agent rebuilds it from
// what it is about to open, so a lease for one root or mode never verifies
// for another, and a write op on a read lease gets read_only before it
// reaches the helper), a session outliving its lease or deadline (a watcher
// ends it at the lease expiry, the deadline or the idle limit), operations
// running as the agent (every op runs in the helper under the session's
// dropped identity; a non-root agent refuses unless --pty-allow-agent-user,
// and file:root needs a root agent), memory growth (write data from the
// server is bounded by the session's 8 MiB credit window and an overrun
// drops the connection; read data waits for credit, so the helper blocks on
// its pipe; the task queue is bounded and a server that overfills it ends
// the session), and a slow disk blocking the agent (each session has its own
// worker goroutine; the connection's read loop only queues). Does NOT check
// the request shape as strictly as the server (the helper re-checks every
// field it uses), and does NOT verify idle_s, file_max or actor (they ride
// the authenticated control-plane socket, not the lease).
package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	fileMaxSessions = 16
	// fileRootReserved of those slots only take file_root sessions, as on
	// the server.
	fileRootReserved = 2
	fileTaskQueue   = 64
	fileMaxDeadline = 7*24*time.Hour + time.Minute
	fileHelperGrace = 2 * time.Second
)

// fileWatchEvery is how often a session checks its lease, deadline and idle time.
var fileWatchEvery = 200 * time.Millisecond

type fileMsg struct {
	Type         string          `json:"type"`
	SessionID    string          `json:"session_id"`
	Action       string          `json:"action"`
	Mode         string          `json:"mode"`
	Root         string          `json:"root"`
	DeadlineUnix int64           `json:"deadline_unix"`
	IdleS        int64           `json:"idle_s"`
	FileMax      int64           `json:"file_max"`
	Actor        string          `json:"actor"`
	Lease        *Lease          `json:"lease"`
	Request      json.RawMessage `json:"request"`
	RequestID    string          `json:"request_id"`
	Offset       int64           `json:"offset"`
	Length       int64           `json:"length"`
	Bytes        interface{}     `json:"bytes"`
}

type fileChunkIn struct {
	reqID  string
	offset int64
	length int
	buf    []byte
}

type fileTask struct {
	req   *fileReq
	chunk *fileChunkIn
	// bad is a request that did not decode but whose request_id did: it
	// is answered bad_request in order.
	bad bool
}

type agentWrite struct {
	reqID    string
	uploadID string
}

type fileSession struct {
	c        *channelConn
	id       string
	action   string
	mode     string
	root     string // as signed: "~" or an absolute path
	actor    string
	fileMax  int64
	deadline time.Time
	idle     time.Duration
	every    time.Duration

	tasks chan fileTask
	stop  chan struct{}
	done  chan struct{}

	// Touched only by the connection's read goroutine.
	chunk *fileChunkIn

	mu           sync.Mutex
	leaseExp     time.Time
	lastActivity time.Time
	ended        bool
	reason       string
	cmd          *exec.Cmd

	// Worker goroutine only.
	ready        bool
	canon        string
	in           io.WriteCloser
	inBuf        *bufio.Writer
	outBuf       *bufio.Reader
	write        *agentWrite
	ops          int64
	bytesRead    int64
	bytesWritten int64
}

func fileStatusError(out ptyOut, sid, code string) {
	_ = out.WriteJSON(ResponseMessage{Type: "file_status", SessionID: sid, Payload: map[string]string{"error": code}})
}

// handleFile processes a file channel frame; it reports whether typ was
// one, and returns an error only for a fatal credit violation.
func (c *channelConn) handleFile(typ string, message []byte) (bool, error) {
	switch typ {
	case "file_open", "file_req", "file_chunk", "file_renew", "file_stop", "file_credit":
	default:
		return false, nil
	}
	var msg fileMsg
	if err := json.Unmarshal(message, &msg); err != nil {
		log.Printf("rejected malformed %s", typ)
		return true, nil
	}
	now := time.Now()
	switch typ {
	case "file_open":
		c.openFile(msg, now)
	case "file_renew":
		if err := c.renewFile(msg.SessionID, msg.Lease, now); err != nil {
			log.Printf("file_renew refused: %s", err.Error())
		}
	case "file_stop":
		if s := c.lookupFile(msg.SessionID); s != nil {
			s.end("stopped")
		}
	case "file_req":
		if s := c.lookupFile(msg.SessionID); s != nil {
			s.queueRequest(msg.Request)
		}
	case "file_chunk":
		if s := c.lookupFile(msg.SessionID); s != nil {
			s.expectChunk(msg)
		}
	case "file_credit":
		n, ok := creditBytes(msg.Bytes)
		if !ok {
			if c.lookupFile(msg.SessionID) != nil {
				return true, errCreditOverflow
			}
			return true, nil
		}
		if err := c.mux.Grant(msg.SessionID, n); err != nil {
			return true, err
		}
	}
	return true, nil
}

func (c *channelConn) lookupFile(id string) *fileSession {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.files[id]
}

// fileData takes write data from the server for a file session.
func (c *channelConn) fileData(sid string, payload []byte) {
	if s := c.lookupFile(sid); s != nil {
		s.addData(payload)
	}
}

// resolveFileIdentity picks the account a file or xfer session runs as
// (FILE §7), through the same per-identity resolution as terminal:open.
func resolveFileIdentity(action, actor string, cfg ptySettings, euid int) (*ptyIdentity, string) {
	if action == "file_root" {
		if euid != 0 {
			log.Printf("file:root needs an agent running as root")
			return nil, "root_unavailable"
		}
		id, code := resolvePTYIdentity("pty_root", actor, cfg, euid)
		if code != "" {
			return nil, "internal"
		}
		return id, ""
	}
	if euid != 0 && !cfg.AllowAgentUser {
		log.Printf("file session refused: the agent is not root and --pty-allow-agent-user is not set")
		return nil, "pty_user_unset"
	}
	id, code := resolvePTYIdentity("pty", actor, cfg, euid)
	switch code {
	case "":
		return id, ""
	case "pty_user_unset", "account_unmapped":
		return nil, code
	}
	return nil, "internal"
}

func newUploadID() (string, error) {
	b := make([]byte, 18)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "upl_" + base64.RawURLEncoding.EncodeToString(b), nil
}

// openFile authorizes a file_open and starts the session's worker. Every
// refusal is a file_status error with a contract code.
func (c *channelConn) openFile(msg fileMsg, now time.Time) {
	sid := msg.SessionID
	if !fileSessionRe.MatchString(sid) {
		log.Printf("file_open refused: bad session id")
		fileStatusError(c.out, "", "internal")
		return
	}
	if msg.Action != "file" && msg.Action != "file_root" {
		fileStatusError(c.out, sid, "lease_required")
		return
	}
	deadline := time.Unix(msg.DeadlineUnix, 0)
	if !deadline.After(now) || deadline.Sub(now) > fileMaxDeadline {
		fileStatusError(c.out, sid, "lease_required")
		return
	}
	payload, err := fileLeasePayload(sid, msg.DeadlineUnix, "start", msg.Mode, msg.Root)
	if err != nil {
		fileStatusError(c.out, sid, "lease_required")
		return
	}
	// The lease signs the mode and root: the agent opens only those.
	if err := authorizeCommand(c.hostID, msg.Action, payload, msg.Lease, now); err != nil {
		log.Printf("file refused: %s", err.Error())
		fileStatusError(c.out, sid, "lease_required")
		return
	}
	if msg.IdleS <= 0 || msg.FileMax < 0 {
		fileStatusError(c.out, sid, "internal")
		return
	}
	if !openat2Available() {
		fileStatusError(c.out, sid, "agent_unsupported")
		return
	}
	leaseExp := time.Unix(msg.Lease.ExpiresUnix, 0)
	if leaseExp.After(deadline) {
		leaseExp = deadline
	}
	s := &fileSession{
		c:            c,
		id:           sid,
		action:       msg.Action,
		mode:         msg.Mode,
		root:         msg.Root,
		actor:        msg.Actor,
		fileMax:      msg.FileMax,
		deadline:     deadline,
		idle:         time.Duration(msg.IdleS) * time.Second,
		every:        fileWatchEvery,
		tasks:        make(chan fileTask, fileTaskQueue),
		stop:         make(chan struct{}),
		done:         make(chan struct{}),
		leaseExp:     leaseExp,
		lastActivity: now,
	}
	c.mu.Lock()
	nonRoot := 0
	for _, f := range c.files {
		if f.action != "file_root" {
			nonRoot++
		}
	}
	if c.closed || c.files[sid] != nil || len(c.files) >= fileMaxSessions ||
		(msg.Action != "file_root" && nonRoot >= fileMaxSessions-fileRootReserved) {
		c.mu.Unlock()
		log.Printf("file refused: duplicate session or no free slot")
		fileStatusError(c.out, sid, "cap_reached")
		return
	}
	if err := c.mux.Open(sid, "file", fileCreditWindow); err != nil {
		c.mu.Unlock()
		fileStatusError(c.out, sid, "internal")
		return
	}
	c.files[sid] = s
	c.mu.Unlock()
	go s.run()
	go s.watch()
}

func (c *channelConn) renewFile(sid string, lease *Lease, now time.Time) error {
	s := c.lookupFile(sid)
	if s == nil {
		return errors.New("unknown_session")
	}
	payload, err := fileLeasePayload(sid, s.deadline.Unix(), "renew", s.mode, s.root)
	if err != nil {
		return err
	}
	if err := authorizeCommand(c.hostID, s.action, payload, lease, now); err != nil {
		return err
	}
	exp := time.Unix(lease.ExpiresUnix, 0)
	if exp.After(s.deadline) {
		exp = s.deadline
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ended {
		return errors.New("session_ended")
	}
	if exp.After(s.leaseExp) {
		s.leaseExp = exp
	}
	return nil
}

func (s *fileSession) touch() {
	s.mu.Lock()
	s.lastActivity = time.Now()
	s.mu.Unlock()
}

func (s *fileSession) queue(t fileTask) {
	select {
	case s.tasks <- t:
	default:
		log.Printf("file %s: task queue full; ending session", s.id)
		s.end("internal")
	}
}

func (s *fileSession) queueRequest(raw json.RawMessage) {
	var req fileReq
	dec := json.NewDecoder(bytes.NewReader(raw))
	if err := dec.Decode(&req); err != nil || !requestIDRe.MatchString(req.RequestID) {
		// A request the server is waiting on must get an answer, or the
		// session wedges: when its request_id is recoverable it gets
		// bad_request (an mtime_ns outside int64, say).
		var head struct {
			RequestID string `json:"request_id"`
			Op        string `json:"op"`
		}
		if json.Unmarshal(raw, &head) != nil || !requestIDRe.MatchString(head.RequestID) {
			log.Printf("file %s: malformed request ignored", s.id)
			return
		}
		if !fileKnownOps[head.Op] {
			head.Op = ""
		}
		log.Printf("file %s: malformed request refused", s.id)
		s.touch()
		s.queue(fileTask{req: &fileReq{RequestID: head.RequestID, Op: head.Op}, bad: true})
		return
	}
	// Agent-only fields never come from the server.
	req.UploadID, req.ResumeID, req.Root, req.Home, req.FileMax = "", "", "", "", 0
	s.touch()
	s.queue(fileTask{req: &req})
}

// expectChunk takes the header of the write data that follows.
func (s *fileSession) expectChunk(msg fileMsg) {
	if s.chunk != nil || !requestIDRe.MatchString(msg.RequestID) || msg.Length < 1 || msg.Length > fileChunkMax || msg.Offset < 0 {
		log.Printf("file %s: bad chunk header; ending session", s.id)
		s.end("internal")
		return
	}
	s.chunk = &fileChunkIn{reqID: msg.RequestID, offset: msg.Offset, length: int(msg.Length), buf: make([]byte, 0, msg.Length)}
}

func (s *fileSession) addData(p []byte) {
	if len(p) == 0 {
		return
	}
	ch := s.chunk
	if ch == nil || len(ch.buf)+len(p) > ch.length {
		log.Printf("file %s: data outside a chunk; ending session", s.id)
		_ = s.c.mux.Drained(s.id, len(p))
		s.end("internal")
		return
	}
	ch.buf = append(ch.buf, p...)
	s.touch()
	if len(ch.buf) == ch.length {
		s.chunk = nil
		s.queue(fileTask{chunk: ch})
	}
}

// end stops the session once with reason; the worker reports file_closed.
func (s *fileSession) end(reason string) {
	s.mu.Lock()
	if s.ended {
		s.mu.Unlock()
		return
	}
	s.ended = true
	s.reason = reason
	close(s.stop)
	cmd := s.cmd
	s.mu.Unlock()
	// Unblocks a worker waiting for credit.
	s.c.mux.Close(s.id)
	go func() {
		select {
		case <-s.done:
		case <-time.After(fileHelperGrace):
			if cmd != nil && cmd.Process != nil {
				_ = cmd.Process.Kill()
			}
		}
	}()
}

func (s *fileSession) watch() {
	t := time.NewTicker(s.every)
	defer t.Stop()
	for {
		select {
		case <-s.done:
			return
		case now := <-t.C:
			s.mu.Lock()
			reason := ""
			switch {
			case !now.Before(s.deadline):
				reason = "max_duration"
			case !now.Before(s.leaseExp):
				reason = "stopped"
			case now.Sub(s.lastActivity) >= s.idle:
				reason = "idle_timeout"
			}
			s.mu.Unlock()
			if reason != "" {
				log.Printf("file %s ending: %s", s.id, reason)
				s.end(reason)
				return
			}
		}
	}
}

func (s *fileSession) stopped() bool {
	select {
	case <-s.stop:
		return true
	default:
		return false
	}
}

// run is the session worker: it starts the helper, reports ready, then
// serves requests and write chunks in order.
func (s *fileSession) run() {
	defer s.exit()
	if s.c.stateDir != "" {
		sweepUploads(s.c.stateDir, time.Now(), removeUploadTemp)
		startUploadSweeper(s.c.stateDir)
	}
	user, uid, code := s.start()
	if code != "" {
		log.Printf("file %s start failed: %s", s.id, code)
		fileStatusError(s.c.out, s.id, code)
		s.end("start_failed")
		return
	}
	if s.stopped() {
		return
	}
	s.ready = true
	_ = s.c.out.WriteJSON(ResponseMessage{Type: "file_status", SessionID: s.id, Payload: map[string]interface{}{
		"status": "ready",
		"root":   s.canon,
		"user":   user,
		"uid":    uid,
	}})
	for {
		select {
		case <-s.stop:
			return
		case t := <-s.tasks:
			if err := s.do(t); err != nil {
				if s.stopped() {
					return
				}
				log.Printf("file %s helper failed; ending session", s.id)
				fileStatusError(s.c.out, s.id, "internal")
				s.end("internal")
				return
			}
		}
	}
}

// checkSessionRoot refuses, for any session but file_root, a root that
// would widen it to the whole host or reach the agent's own secrets: "/"
// (also "~" for an account whose home is unset or "/"), or a root that
// contains the agent's state directory (its identity seed, upload records
// and recordings). The state directory is compared as given and with its
// symlinks resolved; the root itself can hold no symlink (§5.3).
func checkSessionRoot(action, root, home, stateDir string) string {
	if action == "file_root" {
		return ""
	}
	eff := root
	if root == "~" {
		eff = home
	}
	if eff == "" {
		return "root_denied"
	}
	eff = filepath.Clean(eff)
	if eff == "/" {
		return "root_denied"
	}
	if stateDir == "" {
		return ""
	}
	dirs := []string{filepath.Clean(stateDir)}
	if abs, err := filepath.Abs(stateDir); err == nil {
		dirs = append(dirs, abs)
		if real, err := filepath.EvalSymlinks(abs); err == nil {
			dirs = append(dirs, real)
		}
	}
	for _, d := range dirs {
		if d == eff || strings.HasPrefix(d, eff+"/") {
			return "root_denied"
		}
	}
	return ""
}

func (s *fileSession) start() (string, int64, string) {
	id, code := resolveFileIdentity(s.action, s.actor, ptyCfg, agentEUID())
	if code != "" {
		return "", 0, code
	}
	if code := checkSessionRoot(s.action, s.root, id.home, s.c.stateDir); code != "" {
		log.Printf("file %s refused: the root is / or holds the agent state directory", s.id)
		return "", 0, code
	}
	cmd, err := startFileHelperProc(id)
	if err != nil {
		if errors.Is(err, errFileUnsupported) {
			return "", 0, "agent_unsupported"
		}
		return "", 0, "internal"
	}
	in, err := cmd.StdinPipe()
	if err != nil {
		return "", 0, "internal"
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		return "", 0, "internal"
	}
	s.mu.Lock()
	if s.ended {
		s.mu.Unlock()
		return "", 0, "internal"
	}
	if err := cmd.Start(); err != nil {
		s.mu.Unlock()
		log.Printf("file %s: helper did not start", s.id)
		return "", 0, "internal"
	}
	s.cmd = cmd
	s.mu.Unlock()
	s.in, s.inBuf, s.outBuf = in, bufio.NewWriterSize(in, 64*1024), bufio.NewReaderSize(out, 64*1024)
	resp, err := s.call(fileReq{Op: "init", Root: s.root, Home: id.home, FileMax: s.fileMax}, nil, nil)
	if err != nil {
		return "", 0, "internal"
	}
	if resp.Error != "" {
		switch resp.Error {
		case "root_invalid", "agent_unsupported":
			return "", 0, resp.Error
		}
		return "", 0, "internal"
	}
	canon, _ := resp.Fields["root"].(string)
	uidNum, _ := resp.Fields["uid"].(json.Number)
	uid, err := uidNum.Int64()
	if canon == "" || err != nil || (s.root != "~" && canon != s.root) {
		return "", 0, "internal"
	}
	s.canon = canon
	return id.name, uid, ""
}

// call sends one request (and its chunk data) to the helper and reads
// frames until its answer. Binary frames before the answer go to onData.
func (s *fileSession) call(req fileReq, data []byte, onData func([]byte) error) (fileResp, error) {
	var resp fileResp
	if err := writeHelperJSON(s.inBuf, req); err != nil {
		return resp, err
	}
	if data != nil {
		if err := writeHelperFrame(s.inBuf, frameBinary, data); err != nil {
			return resp, err
		}
	}
	if err := s.inBuf.Flush(); err != nil {
		return resp, err
	}
	for {
		kind, payload, err := readHelperFrame(s.outBuf)
		if err != nil {
			return resp, err
		}
		if kind == frameBinary {
			if onData == nil {
				return resp, errors.New("unexpected_data")
			}
			if err := onData(payload); err != nil {
				return resp, err
			}
			continue
		}
		dec := json.NewDecoder(bytes.NewReader(payload))
		dec.UseNumber() // mtime_ns stays exact
		if err := dec.Decode(&resp); err != nil {
			return resp, err
		}
		return resp, nil
	}
}

func (s *fileSession) result(reqID, op, code string, fields map[string]interface{}) {
	m := map[string]interface{}{"type": "file_result", "session_id": s.id, "request_id": reqID, "op": op}
	if code == "" {
		for k, v := range fields {
			m[k] = v
		}
		m["status"], m["error"] = "ok", nil
	} else {
		m["status"], m["error"] = "error", code
	}
	m["type"], m["session_id"], m["request_id"], m["op"] = "file_result", s.id, reqID, op
	_ = s.c.out.WriteJSON(m)
}

// do runs one task. An error means the helper is gone.
func (s *fileSession) do(t fileTask) error {
	if t.chunk != nil {
		return s.doChunk(t.chunk)
	}
	req := *t.req
	switch req.Op {
	case "write_release":
		return s.releaseWrite()
	case "write_discard":
		return s.discardWrite()
	}
	s.ops++
	switch {
	case t.bad:
		s.result(req.RequestID, req.Op, "bad_request", nil)
		return nil
	case !fileKnownOps[req.Op] || req.Op == "write_chunk":
		s.result(req.RequestID, req.Op, "bad_request", nil)
		return nil
	case fileMutatingOps[req.Op] && s.mode != "write":
		s.result(req.RequestID, req.Op, "read_only", nil)
		return nil
	case req.Op == "write_open":
		return s.doWriteOpen(req)
	case req.Op == "write_commit" || req.Op == "write_abort":
		return s.doWriteEnd(req)
	case req.Op == "read":
		resp, err := s.call(req, nil, func(p []byte) error {
			if err := s.c.mux.Write(s.id, p); err != nil {
				return err
			}
			s.bytesRead += int64(len(p))
			return nil
		})
		if err != nil {
			return err
		}
		if err := s.c.mux.Flush(s.id); err != nil {
			return err
		}
		s.result(req.RequestID, req.Op, resp.Error, resp.Fields)
		return nil
	}
	resp, err := s.call(req, nil, nil)
	if err != nil {
		return err
	}
	s.result(req.RequestID, req.Op, resp.Error, resp.Fields)
	return nil
}

func (s *fileSession) doWriteOpen(req fileReq) error {
	if s.write != nil {
		s.result(req.RequestID, req.Op, "bad_request", nil)
		return nil
	}
	newID, err := newUploadID()
	if err != nil {
		s.result(req.RequestID, req.Op, "io_error", nil)
		return nil
	}
	claimUpload(newID)
	if s.c.stateDir != "" {
		mu := uploadCapLock(s.actor, s.canon)
		mu.Lock()
		defer mu.Unlock()
	}
	var prior *uploadRecord
	if req.Resume != nil && *req.Resume && req.Size != nil && s.c.stateDir != "" {
		prior = findUpload(s.c.stateDir, s.actor, s.canon, req.Path, *req.Size, req.SHA256, time.Now())
	}
	// A new upload past the per-actor, per-root cap is refused: interrupted
	// uploads must be resumed, aborted or left to expire first.
	if prior == nil && s.c.stateDir != "" && countUploads(s.c.stateDir, s.actor, s.canon, time.Now()) >= uploadsPerActorRoot {
		unclaimUpload(newID)
		log.Printf("file %s: upload cap reached for this actor and root", s.id)
		s.result(req.RequestID, req.Op, "no_space", nil)
		return nil
	}
	req.UploadID = newID
	if prior != nil {
		req.ResumeID = prior.UploadID
	}
	resp, err := s.call(req, nil, nil)
	if err != nil {
		unclaimUpload(newID)
		if prior != nil {
			unclaimUpload(prior.UploadID)
		}
		return err
	}
	if resp.Error != "" {
		unclaimUpload(newID)
		if prior != nil {
			unclaimUpload(prior.UploadID)
		}
		s.result(req.RequestID, req.Op, resp.Error, nil)
		return nil
	}
	used, _ := resp.Fields["upload_id"].(string)
	if prior != nil && used == prior.UploadID {
		unclaimUpload(newID)
	} else {
		if prior != nil {
			// The helper could not reopen the prior temp file (gone,
			// replaced, or not a regular file), so this is a new upload: the
			// stale record goes first, then the cap applies as to any other.
			// A temp file that cannot be removed keeps its record, which
			// then still counts.
			if err := removeUploadTemp(prior.Root, prior.Path, prior.UploadID); err == nil {
				deleteUpload(s.c.stateDir, prior.UploadID)
			} else {
				log.Printf("file %s: stale upload temp not removed: %v", s.id, err)
			}
			unclaimUpload(prior.UploadID)
		}
		used = newID
		if prior != nil && s.c.stateDir != "" && countUploads(s.c.stateDir, s.actor, s.canon, time.Now()) >= uploadsPerActorRoot {
			log.Printf("file %s: upload cap reached for this actor and root", s.id)
			if _, err := s.call(fileReq{Op: "write_abort"}, nil, nil); err != nil {
				unclaimUpload(newID)
				return err
			}
			unclaimUpload(newID)
			s.result(req.RequestID, req.Op, "no_space", nil)
			return nil
		}
		if s.c.stateDir != "" && req.Size != nil {
			rec := uploadRecord{UploadID: newID, ActorKey: actorKey(s.actor), Root: s.canon, Path: req.Path,
				Size: *req.Size, SHA256: req.SHA256, CreatedUnix: time.Now().Unix()}
			if err := saveUpload(s.c.stateDir, rec); err != nil {
				log.Printf("file %s: upload record not saved; aborting the write", s.id)
				if _, err := s.call(fileReq{Op: "write_abort"}, nil, nil); err != nil {
					unclaimUpload(newID)
					return err
				}
				unclaimUpload(newID)
				s.result(req.RequestID, req.Op, "io_error", nil)
				return nil
			}
		}
	}
	s.write = &agentWrite{reqID: req.RequestID, uploadID: used}
	s.result(req.RequestID, req.Op, "", resp.Fields)
	return nil
}

func (s *fileSession) doWriteEnd(req fileReq) error {
	w := s.write
	if w == nil || w.reqID != req.RequestID {
		s.result(req.RequestID, req.Op, "upload_not_found", nil)
		return nil
	}
	resp, err := s.call(fileReq{Op: req.Op}, nil, nil)
	s.write = nil
	if err != nil {
		unclaimUpload(w.uploadID)
		return err
	}
	// A committed, aborted, hash-mismatched or early-committed
	// (offset_mismatch) upload is gone; any other commit failure keeps the
	// temp file and its record for resume.
	if resp.Error == "" || resp.Error == "sha256_mismatch" || resp.Error == "offset_mismatch" || req.Op == "write_abort" {
		deleteUpload(s.c.stateDir, w.uploadID)
	}
	unclaimUpload(w.uploadID)
	s.result(req.RequestID, req.Op, resp.Error, resp.Fields)
	return nil
}

func (s *fileSession) doChunk(ch *fileChunkIn) error {
	defer func() { _ = s.c.mux.Drained(s.id, ch.length) }()
	w := s.write
	if w == nil || w.reqID != ch.reqID {
		// In flight when the write ended; the server discards it too.
		return nil
	}
	off := ch.offset
	resp, err := s.call(fileReq{Op: "write_chunk", Offset: &off}, ch.buf, nil)
	if err != nil {
		return err
	}
	if resp.Error != "" {
		s.result(ch.reqID, "write_chunk", resp.Error, nil)
		if clientWriteFault(resp.Error) {
			return s.discardWrite()
		}
		return s.releaseWrite()
	}
	s.bytesWritten += int64(ch.length)
	_ = s.c.out.WriteJSON(map[string]interface{}{
		"type": "file_write_ack", "session_id": s.id, "request_id": ch.reqID, "offset": resp.Fields["offset"],
	})
	return nil
}

// clientWriteFault reports a chunk failure caused by what the client sent
// (a wrong offset, data past the declared size, a malformed chunk): such an
// upload cannot be resumed usefully, so it is discarded, not kept.
func clientWriteFault(code string) bool {
	return code == "offset_mismatch" || code == "too_large" || code == "bad_request"
}

// discardWrite closes the open write and deletes its temp file and record.
func (s *fileSession) discardWrite() error {
	w := s.write
	if w == nil {
		return nil
	}
	s.write = nil
	_, err := s.call(fileReq{Op: "write_discard"}, nil, nil)
	if err == nil {
		deleteUpload(s.c.stateDir, w.uploadID)
	}
	unclaimUpload(w.uploadID)
	return err
}

// releaseWrite closes the open write and keeps its temp file for resume.
func (s *fileSession) releaseWrite() error {
	w := s.write
	if w == nil {
		return nil
	}
	s.write = nil
	unclaimUpload(w.uploadID)
	_, err := s.call(fileReq{Op: "write_release"}, nil, nil)
	return err
}

// exit runs when the worker returns: the helper is told to finish (it
// releases an open write), killed after a grace period, and file_closed
// reports the session's counts.
func (s *fileSession) exit() {
	s.end("stopped")
	if s.write != nil {
		unclaimUpload(s.write.uploadID)
		s.write = nil
	}
	if s.in != nil {
		_ = s.in.Close()
	}
	s.mu.Lock()
	cmd := s.cmd
	reason := s.reason
	s.mu.Unlock()
	if cmd != nil {
		waited := make(chan struct{})
		go func() {
			_ = cmd.Wait()
			close(waited)
		}()
		select {
		case <-waited:
		case <-time.After(fileHelperGrace):
			_ = cmd.Process.Kill()
			<-waited
		}
	}
	close(s.done)
	s.c.mux.Close(s.id)
	s.c.mu.Lock()
	if s.c.files[s.id] == s {
		delete(s.c.files, s.id)
	}
	s.c.mu.Unlock()
	if !s.ready {
		return
	}
	log.Printf("file %s closed: %s ops=%d", s.id, reason, s.ops)
	_ = s.c.out.WriteJSON(ResponseMessage{Type: "file_closed", SessionID: s.id, Payload: map[string]interface{}{
		"reason":        reason,
		"ops":           s.ops,
		"bytes_read":    s.bytesRead,
		"bytes_written": s.bytesWritten,
	}})
}
