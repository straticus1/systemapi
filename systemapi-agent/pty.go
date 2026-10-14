// Threats: a terminal that outlives its lease, one session reading or
// writing another session's PTY, a root shell opened with an operator lease,
// an unrecorded shell, a shell that reads the agent's credentials, one stuck
// session freezing the agent, and processes a shell leaves behind. Each
// session is keyed by a server-generated session id and needs a signed lease
// bound to that id, its deadline and its phase (start or renew); it ends at
// the deadline or when the last renewed lease expires, whichever is first.
// Action "pty" runs as --pty-user with uid, gid and supplementary groups
// dropped, and only on a root agent; a non-root agent refuses unless
// --pty-allow-agent-user is set, because the shell would then run as the
// agent's own user and could read its key and state. "pty_root" is a
// separate lease action. The agent records every input and output byte in an
// HMAC-chained file (recorder.go) unless --pty-record=false. Each session has
// its own bounded input queue and writer goroutine; an overflow ends that
// session only. Ending a session signals its process group and, on Linux,
// every process in its session. Does NOT contain a process that starts a new
// session of its own (tmux, setsid, a double fork); that needs cgroups.
package main

import (
	"encoding/base64"
	"errors"
	"log"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"sync"
	"time"

	"github.com/creack/pty"
	"github.com/gorilla/websocket"
)

const (
	scriptMaxBytes   = 64 * 1024
	ptyMaxSessions   = 32
	ptyReservedSlots = 4 // kept free for breakglass and pty_root
	ptyMaxDeadline   = 7*24*time.Hour + time.Minute
	ptyDrainTimeout  = 2 * time.Second
	ptyKillGrace     = 500 * time.Millisecond
	ptyDefaultRows   = 24
	ptyDefaultCols   = 80
	ptyRootRecordDir = "/var/lib/systemapi/recordings"

	recordingAgent     = "agent"
	recordingUserOwned = "user_owned"
	recordingOff       = "off"
)

var (
	sessionIDRe = regexp.MustCompile(`^pts_[A-Za-z0-9_-]{16,64}$`)

	// inputQueueMax caps bytes waiting to be written to one PTY.
	inputQueueMax = 1024 * 1024

	privilegedGroupNames = map[string]bool{
		"root": true, "wheel": true, "sudo": true, "admin": true, "adm": true,
		"docker": true, "lxd": true, "disk": true, "shadow": true,
	}
)

// ptyOut is the agent's write side of the control-plane socket. It must be
// safe for concurrent use: every session writes from its own goroutines.
type ptyOut interface {
	WriteJSON(v interface{}) error
	WriteBinary(b []byte) error
}

// wsWriter serializes writes to one gorilla connection, which allows only
// one concurrent writer.
type wsWriter struct {
	mu sync.Mutex
	c  *websocket.Conn
}

func (w *wsWriter) WriteJSON(v interface{}) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.c.WriteJSON(v)
}

func (w *wsWriter) WriteBinary(b []byte) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.c.WriteMessage(websocket.BinaryMessage, b)
}

func (w *wsWriter) WriteClose() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.c.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
}

// ptySettings come from agent flags. Shell is not a flag; empty means the
// user's passwd shell.
type ptySettings struct {
	User           string
	AllowAgentUser bool
	Record         bool
	RecordDir      string
	Shell          string
}

var (
	ptyCfg    = ptySettings{Record: true}
	agentEUID = os.Geteuid

	ptyMu       sync.Mutex
	ptySessions = map[string]*ptySession{}
)

type ptySession struct {
	id       string
	action   string
	deadline time.Time
	out      ptyOut
	ptmx     *os.File
	cmd      *exec.Cmd
	rec      *recorder

	inCh chan []byte

	mu        sync.Mutex
	leaseExp  time.Time
	timer     *time.Timer
	reason    string
	recordErr string
	ending    bool
	inQueued  int
	inClosed  bool
}

type ptyStartRequest struct {
	SessionID    string
	Action       string
	Rows         int
	Cols         int
	DeadlineUnix int64
	Lease        *Lease
}

type ptyIdentity struct {
	name   string
	uid    uint32
	gid    uint32
	groups []uint32
	home   string
	shell  string
	drop   bool
}

func loginShell() string {
	shell := "bash"
	if runtime.GOOS == "windows" {
		return "powershell.exe"
	}
	if runtime.GOOS == "darwin" {
		if _, err := os.Stat("/bin/zsh"); err == nil {
			return "zsh"
		}
	}
	return shell
}

// breakglassCommand resolves adssh and refuses to fall open to a login shell.
// It does not pass -r. Authorization is the control-plane lease.
func breakglassCommand() (string, []string, error) {
	path, err := exec.LookPath("adssh")
	if err != nil {
		return "", nil, errors.New("adssh_missing")
	}
	return path, nil, nil
}

func writeBreakglassPolicy(dir string) (string, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return "", err
	}
	path := filepath.Join(dir, "breakglass.rego")
	body := []byte("package adssh.authz\n\ndefault allow = true\n")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		return "", err
	}
	return path, nil
}

func ptyStatusError(out ptyOut, sessionID, code string) {
	_ = out.WriteJSON(ResponseMessage{Type: "pty_status", SessionID: sessionID, Payload: map[string]string{"error": code}})
}

func lookupSession(id string) *ptySession {
	ptyMu.Lock()
	defer ptyMu.Unlock()
	return ptySessions[id]
}

func passwdShell(name string) string {
	data, err := os.ReadFile("/etc/passwd")
	if err != nil {
		return ""
	}
	rows, err := parsePasswd(string(data))
	if err != nil {
		return ""
	}
	for _, row := range rows {
		if row["name"] == name && filepath.IsAbs(row["shell"]) {
			return row["shell"]
		}
	}
	return ""
}

func identityFromUser(u *user.User, drop bool) (*ptyIdentity, error) {
	uid, err := strconv.ParseUint(u.Uid, 10, 32)
	if err != nil {
		return nil, err
	}
	gid, err := strconv.ParseUint(u.Gid, 10, 32)
	if err != nil {
		return nil, err
	}
	id := &ptyIdentity{name: u.Username, uid: uint32(uid), gid: uint32(gid), home: u.HomeDir, drop: drop}
	gids, err := u.GroupIds()
	if err != nil && drop {
		return nil, err
	}
	for _, g := range gids {
		n, err := strconv.ParseUint(g, 10, 32)
		if err != nil {
			return nil, err
		}
		id.groups = append(id.groups, uint32(n))
	}
	id.shell = passwdShell(u.Username)
	if ptyCfg.Shell != "" {
		id.shell = ptyCfg.Shell
	}
	if id.shell == "" {
		id.shell = loginShell()
	}
	if id.home == "" {
		id.home = "/"
	}
	return id, nil
}

// privilegedGroups returns the names in names that grant root-equivalent
// or broad host access.
func privilegedGroups(names []string) []string {
	out := []string{}
	for _, n := range names {
		if privilegedGroupNames[n] {
			out = append(out, n)
		}
	}
	return out
}

func groupNames(id *ptyIdentity) []string {
	seen := map[uint32]bool{}
	var names []string
	for _, g := range append([]uint32{id.gid}, id.groups...) {
		if seen[g] {
			continue
		}
		seen[g] = true
		if grp, err := user.LookupGroupId(strconv.FormatUint(uint64(g), 10)); err == nil {
			names = append(names, grp.Name)
		}
	}
	return names
}

// resolvePTYIdentity picks the account a session runs as, or returns a
// contract error code.
func resolvePTYIdentity(action string, cfg ptySettings, euid int) (*ptyIdentity, string) {
	switch action {
	case "pty":
		if euid == 0 {
			if cfg.User == "" {
				return nil, "pty_user_unset"
			}
			u, err := user.Lookup(cfg.User)
			if err != nil {
				log.Printf("pty user lookup failed")
				return nil, "pty_start_failed"
			}
			if u.Uid == "0" {
				log.Printf("pty user must not be root; use terminal:root")
				return nil, "pty_start_failed"
			}
			id, err := identityFromUser(u, true)
			if err != nil {
				return nil, "pty_start_failed"
			}
			return id, ""
		}
		if !cfg.AllowAgentUser {
			log.Printf("terminal:open refused: the agent is not root and --pty-allow-agent-user is not set")
			return nil, "pty_start_failed"
		}
		u, err := user.Current()
		if err != nil {
			return nil, "pty_start_failed"
		}
		if cfg.User != "" && cfg.User != u.Username {
			log.Printf("pty user differs from the agent user and the agent is not root")
			return nil, "pty_start_failed"
		}
		id, err := identityFromUser(u, false)
		if err != nil {
			return nil, "pty_start_failed"
		}
		return id, ""
	case "pty_root":
		if euid != 0 {
			log.Printf("terminal:root needs an agent running as root")
			return nil, "pty_start_failed"
		}
		u, err := user.LookupId("0")
		if err != nil {
			return nil, "pty_start_failed"
		}
		id, err := identityFromUser(u, false)
		if err != nil {
			return nil, "pty_start_failed"
		}
		return id, ""
	case "breakglass":
		u, err := user.Current()
		if err != nil {
			return nil, "pty_start_failed"
		}
		id, err := identityFromUser(u, false)
		if err != nil {
			return nil, "pty_start_failed"
		}
		return id, ""
	}
	return nil, "pty_start_failed"
}

func recordDir(cfg ptySettings, stateDir string, euid int) string {
	if cfg.RecordDir != "" {
		return cfg.RecordDir
	}
	if euid == 0 {
		return ptyRootRecordDir
	}
	return filepath.Join(stateDir, "recordings")
}

// recordingMode is "agent" when only the root agent can write the record,
// "user_owned" when the shell runs as the agent's own user, else "off".
func recordingMode(cfg ptySettings, euid int) string {
	if !cfg.Record {
		return recordingOff
	}
	if euid == 0 {
		return recordingAgent
	}
	return recordingUserOwned
}

func sessionEnv(id *ptyIdentity, extra []string) []string {
	path := os.Getenv("PATH")
	if path == "" {
		path = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
	}
	env := []string{
		"PATH=" + path,
		"TERM=xterm-256color",
		"HOME=" + id.home,
		"USER=" + id.name,
		"LOGNAME=" + id.name,
		"SHELL=" + id.shell,
	}
	if lang := os.Getenv("LANG"); lang != "" {
		env = append(env, "LANG="+lang)
	}
	return stripChildEnv(append(env, extra...), nil)
}

func clampSize(n, fallback int) uint16 {
	if n == 0 {
		return uint16(fallback)
	}
	return uint16(n)
}

// slotFree reports whether a new session of this action fits. The last
// ptyReservedSlots slots are kept for breakglass and pty_root.
func slotFree(action string) bool {
	ptyMu.Lock()
	n := len(ptySessions)
	ptyMu.Unlock()
	if n >= ptyMaxSessions {
		return false
	}
	if action == "pty" && n >= ptyMaxSessions-ptyReservedSlots {
		return false
	}
	return true
}

// startPTYSession authorizes and starts one session. Every refusal is a
// pty_status error with a contract code.
func startPTYSession(out ptyOut, hostID, stateDir string, req ptyStartRequest, now time.Time) {
	sid := req.SessionID
	if !sessionIDRe.MatchString(sid) {
		log.Printf("pty_start refused: bad session id")
		ptyStatusError(out, "", "pty_start_failed")
		return
	}
	if !terminalAction(req.Action) {
		ptyStatusError(out, sid, "pty_start_failed")
		return
	}
	if req.Rows < 0 || req.Rows > 1000 || req.Cols < 0 || req.Cols > 1000 {
		ptyStatusError(out, sid, "pty_start_failed")
		return
	}
	deadline := time.Unix(req.DeadlineUnix, 0)
	if !deadline.After(now) || deadline.Sub(now) > ptyMaxDeadline {
		ptyStatusError(out, sid, "lease_required")
		return
	}
	if err := authorizeCommand(hostID, req.Action, terminalPayload(sid, req.DeadlineUnix, "start"), req.Lease, now); err != nil {
		log.Printf("pty refused: %s", err.Error())
		ptyStatusError(out, sid, "lease_required")
		return
	}
	if lookupSession(sid) != nil || !slotFree(req.Action) {
		log.Printf("pty refused: duplicate session or no free slot")
		ptyStatusError(out, sid, "pty_start_failed")
		return
	}

	euid := agentEUID()
	id, code := resolvePTYIdentity(req.Action, ptyCfg, euid)
	if code != "" {
		ptyStatusError(out, sid, code)
		return
	}
	privileged := privilegedGroups(groupNames(id))
	if len(privileged) > 0 {
		log.Printf("WARNING: pty user %s is in privileged groups %v", id.name, privileged)
	}

	argv0 := id.shell
	env := sessionEnv(id, nil)
	if req.Action == "breakglass" {
		path, _, err := breakglassCommand()
		if err != nil {
			ptyStatusError(out, sid, "recording_unavailable")
			return
		}
		policy, err := writeBreakglassPolicy(stateDir)
		if err != nil {
			ptyStatusError(out, sid, "pty_start_failed")
			return
		}
		argv0 = path
		env = sessionEnv(id, []string{
			"ADSSH_POLICY=" + policy,
			"ADSSH_AUDIT_LOG=" + filepath.Join(stateDir, "breakglass-audit.log"),
		})
	}

	leaseExp := time.Unix(req.Lease.ExpiresUnix, 0)
	if leaseExp.After(deadline) {
		leaseExp = deadline
	}
	s := &ptySession{
		id:       sid,
		action:   req.Action,
		deadline: deadline,
		out:      out,
		leaseExp: leaseExp,
		inCh:     make(chan []byte, 4096),
	}

	mode := recordingMode(ptyCfg, euid)
	if mode != recordingOff {
		key, err := loadRecordingKey(stateDir)
		if err != nil {
			log.Printf("recording key unavailable: %v", err)
			ptyStatusError(out, sid, "recording_unavailable")
			return
		}
		rec, err := openRecorder(recordDir(ptyCfg, stateDir, euid), sid, key, map[string]interface{}{
			"session_id": sid,
			"host_id":    hostID,
			"action":     req.Action,
			"pty_user":   id.name,
			"deadline":   req.DeadlineUnix,
		}, func() { s.failRecording() })
		if err != nil {
			log.Printf("recording unavailable: %v", err)
			ptyStatusError(out, sid, "recording_unavailable")
			return
		}
		s.rec = rec
	}

	cmd := exec.Command(argv0)
	cmd.Env = env
	cmd.Dir = id.home
	if st, err := os.Stat(id.home); err != nil || !st.IsDir() {
		cmd.Dir = "/"
	}
	ptmx, err := startWithIdentity(cmd, id, &pty.Winsize{Rows: clampSize(req.Rows, ptyDefaultRows), Cols: clampSize(req.Cols, ptyDefaultCols)})
	if err != nil {
		log.Printf("Failed to start PTY: %v", err)
		if s.rec != nil {
			_, _ = s.rec.finish(map[string]interface{}{"reason": "start_failed"})
		}
		ptyStatusError(out, sid, "pty_start_failed")
		return
	}
	s.cmd = cmd
	s.ptmx = ptmx

	ptyMu.Lock()
	ptySessions[sid] = s
	ptyMu.Unlock()

	s.mu.Lock()
	s.timer = time.AfterFunc(time.Until(leaseExp), s.onTimer)
	s.mu.Unlock()

	_ = out.WriteJSON(ResponseMessage{Type: "pty_status", SessionID: sid, Payload: map[string]interface{}{
		"status":                     "started",
		"session_id":                 sid,
		"pty_user":                   id.name,
		"recording":                  mode,
		"pty_user_privileged_groups": privileged,
	}})

	go s.inputLoop()

	readerDone := make(chan struct{})
	go func() {
		defer close(readerDone)
		buf := make([]byte, 32*1024)
		for {
			n, err := ptmx.Read(buf)
			if n > 0 {
				if s.rec != nil && !s.rec.add("o", buf[:n]) {
					return
				}
				frame := make([]byte, 0, 1+len(sid)+n)
				frame = append(frame, byte(len(sid)))
				frame = append(frame, sid...)
				frame = append(frame, buf[:n]...)
				_ = out.WriteBinary(frame)
			}
			if err != nil {
				return
			}
		}
	}()

	go func() {
		_ = cmd.Wait()
		code := -1
		if cmd.ProcessState != nil {
			code = cmd.ProcessState.ExitCode()
		}
		// Nothing the session started may outlive it.
		killTree(cmd.Process.Pid, ptyKillGrace)
		select {
		case <-readerDone:
		case <-time.After(ptyDrainTimeout):
		}
		_ = ptmx.Close()
		s.mu.Lock()
		if s.timer != nil {
			s.timer.Stop()
		}
		reason := s.reason
		recordErr := s.recordErr
		s.inClosed = true
		close(s.inCh)
		s.mu.Unlock()
		if reason == "" {
			reason = "exited"
		}
		payload := map[string]interface{}{
			"session_id": sid,
			"code":       code,
			"reason":     reason,
		}
		if s.rec != nil {
			sum, err := s.rec.finish(map[string]interface{}{"reason": reason, "code": code})
			payload["record"] = sum
			if err != nil && recordErr == "" {
				recordErr = "recording_failed"
			}
		}
		if recordErr != "" {
			payload["record_error"] = recordErr
		}
		ptyMu.Lock()
		if ptySessions[sid] == s {
			delete(ptySessions, sid)
		}
		ptyMu.Unlock()
		_ = out.WriteJSON(ResponseMessage{Type: "pty_exit", SessionID: sid, Payload: payload})
	}()
}

// inputLoop is the only writer to this session's PTY, so a shell that stops
// reading blocks this goroutine and nothing else.
func (s *ptySession) inputLoop() {
	for data := range s.inCh {
		if s.rec == nil || s.rec.add("i", data) {
			_, _ = s.ptmx.Write(data)
		}
		s.mu.Lock()
		s.inQueued -= len(data)
		s.mu.Unlock()
	}
}

// queueInput never blocks. Overflow ends this session only.
func (s *ptySession) queueInput(data []byte) {
	if len(data) == 0 {
		return
	}
	s.mu.Lock()
	if s.inClosed || s.ending {
		s.mu.Unlock()
		return
	}
	if s.inQueued+len(data) > inputQueueMax {
		s.mu.Unlock()
		log.Printf("pty %s input queue full; ending session", s.id)
		s.end("stopped")
		return
	}
	select {
	case s.inCh <- append([]byte(nil), data...):
		s.inQueued += len(data)
		s.mu.Unlock()
	default:
		s.mu.Unlock()
		log.Printf("pty %s input queue full; ending session", s.id)
		s.end("stopped")
	}
}

func (s *ptySession) failRecording() {
	s.mu.Lock()
	if s.recordErr == "" {
		s.recordErr = "recording_failed"
	}
	s.mu.Unlock()
	log.Printf("pty %s recording failed or fell behind; ending session", s.id)
	s.end("stopped")
}

// onTimer fires at the earlier of the lease expiry and the deadline.
func (s *ptySession) onTimer() {
	s.mu.Lock()
	now := time.Now()
	if !now.Before(s.deadline) {
		s.mu.Unlock()
		log.Printf("pty %s reached its deadline", s.id)
		s.end("max_duration")
		return
	}
	if now.Before(s.leaseExp) {
		s.timer.Reset(time.Until(s.leaseExp))
		s.mu.Unlock()
		return
	}
	s.mu.Unlock()
	log.Printf("pty %s lease expired", s.id)
	s.end("stopped")
}

// end stops the session once: SIGHUP to its process group and session, then
// SIGKILL after a short grace. The wait goroutine reports pty_exit.
func (s *ptySession) end(reason string) {
	s.mu.Lock()
	if s.ending {
		s.mu.Unlock()
		return
	}
	s.ending = true
	if s.reason == "" {
		s.reason = reason
	}
	if s.timer != nil {
		s.timer.Stop()
	}
	s.mu.Unlock()
	if s.cmd != nil && s.cmd.Process != nil {
		go killTree(s.cmd.Process.Pid, ptyKillGrace)
	}
}

// stopAllSessions ends every session with reason "stopped" and waits up to
// timeout for their pty_exit to be sent. The agent calls it on every exit.
func stopAllSessions(timeout time.Duration) {
	ptyMu.Lock()
	live := make([]*ptySession, 0, len(ptySessions))
	for _, s := range ptySessions {
		live = append(live, s)
	}
	ptyMu.Unlock()
	for _, s := range live {
		s.end("stopped")
	}
	end := time.Now().Add(timeout)
	for time.Now().Before(end) {
		ptyMu.Lock()
		n := len(ptySessions)
		ptyMu.Unlock()
		if n == 0 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// renewPTYSession verifies a renewal lease exactly like the start lease and
// extends the session up to its deadline.
func renewPTYSession(hostID, sessionID string, lease *Lease, now time.Time) error {
	s := lookupSession(sessionID)
	if s == nil {
		return errors.New("unknown_session")
	}
	if err := authorizeCommand(hostID, s.action, terminalPayload(s.id, s.deadline.Unix(), "renew"), lease, now); err != nil {
		return err
	}
	exp := time.Unix(lease.ExpiresUnix, 0)
	if exp.After(s.deadline) {
		exp = s.deadline
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ending {
		return errors.New("session_ended")
	}
	if exp.After(s.leaseExp) {
		s.leaseExp = exp
		if s.timer != nil {
			s.timer.Reset(time.Until(exp))
		}
	}
	return nil
}

func handlePTYInput(sessionID string, data []byte) {
	if s := lookupSession(sessionID); s != nil {
		s.queueInput(data)
	}
}

// handlePTYEOF sends the terminal EOF character. In canonical mode the shell
// reads it as end of input.
func handlePTYEOF(sessionID string) {
	handlePTYInput(sessionID, []byte{4})
}

func handlePTYResize(sessionID string, rows, cols int) {
	if rows < 1 || rows > 1000 || cols < 1 || cols > 1000 {
		return
	}
	s := lookupSession(sessionID)
	if s == nil {
		return
	}
	_ = pty.Setsize(s.ptmx, &pty.Winsize{Rows: uint16(rows), Cols: uint16(cols)})
}

func handlePTYStop(sessionID string) {
	if s := lookupSession(sessionID); s != nil {
		s.end("stopped")
	}
}

func decodePTYInput(dataB64, legacy string) ([]byte, error) {
	if dataB64 != "" {
		return base64.StdEncoding.DecodeString(dataB64)
	}
	return []byte(legacy), nil
}
