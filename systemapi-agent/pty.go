// Threats: a terminal that outlives its lease, one session reading or
// writing another session's PTY, a root shell opened with an operator lease,
// an unrecorded shell, and the agent's own credentials leaking into the
// child. Each session is keyed by a server-generated session id and needs a
// signed lease bound to that id and its deadline; it ends at the deadline or
// when the last renewed lease expires, whichever is first. Action "pty" runs
// as --pty-user with uid, gid and supplementary groups dropped; a root agent
// with no --pty-user refuses (pty_user_unset). Action "pty_root" is a
// separate lease action. Recording runs the session under adssh; a missing
// adssh refuses (recording_unavailable) and never falls back to a bare shell.
// Does NOT stop a dropped user from editing their own adssh audit log: the
// log lives in a per-user directory that user owns. The control plane's audit
// chain records start and end independently.
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
	"syscall"
	"time"

	"github.com/creack/pty"
	"github.com/gorilla/websocket"
)

const (
	scriptMaxBytes   = 64 * 1024
	ptyMaxSessions   = 32
	ptyMaxDeadline   = 7*24*time.Hour + time.Minute
	ptyDrainTimeout  = 2 * time.Second
	ptyDefaultRows   = 24
	ptyDefaultCols   = 80
	ptyRootRecordDir = "/var/lib/systemapi-agent/pty"
)

var sessionIDRe = regexp.MustCompile(`^pts_[A-Za-z0-9_-]{16,64}$`)

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
	User      string
	Record    bool
	RecordDir string
	Shell     string
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
	payload  string
	deadline time.Time
	out      ptyOut
	ptmx     *os.File
	cmd      *exec.Cmd

	writeMu sync.Mutex

	mu       sync.Mutex
	leaseExp time.Time
	timer    *time.Timer
	reason   string
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
	if drop {
		gids, err := u.GroupIds()
		if err != nil {
			return nil, err
		}
		for _, g := range gids {
			n, err := strconv.ParseUint(g, 10, 32)
			if err != nil {
				return nil, err
			}
			id.groups = append(id.groups, uint32(n))
		}
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
	return filepath.Join(stateDir, "pty")
}

// prepareRecording lays out <dir>/terminal.rego (agent-owned, mode 0644) and
// <dir>/<user>/ (owned by the session user, mode 0700) for the adssh audit
// log. The agent never writes inside the user's directory.
func prepareRecording(dir string, id *ptyIdentity, euid int) (policy, auditLog string, err error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", "", err
	}
	if err := checkRealDir(dir, uint32(euid)); err != nil {
		return "", "", err
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		return "", "", err
	}
	tmp, err := os.CreateTemp(dir, ".terminal-*.rego")
	if err != nil {
		return "", "", err
	}
	_, werr := tmp.WriteString("package adssh.authz\n\ndefault allow = true\n")
	cerr := tmp.Close()
	if werr != nil || cerr != nil {
		_ = os.Remove(tmp.Name())
		return "", "", errors.New("policy_write_failed")
	}
	policy = filepath.Join(dir, "terminal.rego")
	if err := os.Chmod(tmp.Name(), 0o644); err != nil {
		_ = os.Remove(tmp.Name())
		return "", "", err
	}
	if err := os.Rename(tmp.Name(), policy); err != nil {
		_ = os.Remove(tmp.Name())
		return "", "", err
	}
	userDir := filepath.Join(dir, id.name)
	if err := os.Mkdir(userDir, 0o700); err != nil && !os.IsExist(err) {
		return "", "", err
	}
	if id.drop {
		if err := os.Lchown(userDir, int(id.uid), int(id.gid)); err != nil {
			return "", "", err
		}
	}
	if err := checkRealDir(userDir, id.uid); err != nil {
		return "", "", err
	}
	if err := os.Chmod(userDir, 0o700); err != nil {
		return "", "", err
	}
	return policy, filepath.Join(userDir, "audit.log"), nil
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
	payload := terminalPayload(sid, req.DeadlineUnix)
	if err := authorizeCommand(hostID, req.Action, payload, req.Lease, now); err != nil {
		log.Printf("pty refused: %s", err.Error())
		ptyStatusError(out, sid, "lease_required")
		return
	}

	id, code := resolvePTYIdentity(req.Action, ptyCfg, agentEUID())
	if code != "" {
		ptyStatusError(out, sid, code)
		return
	}

	var argv0 string
	var env []string
	recording := true
	switch {
	case req.Action == "breakglass":
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
		env = stripChildEnv(os.Environ(), []string{
			"TERM=xterm-256color",
			"ADSSH_POLICY=" + policy,
			"ADSSH_AUDIT_LOG=" + filepath.Join(stateDir, "breakglass-audit.log"),
		})
	case ptyCfg.Record:
		path, _, err := breakglassCommand()
		if err != nil {
			ptyStatusError(out, sid, "recording_unavailable")
			return
		}
		policy, auditLog, err := prepareRecording(recordDir(ptyCfg, stateDir, agentEUID()), id, agentEUID())
		if err != nil {
			log.Printf("recording setup failed: %v", err)
			ptyStatusError(out, sid, "recording_unavailable")
			return
		}
		argv0 = path
		env = sessionEnv(id, []string{"ADSSH_POLICY=" + policy, "ADSSH_AUDIT_LOG=" + auditLog})
	default:
		recording = false
		argv0 = id.shell
		env = sessionEnv(id, nil)
	}

	ptyMu.Lock()
	_, dup := ptySessions[sid]
	full := len(ptySessions) >= ptyMaxSessions
	ptyMu.Unlock()
	if dup || full {
		ptyStatusError(out, sid, "pty_start_failed")
		return
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
		ptyStatusError(out, sid, "pty_start_failed")
		return
	}

	leaseExp := time.Unix(req.Lease.ExpiresUnix, 0)
	if leaseExp.After(deadline) {
		leaseExp = deadline
	}
	s := &ptySession{
		id:       sid,
		action:   req.Action,
		payload:  payload,
		deadline: deadline,
		out:      out,
		ptmx:     ptmx,
		cmd:      cmd,
		leaseExp: leaseExp,
	}
	ptyMu.Lock()
	if _, dup := ptySessions[sid]; dup {
		ptyMu.Unlock()
		_ = cmd.Process.Kill()
		_ = ptmx.Close()
		ptyStatusError(out, sid, "pty_start_failed")
		return
	}
	ptySessions[sid] = s
	ptyMu.Unlock()

	s.mu.Lock()
	s.timer = time.AfterFunc(time.Until(leaseExp), s.onTimer)
	s.mu.Unlock()

	_ = out.WriteJSON(ResponseMessage{Type: "pty_status", SessionID: sid, Payload: map[string]interface{}{
		"status":     "started",
		"session_id": sid,
		"pty_user":   id.name,
		"recording":  recording,
	}})

	readerDone := make(chan struct{})
	go func() {
		defer close(readerDone)
		buf := make([]byte, 32*1024)
		for {
			n, err := ptmx.Read(buf)
			if n > 0 {
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
		s.mu.Unlock()
		if reason == "" {
			reason = "exited"
		}
		ptyMu.Lock()
		if ptySessions[sid] == s {
			delete(ptySessions, sid)
		}
		ptyMu.Unlock()
		_ = out.WriteJSON(ResponseMessage{Type: "pty_exit", SessionID: sid, Payload: map[string]interface{}{
			"session_id": sid,
			"code":       code,
			"reason":     reason,
		}})
	}()
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

// end kills the shell once. The wait goroutine reports pty_exit.
func (s *ptySession) end(reason string) {
	s.mu.Lock()
	if s.reason == "" {
		s.reason = reason
	}
	if s.timer != nil {
		s.timer.Stop()
	}
	s.mu.Unlock()
	if s.cmd != nil && s.cmd.Process != nil {
		_ = s.cmd.Process.Signal(syscall.SIGKILL)
	}
	if s.ptmx != nil {
		_ = s.ptmx.Close()
	}
}

// renewPTYSession verifies a renewal lease exactly like the start lease and
// extends the session up to its deadline.
func renewPTYSession(hostID, sessionID string, lease *Lease, now time.Time) error {
	s := lookupSession(sessionID)
	if s == nil {
		return errors.New("unknown_session")
	}
	if err := authorizeCommand(hostID, s.action, s.payload, lease, now); err != nil {
		return err
	}
	exp := time.Unix(lease.ExpiresUnix, 0)
	if exp.After(s.deadline) {
		exp = s.deadline
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.reason != "" {
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
	s := lookupSession(sessionID)
	if s == nil || len(data) == 0 {
		return
	}
	s.writeMu.Lock()
	_, _ = s.ptmx.Write(data)
	s.writeMu.Unlock()
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
