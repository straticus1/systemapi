// Threats: a terminal user who does not know the session is recorded or
// watched; an administrator watching without the user's knowledge; a support
// or admin actor watching without consent outside the one override (view
// only, admin, with a reason); read-write control taken without consent; the
// keystrokes that answer a consent prompt reaching the shell; a prompt that
// waits forever; and a forged override. Every terminal session starts with a
// monitoring notice the agent writes before any shell output and before any
// client input is accepted; --pty-notice replaces its text but cannot remove
// it. A watch_request needs a lease for the session's action whose payload
// binds the session, watch id, mode, override flag and reason (phase
// "watch"), so only the lease signer can claim an override. Read-write always
// asks the user, whatever the override flag says. While a prompt is open,
// every byte the client sends goes to the prompt, never to the shell or the
// recording, and nothing is echoed; no answer within watchConsentTimeout is
// a refusal. The user is told on the terminal when watching starts and when
// it stops. Does NOT stream output to the watcher (the server relays the
// session's output) and does NOT authenticate the actor beyond the lease.
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
)

const (
	ptyNoticeDefault  = "This session is recorded and may be viewed by an administrator."
	ptyNoticeMaxBytes = 2048
	watchReasonMax    = 256

	watchModeView    = "ro"
	watchModeControl = "rw"
)

var (
	// watchConsentTimeout is how long a consent prompt waits for y or n.
	watchConsentTimeout = 30 * time.Second

	watchIDRe = regexp.MustCompile(`^wch_[A-Za-z0-9_-]{16,64}$`)
)

type watchInfo struct {
	id    string
	actor string
	mode  string
}

// watchPrompt is one open consent prompt. feed and cancel may race; the
// first answer wins.
type watchPrompt struct {
	watchID string
	once    sync.Once
	ch      chan string // "granted", "denied", "cancelled" or "session_ended"
}

func newWatchPrompt(watchID string) *watchPrompt {
	return &watchPrompt{watchID: watchID, ch: make(chan string, 1)}
}

func (p *watchPrompt) answer(result string) {
	p.once.Do(func() { p.ch <- result })
}

// feed reads the user's answer. Only a keystroke that is exactly y or Y
// (optionally followed by Enter) allows, so text typed or pasted while the
// prompt appears cannot consent by accident; n, N, Ctrl-C or Ctrl-D anywhere
// refuses; everything else is dropped.
func (p *watchPrompt) feed(data []byte) {
	for _, b := range data {
		switch b {
		case 'n', 'N', 3, 4:
			p.answer("denied")
			return
		}
	}
	switch strings.TrimRight(string(data), "\r\n") {
	case "y", "Y":
		p.answer("granted")
	}
}

type watchRequest struct {
	SessionID string
	WatchID   string
	Mode      string
	Actor     string
	Reason    string
	Override  bool
	Lease     *Lease
}

// watchPayload is the signed payload of a watch lease. The action is the
// session's own terminal action; phase "watch" keeps it from starting or
// renewing a session.
func watchPayload(sessionID string, deadlineUnix int64, watchID, mode string, override bool, reason string) string {
	return terminalPayload(sessionID, deadlineUnix, "watch") + "\n" + watchID + "\n" + mode + "\n" +
		strconv.FormatBool(override) + "\n" + reason
}

// terminalText keeps printable characters and newlines, so text shown on a
// user's terminal cannot carry escape sequences.
func terminalText(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r == '\n' || r == '\t' || (unicode.IsPrint(r) && r != unicode.ReplacementChar) {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// loadPTYNotice reads --pty-notice: a file owned by root or the agent user,
// not writable by group or other, holding the notice text. An empty notice
// is refused: the file changes the text, never removes the notice.
func loadPTYNotice(path string, euid int) (string, error) {
	f, err := openAgentConfigFile(path, euid, 0o022, ptyNoticeMaxBytes, "pty notice")
	if err != nil {
		return "", err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, ptyNoticeMaxBytes+1))
	if err != nil {
		return "", err
	}
	text := strings.TrimSpace(terminalText(string(raw)))
	if text == "" {
		return "", errors.New("pty notice is empty; the notice cannot be turned off")
	}
	return text, nil
}

func terminalLines(text string) []byte {
	var b strings.Builder
	for _, line := range strings.Split(text, "\n") {
		b.WriteString("[systemapi] " + strings.TrimRight(line, " \t\r") + "\r\n")
	}
	return []byte(b.String())
}

// sessionNotice is the monitoring notice every terminal session starts with.
func sessionNotice(cfg ptySettings) []byte {
	text := cfg.Notice
	if strings.TrimSpace(text) == "" {
		text = ptyNoticeDefault
	}
	text = strings.TrimSpace(terminalText(text))
	if tenant := strings.TrimSpace(terminalText(cfg.Tenant)); tenant != "" {
		text += "\nTenant: " + tenant
	}
	return append(append([]byte("\r\n"), terminalLines(text)...), '\r', '\n')
}

// notifyUser shows text on the user's terminal as session output: it is
// recorded like shell output and never reaches the shell's input.
func (s *ptySession) notifyUser(text []byte) {
	if s.rec != nil && !s.rec.add("o", text) {
		return
	}
	frame := make([]byte, 0, 1+len(s.id)+len(text))
	frame = append(frame, byte(len(s.id)))
	frame = append(frame, s.id...)
	frame = append(frame, text...)
	_ = s.out.WriteBinary(frame)
}

func (s *ptySession) recordWatchEvent(ev map[string]interface{}) {
	if s.rec == nil {
		return
	}
	if b, err := json.Marshal(ev); err == nil {
		s.rec.add("w", b)
	}
}

func watchConsentReply(out ptyOut, sessionID string, payload map[string]interface{}) {
	_ = out.WriteJSON(ResponseMessage{Type: "watch_consent", SessionID: sessionID, Payload: payload})
}

func modeWords(mode string) string {
	if mode == watchModeControl {
		return "with control (they can type into it)"
	}
	return "view only"
}

// handleWatchRequest decides one watch_request. The answer is a
// watch_consent frame; see docs/sahconnect-terminal-protocol.md §6.
func handleWatchRequest(out ptyOut, hostID string, req watchRequest, now time.Time) {
	refuse := func(code string) {
		watchConsentReply(out, req.SessionID, map[string]interface{}{
			"watch_id": req.WatchID, "granted": false, "consent": false, "error": code,
		})
	}
	s := lookupSession(req.SessionID)
	if s == nil {
		refuse("unknown_session")
		return
	}
	if !watchIDRe.MatchString(req.WatchID) || (req.Mode != watchModeView && req.Mode != watchModeControl) ||
		!mapIdentityRe.MatchString(req.Actor) || len(req.Reason) > watchReasonMax || terminalText(req.Reason) != req.Reason ||
		strings.ContainsAny(req.Reason, "\n\t") {
		refuse("bad_request")
		return
	}
	payload := watchPayload(s.id, s.deadline.Unix(), req.WatchID, req.Mode, req.Override, req.Reason)
	if err := authorizeCommand(hostID, s.action, payload, req.Lease, now); err != nil {
		log.Printf("watch_request refused: %s", err.Error())
		refuse("lease_required")
		return
	}
	override := req.Override
	if override && req.Mode == watchModeControl {
		// Read-write control always asks the user.
		log.Printf("pty %s: read-write watch asks for consent despite the override flag", s.id)
		override = false
	}
	if override && strings.TrimSpace(req.Reason) == "" {
		refuse("reason_required")
		return
	}

	s.mu.Lock()
	if s.ending || s.inClosed {
		s.mu.Unlock()
		refuse("session_ended")
		return
	}
	if _, dup := s.watchers[req.WatchID]; dup {
		s.mu.Unlock()
		refuse("bad_request")
		return
	}
	if override {
		s.addWatcherLocked(req)
		s.mu.Unlock()
		s.recordWatchEvent(map[string]interface{}{"event": "watch_started", "watch_id": req.WatchID, "actor": req.Actor, "mode": req.Mode, "reason": req.Reason, "consent": false})
		s.notifyUser(terminalLines(fmt.Sprintf("\nAn administrator (%s) started watching this session, view only. Reason: %s", req.Actor, req.Reason)))
		watchConsentReply(out, s.id, map[string]interface{}{
			"watch_id": req.WatchID, "granted": true, "consent": false, "result": "override",
			"mode": req.Mode, "actor": req.Actor, "reason": req.Reason,
		})
		return
	}
	if s.consent != nil {
		s.mu.Unlock()
		refuse("busy")
		return
	}
	p := newWatchPrompt(req.WatchID)
	s.consent = p
	s.mu.Unlock()

	s.recordWatchEvent(map[string]interface{}{"event": "watch_request", "watch_id": req.WatchID, "actor": req.Actor, "mode": req.Mode, "reason": req.Reason})
	prompt := fmt.Sprintf("\r\n[systemapi] %s asks to watch this session, %s.", req.Actor, modeWords(req.Mode))
	if req.Reason != "" {
		prompt += " Reason: " + req.Reason + "."
	}
	prompt += fmt.Sprintf(" Allow? [y/N] (%d s) ", int(watchConsentTimeout/time.Second))
	s.notifyUser([]byte(prompt))
	go s.awaitConsent(p, req)
}

func (s *ptySession) addWatcherLocked(req watchRequest) {
	if s.watchers == nil {
		s.watchers = map[string]*watchInfo{}
	}
	s.watchers[req.WatchID] = &watchInfo{id: req.WatchID, actor: req.Actor, mode: req.Mode}
}

func (s *ptySession) awaitConsent(p *watchPrompt, req watchRequest) {
	t := time.NewTimer(watchConsentTimeout)
	defer t.Stop()
	var result string
	select {
	case result = <-p.ch:
	case <-t.C:
		p.answer("timeout")
		result = <-p.ch
	}
	s.mu.Lock()
	if s.consent == p {
		s.consent = nil
	}
	granted := result == "granted" && !s.ending && !s.inClosed
	if result == "granted" && !granted {
		result = "session_ended"
	}
	if granted {
		s.addWatcherLocked(req)
	}
	s.mu.Unlock()

	s.recordWatchEvent(map[string]interface{}{"event": "watch_consent", "watch_id": req.WatchID, "actor": req.Actor, "mode": req.Mode, "result": result})
	switch result {
	case "granted":
		s.notifyUser(terminalLines(fmt.Sprintf("\nYou allowed %s to watch this session, %s.", req.Actor, modeWords(req.Mode))))
	case "denied":
		s.notifyUser(terminalLines("\nWatching refused."))
	case "timeout":
		s.notifyUser(terminalLines(fmt.Sprintf("\nNo answer in %d s; watching refused.", int(watchConsentTimeout/time.Second))))
	case "cancelled":
		s.notifyUser(terminalLines("\nThe watch request was withdrawn."))
	}
	payload := map[string]interface{}{
		"watch_id": req.WatchID, "granted": granted, "consent": granted, "result": result,
		"mode": req.Mode, "actor": req.Actor, "reason": req.Reason,
	}
	watchConsentReply(s.out, s.id, payload)
}

// handleWatchStop ends one watch, or withdraws its open prompt, and tells
// the user.
func handleWatchStop(sessionID, watchID string) {
	s := lookupSession(sessionID)
	if s == nil {
		return
	}
	s.mu.Lock()
	if p := s.consent; p != nil && p.watchID == watchID {
		s.mu.Unlock()
		p.answer("cancelled")
		return
	}
	w := s.watchers[watchID]
	delete(s.watchers, watchID)
	s.mu.Unlock()
	if w == nil {
		return
	}
	s.recordWatchEvent(map[string]interface{}{"event": "watch_stopped", "watch_id": w.id, "actor": w.actor, "mode": w.mode})
	s.notifyUser(terminalLines(fmt.Sprintf("\n%s stopped watching this session.", w.actor)))
	watchConsentReply(s.out, s.id, map[string]interface{}{"watch_id": w.id, "result": "stopped", "granted": false, "consent": false, "actor": w.actor, "mode": w.mode})
}

// handleWatcherInput accepts input from a watcher only while that watcher
// holds read-write consent.
func handleWatcherInput(sessionID, watchID string, data []byte) {
	s := lookupSession(sessionID)
	if s == nil {
		return
	}
	s.mu.Lock()
	w := s.watchers[watchID]
	s.mu.Unlock()
	if w == nil || w.mode != watchModeControl {
		log.Printf("pty %s: watcher input dropped: no read-write consent", s.id)
		return
	}
	s.queueInput(data)
}

// cancelConsentLocked ends an open prompt when the session ends. Callers
// hold s.mu.
func (s *ptySession) cancelConsentLocked() {
	if s.consent != nil {
		s.consent.answer("session_ended")
	}
}
