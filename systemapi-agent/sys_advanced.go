package main

import (
	"fmt"
	"log"
	"strings"
	"unicode/utf8"

	"go.starlark.net/starlark"
)

// --- sys.alerts ---

const (
	// alertMessageMaxBytes caps one alert message; longer text is cut at a
	// UTF-8 boundary and flagged truncated. The server rejects anything longer.
	alertMessageMaxBytes = 4096
	// alertsPerRunMax caps alerts per script run so a loop cannot flood the
	// control plane. The server enforces the same cap per execution.
	alertsPerRunMax = 20
)

// alertSeverities matches the server's accepted set (playground/fleet.js).
var alertSeverities = map[string]bool{"info": true, "warning": true, "critical": true}

// alertSink delivers sys.alerts.push frames for one script run. send writes a
// frame on the agent's control-plane connection; scriptID is the run's
// request id, which the server uses to tie the alert to the execution.
type alertSink struct {
	send     func(v interface{}) error
	scriptID string
	sent     int
}

type alertPayload struct {
	Severity  string `json:"severity"`
	Message   string `json:"message"`
	Truncated bool   `json:"truncated,omitempty"`
}

// truncateUTF8 cuts s to at most max bytes without splitting a rune.
func truncateUTF8(s string, max int) string {
	if len(s) <= max {
		return s
	}
	n := max
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

// sys.alerts.push(severity, message) sends a sysscript_alert frame to the
// control plane. severity is one of info, warning, critical. It returns True
// once the frame is handed to the connection, and False (with a local log
// line) when there is no connection, the send fails, or this run already sent
// alertsPerRunMax alerts.
func (engine *SysscriptEngine) alertsPush(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var severity, message string
	if err := starlark.UnpackArgs("push", args, kwargs, "severity", &severity, "message", &message); err != nil {
		return starlark.None, err
	}
	if !alertSeverities[severity] {
		return starlark.None, fmt.Errorf("sys.alerts.push: severity must be info, warning or critical, got %q", severity)
	}
	// JSON encoding turns each invalid byte into U+FFFD (3 bytes), so
	// replace them first and cap what the server will actually see.
	clean := strings.ToValidUTF8(message, "\uFFFD")
	payload := alertPayload{Severity: severity, Message: truncateUTF8(clean, alertMessageMaxBytes)}
	payload.Truncated = len(payload.Message) < len(clean)

	sink := engine.alerts
	if sink == nil || sink.send == nil {
		log.Printf("[sysscript alert, not forwarded: no connection] severity=%s message=%q", severity, payload.Message)
		return starlark.False, nil
	}
	if sink.sent >= alertsPerRunMax {
		log.Printf("[sysscript alert, not forwarded: over %d per run] script=%s severity=%s", alertsPerRunMax, sink.scriptID, severity)
		return starlark.False, nil
	}
	sink.sent++
	if err := sink.send(ResponseMessage{Type: "sysscript_alert", RequestID: sink.scriptID, Payload: payload}); err != nil {
		log.Printf("[sysscript alert, not forwarded: %v] script=%s severity=%s message=%q", err, sink.scriptID, severity, payload.Message)
		return starlark.False, nil
	}
	log.Printf("[sysscript alert] script=%s severity=%s message=%q", sink.scriptID, severity, payload.Message)
	return starlark.True, nil
}

// --- sys.security and sys.events ---
// These names are reserved but have no implementation. They fail so a script
// never mistakes a missing scanner for a clean result.

func notImplemented(name string) error {
	return fmt.Errorf("%s is not implemented in this agent", name)
}

// sys.security.yara_scan(path)
func (engine *SysscriptEngine) securityYaraScan(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	return starlark.None, notImplemented("sys.security.yara_scan")
}

// sys.security.scan_memory(pid)
func (engine *SysscriptEngine) securityScanMemory(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	return starlark.None, notImplemented("sys.security.scan_memory")
}

// sys.events.listen(event_type, callback)
func (engine *SysscriptEngine) eventsListen(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	return starlark.None, notImplemented("sys.events.listen")
}
