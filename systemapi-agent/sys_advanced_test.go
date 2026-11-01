package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"unicode/utf8"

	"go.starlark.net/starlark"
)

func TestAlertsPushReportsNotDeliveredWithoutConnection(t *testing.T) {
	out, err := newTestEngine(&Entitlements{}).Execute(`print(sys.alerts.push("warning", "disk full"))`)
	if err != nil {
		t.Fatalf("push failed: %v", err)
	}
	if strings.TrimSpace(out) != "False" {
		t.Fatalf("push without a connection must return False, got %q", out)
	}
}

// recordingSink returns an engine whose alerts are captured as JSON frames.
func recordingSink(sendErr error) (*SysscriptEngine, *[][]byte) {
	var frames [][]byte
	engine := newTestEngine(&Entitlements{})
	engine.alerts = &alertSink{scriptID: "req-42", send: func(v interface{}) error {
		b, err := json.Marshal(v)
		if err != nil {
			return err
		}
		frames = append(frames, b)
		return sendErr
	}}
	return engine, &frames
}

func TestAlertsPushSendsFrame(t *testing.T) {
	engine, frames := recordingSink(nil)
	out, err := engine.Execute(`print(sys.alerts.push("critical", "disk full"))`)
	if err != nil {
		t.Fatalf("push failed: %v", err)
	}
	if strings.TrimSpace(out) != "True" {
		t.Fatalf("push with a connection must return True, got %q", out)
	}
	if len(*frames) != 1 {
		t.Fatalf("want 1 frame, got %d", len(*frames))
	}
	var got map[string]interface{}
	if err := json.Unmarshal((*frames)[0], &got); err != nil {
		t.Fatal(err)
	}
	want := map[string]interface{}{
		"type":       "sysscript_alert",
		"request_id": "req-42",
		"payload":    map[string]interface{}{"severity": "critical", "message": "disk full"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("frame = %v, want %v", got, want)
	}
}

func TestAlertsPushRejectsBadSeverity(t *testing.T) {
	for _, sev := range []string{"high", "CRITICAL", "", "error"} {
		engine, frames := recordingSink(nil)
		_, err := engine.Execute(fmt.Sprintf("sys.alerts.push(%q, %q)", sev, "x"))
		if err == nil || !strings.Contains(err.Error(), "severity must be") {
			t.Errorf("severity %q: want a severity error, got %v", sev, err)
		}
		if len(*frames) != 0 {
			t.Errorf("severity %q: sent %d frames", sev, len(*frames))
		}
	}
}

func TestAlertsPushTruncatesMessage(t *testing.T) {
	engine, frames := recordingSink(nil)
	// 4095 ASCII bytes then a 3-byte rune: the cut must not split the rune.
	script := fmt.Sprintf("sys.alerts.push(\"info\", \"a\" * %d + \"\u20ac\" * 10)", alertMessageMaxBytes-1)
	if _, err := engine.Execute(script); err != nil {
		t.Fatalf("push failed: %v", err)
	}
	var got struct {
		Payload alertPayload `json:"payload"`
	}
	if err := json.Unmarshal((*frames)[0], &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Payload.Message) != alertMessageMaxBytes-1 || !got.Payload.Truncated {
		t.Fatalf("message len=%d truncated=%v, want %d and true", len(got.Payload.Message), got.Payload.Truncated, alertMessageMaxBytes-1)
	}
	if !utf8.ValidString(got.Payload.Message) {
		t.Fatal("truncated message is not valid UTF-8")
	}
}

// Invalid bytes become U+FFFD (3 bytes) on the wire, so the cap must apply
// after that replacement or the server's byte check would reject the alert.
func TestAlertsPushInvalidUTF8StaysUnderServerCap(t *testing.T) {
	engine, frames := recordingSink(nil)
	// Starlark literals cannot hold invalid UTF-8, so call the builtin directly.
	args := starlark.Tuple{starlark.String("info"), starlark.String(strings.Repeat("\xffa", 1500))}
	if _, err := engine.alertsPush(nil, nil, args, nil); err != nil {
		t.Fatalf("push failed: %v", err)
	}
	var got struct {
		Payload alertPayload `json:"payload"`
	}
	if err := json.Unmarshal((*frames)[0], &got); err != nil {
		t.Fatal(err)
	}
	if n := len(got.Payload.Message); n > alertMessageMaxBytes || n == 0 {
		t.Fatalf("wire message is %d bytes, want 1..%d", n, alertMessageMaxBytes)
	}
	if !got.Payload.Truncated || !utf8.ValidString(got.Payload.Message) {
		t.Fatalf("truncated=%v valid=%v, want true, true", got.Payload.Truncated, utf8.ValidString(got.Payload.Message))
	}
	if !strings.HasPrefix(got.Payload.Message, "\uFFFDa\uFFFDa") {
		t.Fatal("invalid bytes were not replaced with U+FFFD")
	}
}

func TestAlertsPushCapsPerRun(t *testing.T) {
	engine, frames := recordingSink(nil)
	out, err := engine.Execute(`print(len([r for r in [sys.alerts.push("info", "n%d" % i) for i in range(25)] if r]))`)
	if err != nil {
		t.Fatalf("loop failed: %v", err)
	}
	if strings.TrimSpace(out) != fmt.Sprint(alertsPerRunMax) {
		t.Fatalf("want %d delivered, got %q", alertsPerRunMax, out)
	}
	if len(*frames) != alertsPerRunMax {
		t.Fatalf("want %d frames, got %d", alertsPerRunMax, len(*frames))
	}
}

func TestAlertsPushSendFailureReturnsFalse(t *testing.T) {
	engine, _ := recordingSink(errors.New("closed"))
	out, err := engine.Execute(`print(sys.alerts.push("info", "x"))`)
	if err != nil {
		t.Fatalf("push failed: %v", err)
	}
	if strings.TrimSpace(out) != "False" {
		t.Fatalf("a failed send must return False, got %q", out)
	}
}

func TestUnimplementedModulesFail(t *testing.T) {
	for _, script := range []string{
		`sys.security.yara_scan("/tmp/x")`,
		`sys.security.scan_memory(1)`,
		`sys.events.listen("exec", print)`,
	} {
		out, err := newTestEngine(&Entitlements{}).Execute(script)
		if err == nil || !strings.Contains(err.Error(), "not implemented") {
			t.Errorf("%s: want a not-implemented error, got err=%v out=%q", script, err, out)
		}
		if strings.Contains(out, "clean") || strings.Contains(out, "complete") {
			t.Errorf("%s: printed a fabricated result %q", script, out)
		}
	}
}
