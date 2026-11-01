package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

// fakeServiceMgr is an injected ServiceManager that records the verbs and
// units it is asked to act on, so a test can assert Restart then Status ran
// without touching the host's real init system.
type fakeServiceMgr struct {
	avail     bool
	actions   [][2]string
	statuses  []string
	actErr    error
	status    ServiceStatus
	statusErr error
}

func (f *fakeServiceMgr) Name() string    { return "fake" }
func (f *fakeServiceMgr) Available() bool { return f.avail }
func (f *fakeServiceMgr) Action(_ context.Context, verb, service string) (string, error) {
	f.actions = append(f.actions, [2]string{verb, service})
	return "acted on " + service, f.actErr
}
func (f *fakeServiceMgr) Status(_ context.Context, service string) (ServiceStatus, error) {
	f.statuses = append(f.statuses, service)
	return f.status, f.statusErr
}
func (f *fakeServiceMgr) IsEnabled(context.Context, string) (bool, error) {
	return false, errors.New("fake: is-enabled not used by the sys channel")
}

type sysHarness struct {
	priv ed25519.PrivateKey
	out  *fakeOut
	ch   *channelConn
	svc  *fakeServiceMgr
}

func newSysHarness(t *testing.T, avail bool) *sysHarness {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	clearIdentity()
	if err := pinControlPublicKey(base64.StdEncoding.EncodeToString(pub), ptyTestHost); err != nil {
		t.Fatal(err)
	}
	svc := &fakeServiceMgr{avail: avail, status: ServiceStatus{Active: true, State: "active", Output: "running"}}
	prev := sysServices
	sysServices = func() ServiceManager { return svc }
	h := &sysHarness{priv: priv, out: newFakeOut(), svc: svc}
	h.ch = newChannelConn(h.out, ptyTestHost)
	t.Cleanup(func() {
		h.ch.close("stopped")
		sysServices = prev
		clearIdentity()
	})
	return h
}

func newSysRequestID(t *testing.T) string {
	t.Helper()
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return "sys_" + hex.EncodeToString(b)
}

// send marshals v and feeds it through the channel dispatcher.
func (h *sysHarness) send(t *testing.T, v interface{}) {
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
	if !handled {
		t.Fatalf("%s not handled", peek.Type)
	}
	if err != nil {
		t.Fatalf("handle returned error: %v", err)
	}
	// sys frames run off the read goroutine; wait for this one's result.
	h.ch.sysWait()
}

// result returns the sys_result payload for rid.
func (h *sysHarness) result(t *testing.T, rid string) map[string]interface{} {
	t.Helper()
	h.out.mu.Lock()
	defer h.out.mu.Unlock()
	for _, m := range h.out.jsons {
		got, _ := m["request_id"].(string)
		if m["type"] == "sys_result" && got == rid {
			p, _ := m["payload"].(map[string]interface{})
			return p
		}
	}
	t.Fatalf("no sys_result for %s", rid)
	return nil
}

// frame builds a signed sys_service frame. leaseUnit/leaseAction default to
// unit/action; override them to forge a mismatch.
func (h *sysHarness) frame(t *testing.T, rid, unit, action, leaseUnit, leaseAction string, exp int64) map[string]interface{} {
	t.Helper()
	if leaseUnit == "" {
		leaseUnit = unit
	}
	if leaseAction == "" {
		leaseAction = action
	}
	payload, err := sysServiceLeasePayload(leaseUnit, leaseAction)
	if err != nil {
		t.Fatalf("lease payload: %v", err)
	}
	lease := signLease(t, h.priv, ptyTestHost, "sys_service", payload, exp)
	return map[string]interface{}{
		"type": "sys_service", "request_id": rid, "unit": unit, "action": action, "lease": lease,
	}
}

func TestSysServiceRestartHappyPath(t *testing.T) {
	h := newSysHarness(t, true)
	rid := newSysRequestID(t)
	h.send(t, h.frame(t, rid, "nginx.service", "restart", "", "", inFuture(time.Minute)))
	p := h.result(t, rid)
	if p["ok"] != true {
		t.Fatalf("ok=%v, want true: %v", p["ok"], p)
	}
	if p["unit"] != "nginx.service" || p["action"] != "restart" {
		t.Fatalf("unexpected result: %v", p)
	}
	if p["active"] != true || p["state"] != "active" {
		t.Fatalf("status not reported: %v", p)
	}
	// Restart ran, then Status confirmed, both on the signed unit.
	if len(h.svc.actions) != 1 || h.svc.actions[0] != [2]string{"restart", "nginx.service"} {
		t.Fatalf("actions=%v", h.svc.actions)
	}
	if len(h.svc.statuses) != 1 || h.svc.statuses[0] != "nginx.service" {
		t.Fatalf("statuses=%v", h.svc.statuses)
	}
}

func TestSysServiceRefusesWhenCapabilityAbsent(t *testing.T) {
	h := newSysHarness(t, false) // host does not advertise service
	rid := newSysRequestID(t)
	h.send(t, h.frame(t, rid, "nginx.service", "restart", "", "", inFuture(time.Minute)))
	p := h.result(t, rid)
	if p["ok"] != false || p["error"] != "service_unsupported" {
		t.Fatalf("want service_unsupported refusal, got %v", p)
	}
	if len(h.svc.actions) != 0 {
		t.Fatalf("no action should have run, got %v", h.svc.actions)
	}
}

func TestSysServiceRefusesUnitNotInSignedLease(t *testing.T) {
	h := newSysHarness(t, true)
	rid := newSysRequestID(t)
	// Lease signed for postgresql.service, frame asks to restart nginx.service.
	h.send(t, h.frame(t, rid, "nginx.service", "restart", "postgresql.service", "", inFuture(time.Minute)))
	p := h.result(t, rid)
	if p["ok"] != false || p["error"] != "lease_required" {
		t.Fatalf("want lease_required for unit mismatch, got %v", p)
	}
	if len(h.svc.actions) != 0 {
		t.Fatalf("no action should have run, got %v", h.svc.actions)
	}
}

func TestSysServiceRefusesExpiredLease(t *testing.T) {
	h := newSysHarness(t, true)
	rid := newSysRequestID(t)
	h.send(t, h.frame(t, rid, "nginx.service", "restart", "", "", time.Now().Add(-10*time.Minute).Unix()))
	p := h.result(t, rid)
	if p["ok"] != false || p["error"] != "lease_required" {
		t.Fatalf("want lease_required for expired lease, got %v", p)
	}
	if len(h.svc.actions) != 0 {
		t.Fatalf("no action should have run, got %v", h.svc.actions)
	}
}

func TestSysServiceRefusesWrongKey(t *testing.T) {
	h := newSysHarness(t, true)
	rid := newSysRequestID(t)
	_, otherPriv, _ := ed25519.GenerateKey(rand.Reader)
	payload, _ := sysServiceLeasePayload("nginx.service", "restart")
	lease := signLease(t, otherPriv, ptyTestHost, "sys_service", payload, inFuture(time.Minute))
	h.send(t, map[string]interface{}{
		"type": "sys_service", "request_id": rid, "unit": "nginx.service", "action": "restart", "lease": lease,
	})
	p := h.result(t, rid)
	if p["ok"] != false || p["error"] != "lease_required" {
		t.Fatalf("want lease_required for wrong key, got %v", p)
	}
}

func TestSysServiceStopHappyPath(t *testing.T) {
	h := newSysHarness(t, true)
	rid := newSysRequestID(t)
	h.send(t, h.frame(t, rid, "nginx.service", "stop", "", "", inFuture(time.Minute)))
	p := h.result(t, rid)
	if p["ok"] != true || p["unit"] != "nginx.service" || p["action"] != "stop" {
		t.Fatalf("unexpected result: %v", p)
	}
	if len(h.svc.actions) != 1 || h.svc.actions[0] != [2]string{"stop", "nginx.service"} {
		t.Fatalf("actions=%v", h.svc.actions)
	}
}

func TestSysServiceLeaseBindsAction(t *testing.T) {
	h := newSysHarness(t, true)
	rid := newSysRequestID(t)
	// A lease signed for restart cannot drive a stop: the agent rebuilds the
	// payload from the frame's verb, so the signature no longer verifies.
	h.send(t, h.frame(t, rid, "nginx.service", "stop", "", "restart", inFuture(time.Minute)))
	p := h.result(t, rid)
	if p["ok"] != false || p["error"] != "lease_required" {
		t.Fatalf("want lease_required for action mismatch, got %v", p)
	}
	if len(h.svc.actions) != 0 {
		t.Fatalf("no action should have run, got %v", h.svc.actions)
	}
}

func TestSysServiceRefusesUnknownAction(t *testing.T) {
	h := newSysHarness(t, true)
	rid := newSysRequestID(t)
	// "reload" is not a channel verb, so no lease can be built for it and the
	// agent refuses before any command runs.
	h.send(t, map[string]interface{}{
		"type": "sys_service", "request_id": rid, "unit": "nginx.service", "action": "reload",
		"lease": signLease(t, h.priv, ptyTestHost, "sys_service", "nginx.service\nreload", inFuture(time.Minute)),
	})
	p := h.result(t, rid)
	if p["ok"] != false || p["error"] != "lease_required" {
		t.Fatalf("want lease_required for unknown action, got %v", p)
	}
	if len(h.svc.actions) != 0 {
		t.Fatalf("no action should have run, got %v", h.svc.actions)
	}
}

func TestSysServiceReportsActionFailure(t *testing.T) {
	h := newSysHarness(t, true)
	h.svc.actErr = errSysUnitDenied // any non-nil error
	rid := newSysRequestID(t)
	h.send(t, h.frame(t, rid, "nginx.service", "restart", "", "", inFuture(time.Minute)))
	p := h.result(t, rid)
	if p["ok"] != false || p["error"] != "action_failed" {
		t.Fatalf("want action_failed, got %v", p)
	}
	// The command was still attempted and its status still read.
	if len(h.svc.actions) != 1 || len(h.svc.statuses) != 1 {
		t.Fatalf("actions=%v statuses=%v", h.svc.actions, h.svc.statuses)
	}
}

func TestSysServiceLeasePayloadBuilder(t *testing.T) {
	// The Go builder must produce the exact string the server signs
	// (controlplane/lease.js sysServicePayload): "<unit>\n<action>".
	for _, action := range []string{"start", "stop", "restart", "enable", "disable"} {
		got, err := sysServiceLeasePayload("nginx.service", action)
		if err != nil || got != "nginx.service\n"+action {
			t.Fatalf("payload %q err %v for %s", got, err, action)
		}
	}
	for _, c := range []struct {
		name         string
		unit, action string
	}{
		{"bad action", "nginx.service", "reload"},
		{"empty action", "nginx.service", ""},
		{"bad unit newline", "nginx\n.service", "restart"},
		{"empty unit", "", "restart"},
	} {
		if _, err := sysServiceLeasePayload(c.unit, c.action); err == nil {
			t.Fatalf("%s: accepted", c.name)
		}
	}
}
