package main

import (
	"strings"
	"testing"
)

func TestAlertsPushReportsNotDelivered(t *testing.T) {
	out, err := newTestEngine(&Entitlements{}).Execute(`print(sys.alerts.push("high", "disk full"))`)
	if err != nil {
		t.Fatalf("push failed: %v", err)
	}
	if strings.TrimSpace(out) != "False" {
		t.Fatalf("push must return False while alerts are not forwarded, got %q", out)
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
