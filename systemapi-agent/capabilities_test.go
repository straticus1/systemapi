package main

import (
	"runtime"
	"testing"
)

func TestCapabilitiesAdvertiseOnlyWhatIsReal(t *testing.T) {
	got := capabilitiesHeaderValue()
	want := "pty"
	if runtime.GOOS == "windows" {
		want = ""
	}
	if got != want {
		t.Fatalf("capabilities %q, want %q (tcp/file are advertised only once their handlers register)", got, want)
	}
	registerCapability("zz_test_off", func() bool { return false })
	registerCapability("aa_test_on", func() bool { return true })
	defer func() {
		capMu.Lock()
		delete(capProbes, "zz_test_off")
		delete(capProbes, "aa_test_on")
		capMu.Unlock()
	}()
	caps := agentCapabilities()
	if len(caps) == 0 || caps[0] != "aa_test_on" {
		t.Fatalf("sorted, probed list: %v", caps)
	}
	for _, c := range caps {
		if c == "zz_test_off" {
			t.Fatal("a capability whose probe fails was advertised")
		}
	}
}
