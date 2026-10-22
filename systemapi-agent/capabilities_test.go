package main

import (
	"runtime"
	"sort"
	"strings"
	"testing"
)

// expectedCaps builds the capability set this host should advertise from the
// same probes the implementation uses: tcp and config are always on, pty off
// only on windows, file only on Linux with openat2, and service/package/tweak
// follow their platform probes.
func expectedCaps() string {
	present := map[string]bool{
		"tcp":    true, // tcp.go
		"config": true, // config store is a filesystem op, available everywhere
	}
	if runtime.GOOS != "windows" {
		present["pty"] = true
	}
	if runtime.GOOS == "linux" && openat2Available() {
		present["file"] = true
	}
	if serviceCapable() {
		present["service"] = true
	}
	if packageCapable() {
		present["package"] = true
	}
	if tweakCapable() {
		present["tweak"] = true
	}
	out := make([]string, 0, len(present))
	for name := range present {
		out = append(out, name)
	}
	sort.Strings(out)
	return strings.Join(out, ",")
}

func TestCapabilitiesAdvertiseOnlyWhatIsReal(t *testing.T) {
	got := capabilitiesHeaderValue()
	want := expectedCaps()
	if got != want {
		t.Fatalf("capabilities %q, want %q", got, want)
	}
	// config and tcp are always advertised; a host that drops them is a bug.
	for _, must := range []string{"config", "tcp"} {
		if !strings.Contains(","+got+",", ","+must+",") {
			t.Fatalf("capability %q must always be advertised, got %q", must, got)
		}
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
