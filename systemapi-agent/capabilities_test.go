package main

import (
	"runtime"
	"sort"
	"strings"
	"testing"
)

// expectedCaps builds the capability set this host should advertise from the
// same probes the implementation uses: tcp and config are always on, pty off
// only on windows, sysscript_jobs only on Linux and macOS (unless
// --sysscript-jobs=false), file only on Linux with openat2, and
// service/package/tweak follow their platform probes.
func expectedCaps() string {
	present := map[string]bool{
		"tcp":    true, // tcp.go
		"config": true, // config store is a filesystem op, available everywhere
	}
	if runtime.GOOS != "windows" {
		present["pty"] = true
	}
	if runtime.GOOS == "linux" || runtime.GOOS == "darwin" {
		present["sysscript_jobs"] = true // the process-group kill exists here
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

func hasCap(name string) bool {
	return strings.Contains(","+capabilitiesHeaderValue()+",", ","+name+",")
}

// sysscript_jobs: on by default on Linux and macOS only, and
// --sysscript-jobs=false (sysscriptJobsOn) turns it off on any OS, so the
// server sends that host's scripts the legacy way.
func TestSysscriptJobsCapabilitySwitch(t *testing.T) {
	defer func(prev bool) { sysscriptJobsOn = prev }(sysscriptJobsOn)
	sysscriptJobsOn = true
	groupKill := runtime.GOOS == "linux" || runtime.GOOS == "darwin"
	if got := hasCap("sysscript_jobs"); got != groupKill {
		t.Fatalf("GOOS=%s: sysscript_jobs advertised=%v, want %v", runtime.GOOS, got, groupKill)
	}
	sysscriptJobsOn = false
	if hasCap("sysscript_jobs") {
		t.Fatal("--sysscript-jobs=false still advertises sysscript_jobs")
	}
	if !hasCap("tcp") || !hasCap("config") {
		t.Fatal("--sysscript-jobs=false must not touch other capabilities")
	}
}

// converge: off by default; --converge (convergeOn) advertises it only on
// Linux and macOS, and only while async jobs are advertised.
func TestConvergeCapabilitySwitch(t *testing.T) {
	defer func(prevJobs, prevConv bool) { sysscriptJobsOn, convergeOn = prevJobs, prevConv }(sysscriptJobsOn, convergeOn)
	if convergeOn {
		t.Fatal("--converge must default to off")
	}
	sysscriptJobsOn = true
	if hasCap("converge") {
		t.Fatal("converge advertised without --converge")
	}
	convergeOn = true
	groupKill := runtime.GOOS == "linux" || runtime.GOOS == "darwin"
	if got := hasCap("converge"); got != groupKill {
		t.Fatalf("GOOS=%s: converge advertised=%v, want %v", runtime.GOOS, got, groupKill)
	}
	sysscriptJobsOn = false
	if hasCap("converge") {
		t.Fatal("--sysscript-jobs=false still advertises converge")
	}
}
