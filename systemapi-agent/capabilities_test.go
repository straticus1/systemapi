package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// leakyErr carries a path and secret-looking text: none of it may ever
// reach a header or a report.
var leakyErr = errors.New("open /etc/systemapi-agent/helper-trust.json: permission denied token=sk_live_SECRET")

// fakeCapEnv is a healthy Linux + systemd host with every flag on.
func fakeCapEnv() *capEnv {
	return &capEnv{
		goos:           "linux",
		systemd:        func() bool { return true },
		openat2Root:    func() error { return nil },
		configOpen:     func() error { return nil },
		tweakRead:      func() error { return nil },
		ptmx:           func() error { return nil },
		serviceBackend: func() string { return "systemd" },
		managerUp:      func(string) error { return nil },
		unitLoaded:     func(string) (bool, error) { return true, nil },
		trust:          func() error { return nil },
		xferConfigured: func() bool { return true },
		xferBin:        func() error { return nil },
		pkgBackend:     func() string { return "apt-get" },
		pkgVersion:     func(string) error { return nil },
		jobsOn:         func() bool { return true },
		convergeOn:     func() bool { return true },
		stateDir:       func() error { return nil },
	}
}

func capsByName(rs []capResult) map[string]capResult {
	m := map[string]capResult{}
	for _, r := range rs {
		m[r.Name] = r
	}
	return m
}

func probeOne(t *testing.T, e *capEnv, name string) capResult {
	t.Helper()
	r, ok := capsByName(probeCapabilities(e, nil))[name]
	if !ok {
		t.Fatalf("%s not reported", name)
	}
	return r
}

func TestCapRegistryFitsTheWireGrammar(t *testing.T) {
	if len(capRegistry) > capTokensMax {
		t.Fatalf("%d capabilities, the header allows %d", len(capRegistry), capTokensMax)
	}
	for name := range capRegistry {
		if !capNameRE.MatchString(name) {
			t.Fatalf("capability %q breaks the token grammar", name)
		}
	}
	sup, deg := capHeaderValues(probeCapabilities(fakeCapEnv(), nil))
	if len(sup) > capHeaderMax {
		t.Fatalf("supported header %d bytes", len(sup))
	}
	if deg != "" {
		t.Fatalf("healthy host has degraded %q", deg)
	}
	want := "config,config_write,converge,file,intent_v1,override_write,package,pty,service,sysctl_write,sysscript_jobs,tcp,tweak,xfer"
	if sup != want {
		t.Fatalf("supported %q, want %q", sup, want)
	}
}

// Every probe: ok on a healthy host, and its degraded path with its fixed
// reason when its check fails.
func TestCapProbesOkAndDegraded(t *testing.T) {
	for name := range capRegistry {
		if r := probeOne(t, fakeCapEnv(), name); r.State != capStateOK || r.Reason != "" {
			t.Fatalf("%s on a healthy host: %+v", name, r)
		}
	}
	cases := []struct {
		name   string
		cap    string
		break_ func(e *capEnv)
		reason string
	}{
		{"pty no ptmx", "pty", func(e *capEnv) { e.ptmx = func() error { return leakyErr } }, "probe_error"},
		{"file ENOSYS", "file", func(e *capEnv) { e.openat2Root = func() error { return syscall.ENOSYS } }, "enosys_openat2"},
		{"file seccomp EPERM", "file", func(e *capEnv) { e.openat2Root = func() error { return fmt.Errorf("x: %w", syscall.EPERM) } }, "enosys_openat2"},
		{"file other", "file", func(e *capEnv) { e.openat2Root = func() error { return leakyErr } }, "probe_error"},
		{"xfer openat2", "xfer", func(e *capEnv) { e.openat2Root = func() error { return syscall.ENOSYS } }, "enosys_openat2"},
		{"xfer bin", "xfer", func(e *capEnv) { e.xferBin = func() error { return leakyErr } }, "binary_missing"},
		{"config ENOSYS", "config", func(e *capEnv) { e.configOpen = func() error { return syscall.ENOSYS } }, "enosys_openat2"},
		{"config other", "config", func(e *capEnv) { e.configOpen = func() error { return leakyErr } }, "probe_error"},
		{"config_write config", "config_write", func(e *capEnv) { e.configOpen = func() error { return syscall.ENOSYS } }, "enosys_openat2"},
		{"config_write unit", "config_write", func(e *capEnv) {
			e.unitLoaded = func(u string) (bool, error) { return u != configHelperProbeUnit, nil }
		}, "helper_unit_missing"},
		{"config_write manager", "config_write", func(e *capEnv) {
			e.unitLoaded = func(string) (bool, error) { return false, leakyErr }
		}, "manager_unreachable"},
		{"config_write trust", "config_write", func(e *capEnv) { e.trust = func() error { return leakyErr } }, "helper_trust_missing"},
		{"tweak read", "tweak", func(e *capEnv) { e.tweakRead = func() error { return leakyErr } }, "probe_error"},
		{"sysctl_write unit", "sysctl_write", func(e *capEnv) {
			e.unitLoaded = func(u string) (bool, error) { return u != sysctlHelperProbeUnit, nil }
		}, "helper_unit_missing"},
		{"sysctl_write trust", "sysctl_write", func(e *capEnv) { e.trust = func() error { return leakyErr } }, "helper_trust_missing"},
		{"override_write unit", "override_write", func(e *capEnv) {
			e.unitLoaded = func(u string) (bool, error) { return u != overrideHelperProbeUnit, nil }
		}, "helper_unit_missing"},
		{"override_write manager", "override_write", func(e *capEnv) {
			e.unitLoaded = func(string) (bool, error) { return false, leakyErr }
		}, "manager_unreachable"},
		{"service manager", "service", func(e *capEnv) { e.managerUp = func(string) error { return leakyErr } }, "manager_unreachable"},
		{"package missing", "package", func(e *capEnv) { e.pkgVersion = func(string) error { return errCapMissing } }, "binary_missing"},
		{"package error", "package", func(e *capEnv) { e.pkgVersion = func(string) error { return leakyErr } }, "probe_error"},
		{"sysscript_jobs dir gone", "sysscript_jobs", func(e *capEnv) { e.stateDir = func() error { return errCapMissing } }, "probe_error"},
		{"converge dir gone", "converge", func(e *capEnv) { e.stateDir = func() error { return errCapMissing } }, "probe_error"},
	}
	for _, c := range cases {
		e := fakeCapEnv()
		c.break_(e)
		r := probeOne(t, e, c.cap)
		if r.State != capStateDegraded || r.Reason != c.reason {
			t.Errorf("%s: %+v, want degraded %s", c.name, r, c.reason)
		}
	}
	// One helper missing does not block the others.
	e := fakeCapEnv()
	e.unitLoaded = func(u string) (bool, error) { return u != sysctlHelperProbeUnit, nil }
	got := capsByName(probeCapabilities(e, nil))
	if got["config_write"].State != capStateOK || got["override_write"].State != capStateOK {
		t.Fatalf("a missing sysctl helper degraded others: %+v", got)
	}
}

func TestCapProbesAbsent(t *testing.T) {
	cases := []struct {
		name   string
		cap    string
		set    func(e *capEnv)
		reason string
	}{
		{"xfer without --xfer-bin", "xfer", func(e *capEnv) { e.xferConfigured = func() bool { return false } }, "flag_off"},
		{"jobs off", "sysscript_jobs", func(e *capEnv) { e.jobsOn = func() bool { return false } }, "flag_off"},
		{"converge off", "converge", func(e *capEnv) { e.convergeOn = func() bool { return false } }, "flag_off"},
		{"converge without jobs", "converge", func(e *capEnv) { e.jobsOn = func() bool { return false } }, "flag_off"},
		{"package none", "package", func(e *capEnv) { e.pkgBackend = func() string { return "" } }, "unsupported_os"},
		{"windows pty", "pty", func(e *capEnv) { e.goos = "windows" }, "unsupported_os"},
		{"windows jobs", "sysscript_jobs", func(e *capEnv) { e.goos = "windows" }, "unsupported_os"},
		{"darwin file", "file", func(e *capEnv) { e.goos = "darwin" }, "unsupported_os"},
		{"darwin config_write", "config_write", func(e *capEnv) { e.goos = "darwin" }, "unsupported_os"},
		{"darwin tweak", "tweak", func(e *capEnv) { e.goos = "darwin" }, "unsupported_os"},
		{"windows service", "service", func(e *capEnv) { e.goos = "windows"; e.serviceBackend = func() string { return "" } }, "unsupported_os"},
	}
	for _, c := range cases {
		e := fakeCapEnv()
		c.set(e)
		r := probeOne(t, e, c.cap)
		if r.State != capStateAbsent || r.Reason != c.reason {
			t.Errorf("%s: %+v, want absent %s", c.name, r, c.reason)
		}
	}
}

// No /run/systemd/system and no service backend at all (a plain container):
// only the helper-backed writes are absent no_systemd, and service is absent
// because there is no backend; tweak, pty, file, tcp and sysscript_jobs keep
// working.
func TestCapNoSystemdDegradesNeverBreaks(t *testing.T) {
	e := fakeCapEnv()
	e.systemd = func() bool { return false }
	e.serviceBackend = func() string { return "" }
	// A host without systemd must not even be asked about units.
	e.unitLoaded = func(string) (bool, error) { panic("unit probe without systemd") }
	e.managerUp = func(string) error { panic("manager probe without a backend") }
	got := capsByName(probeCapabilities(e, nil))
	for _, name := range []string{"service", "config_write", "sysctl_write", "override_write"} {
		if r := got[name]; r.State != capStateAbsent || r.Reason != "no_systemd" {
			t.Errorf("%s: %+v, want absent no_systemd", name, r)
		}
	}
	for _, name := range []string{"pty", "file", "tcp", "sysscript_jobs", "config", "tweak"} {
		if r := got[name]; r.State != capStateOK {
			t.Errorf("%s: %+v, want ok", name, r)
		}
	}
	sup, deg := capHeaderValues(probeCapabilities(e, nil))
	if strings.Contains(","+sup+",", ",service,") {
		t.Errorf("service advertised with no backend: %q", sup)
	}
	// The write tokens are still sent (a new agent), and listed degraded.
	if deg != "config_write,override_write,sysctl_write" {
		t.Errorf("degraded %q", deg)
	}
	for _, name := range []string{"config_write", "sysctl_write", "override_write"} {
		if !strings.Contains(","+sup+",", ","+name+",") {
			t.Errorf("%s missing from supported %q", name, sup)
		}
	}
	if !strings.Contains(","+sup+",", ",tweak,") {
		t.Errorf("tweak withdrawn without systemd: %q", sup)
	}
}

// An OpenRC host (no /run/systemd/system, rc-service present): service and
// tweak keep working as before; only the helper-backed writes are absent.
func TestCapOpenRCHost(t *testing.T) {
	e := fakeCapEnv()
	e.systemd = func() bool { return false }
	e.serviceBackend = func() string { return "openrc" }
	var asked []string
	e.managerUp = func(b string) error { asked = append(asked, b); return nil }
	e.unitLoaded = func(string) (bool, error) { panic("unit probe on openrc") }
	got := capsByName(probeCapabilities(e, nil))
	if r := got["service"]; r.State != capStateOK {
		t.Fatalf("service on openrc: %+v", r)
	}
	if len(asked) != 1 || asked[0] != "openrc" {
		t.Fatalf("manager probe asked %v, want the openrc backend", asked)
	}
	if r := got["tweak"]; r.State != capStateOK {
		t.Fatalf("tweak on openrc: %+v", r)
	}
	for _, name := range []string{"config_write", "sysctl_write", "override_write"} {
		if r := got[name]; r.State != capStateAbsent || r.Reason != "no_systemd" {
			t.Errorf("%s: %+v, want absent no_systemd", name, r)
		}
	}
	// rc-service not answering: degraded, still supported.
	e.managerUp = func(string) error { return leakyErr }
	if r := probeOne(t, e, "service"); r.State != capStateDegraded || r.Reason != "manager_unreachable" {
		t.Fatalf("dead openrc: %+v", r)
	}
	sup, deg := capHeaderValues(probeCapabilities(e, nil))
	if !strings.Contains(","+sup+",", ",service,") || deg != "config_write,override_write,service,sysctl_write" {
		t.Fatalf("supported %q degraded %q", sup, deg)
	}
}

// capManagerUp asks each backend its own read-only question; an unknown
// backend fails closed.
func TestCapManagerUpUnknownBackend(t *testing.T) {
	if capManagerUp("") == nil || capManagerUp("runit") == nil {
		t.Fatal("unknown backend reported up")
	}
}

// sysscript_jobs and converge: a transient stat error keeps the last known
// state and never makes them absent; only the flag does.
func TestCapJobsKeepLastKnownOnTransientError(t *testing.T) {
	e := fakeCapEnv()
	e.stateDir = func() error { return leakyErr }
	// No previous result: ok (never absent).
	for _, name := range []string{"sysscript_jobs", "converge"} {
		if r := probeOne(t, e, name); r.State != capStateOK {
			t.Fatalf("%s with no history: %+v", name, r)
		}
	}
	prev := map[string]capResult{
		"sysscript_jobs": capDegraded("sysscript_jobs", "probe_error"),
		"converge":       capOK("converge"),
	}
	got := capsByName(probeCapabilities(e, prev))
	if got["sysscript_jobs"] != prev["sysscript_jobs"] || got["converge"] != prev["converge"] {
		t.Fatalf("transient error changed the state: %+v", got)
	}
	e.jobsOn = func() bool { return false }
	got = capsByName(probeCapabilities(e, prev))
	if got["sysscript_jobs"].State != capStateAbsent || got["converge"].State != capStateAbsent {
		t.Fatalf("flag off must be absent: %+v", got)
	}
	// Through the manager: a good probe, then transient errors, stays ok.
	m := newCapManager(fakeCapEnv())
	m.probe()
	m.env.stateDir = func() error { return leakyErr }
	for i := 0; i < 3; i++ {
		if r := capsByName(m.probe())["sysscript_jobs"]; r.State != capStateOK {
			t.Fatalf("round %d: %+v", i, r)
		}
	}
}

// The report is bounded: registry names only, at most 16, states and
// reasons from the fixed sets, and no path or raw error text anywhere.
func TestCapReportBoundedAndClean(t *testing.T) {
	e := fakeCapEnv()
	fail := func() error { return leakyErr }
	e.openat2Root, e.configOpen, e.tweakRead, e.ptmx, e.trust, e.xferBin, e.stateDir = fail, fail, fail, fail, fail, fail, fail
	e.managerUp = func(string) error { return leakyErr }
	e.unitLoaded = func(string) (bool, error) { return false, leakyErr }
	e.pkgVersion = func(string) error { return leakyErr }
	m := newCapManager(e)
	out := &capFrameSink{}
	if sent, err := m.sendReport(out, make(chan struct{}), 15*time.Minute); !sent || err != nil {
		t.Fatalf("sent=%v err=%v", sent, err)
	}
	raw := out.raw()
	if len(raw) != 1 {
		t.Fatalf("%d frames", len(raw))
	}
	for _, bad := range []string{"/", "permission", "SECRET", "token", "denied", "helper-trust"} {
		if strings.Contains(raw[0], bad) {
			t.Fatalf("report leaks %q: %s", bad, raw[0])
		}
	}
	var f capReportFrame
	if err := json.Unmarshal([]byte(raw[0]), &f); err != nil {
		t.Fatal(err)
	}
	if f.Type != "capability_report" || f.V != 1 || len(f.Caps) == 0 || len(f.Caps) > capTokensMax {
		t.Fatalf("frame %+v", f)
	}
	if f.IntervalS != 900 || !strings.Contains(raw[0], `"interval_s":900`) {
		t.Fatalf("interval_s %d in %s", f.IntervalS, raw[0])
	}
	if ts, err := time.Parse(time.RFC3339, f.ProbedAt); err != nil || ts.Location() != time.UTC || !strings.HasSuffix(f.ProbedAt, "Z") {
		t.Fatalf("probed_at %q", f.ProbedAt)
	}
	for _, c := range f.Caps {
		if _, ok := capRegistry[c.Name]; !ok {
			t.Fatalf("unknown name %q", c.Name)
		}
		switch c.State {
		case capStateOK:
			if c.Reason != "" {
				t.Fatalf("ok with reason: %+v", c)
			}
		case capStateDegraded, capStateAbsent:
			if !capReasons[c.Reason] {
				t.Fatalf("reason outside the set: %+v", c)
			}
		default:
			t.Fatalf("bad state: %+v", c)
		}
	}

	// The gate itself: unknown names dropped, bad reasons and states
	// replaced, ok reasons cleared, at most 16.
	var in []capResult
	for i := 0; i < 40; i++ {
		in = append(in, capResult{Name: fmt.Sprintf("zz%d", i), State: capStateOK})
	}
	for name := range capRegistry {
		in = append(in, capResult{Name: name, State: capStateDegraded, Reason: "/etc/shadow"})
	}
	in = append(in, capResult{Name: "tcp", State: "weird", Reason: "x"}, capResult{Name: "pty", State: capStateOK, Reason: "leak"})
	got := boundCapResults(in)
	if len(got) > capTokensMax {
		t.Fatalf("%d entries", len(got))
	}
	for _, r := range got {
		if _, ok := capRegistry[r.Name]; !ok {
			t.Fatalf("unknown name kept: %+v", r)
		}
		if r.State == capStateOK && r.Reason != "" {
			t.Fatalf("ok reason kept: %+v", r)
		}
		if r.State != capStateOK && !capReasons[r.Reason] {
			t.Fatalf("bad reason kept: %+v", r)
		}
		if r.State != capStateOK && r.State != capStateDegraded && r.State != capStateAbsent {
			t.Fatalf("bad state kept: %+v", r)
		}
	}
}

func TestCapHeaderTokenBounds(t *testing.T) {
	var many []string
	for i := 0; i < 40; i++ {
		many = append(many, fmt.Sprintf("tok_%011d", i)) // 15 bytes each
	}
	v := joinCapTokens(many)
	if n := len(strings.Split(v, ",")); n > capTokensMax || len(v) > capHeaderMax {
		t.Fatalf("%d tokens, %d bytes", n, len(v))
	}
	if got := joinCapTokens([]string{"ok_one", "Bad", "has space", "/etc", "this_is_far_too_long_a_token", "ok_two"}); got != "ok_one,ok_two" {
		t.Fatalf("got %q", got)
	}
	var long []string
	for i := 0; i < 16; i++ {
		long = append(long, fmt.Sprintf("t%015d", i)) // 16 bytes: 16*17-1 = 271 > 256
	}
	if v := joinCapTokens(long); len(v) > capHeaderMax {
		t.Fatalf("%d bytes", len(v))
	}
}

// A probe that fails at dial time lands in the degraded header and stays in
// the supported one.
func TestCapStartFailedProbeInDegradedHeader(t *testing.T) {
	e := fakeCapEnv()
	e.openat2Root = func() error { return syscall.ENOSYS }
	e.trust = func() error { return leakyErr }
	sup, deg := newCapManager(e).dialHeaders()
	if deg != "config_write,file,override_write,sysctl_write,xfer" {
		t.Fatalf("degraded %q", deg)
	}
	for _, name := range strings.Split(deg, ",") {
		if !strings.Contains(","+sup+",", ","+name+",") {
			t.Fatalf("degraded %s missing from supported %q", name, sup)
		}
	}
	// Absent is in neither.
	e.xferConfigured = func() bool { return false }
	sup, deg = newCapManager(e).dialHeaders()
	if strings.Contains(sup, "xfer") || strings.Contains(deg, "xfer") {
		t.Fatalf("absent xfer advertised: %q / %q", sup, deg)
	}
}

// A dial during a slow probe does not wait for it: it uses the last
// complete results. The slow probe's results are swapped in when it ends.
func TestCapDialDoesNotWaitBehindSlowProbe(t *testing.T) {
	e := fakeCapEnv()
	var block atomic.Bool
	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	e.tweakRead = func() error {
		if block.Load() {
			select {
			case entered <- struct{}{}:
			default:
			}
			<-release
			return leakyErr
		}
		return nil
	}
	m := newCapManager(e)
	m.probe() // the last complete results: all ok
	block.Store(true)
	slowDone := make(chan struct{})
	go func() { m.probe(); close(slowDone) }()
	<-entered

	dialed := make(chan [2]string, 1)
	go func() { s, d := m.dialHeaders(); dialed <- [2]string{s, d} }()
	select {
	case h := <-dialed:
		if !strings.Contains(","+h[0]+",", ",tweak,") || h[1] != "" {
			t.Fatalf("dial headers %q", h)
		}
	case <-time.After(2 * time.Second):
		close(release)
		t.Fatal("dial waited behind the running probe")
	}
	// A report's gap check and the frame write do not hold the lock either:
	// untilAllowed answers at once.
	waitDone := make(chan struct{})
	go func() { m.untilAllowed(time.Now()); close(waitDone) }()
	select {
	case <-waitDone:
	case <-time.After(2 * time.Second):
		t.Fatal("untilAllowed blocked behind a probe")
	}
	close(release)
	<-slowDone
	if r := capsByName(m.lastRes)["tweak"]; r.State != capStateDegraded {
		t.Fatalf("slow probe result not swapped in: %+v", r)
	}
}

func TestCapIntervalAndJitter(t *testing.T) {
	for _, d := range []time.Duration{0, 59 * time.Second, 61 * time.Minute} {
		if parseCapabilityInterval(d) == nil {
			t.Fatalf("%s accepted", d)
		}
	}
	for _, d := range []time.Duration{time.Minute, 10 * time.Minute, 60 * time.Minute} {
		if err := parseCapabilityInterval(d); err != nil {
			t.Fatalf("%s: %v", d, err)
		}
	}
	for i := 0; i < 200; i++ {
		j := capJitter(10 * time.Minute)
		if j < 9*time.Minute || j > 11*time.Minute {
			t.Fatalf("jitter %s", j)
		}
	}
}

func TestCheckHelperTrustFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("owner checks are unix only")
	}
	path := withHelperTrust(t, make([]byte, 32), ptyTestHost)
	if err := checkHelperTrustFile(); err != nil {
		t.Fatalf("good trust file: %v", err)
	}
	// Any mode without a group or other write bit is fine.
	for _, mode := range []os.FileMode{0o600, 0o640, 0o644, 0o400} {
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		if err := checkHelperTrustFile(); err != nil {
			t.Fatalf("mode %o refused: %v", mode, err)
		}
	}
	// Group or world writable is refused.
	for _, mode := range []os.FileMode{0o664, 0o646, 0o666, 0o620} {
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		if checkHelperTrustFile() == nil {
			t.Fatalf("mode %o accepted", mode)
		}
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	// Not owned by the trusted owner (root in production): refused.
	prevUID := helperTrustOwnerUID
	helperTrustOwnerUID = prevUID + 1
	if checkHelperTrustFile() == nil {
		t.Fatal("foreign-owned trust file accepted")
	}
	helperTrustOwnerUID = prevUID
	// A symlink to a good file: refused.
	good, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	real := path + ".real"
	if err := os.WriteFile(real, good, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, path); err != nil {
		t.Fatal(err)
	}
	if checkHelperTrustFile() == nil {
		t.Fatal("symlinked trust file accepted")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("{not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	if checkHelperTrustFile() == nil {
		t.Fatal("unparseable trust file accepted")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if checkHelperTrustFile() == nil {
		t.Fatal("missing trust file accepted")
	}
}

func TestStatDir(t *testing.T) {
	if !errors.Is(statDir(""), errCapMissing) {
		t.Fatal("unset dir accepted")
	}
	dir := t.TempDir()
	if err := statDir(dir); err != nil {
		t.Fatal(err)
	}
	if !errors.Is(statDir(dir+"/gone"), errCapMissing) {
		t.Fatal("missing dir")
	}
	f := dir + "/file"
	if err := os.WriteFile(f, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if !errors.Is(statDir(f), errCapMissing) {
		t.Fatal("a file is not a dir")
	}
}

// The real env on this host: the old switches still decide.
func hasCap(name string) bool {
	return strings.Contains(","+capabilitiesHeaderValue()+",", ","+name+",")
}

func TestCapabilitiesAlwaysAdvertised(t *testing.T) {
	for _, must := range []string{"config", "tcp"} {
		if !hasCap(must) {
			t.Fatalf("capability %q must always be advertised, got %q", must, capabilitiesHeaderValue())
		}
	}
	if got := hasCap("file"); got != (runtime.GOOS == "linux") {
		t.Fatalf("file supported=%v on %s", got, runtime.GOOS)
	}
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

// capFrameSink is a ptyOut that records capability_report frames.
type capFrameSink struct {
	mu     sync.Mutex
	frames []string
	at     []time.Time
}

func (s *capFrameSink) WriteJSON(v interface{}) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.frames = append(s.frames, string(b))
	s.at = append(s.at, time.Now())
	s.mu.Unlock()
	return nil
}
func (s *capFrameSink) WriteBinary([]byte) error { return nil }
func (s *capFrameSink) WriteText(b []byte) error { return s.WriteJSON(json.RawMessage(b)) }
func (s *capFrameSink) raw() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.frames...)
}
func (s *capFrameSink) times() []time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]time.Time(nil), s.at...)
}

// Reports go out at most once per capReportMinGap, also under
// capability_probe spam; a probe inside the gap is answered at its end.
func TestCapReportsRateLimited(t *testing.T) {
	defer func(prev time.Duration) { capReportMinGap = prev }(capReportMinGap)
	capReportMinGap = 300 * time.Millisecond
	m := newCapManager(fakeCapEnv())
	out := &capFrameSink{}
	probe := make(chan struct{}, 1)
	quit := make(chan struct{})
	done := make(chan struct{})
	start := time.Now()
	go func() { m.serve(out, probe, quit, time.Hour); close(done) }()
	waitFor(t, "first report", 2*time.Second, func() bool { return len(out.raw()) == 1 })
	// Spam for ~1 s.
	spamEnd := time.Now().Add(time.Second)
	for time.Now().Before(spamEnd) {
		select {
		case probe <- struct{}{}:
		default:
		}
		time.Sleep(2 * time.Millisecond)
	}
	time.Sleep(capReportMinGap + 100*time.Millisecond)
	close(quit)
	<-done
	ts := out.times()
	elapsed := time.Since(start)
	if max := int(elapsed/capReportMinGap) + 1; len(ts) > max {
		t.Fatalf("%d reports in %s (max %d)", len(ts), elapsed, max)
	}
	if len(ts) < 3 {
		t.Fatalf("probe requests not answered: %d reports", len(ts))
	}
	for i := 1; i < len(ts); i++ {
		if gap := ts[i].Sub(ts[i-1]); gap < capReportMinGap {
			t.Fatalf("reports %d and %d only %s apart", i-1, i, gap)
		}
	}

	// A single probe inside the gap is answered when the gap ends, not
	// dropped and not early.
	m2 := newCapManager(fakeCapEnv())
	out2 := &capFrameSink{}
	probe2 := make(chan struct{}, 1)
	quit2 := make(chan struct{})
	done2 := make(chan struct{})
	go func() { m2.serve(out2, probe2, quit2, time.Hour); close(done2) }()
	waitFor(t, "first report", 2*time.Second, func() bool { return len(out2.raw()) == 1 })
	probe2 <- struct{}{}
	waitFor(t, "probe answered", 2*time.Second, func() bool { return len(out2.raw()) == 2 })
	close(quit2)
	<-done2
	ts2 := out2.times()
	if gap := ts2[1].Sub(ts2[0]); gap < capReportMinGap {
		t.Fatalf("probe answered after %s, inside the gap", gap)
	}
}

// Every cycle sends a report (the heartbeat).
func TestCapReportsEveryCycle(t *testing.T) {
	defer func(prev time.Duration) { capReportMinGap = prev }(capReportMinGap)
	capReportMinGap = 20 * time.Millisecond
	m := newCapManager(fakeCapEnv())
	out := &capFrameSink{}
	quit := make(chan struct{})
	done := make(chan struct{})
	go func() { m.serve(out, make(chan struct{}), quit, 60*time.Millisecond); close(done) }()
	waitFor(t, "three cycle reports", 3*time.Second, func() bool { return len(out.raw()) >= 3 })
	close(quit)
	<-done
}

// capServer is a fake control plane that records each dial's capability
// headers and every capability_report, and sends capability_probe frames.
type capServer struct {
	mu      sync.Mutex
	dials   [][2]string
	reports []capReportFrame
	probes  int // capability_probe frames to send after the first report
	conns   int64
	dropAt  int64 // close the first connection after its first report
	early   bool  // send the probes right after enroll
}

func (s *capServer) start(t *testing.T, a **agentConn, pub string) *httptest.Server {
	t.Helper()
	up := websocket.Upgrader{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		s.dials = append(s.dials, [2]string{r.Header.Get(capabilitiesHeader), r.Header.Get(capabilitiesDegradedHeader)})
		_, hasDeg := r.Header[http.CanonicalHeaderKey(capabilitiesDegradedHeader)]
		if !hasDeg {
			s.dials[len(s.dials)-1][1] = "<none>"
		}
		s.mu.Unlock()
		c, err := up.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer c.Close()
		n := atomic.AddInt64(&s.conns, 1)
		_ = c.WriteJSON(map[string]string{"type": "enrolled", "host_id": (*a).st.HostID, "control_pubkey": pub})
		sent := 0
		if s.early {
			for ; sent < s.probes; sent++ {
				_ = c.WriteJSON(map[string]string{"type": "capability_probe"})
			}
		}
		for {
			_, msg, err := c.ReadMessage()
			if err != nil {
				return
			}
			var peek struct {
				Type string `json:"type"`
			}
			_ = json.Unmarshal(msg, &peek)
			if peek.Type != "capability_report" {
				continue
			}
			var f capReportFrame
			_ = json.Unmarshal(msg, &f)
			s.mu.Lock()
			s.reports = append(s.reports, f)
			probes := s.probes
			s.mu.Unlock()
			if n == 1 && s.dropAt > 0 {
				return
			}
			for ; sent < probes; sent++ {
				_ = c.WriteJSON(map[string]string{"type": "capability_probe"})
			}
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func (s *capServer) snapshot() ([][2]string, []capReportFrame) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([][2]string(nil), s.dials...), append([]capReportFrame(nil), s.reports...)
}

// Both headers are recomputed on every dial: a capability that failed on
// the first dial and recovered is healthy on the redial, and the degraded
// header is omitted when empty.
func TestCapHeadersRecomputedOnRedial(t *testing.T) {
	defer func(prev time.Duration) { capReportMinGap = prev }(capReportMinGap)
	capReportMinGap = 10 * time.Millisecond
	pub := controlKeyB64(t)
	var a *agentConn
	s := &capServer{dropAt: 1}
	srv := s.start(t, &a, pub)
	a = testConn(t, srv, "good")
	e := fakeCapEnv()
	var dial int64
	e.openat2Root = func() error {
		if atomic.LoadInt64(&dial) <= 1 {
			return syscall.ENOSYS
		}
		return nil
	}
	m := newCapManager(e)
	a.capHeaders = func() (string, string) {
		atomic.AddInt64(&dial, 1)
		return m.dialHeaders()
	}
	a.caps = m
	a.capInterval = time.Hour
	stop := make(chan struct{})
	result := make(chan error, 1)
	go func() { result <- a.run(stop) }()
	waitFor(t, "second dial", 5*time.Second, func() bool { d, _ := s.snapshot(); return len(d) >= 2 })
	close(stop)
	<-result
	dials, reports := s.snapshot()
	if !strings.Contains(dials[0][0], "file") || dials[0][1] != "file,xfer" {
		t.Fatalf("first dial %q", dials[0])
	}
	if !strings.Contains(dials[1][0], "file") || dials[1][1] != "<none>" {
		t.Fatalf("redial %q", dials[1])
	}
	if !strings.Contains(dials[0][0], "config_write") || !strings.Contains(dials[0][0], "sysctl_write") || !strings.Contains(dials[0][0], "override_write") {
		t.Fatalf("new write tokens missing: %q", dials[0][0])
	}
	if len(reports) == 0 {
		t.Fatal("no capability_report after enroll")
	}
}

// fakeFileInfo is a FileInfo for the brew probe's fake stat.
type fakeFileInfo struct {
	mode os.FileMode
	uid  int
}

func (f fakeFileInfo) Name() string       { return "brew" }
func (f fakeFileInfo) Size() int64        { return 1 }
func (f fakeFileInfo) Mode() os.FileMode  { return f.mode }
func (f fakeFileInfo) ModTime() time.Time { return time.Time{} }
func (f fakeFileInfo) IsDir() bool        { return f.mode.IsDir() }
func (f fakeFileInfo) Sys() interface{}   { return nil }

func fakeOwner(fi os.FileInfo) (int, int, bool) { return fi.(fakeFileInfo).uid, 0, true }

// M1: brew is never executed; as root, a brew not owned by root is a probe
// error (degraded probe_error), and nothing runs either way.
func TestBrewProbeChecksPresenceOnly(t *testing.T) {
	statOf := func(fi fakeFileInfo) func(string) (os.FileInfo, error) {
		return func(string) (os.FileInfo, error) { return fi, nil }
	}
	userBrew := fakeFileInfo{mode: 0o755, uid: 501}
	rootBrew := fakeFileInfo{mode: 0o755, uid: 0}
	if err := brewPresent("/opt/homebrew/bin/brew", statOf(userBrew), fakeOwner, 0); err == nil || errors.Is(err, errCapMissing) {
		t.Fatalf("root agent accepted a user-owned brew: %v", err)
	}
	if err := brewPresent("/opt/homebrew/bin/brew", statOf(rootBrew), fakeOwner, 0); err != nil {
		t.Fatalf("root-owned brew as root: %v", err)
	}
	if err := brewPresent("/opt/homebrew/bin/brew", statOf(userBrew), fakeOwner, 501); err != nil {
		t.Fatalf("user brew for a non-root agent: %v", err)
	}
	if err := brewPresent("x", statOf(fakeFileInfo{mode: os.ModeDir | 0o755}), fakeOwner, 0); !errors.Is(err, errCapMissing) {
		t.Fatalf("a directory is not brew: %v", err)
	}
	if err := brewPresent("x", func(string) (os.FileInfo, error) { return nil, os.ErrNotExist }, fakeOwner, 0); !errors.Is(err, errCapMissing) {
		t.Fatalf("dangling brew symlink: %v", err)
	}
	// Through the probe: the user-owned case reports degraded probe_error.
	e := fakeCapEnv()
	e.goos = "darwin"
	e.pkgBackend = func() string { return "brew" }
	e.pkgVersion = func(string) error {
		return brewPresent("/opt/homebrew/bin/brew", statOf(userBrew), fakeOwner, 0)
	}
	if r := probeOne(t, e, "package"); r.State != capStateDegraded || r.Reason != "probe_error" {
		t.Fatalf("package with a user brew as root: %+v", r)
	}
}

// L1: the write tokens are in the supported header on every new agent; where
// absent they are also in the degraded header, and the report says absent
// with its reason.
func TestCapWriteTokensAlwaysSent(t *testing.T) {
	noSystemd := fakeCapEnv()
	noSystemd.systemd = func() bool { return false }
	mac := fakeCapEnv()
	mac.goos = "darwin"
	mac.serviceBackend = func() string { return "launchd" }
	for _, c := range []struct {
		name   string
		e      *capEnv
		reason string
	}{{"no systemd", noSystemd, "no_systemd"}, {"macOS", mac, "unsupported_os"}} {
		res := probeCapabilities(c.e, nil)
		sup, deg := capHeaderValues(res)
		got := capsByName(res)
		for _, name := range []string{"config_write", "sysctl_write", "override_write"} {
			if !strings.Contains(","+sup+",", ","+name+",") {
				t.Errorf("%s: %s missing from supported %q", c.name, name, sup)
			}
			if !strings.Contains(","+deg+",", ","+name+",") {
				t.Errorf("%s: %s missing from degraded %q", c.name, name, deg)
			}
			if r := got[name]; r.State != capStateAbsent || r.Reason != c.reason {
				t.Errorf("%s: report %+v, want absent %s", c.name, r, c.reason)
			}
		}
		// Other absent capabilities stay out of both headers.
		if c.name == "macOS" && (strings.Contains(sup, "file") || strings.Contains(deg, "file")) {
			t.Errorf("absent file advertised on macOS: %q / %q", sup, deg)
		}
	}
}

// L6: a slow older probe finishing after a newer one does not overwrite it.
func TestCapOlderProbeNeverOverwritesNewer(t *testing.T) {
	e := fakeCapEnv()
	var calls atomic.Int32
	entered := make(chan struct{})
	release := make(chan struct{})
	e.tweakRead = func() error {
		if calls.Add(1) == 1 {
			close(entered)
			<-release
			return leakyErr // the older, slow probe sees tweak broken
		}
		return nil // the newer probe sees it ok
	}
	m := newCapManager(e)
	oldDone := make(chan struct{})
	go func() { m.probe(); close(oldDone) }()
	<-entered
	m.probe() // newer, finishes first
	close(release)
	<-oldDone
	if r := capsByName(m.lastRes)["tweak"]; r.State != capStateOK {
		t.Fatalf("older probe overwrote lastRes: %+v", r)
	}
	if r := m.last["tweak"]; r.State != capStateOK {
		t.Fatalf("older probe overwrote last: %+v", r)
	}
}

// L6: a report whose own probe was superseded by a newer one sends the
// newer results (lastRes), never its stale ones.
func TestCapSupersededReportSendsNewest(t *testing.T) {
	e := fakeCapEnv()
	var calls atomic.Int32
	entered := make(chan struct{})
	release := make(chan struct{})
	e.tweakRead = func() error {
		if calls.Add(1) == 1 {
			close(entered)
			<-release
			return leakyErr // the report's own, older probe sees tweak broken
		}
		return nil // the newer probe sees it ok
	}
	m := newCapManager(e)
	out := &capFrameSink{}
	done := make(chan struct{})
	go func() {
		if sent, err := m.sendReport(out, make(chan struct{}), time.Hour); !sent || err != nil {
			t.Errorf("sent=%v err=%v", sent, err)
		}
		close(done)
	}()
	<-entered
	m.probe() // newer, finishes first
	close(release)
	<-done
	raw := out.raw()
	if len(raw) != 1 {
		t.Fatalf("%d frames", len(raw))
	}
	var f capReportFrame
	if err := json.Unmarshal([]byte(raw[0]), &f); err != nil {
		t.Fatal(err)
	}
	if r := capsByName(f.Caps)["tweak"]; r.State != capStateOK {
		t.Fatalf("superseded report sent the stale result: %+v", r)
	}
	if f.IntervalS != 3600 {
		t.Fatalf("interval_s %d", f.IntervalS)
	}
}

func TestCapIntervalSeconds(t *testing.T) {
	for _, c := range []struct {
		d    time.Duration
		want int
	}{{time.Minute, 60}, {90*time.Second + 500*time.Millisecond, 90}, {10 * time.Minute, 600}, {time.Hour, 3600}, {0, 60}, {2 * time.Hour, 3600}} {
		if got := capIntervalSeconds(c.d); got != c.want {
			t.Errorf("capIntervalSeconds(%s) = %d, want %d", c.d, got, c.want)
		}
	}
}

// L6: a closed connection's goroutine never sends a pending report nor
// reserves the report gap.
func TestCapClosedConnectionSendsNothing(t *testing.T) {
	m := newCapManager(fakeCapEnv())
	out := &capFrameSink{}
	quit := make(chan struct{})
	close(quit)
	if sent, err := m.sendReport(out, quit, time.Hour); sent || err != nil {
		t.Fatalf("sent=%v err=%v on a closed connection", sent, err)
	}
	done := make(chan struct{})
	probe := make(chan struct{}, 1)
	probe <- struct{}{}
	go func() { m.serve(out, probe, quit, time.Hour); close(done) }()
	<-done
	if n := len(out.raw()); n != 0 {
		t.Fatalf("%d frames from a closed connection", n)
	}
	if m.sentAny || !m.lastSent.IsZero() {
		t.Fatal("a closed connection reserved the report gap")
	}

	// Closed while its probe runs: nothing is written and the reservation is
	// given back.
	e := fakeCapEnv()
	quit2 := make(chan struct{})
	e.tweakRead = func() error { close(quit2); return nil }
	m2 := newCapManager(e)
	if sent, _ := m2.sendReport(out, quit2, time.Hour); sent {
		t.Fatal("report sent after the connection closed mid-probe")
	}
	if len(out.raw()) != 0 || m2.sentAny {
		t.Fatal("frame written or gap kept after a mid-probe close")
	}
}

// After enroll a report goes out; capability_probe frames get answered,
// rate limited; --capability-reports=false sends no frame at all but keeps
// the degraded header.
func TestCapReportsOverTheConnection(t *testing.T) {
	defer func(prev time.Duration) { capReportMinGap = prev }(capReportMinGap)
	capReportMinGap = 200 * time.Millisecond
	pub := controlKeyB64(t)

	var a *agentConn
	s := &capServer{probes: 25}
	srv := s.start(t, &a, pub)
	a = testConn(t, srv, "good")
	m := newCapManager(fakeCapEnv())
	a.capHeaders, a.caps, a.capInterval = m.dialHeaders, m, time.Hour
	stop := make(chan struct{})
	result := make(chan error, 1)
	start := time.Now()
	go func() { result <- a.run(stop) }()
	waitFor(t, "probe answered", 5*time.Second, func() bool { _, r := s.snapshot(); return len(r) >= 2 })
	time.Sleep(500 * time.Millisecond)
	close(stop)
	<-result
	_, reports := s.snapshot()
	if max := int(time.Since(start)/capReportMinGap) + 1; len(reports) > max {
		t.Fatalf("%d reports for 25 probes in %s (max %d)", len(reports), time.Since(start), max)
	}
	if reports[0].Type != "capability_report" || reports[0].V != 1 || len(reports[0].Caps) != len(capRegistry) {
		t.Fatalf("report %+v", reports[0])
	}

	var b *agentConn
	off := &capServer{probes: 5, early: true}
	srv2 := off.start(t, &b, pub)
	b = testConn(t, srv2, "good")
	e := fakeCapEnv()
	e.openat2Root = func() error { return syscall.ENOSYS }
	m2 := newCapManager(e)
	b.capHeaders, b.caps = m2.dialHeaders, nil // --capability-reports=false
	stop2 := make(chan struct{})
	result2 := make(chan error, 1)
	go func() { result2 <- b.run(stop2) }()
	waitFor(t, "dial", 5*time.Second, func() bool { d, _ := off.snapshot(); return len(d) >= 1 })
	time.Sleep(400 * time.Millisecond)
	close(stop2)
	<-result2
	dials, reports2 := off.snapshot()
	if len(reports2) != 0 {
		t.Fatalf("--capability-reports=false sent %d reports", len(reports2))
	}
	if dials[0][1] != "file,xfer" {
		t.Fatalf("degraded header with reports off: %q", dials[0][1])
	}
}

// The helper probes ask systemctl about an instance (systemd refuses `show`
// on a bare template) and map its answer: loaded -> ok, not-found or any
// other state -> helper_unit_missing, a failed or empty answer ->
// manager_unreachable.
func TestCapHelperProbeAsksAnInstance(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("needs sh for real systemctl-style exit codes")
	}
	exit4 := exec.Command("sh", "-c", "exit 4").Run()
	exit1 := exec.Command("sh", "-c", "exit 1").Run()
	cases := []struct {
		name   string
		out    string
		err    error
		state  string
		reason string
	}{
		{"template present", "loaded", nil, capStateOK, ""},
		{"template missing", "not-found", nil, capStateDegraded, "helper_unit_missing"},
		{"masked", "masked", nil, capStateDegraded, "helper_unit_missing"},
		{"bad unit file", "error", nil, capStateDegraded, "helper_unit_missing"},
		{"no such unit exit", "", exit4, capStateDegraded, "helper_unit_missing"},
		{"systemctl failed", "", exit1, capStateDegraded, "manager_unreachable"},
		{"systemctl missing", "", errCapMissing, capStateDegraded, "manager_unreachable"},
		{"empty answer", "", nil, capStateDegraded, "manager_unreachable"},
	}
	want := map[string]string{
		"config_write":   "sah-config-helper@probe.service",
		"sysctl_write":   "sah-sysctl-helper@probe.service",
		"override_write": "sah-systemd-override-helper@probe.service",
	}
	for _, c := range cases {
		for capName, unit := range want {
			var asked [][]string
			e := fakeCapEnv()
			e.unitLoaded = func(u string) (bool, error) {
				return capUnitLoaded(func(args ...string) (string, error) {
					asked = append(asked, args)
					return c.out, c.err
				}, u)
			}
			r := probeOne(t, e, capName)
			if r.State != c.state || r.Reason != c.reason {
				t.Errorf("%s %s: %+v, want %s %s", c.name, capName, r, c.state, c.reason)
			}
			var mine []string
			for _, a := range asked {
				if a[len(a)-1] == unit {
					mine = a
				}
			}
			if strings.Join(mine, " ") != "show -p LoadState --value "+unit {
				t.Errorf("%s %s: systemctl asked %q, want an instance query for %s", c.name, capName, asked, unit)
			}
			for _, a := range asked {
				if strings.HasSuffix(a[len(a)-1], "@.service") {
					t.Errorf("%s %s: bare template queried: %q", c.name, capName, a)
				}
			}
		}
	}
}

// The probe instance must never be a real request id, or a probe could
// name (and load over) a live request's helper unit.
func TestCapHelperProbeInstanceIsNotARequestID(t *testing.T) {
	for _, re := range []*regexp.Regexp{configHelperIDRE, sysctlHelperIDRE, overrideHelperIDRE} {
		if re.MatchString(capHelperProbeInstance) {
			t.Fatalf("probe instance %q matches request id %s", capHelperProbeInstance, re)
		}
	}
}
