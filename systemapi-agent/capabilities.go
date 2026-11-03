// Capability advertisement and health (.omc/plans/sah-fleet-readiness.md
// P1a). On every dial the agent sends X-SystemAPI-Capabilities, the
// capabilities this binary SUPPORTS on this OS with these flags, and
// X-SystemAPI-Capabilities-Degraded, the supported ones whose probe failed
// right then. After enroll it sends a capability_report frame every cycle
// (--capability-interval, jittered), and on a server capability_probe frame,
// never more than one per capReportMinGap. Each capability has one probe
// here; every probe is read-only and cheap: it never starts a privileged unit,
// never takes a package-manager lock and never writes.
//
// Threats: a capability that silently stopped working (openat2 refused by a
// seccomp filter, a helper unit or trust file not installed, a dead service
// manager) being routed to as if healthy; and a report leaking host detail.
// Every probe result is reduced to a name from capRegistry, a state from a
// closed set and a reason from capReasons, so a report or header never
// carries a path, an error text or anything read from the host; the token
// grammar and the 16-token / 256-byte header bound are enforced on the way
// out. Health is self-reported: it detects breakage, NOT compromise (a
// compromised agent can report everything ok). The headers and reports are
// advisory routing input for the server; they never grant anything. Leases,
// scopes and the agent's own allowlists still decide every request.
package main

import (
	"context"
	"crypto/rand"
	"errors"
	"io"
	"io/fs"
	"log"
	"math/big"
	"os"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	capabilitiesHeader         = "X-SystemAPI-Capabilities"
	capabilitiesDegradedHeader = "X-SystemAPI-Capabilities-Degraded"

	capStateOK       = "ok"
	capStateDegraded = "degraded"
	capStateAbsent   = "absent"

	// capTokensMax and capHeaderMax are the server's parseCapabilities
	// bounds (controlplane/channels.js).
	capTokensMax = 16
	capHeaderMax = 256

	// capProbeTimeout bounds each command a probe runs.
	capProbeTimeout = 5 * time.Second

	capIntervalDefault = 10 * time.Minute
	capIntervalMin     = time.Minute
	capIntervalMax     = 60 * time.Minute
)

// capReportMinGap is the least time between two capability_report frames.
// A var only so tests can shorten it.
var capReportMinGap = 60 * time.Second

var capNameRE = regexp.MustCompile(`^[a-z][a-z0-9_]{0,15}$`)

// capReasons is the closed reason set of the capability_report frame.
var capReasons = map[string]bool{
	"enosys_openat2":       true,
	"binary_missing":       true,
	"helper_unit_missing":  true,
	"helper_trust_missing": true,
	"manager_unreachable":  true,
	"flag_off":             true,
	"unsupported_os":       true,
	"no_systemd":           true,
	"probe_error":          true,
}

// The privileged helper templates the write-side capabilities depend on.
const (
	configHelperTemplate   = configHelperUnitPrefix + ".service"
	sysctlHelperTemplate   = sysctlHelperUnitPrefix + ".service"
	overrideHelperTemplate = overrideHelperUnitPrefix + ".service"
)

// errCapMissing marks a probe target that does not exist (a binary or a
// directory), as opposed to one that could not be checked.
var errCapMissing = errors.New("missing")

// capResult is one capability's probe outcome, as reported.
type capResult struct {
	Name   string `json:"name"`
	State  string `json:"state"`
	Reason string `json:"reason"`
}

func capOK(name string) capResult { return capResult{Name: name, State: capStateOK} }
func capDegraded(name, reason string) capResult {
	return capResult{Name: name, State: capStateDegraded, Reason: reason}
}
func capAbsent(name, reason string) capResult {
	return capResult{Name: name, State: capStateAbsent, Reason: reason}
}

// capEnv is every host check a probe makes. Each answers only a bool or an
// error, which the probe maps to a fixed reason code. Tests replace it.
type capEnv struct {
	goos string
	// systemd reports whether /run/systemd/system is a directory.
	systemd func() bool
	// openat2Root opens "/" with openat2(O_PATH|O_DIRECTORY).
	openat2Root func() error
	// configOpen is the config read path's check: a read-only openat2 open
	// of /etc/hostname on Linux.
	configOpen func() error
	// tweakRead reads /proc/sys/kernel/hostname.
	tweakRead func() error
	// ptmx stats /dev/ptmx.
	ptmx func() error
	// serviceBackend names the platform's service backend when it is
	// available (platform_service.go: systemd, openrc, launchd), else "".
	serviceBackend func() string
	// managerUp checks that backend answers, read-only: systemctl show -p
	// Version, rc-service --version, or the launchd backend's own check.
	managerUp func(backend string) error
	// unitLoaded reports whether a unit's LoadState is "loaded"; an error
	// means the manager did not answer.
	unitLoaded func(unit string) (bool, error)
	// trust checks the helpers' trust file.
	trust func() error
	// xferConfigured reports whether --xfer-bin (and on macOS
	// --xfer-allow-darwin) is set.
	xferConfigured func() bool
	// xferBin re-checks --xfer-bin with checkXferBin.
	xferBin func() error
	// pkgBackend names this host's package backend ("" for none).
	pkgBackend func() string
	// pkgVersion runs the backend's version query; errCapMissing when its
	// binary is not installed.
	pkgVersion func(backend string) error
	jobsOn     func() bool
	convergeOn func() bool
	// stateDir stats the agent's state directory; errCapMissing when it is
	// gone or not a directory.
	stateDir func() error
}

// capRegistry is every capability this agent knows, with its probe. prev is
// the last result of that capability ("" state when none), used where a
// transient probe error must not flip the state.
var capRegistry = map[string]func(e *capEnv, prev capResult) capResult{
	"tcp":          func(e *capEnv, _ capResult) capResult { return capOK("tcp") },
	"pty":          probePTY,
	"file":         probeFile,
	"xfer":         probeXfer,
	"config":       probeConfig,
	"config_write": probeConfigWrite,
	"tweak":        probeTweak,
	"sysctl_write": func(e *capEnv, _ capResult) capResult {
		return probeHelperWrite(e, "sysctl_write", sysctlHelperTemplate)
	},
	"override_write": func(e *capEnv, _ capResult) capResult {
		return probeHelperWrite(e, "override_write", overrideHelperTemplate)
	},
	"service":        probeService,
	"package":        probePackage,
	"sysscript_jobs": probeSysscriptJobs,
	"converge":       probeConverge,
}

// openat2Reason maps an openat2 failure: ENOSYS (an old kernel) and EPERM (a
// seccomp filter; opening "/" O_PATH cannot otherwise be refused) are
// enosys_openat2, anything else probe_error.
func openat2Reason(err error) string {
	if errors.Is(err, syscall.ENOSYS) || errors.Is(err, syscall.EPERM) {
		return "enosys_openat2"
	}
	return "probe_error"
}

func probePTY(e *capEnv, _ capResult) capResult {
	if e.goos == "windows" {
		return capAbsent("pty", "unsupported_os")
	}
	if e.ptmx() != nil {
		return capDegraded("pty", "probe_error")
	}
	return capOK("pty")
}

func probeFile(e *capEnv, _ capResult) capResult {
	if e.goos != "linux" {
		return capAbsent("file", "unsupported_os")
	}
	if err := e.openat2Root(); err != nil {
		return capDegraded("file", openat2Reason(err))
	}
	return capOK("file")
}

func probeXfer(e *capEnv, _ capResult) capResult {
	if e.goos != "linux" && e.goos != "darwin" {
		return capAbsent("xfer", "unsupported_os")
	}
	if !e.xferConfigured() {
		return capAbsent("xfer", "flag_off")
	}
	if e.goos == "linux" {
		if err := e.openat2Root(); err != nil {
			return capDegraded("xfer", openat2Reason(err))
		}
	}
	if e.xferBin() != nil {
		return capDegraded("xfer", "binary_missing")
	}
	return capOK("xfer")
}

// probeConfig: config (read, reload) is supported everywhere, as before;
// the probe is the read path's own open.
func probeConfig(e *capEnv, _ capResult) capResult {
	if err := e.configOpen(); err != nil {
		if e.goos == "linux" {
			return capDegraded("config", openat2Reason(err))
		}
		return capDegraded("config", "probe_error")
	}
	return capOK("config")
}

// linuxSystemd answers the absent cases shared by every systemd-backed
// capability: not Linux, or no live systemd.
func linuxSystemd(e *capEnv, name string) (capResult, bool) {
	if e.goos != "linux" {
		return capAbsent(name, "unsupported_os"), false
	}
	if !e.systemd() {
		return capAbsent(name, "no_systemd"), false
	}
	return capResult{}, true
}

// helperReady checks a helper template is loaded and the trust file usable.
func helperReady(e *capEnv, name, unit string) capResult {
	loaded, err := e.unitLoaded(unit)
	if err != nil {
		return capDegraded(name, "manager_unreachable")
	}
	if !loaded {
		return capDegraded(name, "helper_unit_missing")
	}
	if e.trust() != nil {
		return capDegraded(name, "helper_trust_missing")
	}
	return capOK(name)
}

func probeConfigWrite(e *capEnv, _ capResult) capResult {
	if r, ok := linuxSystemd(e, "config_write"); !ok {
		return r
	}
	if c := probeConfig(e, capResult{}); c.State != capStateOK {
		return capDegraded("config_write", c.Reason)
	}
	return helperReady(e, "config_write", configHelperTemplate)
}

func probeHelperWrite(e *capEnv, name, unit string) capResult {
	if r, ok := linuxSystemd(e, name); !ok {
		return r
	}
	return helperReady(e, name, unit)
}

// probeTweak: a sysctl get needs only /proc/sys, not systemd.
func probeTweak(e *capEnv, _ capResult) capResult {
	if e.goos != "linux" {
		return capAbsent("tweak", "unsupported_os")
	}
	if e.tweakRead() != nil {
		return capDegraded("tweak", "probe_error")
	}
	return capOK("tweak")
}

// probeService: supported wherever the platform's own service backend is
// (systemd, OpenRC, launchd), as before; the probe checks it answers.
func probeService(e *capEnv, _ capResult) capResult {
	b := e.serviceBackend()
	if b == "" {
		if e.goos == "linux" {
			return capAbsent("service", "no_systemd")
		}
		return capAbsent("service", "unsupported_os")
	}
	if e.managerUp(b) != nil {
		return capDegraded("service", "manager_unreachable")
	}
	return capOK("service")
}

func probePackage(e *capEnv, _ capResult) capResult {
	b := e.pkgBackend()
	if b == "" {
		return capAbsent("package", "unsupported_os")
	}
	if err := e.pkgVersion(b); err != nil {
		if errors.Is(err, errCapMissing) {
			return capDegraded("package", "binary_missing")
		}
		return capDegraded("package", "probe_error")
	}
	return capOK("package")
}

// jobsState is the shared rule of sysscript_jobs and converge: the state dir
// must exist, and a stat error other than "missing" keeps the last known
// state (ok when there is none), so a transient error never withdraws them.
func jobsState(e *capEnv, name string, prev capResult) capResult {
	err := e.stateDir()
	switch {
	case err == nil:
		return capOK(name)
	case errors.Is(err, errCapMissing):
		return capDegraded(name, "probe_error")
	case prev.State == capStateOK || prev.State == capStateDegraded:
		return capResult{Name: name, State: prev.State, Reason: prev.Reason}
	}
	return capOK(name)
}

func probeSysscriptJobs(e *capEnv, prev capResult) capResult {
	if e.goos != "linux" && e.goos != "darwin" {
		return capAbsent("sysscript_jobs", "unsupported_os")
	}
	if !e.jobsOn() {
		return capAbsent("sysscript_jobs", "flag_off")
	}
	return jobsState(e, "sysscript_jobs", prev)
}

func probeConverge(e *capEnv, prev capResult) capResult {
	if e.goos != "linux" && e.goos != "darwin" {
		return capAbsent("converge", "unsupported_os")
	}
	if !e.convergeOn() || !e.jobsOn() {
		return capAbsent("converge", "flag_off")
	}
	return jobsState(e, "converge", prev)
}

// probeCapabilities runs every registered probe and returns the results
// sorted by name, bounded by boundCapResults.
func probeCapabilities(e *capEnv, prev map[string]capResult) []capResult {
	out := make([]capResult, 0, len(capRegistry))
	for name, probe := range capRegistry {
		r := probe(e, prev[name])
		r.Name = name
		out = append(out, r)
	}
	return boundCapResults(out)
}

// boundCapResults is the last gate before anything leaves the agent: names
// from capRegistry matching the token grammar, a known state, a reason from
// capReasons (empty exactly when ok; an unknown one becomes probe_error),
// sorted, at most capTokensMax entries.
func boundCapResults(in []capResult) []capResult {
	out := make([]capResult, 0, len(in))
	for _, r := range in {
		if _, ok := capRegistry[r.Name]; !ok || !capNameRE.MatchString(r.Name) {
			continue
		}
		switch r.State {
		case capStateOK:
			r.Reason = ""
		case capStateDegraded, capStateAbsent:
			if !capReasons[r.Reason] {
				r.Reason = "probe_error"
			}
		default:
			r = capDegraded(r.Name, "probe_error")
		}
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	if len(out) > capTokensMax {
		out = out[:capTokensMax]
	}
	return out
}

// capWriteTokens are always in the supported header of a new agent, on every
// OS: their presence is how the server tells a new agent (write verbs gate on
// them) from an old one (write verbs gate on config/tweak). Where one is
// absent (no_systemd, unsupported_os) it is listed as degraded instead, so it
// is never routed to; the report still says absent with the reason.
var capWriteTokens = map[string]bool{"config_write": true, "sysctl_write": true, "override_write": true}

// capHeaderValues builds the two dial headers from probe results: every
// name this binary knows here (not absent, plus the write tokens always),
// and the degraded ones (plus absent write tokens). Each list holds at most
// capTokensMax tokens and capHeaderMax bytes.
func capHeaderValues(results []capResult) (supported, degraded string) {
	var sup, deg []string
	for _, r := range boundCapResults(results) {
		if r.State == capStateAbsent {
			if capWriteTokens[r.Name] {
				sup = append(sup, r.Name)
				deg = append(deg, r.Name)
			}
			continue
		}
		sup = append(sup, r.Name)
		if r.State == capStateDegraded {
			deg = append(deg, r.Name)
		}
	}
	return joinCapTokens(sup), joinCapTokens(deg)
}

func joinCapTokens(tokens []string) string {
	var b strings.Builder
	n := 0
	for _, t := range tokens {
		if n == capTokensMax || !capNameRE.MatchString(t) {
			continue
		}
		add := len(t)
		if n > 0 {
			add++
		}
		if b.Len()+add > capHeaderMax {
			break
		}
		if n > 0 {
			b.WriteByte(',')
		}
		b.WriteString(t)
		n++
	}
	return b.String()
}

// capReportFrame is the agent -> server capability_report frame.
type capReportFrame struct {
	Type     string      `json:"type"`
	V        int         `json:"v"`
	ProbedAt string      `json:"probed_at"`
	Caps     []capResult `json:"caps"`
	// IntervalS is --capability-interval in whole seconds (60..3600), so
	// the control plane times its missing-report alerts to this agent's
	// cadence rather than its own default.
	IntervalS int `json:"interval_s"`
}

// capManager holds the last probe results (for transitions and the
// keep-last-known rule) and the time of the last report, process-wide, so the
// report gap holds across reconnects too. mu guards only these fields and is
// never held while a probe runs or a frame is written, so a dial never waits
// behind a running probe.
type capManager struct {
	mu       sync.Mutex
	env      *capEnv
	last     map[string]capResult
	lastRes  []capResult // the last complete probe, sorted
	inFlight int         // probes running now
	// probeSeq numbers probes as they start; appliedSeq is the newest one
	// whose results are in last/lastRes.
	probeSeq, appliedSeq uint64
	lastSent             time.Time
	sentAny              bool
}

var (
	capMgrOnce sync.Once
	capMgrInst *capManager
)

func capMgr() *capManager {
	capMgrOnce.Do(func() { capMgrInst = newCapManager(realCapEnv()) })
	return capMgrInst
}

func newCapManager(e *capEnv) *capManager {
	return &capManager{env: e, last: map[string]capResult{}}
}

// probe runs every probe now, outside the lock, against a snapshot of the
// last results, then swaps the new results in under the lock and logs
// transitions (name, state and reason code only).
func (m *capManager) probe() []capResult {
	m.mu.Lock()
	prev := make(map[string]capResult, len(m.last))
	for k, v := range m.last {
		prev[k] = v
	}
	m.inFlight++
	m.probeSeq++
	seq := m.probeSeq
	m.mu.Unlock()

	res := probeCapabilities(m.env, prev)

	m.mu.Lock()
	defer m.mu.Unlock()
	m.inFlight--
	// Only the newest started probe that finishes is applied: a slow older
	// probe never overwrites a newer one's results.
	if seq <= m.appliedSeq {
		return res
	}
	m.appliedSeq = seq
	for _, r := range res {
		if p, ok := m.last[r.Name]; !ok || p != r {
			log.Printf("capability %s: %s %s", r.Name, r.State, r.Reason)
		}
		m.last[r.Name] = r
	}
	m.lastRes = res
	return res
}

// dialHeaders returns both header values for a new dial. It runs a fresh
// probe of its own, unless another probe is already running and a complete
// earlier result exists: then it uses that result rather than wait.
func (m *capManager) dialHeaders() (supported, degraded string) {
	m.mu.Lock()
	var res []capResult
	if m.inFlight > 0 && m.lastRes != nil {
		res = m.lastRes
	}
	m.mu.Unlock()
	if res == nil {
		res = m.probe()
	}
	supported, degraded = capHeaderValues(res)
	log.Printf("advertised capabilities=%q degraded=%q", supported, degraded)
	return supported, degraded
}

// untilAllowed is how long until the next report may go out.
func (m *capManager) untilAllowed(now time.Time) time.Duration {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.sentAny {
		return 0
	}
	return m.lastSent.Add(capReportMinGap).Sub(now)
}

func closed(quit <-chan struct{}) bool {
	select {
	case <-quit:
		return true
	default:
		return false
	}
}

// sendReport probes and writes one capability_report, unless the gap has
// not passed or quit (the connection) has closed: then it reports false with
// no error, sends nothing and leaves the gap as it was, so a goroutine of an
// old connection can never take the next connection's slot. The frame
// carries the newest applied probe (lastRes): when a newer probe superseded
// this one, its results are sent, never this probe's stale ones. interval
// is the connection's report cadence, sent as interval_s.
func (m *capManager) sendReport(out ptyOut, quit <-chan struct{}, interval time.Duration) (bool, error) {
	m.mu.Lock()
	now := time.Now()
	if closed(quit) || (m.sentAny && now.Sub(m.lastSent) < capReportMinGap) {
		m.mu.Unlock()
		return false, nil
	}
	// Reserve the slot before probing, so a concurrent sender backs off.
	prevSent, prevAny := m.lastSent, m.sentAny
	m.lastSent, m.sentAny = now, true
	m.mu.Unlock()

	m.probe()
	m.mu.Lock()
	res := append([]capResult(nil), m.lastRes...)
	m.mu.Unlock()
	if closed(quit) {
		m.mu.Lock()
		if m.lastSent.Equal(now) {
			m.lastSent, m.sentAny = prevSent, prevAny
		}
		m.mu.Unlock()
		return false, nil
	}
	frame := capReportFrame{
		Type:      "capability_report",
		V:         1,
		ProbedAt:  now.UTC().Format(time.RFC3339),
		Caps:      res,
		IntervalS: capIntervalSeconds(interval),
	}
	err := out.WriteJSON(frame)
	// The gap runs from the write, not from the probe before it.
	m.mu.Lock()
	m.lastSent = time.Now()
	m.mu.Unlock()
	return true, err
}

// serve sends capability reports on one enrolled connection until quit
// closes: one at once, one every jittered interval, one per request on
// probe; never two within capReportMinGap (a request inside the gap is
// answered when it ends). It returns when a write fails.
func (m *capManager) serve(out ptyOut, probe <-chan struct{}, quit <-chan struct{}, interval time.Duration) {
	want := true
	cycle := time.NewTimer(capJitter(interval))
	defer cycle.Stop()
	var gate *time.Timer
	var gateC <-chan time.Time
	defer func() {
		if gate != nil {
			gate.Stop()
		}
	}()
	for {
		if closed(quit) {
			return
		}
		if want && gateC == nil {
			if wait := m.untilAllowed(time.Now()); wait > 0 {
				gate = time.NewTimer(wait)
				gateC = gate.C
			} else {
				sent, err := m.sendReport(out, quit, interval)
				if closed(quit) {
					return
				}
				if err != nil {
					log.Printf("capability_report not sent; reports stop on this connection")
					return
				}
				want = !sent
				if want {
					// Lost a race with another sender: wait for the gap.
					gate = time.NewTimer(capReportMinGap)
					gateC = gate.C
				}
			}
		}
		select {
		case <-quit:
			return
		case <-cycle.C:
			want = true
			cycle.Reset(capJitter(interval))
		case <-probe:
			want = true
		case <-gateC:
			gateC = nil
		}
	}
}

// capJitter returns d +/- 10%, from crypto/rand (d itself if it fails).
func capJitter(d time.Duration) time.Duration {
	span := int64(d / 5)
	if span <= 0 {
		return d
	}
	n, err := rand.Int(rand.Reader, big.NewInt(span+1))
	if err != nil {
		return d
	}
	return d - time.Duration(span/2) + time.Duration(n.Int64())
}

// capIntervalSeconds is interval in whole seconds, held to the
// --capability-interval bounds (the control plane refuses anything else).
func capIntervalSeconds(d time.Duration) int {
	if d < capIntervalMin {
		d = capIntervalMin
	}
	if d > capIntervalMax {
		d = capIntervalMax
	}
	return int(d / time.Second)
}

// parseCapabilityInterval checks --capability-interval.
func parseCapabilityInterval(d time.Duration) error {
	if d < capIntervalMin || d > capIntervalMax {
		return errors.New("--capability-interval must be between 1m and 60m")
	}
	return nil
}

// Compatibility helpers: the supported list and header from a fresh probe.
func agentCapabilities() []string {
	s, _ := capHeaderValues(capMgr().probe())
	if s == "" {
		return nil
	}
	return strings.Split(s, ",")
}

func capabilitiesHeaderValue() string {
	s, _ := capHeaderValues(capMgr().probe())
	return s
}

// --- the real host checks ---

var (
	// sysscriptJobsOn is --sysscript-jobs (default true). Off, the agent
	// stops advertising sysscript_jobs and the server sends its scripts
	// the legacy way: a per-host off switch.
	sysscriptJobsOn = true
	// convergeOn is --converge (default false until the server runs the
	// converge wiring on every replica, .omc/plans/convergence-drift.md
	// §7.6). Off, the agent does not advertise converge and refuses
	// converge_job frames as converge_unsupported.
	convergeOn = false
	// capStateDir is the agent's state directory (the --state file's
	// directory), set from main.
	capStateDir string
)

// sysscriptJobsCapable reports whether async sysscript jobs run here
// (sysscript_jobs.go: sysscript_job frames with acked results and a sync on
// every connection). Only Linux and macOS, where jobCommand kills the whole
// process group (proc_group_unix.go); elsewhere the kill reaches only the
// direct child, so those agents stay on the legacy path.
func sysscriptJobsCapable() bool {
	return sysscriptJobsOn && (runtime.GOOS == "linux" || runtime.GOOS == "darwin")
}

// convergeCapable reports whether converge jobs (kind "converge"
// sysscript_job frames under a converge_job lease) run here: only with
// --converge, and only where async jobs run (Linux and macOS).
func convergeCapable() bool {
	return convergeOn && sysscriptJobsCapable()
}

func realCapEnv() *capEnv {
	return &capEnv{
		goos: runtime.GOOS,
		systemd: func() bool {
			fi, err := os.Stat("/run/systemd/system")
			return err == nil && fi.IsDir()
		},
		openat2Root: probeOpenat2Root,
		configOpen:  probeConfigOpen,
		tweakRead: func() error {
			f, err := os.Open("/proc/sys/kernel/hostname")
			if err != nil {
				return err
			}
			defer f.Close()
			_, err = io.Copy(io.Discard, io.LimitReader(f, 256))
			return err
		},
		ptmx: func() error {
			_, err := os.Stat("/dev/ptmx")
			return err
		},
		serviceBackend: func() string {
			s := currentPlatform().Services
			if s.Name() == "none" || !s.Available() {
				return ""
			}
			return s.Name()
		},
		managerUp: capManagerUp,
		unitLoaded: func(unit string) (bool, error) {
			v, err := capSystemctl("show", "-p", "LoadState", "--value", unit)
			if err != nil {
				return false, err
			}
			return v == "loaded", nil
		},
		trust:          checkHelperTrustFile,
		xferConfigured: func() bool { return xferCfg.bin != "" && (runtime.GOOS == "linux" || xferCfg.allowDarwin) },
		xferBin:        func() error { return checkXferBin(xferCfg.bin, os.Geteuid()) },
		pkgBackend:     capPackageBackend,
		pkgVersion:     capPackageVersion,
		jobsOn:         func() bool { return sysscriptJobsOn },
		convergeOn:     func() bool { return convergeOn },
		stateDir:       func() error { return statDir(capStateDir) },
	}
}

// statDir is the state-dir check: errCapMissing when it is unset, gone or
// not a directory; any other stat error as is.
func statDir(dir string) error {
	if dir == "" {
		return errCapMissing
	}
	fi, err := os.Stat(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return errCapMissing
	}
	if err != nil {
		return err
	}
	if !fi.IsDir() {
		return errCapMissing
	}
	return nil
}

// capSystemctl runs a read-only systemctl query (fixed argv, absolute path,
// no shell, bounded) and returns its trimmed stdout.
func capSystemctl(args ...string) (string, error) {
	return capRun("systemctl", args...)
}

// capRun runs a read-only probe command found in execDirs (never $PATH),
// fixed argv, no shell, capProbeTimeout, and returns its trimmed stdout.
func capRun(bin string, args ...string) (string, error) {
	path, ok := findExecutable(bin, execDirs)
	if !ok {
		return "", errCapMissing
	}
	ctx, cancel := context.WithTimeout(context.Background(), capProbeTimeout)
	defer cancel()
	out, err := jobCommand(ctx, path, args...).Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

// capManagerUp checks a service backend answers, read-only and bounded:
// systemd `systemctl show -p Version --value` (non-empty), OpenRC
// `rc-service --version`, launchd the backend's own presence check.
func capManagerUp(backend string) error {
	switch backend {
	case "systemd":
		v, err := capSystemctl("show", "-p", "Version", "--value")
		if err != nil {
			return err
		}
		if v == "" {
			return errors.New("no version")
		}
		return nil
	case "openrc":
		_, err := capRun("rc-service", "--version")
		return err
	case "launchd":
		if !currentPlatform().Services.Available() {
			return errCapMissing
		}
		return nil
	}
	return errCapMissing
}

// checkHelperTrustFile is the helpers' own loader, loadHelperTrust: the
// file and its directory root-owned and without a group or other write bit
// (so 0644, 0640 and 0600 all pass), a regular file opened without
// following a symlink, and a body that parses.
func checkHelperTrustFile() error {
	_, _, err := loadHelperTrust()
	return err
}

// capPackageBackend is the selected package backend, or the family's native
// one when its binary is missing (reported binary_missing), "" when the
// family has none.
func capPackageBackend() string {
	if p := currentPlatform().Packages; p.Name() != "none" {
		return p.Name()
	}
	switch currentFamily() {
	case familyDebian:
		return "apt-get"
	case familyRHEL:
		return "dnf"
	case familySUSE:
		return "zypper"
	case familyDarwin:
		return "brew"
	}
	return ""
}

// capPackageVersion runs the backend's version query: dpkg-query for apt,
// rpm for the rpm family. None takes a lock. brew is never executed (it is
// a user-owned script on macOS, and the agent may be root): only its
// presence is checked, by brewPresent.
func capPackageVersion(backend string) error {
	var bin string
	switch backend {
	case "apt-get":
		bin = "dpkg-query"
	case "dnf", "yum", "zypper":
		bin = "rpm"
	case "brew":
		path, ok := findExecutable("brew", execDirs)
		if !ok {
			return errCapMissing
		}
		return brewPresent(path, os.Stat, fileOwnerIDs, os.Geteuid())
	default:
		return errCapMissing
	}
	path, ok := findExecutable(bin, execDirs)
	if !ok {
		return errCapMissing
	}
	ctx, cancel := context.WithTimeout(context.Background(), capProbeTimeout)
	defer cancel()
	_, err := jobCommand(ctx, path, "--version").Output()
	return err
}

// brewPresent is the brew probe; nothing runs. stat follows the symlink
// (brew is usually one) to the real file, which must be a regular file. When
// the agent is root (euid 0) that file must also be root-owned, else it is
// an error (reported degraded probe_error): a root agent must not treat a
// user-replaceable binary as healthy.
func brewPresent(path string, stat func(string) (os.FileInfo, error), owner func(os.FileInfo) (int, int, bool), euid int) error {
	fi, err := stat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return errCapMissing
	}
	if err != nil {
		return err
	}
	if !fi.Mode().IsRegular() {
		return errCapMissing
	}
	if euid == 0 {
		uid, _, ok := owner(fi)
		if !ok || uid != 0 {
			return errors.New("brew is not root-owned")
		}
	}
	return nil
}
