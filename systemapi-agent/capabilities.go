// Capability advertisement. The agent tells the server which channel
// handlers it really has (X-SystemAPI-Capabilities on the WebSocket dial),
// so the server can answer agent_unsupported for an old or partial agent
// instead of sending frames nobody handles. A handler registers itself with
// registerCapability (normally from an init function in its own file) and a
// probe that reports whether it can run on this host, e.g. the file channel
// only where openat2 exists (docs/sah-file-protocol.md §5.4).
// Threats: none on its own. The header is advisory for the server's error
// reporting; it never grants anything. Leases, scopes and the agent's own
// allowlists still decide every request.
package main

import (
	"runtime"
	"sort"
	"strings"
	"sync"
)

const capabilitiesHeader = "X-SystemAPI-Capabilities"

var (
	capMu     sync.Mutex
	capProbes = map[string]func() bool{
		"pty":            func() bool { return runtime.GOOS != "windows" },
		"sysscript_jobs": sysscriptJobsCapable,
		"converge":       convergeCapable,
	}
	// sysscriptJobsOn is --sysscript-jobs (default true). Off, the agent
	// stops advertising sysscript_jobs and the server sends its scripts
	// the legacy way: a per-host off switch.
	sysscriptJobsOn = true
	// convergeOn is --converge (default false until the server runs the
	// converge wiring on every replica, .omc/plans/convergence-drift.md
	// §7.6). Off, the agent does not advertise converge and refuses
	// converge_job frames as converge_unsupported.
	convergeOn = false
)

// sysscriptJobsCapable reports whether to advertise async sysscript jobs
// (sysscript_jobs.go: sysscript_job frames with acked results and a sync on
// every connection). Only Linux and macOS, where jobCommand kills the whole
// process group (proc_group_unix.go); elsewhere the kill reaches only the
// direct child, so those agents stay on the legacy path.
func sysscriptJobsCapable() bool {
	return sysscriptJobsOn && (runtime.GOOS == "linux" || runtime.GOOS == "darwin")
}

// convergeCapable reports whether to advertise converge jobs (kind
// "converge" sysscript_job frames under a converge_job lease): only with
// --converge, and only where async jobs are advertised (Linux and macOS).
func convergeCapable() bool {
	return convergeOn && sysscriptJobsCapable()
}

// registerCapability adds a capability and its probe. A later registration
// of the same name replaces the probe.
func registerCapability(name string, probe func() bool) {
	capMu.Lock()
	capProbes[name] = probe
	capMu.Unlock()
}

// agentCapabilities lists, sorted, every capability whose probe passes now.
func agentCapabilities() []string {
	capMu.Lock()
	defer capMu.Unlock()
	out := make([]string, 0, len(capProbes))
	for name, probe := range capProbes {
		if probe != nil && probe() {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

// capabilitiesHeaderValue is the comma list sent on dial.
func capabilitiesHeaderValue() string {
	return strings.Join(agentCapabilities(), ",")
}
