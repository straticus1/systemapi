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
		"pty": func() bool { return runtime.GOOS != "windows" },
	}
)

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
