// Service-management channel policy on the agent (docs/sah-os-management-design.md
// Phase 1), the sys counterpart of tcp_policy.go.
//
// Threats: a compromised or buggy control plane trying to act on a unit the
// host cannot or must not touch. The agent keeps its own fail-closed gate,
// independent of the signed lease: it refuses unless the host actually
// advertises the service capability (the same probe sent on dial), the verb
// is in the closed set (the service lifecycle verbs), and the unit passes the shape
// guard. The unit binding itself is enforced by the lease (sys.go rebuilds the
// signed "<unit>\n<action>" payload from the unit it is about to act on, so a
// lease for one unit never acts on another). An unsupported platform returns
// errSysUnsupported, never a silent success. This file runs no command and
// opens no socket; it only decides allow or deny.
package main

import "errors"

var (
	errSysUnsupported = errors.New("service_unsupported")
	errSysUnitDenied  = errors.New("unit_denied")
	errSysBadAction   = errors.New("bad_action")
)

// sysServiceActions is the closed set of mutating verbs this channel exposes:
// the service lifecycle verbs. status is the confirm read, not a channel verb.
// Kept byte-for-byte in sync with platform_service.go serviceVerbs, the
// server's SERVICE_LEASE_ACTIONS (controlplane/lease.js) and SERVICE_ACTIONS
// (controlplane/channels.js, controlplane/tickets.js).
var sysServiceActions = map[string]struct{}{
	"start": {}, "stop": {}, "restart": {}, "enable": {}, "disable": {},
}

// checkSysServicePolicy is the agent's own gate, run after the lease verifies.
// It fails closed on an unsupported platform, an unknown verb, or a badly
// shaped unit name.
func checkSysServicePolicy(unit, action string) error {
	if !sysServices().Available() {
		return errSysUnsupported
	}
	if _, ok := sysServiceActions[action]; !ok {
		return errSysBadAction
	}
	if !serviceNameRE.MatchString(unit) {
		return errSysUnitDenied
	}
	return nil
}
