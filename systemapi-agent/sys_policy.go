// Service-management channel policy on the agent (docs/sah-os-management-design.md
// Phase 1), the sys counterpart of tcp_policy.go.
//
// Threats: a compromised or buggy control plane trying to act on a unit the
// host cannot or must not touch. The agent keeps its own fail-closed gate,
// independent of the signed lease: it refuses unless the host actually
// advertises the service capability (the same probe sent on dial), the verb
// is in the closed set (Phase 1: restart only), and the unit passes the shape
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

// sysServiceActions is the closed set of mutating verbs this channel exposes.
// Phase 1 is restart only; status is the confirm read, not a channel verb.
var sysServiceActions = map[string]struct{}{"restart": {}}

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
