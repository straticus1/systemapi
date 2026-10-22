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

	errPkgUnsupported = errors.New("package_unsupported")
	errPkgNameDenied  = errors.New("package_denied")
	errPkgBadAction   = errors.New("bad_action")

	errCfgUnsupported = errors.New("config_unsupported")
	errCfgTargetBad   = errors.New("target_denied")
	errCfgBadAction   = errors.New("bad_action")
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

// sysPackageActions is the closed set of sys:package channel verbs: query
// (a read) plus the mutations. Kept byte-for-byte in sync with the server's
// PACKAGE_LEASE_ACTIONS (controlplane/lease.js) and PACKAGE_ACTIONS
// (controlplane/channels.js, controlplane/tickets.js).
var sysPackageActions = map[string]struct{}{
	"query": {}, "install": {}, "remove": {}, "upgrade": {},
}

// checkSysPackagePolicy is the agent's own fail-closed gate for sys:package,
// run after the lease verifies and independent of it. The per-host name
// allowlist is enforced by the control plane (package_policy) and the lease
// binds the exact name; the agent refuses unless the host advertises the
// package capability, the verb is in the closed set, and the name passes the
// shape guard (grant.go packageNameRE; "*" never matches).
func checkSysPackagePolicy(name, action string) error {
	if !sysPackages().Available() {
		return errPkgUnsupported
	}
	if _, ok := sysPackageActions[action]; !ok {
		return errPkgBadAction
	}
	if !packageNameRE.MatchString(name) {
		return errPkgNameDenied
	}
	return nil
}

// sysConfigActions is the closed set of sys:config channel verbs. read is a
// read; write/reload are mutations. Kept byte-for-byte in sync with the
// server's CONFIG_ACTIONS (controlplane/channels.js).
var sysConfigActions = map[string]struct{}{
	"read": {}, "write": {}, "reload": {},
}

// checkSysConfigPolicy is the agent's own fail-closed gate for sys:config. The
// per-host path/unit allowlists are enforced by the control plane and the
// lease binds the exact target (and, for a write, the content hash); the agent
// refuses unless the host advertises the config capability, the verb is in the
// closed set, and the target passes its shape guard (an absolute path for
// read/write, a unit for reload).
func checkSysConfigPolicy(action, target string) error {
	if !sysConfig().Available() {
		return errCfgUnsupported
	}
	if _, ok := sysConfigActions[action]; !ok {
		return errCfgBadAction
	}
	if action == "reload" {
		if !serviceNameRE.MatchString(target) {
			return errCfgTargetBad
		}
		return nil
	}
	if target == "" || len(target) > 4096 || target == "/" || target[0] != '/' || !noControl(target) {
		return errCfgTargetBad
	}
	return nil
}
