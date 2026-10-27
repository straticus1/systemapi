package main

// Privilege-separated systemd drop-in override helper
// (docs/sah-os-management-design.md, mutation-helper section, option 2). This
// extends the sysctl-set spike (sysctl_helper.go) to the TWO tweak verbs that
// write a systemd drop-in: sys:tweak unit-override-set and
// sys:tweak resource-limit-set. Both land at
// /etc/systemd/system/<unit>.d/<name>.conf, so ONE committed helper + unit
// serves them. Read sysctl_helper.go first; only the differences are noted.
//
// Why this exists: the agent runs under ProtectSystem=strict, so it cannot
// write /etc/systemd/system itself. Rather than widen the agent's own sandbox,
// the write is handed off to this minimally-scoped helper whose sandbox is the
// agent's hardening with exactly ONE relaxation: /etc/systemd/system is in
// ReadWritePaths (ProtectSystem stays strict). The sandbox is defined in a
// COMMITTED systemd unit (systemd/sah-systemd-override-helper@.service), NOT
// constructed by the agent; the agent triggers it and passes only a request id.
//
// Trust boundary:
//   - The agent gates the channel on lease + per-host policy (sys.go /
//     sys_policy.go, unchanged): the lease binds the verb and, for
//     resource-limit-set, the exact unit/limit/value; for unit-override-set it
//     binds the unit, the drop-in name and the body's SHA-256. The per-host
//     unit allowlist is enforced by the control plane.
//   - The helper does NOT trust the caller, which may be a compromised agent.
//     It authorizes the write itself (helper_auth.go): the request carries
//     the original signed sys_tweak lease, and the helper verifies it against
//     the control-plane key it loads from its own root-owned trust file, over
//     the payload it rebuilds from the exact unit/limit/value (or unit, name
//     and the SHA-256 it computes over the body), checks host/action/expiry,
//     and consumes the nonce in a durable store the agent cannot write. It
//     also INDEPENDENTLY re-validates the unit name (serviceNameRE) and, per
//     kind: for a resource limit, that the directive is in the closed
//     resourceLimits set and the value matches limitValueRE, and it rebuilds
//     the drop-in body itself (it never writes caller-supplied content for a
//     limit); for a unit override, that the drop-in name matches
//     overrideNameRE and the body is non-empty, within overrideContentCap and
//     null-free. It then pins the path under /etc/systemd/system and refuses
//     anything else. It fails closed.
//   - The handoff files are the agent's own: 0600, O_EXCL on write, O_NOFOLLOW
//     on both ends, one request per invocation keyed by a fresh random id,
//     cleaned up after.
//
// Threats: a root-equivalent /etc/systemd/system write. The unit and drop-in
// names are regex-checked so the constructed path has no "/" or ".." and always
// resolves directly under /etc/systemd/system/<unit>.d/; a defensive
// pathWithin check backs that up. No shell is involved: the write is an atomic
// temp-file-fsync-rename, the trigger a fixed systemctl argv carrying only a
// hex id.
//
// DAEMON-RELOAD: the Phase 0 Tweaks backend (platform_tweak.go SetUnitOverride)
// wrote the drop-in and did NOT run `systemctl daemon-reload`; the drop-in
// takes effect on the unit's next daemon-reload/restart. This helper preserves
// that behavior exactly — it only writes the file. A reload to activate the
// drop-in is deliberately NOT added here (it would be a separate privileged
// action the agent can do over systemd's manager, the same way it restarts a
// service); adding it is a follow-up, not part of mirroring the Phase 0 write.
//
// UNVERIFIED HOST ASSUMPTION: identical to the sysctl spike — that the confined
// agent may StartUnit this privileged helper over systemd's manager.

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"crypto/rand"
)

// overrideHelperStateDir is the agent-owned handoff directory. The committed
// helper unit lists exactly this path (plus /etc/systemd/system) in its
// ReadWritePaths. A var so tests can point it at a temp dir.
var overrideHelperStateDir = "/var/lib/systemapi-agent/override-helper"

// overrideHelperUnitPrefix is the committed per-verb sandbox unit
// (systemd/sah-systemd-override-helper@.service). The instance name is the id.
const overrideHelperUnitPrefix = "sah-systemd-override-helper@"

// overrideSystemdRoot is the fixed directory every drop-in lands beneath.
const overrideSystemdRoot = "/etc/systemd/system"

// overrideHandoffMax caps a handoff file. A request carries a drop-in body up
// to overrideContentCap (platform_tweak.go); JSON-escaping expands it, so the
// cap is generously larger. The body is re-capped after unmarshal.
const overrideHandoffMax = 512 * 1024

// overrideHelperIDRE matches the fresh random id the agent mints. Hex only, so
// it is a safe systemd instance name and filename component.
var overrideHelperIDRE = regexp.MustCompile(`^[0-9a-f]{32}$`)

// overrideKind selects which verb a request carries. The helper rebuilds the
// drop-in independently per kind; it never writes a limit body supplied by the
// caller.
const (
	overrideKindUnit  = "unit-override"
	overrideKindLimit = "resource-limit"
)

// overrideHelperReq is the agent->helper request. One per invocation.
//   - kind=unit-override: Unit, Name, Content (body bound by its hash in the lease).
//   - kind=resource-limit: Unit, Limit, Value (body rebuilt by the helper).
//
// Lease is the signed sys_tweak lease exactly as the control plane sent it.
type overrideHelperReq struct {
	Kind    string `json:"kind"`
	Unit    string `json:"unit"`
	Name    string `json:"name,omitempty"`
	Content string `json:"content,omitempty"`
	Limit   string `json:"limit,omitempty"`
	Value   string `json:"value,omitempty"`
	Lease   *Lease `json:"lease"`
}

// overrideHelperRes is the helper->agent result.
type overrideHelperRes struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
	Errno int    `json:"errno,omitempty"`
}

// overrideResolve independently re-validates a request's shape and resolves
// the concrete drop-in name, body, path and the sys_tweak lease payload that
// must authorize it. It returns code != "" on refusal. Shared by the agent-side
// handoff and the helper subcommand; trusts nothing and fails closed. The
// lease itself is checked only in the helper (helperAuthorize).
func overrideResolve(req overrideHelperReq) (name, content, path, payload, code string) {
	if !serviceNameRE.MatchString(req.Unit) {
		return "", "", "", "", "unit_denied"
	}
	switch req.Kind {
	case overrideKindLimit:
		if _, ok := resourceLimits[req.Limit]; !ok {
			return "", "", "", "", "limit_denied"
		}
		if !limitValueRE.MatchString(req.Value) {
			return "", "", "", "", "value_denied"
		}
		// Rebuild the drop-in exactly as platform_tweak.go SetResourceLimit
		// does; the helper never writes a caller-supplied limit body.
		name = "limit-" + strings.ToLower(req.Limit)
		content = "[Service]\n" + req.Limit + "=" + req.Value + "\n"
	case overrideKindUnit:
		if !overrideNameRE.MatchString(req.Name) {
			return "", "", "", "", "name_denied"
		}
		if req.Content == "" || len(req.Content) > overrideContentCap || strings.ContainsRune(req.Content, 0) {
			return "", "", "", "", "content_denied"
		}
		name = req.Name
		content = req.Content
	default:
		return "", "", "", "", "bad_request"
	}
	var err error
	if req.Kind == overrideKindLimit {
		payload, err = sysTweakLeasePayload("resource-limit-set", "", req.Value, req.Unit, req.Limit, "", "")
	} else {
		payload, err = sysTweakLeasePayload("unit-override-set", "", "", req.Unit, "", name, sysSHA256Hex(content))
	}
	if err != nil {
		return "", "", "", "", "bad_request"
	}
	dir := filepath.Join(overrideSystemdRoot, req.Unit+".d")
	path = filepath.Join(dir, name+".conf")
	// Never a drop-in for the agent's own unit, a helper's unit, or a
	// top-level/prefix drop-in that applies to them: that would let the
	// override channel lift the agent's or a helper's sandbox.
	if configSystemdSelfEntry(req.Unit + ".d") {
		return "", "", "", "", "unit_denied"
	}
	// Defensive: the regexes already forbid "/" and ".." so this always holds,
	// but re-assert it so the write can never escape the systemd root.
	if filepath.Clean(path) != path || !pathWithin(overrideSystemdRoot, path) {
		return "", "", "", "", "unit_denied"
	}
	return name, content, path, payload, ""
}

// overrideHelperTrigger starts the committed, privileged helper unit, passing
// only the request id. `systemctl start` blocks until the oneshot completes.
// tests replace it.
var overrideHelperTrigger = func(id string) error {
	out, err := exec.Command("systemctl", "start", overrideHelperUnitPrefix+id+".service").CombinedOutput()
	if err != nil {
		return fmt.Errorf("start override helper: %v: %s", err, capSysOutput(string(out)))
	}
	return nil
}

// overrideHelperWrite creates the <unit>.d directory and performs the atomic
// drop-in write. It runs ONLY inside the helper process. tests replace it.
var overrideHelperWrite = func(path, content string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return writeFileAtomicSync(path, content, 0o644)
}

// unitOverrideSetViaHelper is the agent-side handoff for sys:tweak
// unit-override-set. The channel has verified the lease (unit + name + body
// hash) and applied checkSysTweakPolicy; this re-validates defensively and
// hands off the request with the original lease for the helper to verify.
func unitOverrideSetViaHelper(unit, name, content string, lease *Lease) error {
	return overrideSetViaHelper(overrideHelperReq{
		Kind: overrideKindUnit, Unit: unit, Name: name, Content: content, Lease: lease,
	})
}

// resourceLimitSetViaHelper is the agent-side handoff for sys:tweak
// resource-limit-set. The lease binds unit/limit/value directly; there is no
// caller-supplied body.
func resourceLimitSetViaHelper(unit, limit, value string, lease *Lease) error {
	return overrideSetViaHelper(overrideHelperReq{
		Kind: overrideKindLimit, Unit: unit, Limit: limit, Value: value, Lease: lease,
	})
}

// overrideSetViaHelper writes a 0600 request the agent owns, triggers the
// committed helper unit, and reads back its result. It re-validates defensively
// before the handoff and never writes /etc itself.
func overrideSetViaHelper(req overrideHelperReq) error {
	if _, _, _, _, code := overrideResolve(req); code != "" {
		return fmt.Errorf("unit override refused: %s", code)
	}
	if req.Lease == nil {
		return fmt.Errorf("unit override refused: lease_missing")
	}
	if err := os.MkdirAll(overrideHelperStateDir, 0o700); err != nil {
		return fmt.Errorf("handoff dir: %w", err)
	}
	idb := make([]byte, 16)
	if _, err := rand.Read(idb); err != nil {
		return err
	}
	id := hex.EncodeToString(idb)
	reqPath := filepath.Join(overrideHelperStateDir, id+".req")
	resPath := filepath.Join(overrideHelperStateDir, id+".res")
	defer os.Remove(reqPath)
	defer os.Remove(resPath)

	reqBytes, err := json.Marshal(req)
	if err != nil {
		return err
	}
	if err := writeHandoffFile(reqPath, reqBytes); err != nil {
		return fmt.Errorf("write request: %w", err)
	}
	if err := overrideHelperTrigger(id); err != nil {
		return err
	}
	res, err := readOverrideResult(resPath)
	if err != nil {
		return fmt.Errorf("override helper result: %w", err)
	}
	if !res.OK {
		code := res.Error
		if code == "" {
			code = "helper_failed"
		}
		if res.Errno != 0 {
			return fmt.Errorf("override helper: %s (errno %d)", code, res.Errno)
		}
		return fmt.Errorf("override helper: %s", code)
	}
	return nil
}

// runOverrideHelper is the hidden `__systemd-override-helper <id>` subcommand of
// the agent binary, invoked only by the committed helper unit. Same contract as
// runSysctlHelper: 0 when a result was recorded, non-zero only when the id or
// the result file could not be handled.
func runOverrideHelper(args []string) int {
	if len(args) != 1 || !overrideHelperIDRE.MatchString(args[0]) {
		fmt.Fprintln(os.Stderr, "override-helper: bad or missing request id")
		return 2
	}
	id := args[0]
	reqPath := filepath.Join(overrideHelperStateDir, id+".req")
	resPath := filepath.Join(overrideHelperStateDir, id+".res")
	res := doOverrideHelper(reqPath)
	if err := writeOverrideResult(resPath, res); err != nil {
		fmt.Fprintf(os.Stderr, "override-helper: write result: %v\n", err)
		return 2
	}
	return 0
}

// doOverrideHelper reads the request, re-validates and authorizes it (not
// trusting the caller), rebuilds the drop-in, and performs the write. It never panics or
// exits; it always returns a result.
func doOverrideHelper(reqPath string) overrideHelperRes {
	data, err := readHandoffFile(reqPath, overrideHandoffMax)
	if err != nil {
		return overrideHelperRes{Error: "no_request"}
	}
	var req overrideHelperReq
	if err := json.Unmarshal(data, &req); err != nil {
		return overrideHelperRes{Error: "bad_request"}
	}
	_, content, path, payload, code := overrideResolve(req)
	if code != "" {
		return overrideHelperRes{Error: code}
	}
	if code := helperAuthorize("sys_tweak", payload, req.Lease, time.Now()); code != "" {
		return overrideHelperRes{Error: code}
	}
	if err := overrideHelperWrite(path, content); err != nil {
		return overrideHelperRes{Error: "write_failed", Errno: errnoOf(err)}
	}
	return overrideHelperRes{OK: true}
}

func writeOverrideResult(path string, res overrideHelperRes) error {
	data, err := json.Marshal(res)
	if err != nil {
		return err
	}
	return writeHandoffFile(path, data)
}

func readOverrideResult(path string) (overrideHelperRes, error) {
	var res overrideHelperRes
	data, err := readHandoffFile(path, overrideHandoffMax)
	if err != nil {
		return res, err
	}
	if err := json.Unmarshal(data, &res); err != nil {
		return res, err
	}
	return res, nil
}
