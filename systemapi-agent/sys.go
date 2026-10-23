// OS-management channel, agent side (docs/sah-os-management-design.md),
// modelled on tcp.go. Unlike the TCP forward this is one request/response:
// a sys_service frame controls one unit (then reads its status to confirm),
// and a sys_package frame runs one package verb. Each answers with one
// sys_result frame.
//
// Threats: every sys write is root-equivalent. The lease signs "<resource>\n
// <action>" (unit/action or name/action) and the agent rebuilds that payload
// from the frame, so a lease minted for one resource or verb can never act on
// another, and a tampered or expired lease is refused by verifyLease
// (lease.go). The agent then applies its own fail-closed gate (sys_policy.go):
// the host must advertise the resource's capability, the verb must be in the
// closed set, and the resource name must pass the shape guard. Service control
// runs through the Phase 0 ServiceManager (platform_service.go); a package verb
// runs the PackageManager's fixed argv (platform_package.go) with a minimal
// environment and no shell, so a name can never inject a flag or a command.
// Command output is capped before it is returned and is never logged. Every
// refusal is a sys_result with an error code, never a dropped connection. Does
// NOT persist across a reconnect: a request whose connection drops is simply
// retried by the caller.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log"
	"os"
	"os/exec"
	"regexp"
	"syscall"
	"time"
)

// errSysPkgBadArgv is an internal guard: the package manager produced no argv.
var errSysPkgBadArgv = errors.New("package manager unavailable")

// sysConfigReadMax caps the bytes a sys:config read returns.
const sysConfigReadMax = 64 * 1024

// sysConfig returns the host's ConfigStore; tests replace it.
var sysConfig = func() ConfigStore { return currentPlatform().Config }

// sysTweaks returns the host's Tweaks backend; tests replace it.
var sysTweaks = func() Tweaks { return currentPlatform().Tweaks }

// sysConfigReadFile reads one config file for a sys:config read. It opens the
// final component without following a symlink and refuses anything that is not
// a regular file, so a planted symlink cannot redirect the read out of an
// allowed prefix. tests replace it. Output is capped at sysConfigReadMax.
var sysConfigReadFile = func(path string) (string, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return "", err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() {
		return "", errors.New("not a regular file")
	}
	buf, err := io.ReadAll(io.LimitReader(f, sysConfigReadMax))
	if err != nil {
		return "", err
	}
	return string(buf), nil
}

func sysSHA256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// sysRequestRe matches a server-minted request id (playground/sys.js).
var sysRequestRe = regexp.MustCompile(`^sys_[A-Za-z0-9_-]{16,64}$`)

// sysOutputMax caps the bytes of command output returned to the server.
const sysOutputMax = 8 * 1024

// sysServices returns the host's ServiceManager; tests replace it.
var sysServices = func() ServiceManager { return currentPlatform().Services }

// sysPackages returns the host's PackageManager; tests replace it.
var sysPackages = func() PackageManager { return currentPlatform().Packages }

// sysPackageTimeout bounds one package operation.
const sysPackageTimeout = 120 * time.Second

// sysPackagePATH and sysPackageEnv are the fixed, minimal environment a
// package command runs with: no inherited env, no shell.
const sysPackagePATH = "/usr/sbin:/usr/bin:/sbin:/bin:/opt/homebrew/bin:/usr/local/bin"

// sysPackageRun execs a fixed package argv with a minimal environment and
// returns the combined output. tests replace it so no real package manager
// runs. It is the only exec path for sys:package.
var sysPackageRun = func(ctx context.Context, argv []string) (string, error) {
	if len(argv) < 1 {
		return "", errSysPkgBadArgv
	}
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	cmd.Env = []string{
		"PATH=" + sysPackagePATH,
		"DEBIAN_FRONTEND=noninteractive",
		"LC_ALL=C",
	}
	cmd.Dir = "/"
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// sysServiceMsg is the server's sys_service request frame.
type sysServiceMsg struct {
	Type      string `json:"type"`
	RequestID string `json:"request_id"`
	Unit      string `json:"unit"`
	Action    string `json:"action"`
	Lease     *Lease `json:"lease"`
}

// handleSys dispatches the sys channel frames. It reports whether typ was a
// sys frame. A refusal is a sys_result error, never a fatal connection error.
func (c *channelConn) handleSys(typ string, message []byte) bool {
	switch typ {
	case "sys_service":
		var msg sysServiceMsg
		if err := json.Unmarshal(message, &msg); err != nil {
			log.Printf("rejected malformed sys_service")
			return true
		}
		c.sysService(msg, time.Now())
		return true
	case "sys_package":
		var msg sysPackageMsg
		if err := json.Unmarshal(message, &msg); err != nil {
			log.Printf("rejected malformed sys_package")
			return true
		}
		c.sysPackage(msg, time.Now())
		return true
	case "sys_config":
		var msg sysConfigMsg
		if err := json.Unmarshal(message, &msg); err != nil {
			log.Printf("rejected malformed sys_config")
			return true
		}
		c.sysConfig(msg, time.Now())
		return true
	case "sys_tweak":
		var msg sysTweakMsg
		if err := json.Unmarshal(message, &msg); err != nil {
			log.Printf("rejected malformed sys_tweak")
			return true
		}
		c.sysTweak(msg, time.Now())
		return true
	default:
		return false
	}
}

func capSysOutput(s string) string {
	if len(s) > sysOutputMax {
		return s[:sysOutputMax]
	}
	return s
}

func sysResultError(out ptyOut, rid, code string) {
	_ = out.WriteJSON(ResponseMessage{Type: "sys_result", RequestID: rid, Payload: map[string]interface{}{
		"ok":    false,
		"error": code,
	}})
}

// sysService verifies the lease, applies the agent's own gate, then restarts
// the unit and reads its status to confirm.
func (c *channelConn) sysService(msg sysServiceMsg, now time.Time) {
	rid := msg.RequestID
	if !sysRequestRe.MatchString(rid) {
		log.Printf("sys_service refused: bad request id")
		sysResultError(c.out, "", "internal")
		return
	}
	// The lease signs the exact unit and action; rebuild the payload from what
	// we are about to act on so a lease for one unit never acts on another.
	payload, err := sysServiceLeasePayload(msg.Unit, msg.Action)
	if err != nil {
		log.Printf("sys_service refused: %s", err.Error())
		sysResultError(c.out, rid, "lease_required")
		return
	}
	if err := authorizeCommand(c.hostID, "sys_service", payload, msg.Lease, now); err != nil {
		log.Printf("sys_service refused: %s", err.Error())
		sysResultError(c.out, rid, "lease_required")
		return
	}
	// The agent's own fail-closed gate, independent of the lease.
	if err := checkSysServicePolicy(msg.Unit, msg.Action); err != nil {
		log.Printf("sys_service refused: %s", err.Error())
		sysResultError(c.out, rid, err.Error())
		return
	}
	svc := sysServices()
	output, actErr := svc.Action(msg.Action, msg.Unit)
	result := map[string]interface{}{
		"ok":     actErr == nil,
		"unit":   msg.Unit,
		"action": msg.Action,
		"output": capSysOutput(output),
	}
	if actErr != nil {
		result["error"] = "action_failed"
	}
	// Status is the confirm read (same unit, no separate lease).
	if status, statusErr := svc.Status(msg.Unit); statusErr == nil {
		result["active"] = status.Active
		result["state"] = status.State
		result["status_output"] = capSysOutput(status.Output)
	}
	_ = c.out.WriteJSON(ResponseMessage{Type: "sys_result", RequestID: rid, Payload: result})
	log.Printf("sys_service %s unit=%s action=%s ok=%t", rid, msg.Unit, msg.Action, actErr == nil)
}

// sysPackageMsg is the server's sys_package request frame.
type sysPackageMsg struct {
	Type      string `json:"type"`
	RequestID string `json:"request_id"`
	Name      string `json:"name"`
	Action    string `json:"action"`
	Lease     *Lease `json:"lease"`
}

// sysPackageArgv builds the fixed argv for one verb from the host's package
// manager. The name has already passed packageNameRE; the manager rejects it
// again and refuses "*".
func sysPackageArgv(pm PackageManager, action, name string) ([]string, error) {
	switch action {
	case "query":
		return pm.QueryArgv(name)
	case "install":
		return pm.InstallArgv(name)
	case "remove":
		return pm.RemoveArgv(name)
	case "upgrade":
		return pm.UpgradeArgv(name)
	default:
		return nil, errPkgBadAction
	}
}

// sysPackage verifies the lease, applies the agent's own fail-closed gate,
// then runs one package verb through the Phase 0 PackageManager with fixed
// argv and no shell, and returns the capped combined output.
func (c *channelConn) sysPackage(msg sysPackageMsg, now time.Time) {
	rid := msg.RequestID
	if !sysRequestRe.MatchString(rid) {
		log.Printf("sys_package refused: bad request id")
		sysResultError(c.out, "", "internal")
		return
	}
	// Rebuild the signed payload from the name and verb we are about to act
	// on, so a lease for one package or verb never acts on another.
	payload, err := sysPackageLeasePayload(msg.Name, msg.Action)
	if err != nil {
		log.Printf("sys_package refused: %s", err.Error())
		sysResultError(c.out, rid, "lease_required")
		return
	}
	if err := authorizeCommand(c.hostID, "sys_package", payload, msg.Lease, now); err != nil {
		log.Printf("sys_package refused: %s", err.Error())
		sysResultError(c.out, rid, "lease_required")
		return
	}
	// The agent's own fail-closed gate, independent of the lease.
	if err := checkSysPackagePolicy(msg.Name, msg.Action); err != nil {
		log.Printf("sys_package refused: %s", err.Error())
		sysResultError(c.out, rid, err.Error())
		return
	}
	pm := sysPackages()
	argv, err := sysPackageArgv(pm, msg.Action, msg.Name)
	if err != nil {
		log.Printf("sys_package refused: %s", err.Error())
		sysResultError(c.out, rid, "action_failed")
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), sysPackageTimeout)
	defer cancel()
	output, actErr := sysPackageRun(ctx, argv)
	result := map[string]interface{}{
		"ok":     actErr == nil,
		"name":   msg.Name,
		"action": msg.Action,
		"output": capSysOutput(output),
	}
	if actErr != nil {
		result["error"] = "action_failed"
	}
	_ = c.out.WriteJSON(ResponseMessage{Type: "sys_result", RequestID: rid, Payload: result})
	log.Printf("sys_package %s name=%s action=%s ok=%t", rid, msg.Name, msg.Action, actErr == nil)
}

// sysConfigMsg is the server's sys_config request frame. Content is present
// only for a write; its SHA-256 is bound in the lease.
type sysConfigMsg struct {
	Type      string `json:"type"`
	RequestID string `json:"request_id"`
	Action    string `json:"action"`
	Target    string `json:"target"`
	Content   string `json:"content"`
	Lease     *Lease `json:"lease"`
}

// sysConfig reads, writes or reloads one config target. read returns the file
// content (symlink-guarded, capped); write rebuilds the signed payload from
// the body's hash (so a tampered body is refused) and does an atomic write;
// reload reloads a unit through the ConfigStore.
func (c *channelConn) sysConfig(msg sysConfigMsg, now time.Time) {
	rid := msg.RequestID
	if !sysRequestRe.MatchString(rid) {
		log.Printf("sys_config refused: bad request id")
		sysResultError(c.out, "", "internal")
		return
	}
	// Rebuild the signed payload from the target and verb we are about to act
	// on. A write binds the content by its SHA-256, so a body swapped in
	// transit yields a different hash and the lease no longer verifies.
	contentSHA := ""
	if msg.Action == "write" {
		contentSHA = sysSHA256Hex(msg.Content)
	}
	payload, err := sysConfigLeasePayload(msg.Action, msg.Target, contentSHA)
	if err != nil {
		log.Printf("sys_config refused: %s", err.Error())
		sysResultError(c.out, rid, "lease_required")
		return
	}
	if err := authorizeCommand(c.hostID, "sys_config", payload, msg.Lease, now); err != nil {
		log.Printf("sys_config refused: %s", err.Error())
		sysResultError(c.out, rid, "lease_required")
		return
	}
	if err := checkSysConfigPolicy(msg.Action, msg.Target); err != nil {
		log.Printf("sys_config refused: %s", err.Error())
		sysResultError(c.out, rid, err.Error())
		return
	}
	result := map[string]interface{}{"action": msg.Action, "target": msg.Target}
	var actErr error
	switch msg.Action {
	case "read":
		var out string
		out, actErr = sysConfigReadFile(msg.Target)
		if actErr == nil {
			result["output"] = out
		}
	case "write":
		// Privilege-separated write (config_helper.go). The agent's own sandbox
		// has ProtectSystem=strict (/etc read-only), so it cannot write a real
		// /etc config itself; it hands off to the committed helper unit whose
		// one relaxation is /etc in ReadWritePaths. The lease + policy gate
		// above is unchanged; the content hash (contentSHA) is carried through
		// and re-verified by the helper. read and reload are NOT helper'd: read
		// is a read, and reload runs `systemctl reload` over systemd like a
		// service restart and already works.
		actErr = configWriteViaHelper(msg.Target, msg.Content, contentSHA)
	case "reload":
		var out string
		out, actErr = sysConfig().Reload(msg.Target)
		result["output"] = capSysOutput(out)
	}
	result["ok"] = actErr == nil
	if actErr != nil {
		result["error"] = "action_failed"
	}
	_ = c.out.WriteJSON(ResponseMessage{Type: "sys_result", RequestID: rid, Payload: result})
	log.Printf("sys_config %s action=%s target=%s ok=%t", rid, msg.Action, msg.Target, actErr == nil)
}

// sysTweakMsg is the server's sys_tweak request frame. Only the fields the
// verb uses are set; content is present only for a unit-override, bound by its
// SHA-256 in the lease.
type sysTweakMsg struct {
	Type      string `json:"type"`
	RequestID string `json:"request_id"`
	Verb      string `json:"verb"`
	Key       string `json:"key"`
	Value     string `json:"value"`
	Unit      string `json:"unit"`
	Limit     string `json:"limit"`
	Name      string `json:"name"`
	Content   string `json:"content"`
	Lease     *Lease `json:"lease"`
}

// sysTweak applies one kernel/service knob: sysctl get/set, a resource limit,
// or a unit override. It rebuilds the signed payload from the frame (hashing a
// unit-override body), verifies the lease, applies its own gate, then performs
// the verb. sysctl-get reads through the Phase 0 Tweaks backend; the mutating
// verbs (sysctl-set, resource-limit-set, unit-override-set) are
// privilege-separated through committed helper units
// (sysctl_helper.go / systemd_override_helper.go), which re-validate the
// request independently before the root-equivalent write.
func (c *channelConn) sysTweak(msg sysTweakMsg, now time.Time) {
	rid := msg.RequestID
	if !sysRequestRe.MatchString(rid) {
		log.Printf("sys_tweak refused: bad request id")
		sysResultError(c.out, "", "internal")
		return
	}
	contentSHA := ""
	if msg.Verb == "unit-override-set" {
		contentSHA = sysSHA256Hex(msg.Content)
	}
	payload, err := sysTweakLeasePayload(msg.Verb, msg.Key, msg.Value, msg.Unit, msg.Limit, msg.Name, contentSHA)
	if err != nil {
		log.Printf("sys_tweak refused: %s", err.Error())
		sysResultError(c.out, rid, "lease_required")
		return
	}
	if err := authorizeCommand(c.hostID, "sys_tweak", payload, msg.Lease, now); err != nil {
		log.Printf("sys_tweak refused: %s", err.Error())
		sysResultError(c.out, rid, "lease_required")
		return
	}
	if err := checkSysTweakPolicy(msg.Verb, msg.Key, msg.Unit); err != nil {
		log.Printf("sys_tweak refused: %s", err.Error())
		sysResultError(c.out, rid, err.Error())
		return
	}
	tw := sysTweaks()
	result := map[string]interface{}{"verb": msg.Verb}
	var actErr error
	switch msg.Verb {
	case "sysctl-get":
		var out string
		out, actErr = tw.SysctlGet(msg.Key, []string{msg.Key})
		result["key"] = msg.Key
		if actErr == nil {
			result["output"] = capSysOutput(out)
		}
	case "sysctl-set":
		// Privilege-separated write (sysctl_helper.go). The agent's own sandbox
		// has ProtectKernelTunables=yes (/proc/sys read-only), so it cannot
		// write a sysctl itself; it hands off to the committed helper unit. The
		// lease + policy gate above is unchanged. The other mutating verbs
		// (resource-limit-set, unit-override-set, and sys:config write) are now
		// privilege-separated the same way; only sysctl-get (a read) still calls
		// the Phase 0 Tweaks backend directly.
		actErr = sysctlSetViaHelper(msg.Key, msg.Value)
		result["key"] = msg.Key
	case "resource-limit-set":
		// Privilege-separated write (systemd_override_helper.go): a drop-in
		// under /etc/systemd/system, which the agent's ProtectSystem=strict
		// sandbox forbids. Handed off to the committed helper whose one
		// relaxation is /etc/systemd/system in ReadWritePaths. The lease +
		// policy gate above is unchanged; the helper rebuilds the limit body
		// itself from unit/limit/value.
		actErr = resourceLimitSetViaHelper(msg.Unit, msg.Limit, msg.Value)
		result["unit"] = msg.Unit
		result["limit"] = msg.Limit
	case "unit-override-set":
		// Privilege-separated write (systemd_override_helper.go), same helper as
		// resource-limit-set. The content hash (contentSHA) is carried through
		// and re-verified by the helper.
		actErr = unitOverrideSetViaHelper(msg.Unit, msg.Name, msg.Content, contentSHA)
		result["unit"] = msg.Unit
		result["name"] = msg.Name
	}
	result["ok"] = actErr == nil
	if actErr != nil {
		result["error"] = "action_failed"
	}
	_ = c.out.WriteJSON(ResponseMessage{Type: "sys_result", RequestID: rid, Payload: result})
	log.Printf("sys_tweak %s verb=%s ok=%t", rid, msg.Verb, actErr == nil)
}
