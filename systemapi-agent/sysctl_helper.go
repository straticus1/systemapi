package main

// Privilege-separated sysctl mutation helper (docs/sah-os-management-design.md,
// "Finding 2026-10-23" + mutation-helper section, option 2). This is a
// security-keystone spike for the ONE verb sys:tweak sysctl-set.
//
// Why this exists: the agent runs under a sandbox with ProtectKernelTunables=yes,
// which makes /proc/sys read-only, so the agent process itself cannot write a
// sysctl. Rather than widen the agent's own sandbox (which would hand every
// agent code path the ability to write kernel tunables), the write is handed
// off to a separate, minimally-scoped helper whose sandbox is the agent's MINUS
// ProtectKernelTunables and nothing else. The sandbox is defined in a COMMITTED
// systemd unit (systemd/sah-sysctl-helper@.service), NOT constructed by the
// agent at runtime: the agent triggers it through systemd's manager and passes
// only a request id, never the confinement.
//
// Trust boundary (the whole point of the separation):
//   - The agent gates the channel on lease + per-host policy (sys.go /
//     sys_policy.go, unchanged): the Ed25519 lease binds the exact key/value,
//     the control plane enforces the per-host sysctl allowlist, and
//     checkSysTweakPolicy re-checks the shape and the DENIED_SYSCTL set. That
//     authorization stays entirely on the agent side.
//   - The helper does NOT trust the caller, which may be a compromised agent.
//     It authorizes the write itself (helper_auth.go): the request carries
//     the original signed sys_tweak lease, and the helper verifies it against
//     the control-plane key it loads from its own root-owned trust file, over
//     the payload it rebuilds from the exact key and value, checks
//     host/action/expiry, and consumes the nonce in a durable store the agent
//     cannot write. It also independently re-validates the key against the
//     same sysctlKeyRE and sysctlDenied list the channel uses, and the value
//     against sysctlValueOK. The per-host sysctl allowlist is enforced by the
//     control plane before it signs. It fails closed on every error.
//   - The handoff files are the agent's own: 0600, under the agent's writable
//     state dir, O_EXCL on write and O_NOFOLLOW on both ends, one request per
//     invocation keyed by a fresh random id, and cleaned up after. A planted
//     symlink cannot redirect either read; a non-regular file is refused.
//
// Threats: this path performs a root-equivalent kernel write. Every failure is
// a recorded result ({ok:false,error,errno}) or a refusal, never a silent
// success and never an unbounded wait. The value and key are size- and
// charset-capped before the write. No shell is ever involved: the write is a
// plain unix open/write syscall against a /proc/sys path resolved by
// sysctlProcPath (traversal-checked), and the trigger is a fixed systemctl
// argv carrying only a hex id.
//
// UNVERIFIED HOST ASSUMPTION (what this spike exists to test): that the agent,
// running under its own sandbox (NoNewPrivileges=yes and a restricted
// capability bounding set), is actually permitted to StartUnit the privileged
// sah-sysctl-helper@<id>.service over D-Bus / systemd's manager. That is the
// same StartUnit/job-wait access the agent already uses to restart a service
// (platform_service.go execs `systemctl`), but whether PID 1's policy lets a
// confined agent start THIS unit can only be confirmed on a real host. If it
// cannot, the handoff + helper + committed unit built here are still correct;
// only the trigger edge needs another mechanism.

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"syscall"
	"time"

	"crypto/rand"
)

// sysctlHelperStateDir is the agent-owned handoff directory. It sits under the
// agent's writable state dir (/var/lib/systemapi-agent is in the agent unit's
// ReadWritePaths), in a subdir the agent creates 0700. The committed helper
// unit lists exactly this path (plus /proc/sys) in its ReadWritePaths. A var so
// tests can point it at a temp dir.
var sysctlHelperStateDir = "/var/lib/systemapi-agent/sysctl-helper"

// sysctlHelperUnitPrefix is the committed per-verb sandbox unit
// (systemd/sah-sysctl-helper@.service). The instance name is the request id.
const sysctlHelperUnitPrefix = "sah-sysctl-helper@"

// sysctlHandoffMax caps a handoff file. A request is {key,value,lease} and a
// result is {ok,error,errno}; both are small.
const sysctlHandoffMax = 4 * 1024

// sysctlHelperIDRE matches the fresh random id the agent mints for one
// handoff. Hex only, so it is always a safe systemd instance name and a safe
// filename component.
var sysctlHelperIDRE = regexp.MustCompile(`^[0-9a-f]{32}$`)

// sysctlHelperReq is the agent->helper request. One per invocation. Lease is
// the signed sys_tweak lease exactly as the control plane sent it.
type sysctlHelperReq struct {
	Key   string `json:"key"`
	Value string `json:"value"`
	Lease *Lease `json:"lease"`
}

// sysctlHelperRes is the helper->agent result.
type sysctlHelperRes struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
	Errno int    `json:"errno,omitempty"`
}

// sysctlHelperTrigger starts the committed, privileged helper unit through
// systemd's manager, passing only the request id. `systemctl start` blocks
// until the oneshot job completes (the job-wait), so when it returns the result
// file is already written. tests replace it. See the UNVERIFIED HOST
// ASSUMPTION note above: this is the one edge that can only be proven on a host.
var sysctlHelperTrigger = func(id string) error {
	out, err := exec.Command("systemctl", "start", sysctlHelperUnitPrefix+id+".service").CombinedOutput()
	if err != nil {
		return fmt.Errorf("start sysctl helper: %v: %s", err, capSysOutput(string(out)))
	}
	return nil
}

// sysctlHelperWrite performs the actual /proc/sys write. It is the only write
// path for the helper and runs ONLY inside the helper process (under the
// helper's sandbox). tests replace it so no real kernel write happens. The raw
// error is returned so the caller can record its errno.
var sysctlHelperWrite = func(path, value string) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_TRUNC, 0)
	if err != nil {
		return err
	}
	_, writeErr := f.WriteString(value + "\n")
	closeErr := f.Close()
	if writeErr != nil {
		return writeErr
	}
	return closeErr
}

// sysctlSetViaHelper is the agent-side handoff for sys:tweak sysctl-set. The
// channel has already verified the lease and applied checkSysTweakPolicy; this
// re-validates defensively, writes a 0600 request the agent owns, triggers the
// committed helper unit, and reads back its result. It never writes /proc/sys
// itself (the agent's sandbox forbids it). Request and result files are removed
// before returning, so the handoff is one-shot and leaves nothing behind.
func sysctlSetViaHelper(key, value string, lease *Lease) error {
	// Defensive re-validation at the agent gate. The real authorization is the
	// lease + per-host allowlist (already enforced); the helper re-validates
	// again, independently. Fail closed.
	if sysctlDenied(key) || !sysctlKeyRE.MatchString(key) {
		return fmt.Errorf("sysctl not allowed")
	}
	if !sysctlValueOK(value) {
		return fmt.Errorf("sysctl value not allowed")
	}
	if lease == nil {
		return fmt.Errorf("sysctl set refused: lease_missing")
	}
	if err := os.MkdirAll(sysctlHelperStateDir, 0o700); err != nil {
		return fmt.Errorf("handoff dir: %w", err)
	}
	idb := make([]byte, 16)
	if _, err := rand.Read(idb); err != nil {
		return err
	}
	id := hex.EncodeToString(idb)
	reqPath := filepath.Join(sysctlHelperStateDir, id+".req")
	resPath := filepath.Join(sysctlHelperStateDir, id+".res")
	// One-shot: clean up both files no matter how this returns.
	defer os.Remove(reqPath)
	defer os.Remove(resPath)

	reqBytes, err := json.Marshal(sysctlHelperReq{Key: key, Value: value, Lease: lease})
	if err != nil {
		return err
	}
	if err := writeHandoffFile(reqPath, reqBytes); err != nil {
		return fmt.Errorf("write request: %w", err)
	}
	if err := sysctlHelperTrigger(id); err != nil {
		return err
	}
	res, err := readHandoffResult(resPath)
	if err != nil {
		return fmt.Errorf("sysctl helper result: %w", err)
	}
	if !res.OK {
		code := res.Error
		if code == "" {
			code = "helper_failed"
		}
		if res.Errno != 0 {
			return fmt.Errorf("sysctl helper: %s (errno %d)", code, res.Errno)
		}
		return fmt.Errorf("sysctl helper: %s", code)
	}
	return nil
}

// runSysctlHelper is the hidden `__sysctl-helper <id>` subcommand of the agent
// binary, invoked only by the committed helper unit. It reads one request,
// re-validates it independently, performs the write under its own sandbox, and
// writes a result file. It returns 0 whenever it managed to record a result
// (success OR a logical refusal/failure); it returns non-zero only when it
// could not read the request id or could not write the result at all.
func runSysctlHelper(args []string) int {
	if len(args) != 1 || !sysctlHelperIDRE.MatchString(args[0]) {
		fmt.Fprintln(os.Stderr, "sysctl-helper: bad or missing request id")
		return 2
	}
	id := args[0]
	reqPath := filepath.Join(sysctlHelperStateDir, id+".req")
	resPath := filepath.Join(sysctlHelperStateDir, id+".res")
	res := doSysctlHelper(reqPath)
	if err := writeHandoffResult(resPath, res); err != nil {
		fmt.Fprintf(os.Stderr, "sysctl-helper: write result: %v\n", err)
		return 2
	}
	return 0
}

// doSysctlHelper reads the request, re-validates and authorizes it (not
// trusting the caller), and performs the write. It never panics or exits; it always returns a result.
func doSysctlHelper(reqPath string) sysctlHelperRes {
	data, err := readHandoffFile(reqPath, sysctlHandoffMax)
	if err != nil {
		return sysctlHelperRes{Error: "no_request"}
	}
	var req sysctlHelperReq
	if err := json.Unmarshal(data, &req); err != nil {
		return sysctlHelperRes{Error: "bad_request"}
	}
	// Independent re-validation: the same key shape and DENIED_SYSCTL set the
	// channel uses, plus the value shape. The helper trusts none of this from
	// the caller and fails closed.
	if sysctlDenied(req.Key) || !sysctlKeyRE.MatchString(req.Key) {
		return sysctlHelperRes{Error: "key_denied"}
	}
	if !sysctlValueOK(req.Value) {
		return sysctlHelperRes{Error: "value_denied"}
	}
	path, err := sysctlProcPath(req.Key)
	if err != nil {
		return sysctlHelperRes{Error: "key_denied"}
	}
	payload, err := sysTweakLeasePayload("sysctl-set", req.Key, req.Value, "", "", "", "")
	if err != nil {
		return sysctlHelperRes{Error: "key_denied"}
	}
	if code := helperAuthorize("sys_tweak", payload, req.Lease, time.Now()); code != "" {
		return sysctlHelperRes{Error: code}
	}
	if err := sysctlHelperWrite(path, req.Value); err != nil {
		return sysctlHelperRes{Error: "write_failed", Errno: errnoOf(err)}
	}
	return sysctlHelperRes{OK: true}
}

// writeHandoffFile writes data to a fresh 0600 file. O_EXCL means the unique id
// must not already exist; O_NOFOLLOW means a planted symlink is refused.
func writeHandoffFile(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return err
	}
	_, writeErr := f.Write(data)
	closeErr := f.Close()
	if writeErr != nil {
		return writeErr
	}
	return closeErr
}

// readHandoffFile reads a handoff file without following a symlink, refuses a
// non-regular file, and caps the bytes at max. Shared by every mutation helper
// (sysctl, config, systemd-override); each passes its own cap because a config
// or unit-override request carries far more bytes than a sysctl one.
func readHandoffFile(path string, max int64) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("not a regular file")
	}
	return io.ReadAll(io.LimitReader(f, max))
}

func writeHandoffResult(path string, res sysctlHelperRes) error {
	data, err := json.Marshal(res)
	if err != nil {
		return err
	}
	return writeHandoffFile(path, data)
}

func readHandoffResult(path string) (sysctlHelperRes, error) {
	var res sysctlHelperRes
	data, err := readHandoffFile(path, sysctlHandoffMax)
	if err != nil {
		return res, err
	}
	if err := json.Unmarshal(data, &res); err != nil {
		return res, err
	}
	return res, nil
}

// errnoOf extracts the numeric errno from a syscall error, or 0 if there is
// none. Recorded in the result so the control plane can distinguish EPERM
// (sandbox denied the write) from EINVAL (bad value for the key), etc.
func errnoOf(err error) int {
	var errno syscall.Errno
	if errors.As(err, &errno) {
		return int(errno)
	}
	return 0
}
