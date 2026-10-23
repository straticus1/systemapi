package main

// Privilege-separated sys:config write helper (docs/sah-os-management-design.md,
// mutation-helper section, option 2). This extends the sysctl-set spike
// (sysctl_helper.go) to the ONE verb sys:config write. It is the same pattern,
// so read sysctl_helper.go first; only the differences are noted here.
//
// Why this exists: the agent runs under a sandbox with ProtectSystem=strict,
// which mounts the whole hierarchy (including /etc) read-only, so the agent
// process itself cannot do a real /etc config write. Rather than widen the
// agent's own sandbox (which would let every agent code path rewrite /etc), the
// write is handed off to a separate, minimally-scoped helper whose sandbox is
// the agent's hardening with exactly ONE relaxation: /etc is in ReadWritePaths
// (ProtectSystem stays strict). The sandbox is defined in a COMMITTED systemd
// unit (systemd/sah-config-helper@.service), NOT constructed by the agent; the
// agent triggers it through systemd's manager and passes only a request id.
//
// Trust boundary (the whole point of the separation):
//   - The agent gates the channel on lease + per-host policy (sys.go /
//     sys_policy.go, unchanged): the Ed25519 lease binds action, target AND the
//     content's SHA-256 (so a body swapped in transit no longer verifies), and
//     the control plane enforces the per-host config-path allowlist, which can
//     never include the agent/server self-roots (channel-policy.js
//     CONFIG_SELF_ROOTS). That authorization stays entirely on the agent side.
//   - The helper does NOT trust the caller. It independently re-validates the
//     target against the same rootShapeOk the channel uses, independently
//     refuses the agent/server self-roots (configSelfRoots, the Go copy of the
//     control-plane CONFIG_SELF_ROOTS deny set, so the config channel can never
//     rewrite the agent's own config even if the request file asks for it), and
//     independently re-verifies that the content hashes to the lease-bound
//     SHA-256 before writing. It fails closed otherwise. It cannot widen policy
//     because it has no lease and no allowlist; its only extra power is that
//     its sandbox lets it write /etc.
//   - The handoff files are the agent's own: 0600, under the agent's writable
//     state dir, O_EXCL on write and O_NOFOLLOW on both ends, one request per
//     invocation keyed by a fresh random id, and cleaned up after.
//
// Threats: this path performs a root-equivalent /etc write. Every failure is a
// recorded result ({ok:false,error,errno}) or a refusal, never a silent success
// and never an unbounded wait. The target and content are shape-, size- and
// hash-checked before the write. No shell is ever involved: the write is a
// plain atomic temp-file-fsync-rename against the resolved target, and the
// trigger is a fixed systemctl argv carrying only a hex id.
//
// UNVERIFIED HOST ASSUMPTION: identical to the sysctl spike (sysctl_helper.go)
// — that the confined agent is permitted to StartUnit this privileged helper
// over systemd's manager. Documented there; not re-litigated.

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"crypto/rand"
)

// configHelperStateDir is the agent-owned handoff directory, under the agent's
// writable state dir. The committed helper unit lists exactly this path (plus
// /etc) in its ReadWritePaths. A var so tests can point it at a temp dir.
var configHelperStateDir = "/var/lib/systemapi-agent/config-helper"

// configHelperUnitPrefix is the committed per-verb sandbox unit
// (systemd/sah-config-helper@.service). The instance name is the request id.
const configHelperUnitPrefix = "sah-config-helper@"

// configContentMax caps a config body. Mirrors the control plane's
// CONFIG_CONTENT_MAX (controlplane/channels.js) and the agent's read cap
// (sysConfigReadMax).
const configContentMax = 64 * 1024

// configHandoffMax caps a handoff file. A request is {target,content,sha};
// content is up to configContentMax, and JSON-escaping a worst-case control
// byte expands it ~6x, so the handoff cap is generously larger than the content
// cap. (The content itself is re-capped after unmarshal.)
const configHandoffMax = 512 * 1024

// configHelperIDRE matches the fresh random id the agent mints for one handoff.
// Hex only, so it is always a safe systemd instance name and filename
// component. Kept independent of the other helpers on purpose.
var configHelperIDRE = regexp.MustCompile(`^[0-9a-f]{32}$`)

// configSelfRoots are the agent/server self-roots a config write may never
// touch. This is the Go copy of controlplane/scripts/channel-policy.js
// CONFIG_SELF_ROOTS: the control plane refuses to GRANT a --config prefix at or
// around these, and the helper refuses to WRITE at or beneath them, so the
// config channel can never rewrite the agent's own config, keys or state even
// if the (0600, agent-owned) request file asks for it. Deny by prefix on a
// component boundary.
var configSelfRoots = []string{
	"/proc", "/sys", "/dev", "/boot",
	"/var/lib/systemapi-agent", "/etc/systemapi-agent", "/var/lib/postgresql", "/etc/sahcore",
}

// configHelperReq is the agent->helper request. One per invocation. SHA is the
// content's SHA-256 as bound in the lease; the helper re-verifies it.
type configHelperReq struct {
	Target  string `json:"target"`
	Content string `json:"content"`
	SHA     string `json:"sha"`
}

// configHelperRes is the helper->agent result.
type configHelperRes struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
	Errno int    `json:"errno,omitempty"`
}

// configTargetShapeOK is the Go copy of the server's rootShapeOk
// (controlplane/channels.js), the same shape the sys:config channel requires:
// a well-formed absolute path, at most 4096 bytes, no control byte, no empty,
// "." or ".." component, no trailing slash, and not "/" itself. Rejecting ".."
// here is what stops a request file from escaping an /etc prefix by traversal.
func configTargetShapeOK(p string) bool {
	if p == "" || len(p) > 4096 || p == "/" || !strings.HasPrefix(p, "/") || !noControl(p) {
		return false
	}
	if strings.HasSuffix(p, "/") {
		return false
	}
	for _, c := range strings.Split(p[1:], "/") {
		if c == "" || c == "." || c == ".." {
			return false
		}
	}
	return true
}

// configTargetDenied reports whether target is, or sits beneath, a self-root.
func configTargetDenied(target string) bool {
	for _, s := range configSelfRoots {
		if target == s || strings.HasPrefix(target, s+"/") {
			return true
		}
	}
	return false
}

// configRevalidate is the independent re-validation shared by the agent-side
// handoff and the helper subcommand. It returns "" when the write is allowed,
// or a stable error code. It trusts nothing from the caller and fails closed.
func configRevalidate(target, content, sha string) string {
	if !configTargetShapeOK(target) || configTargetDenied(target) {
		return "target_denied"
	}
	if len(content) > configContentMax {
		return "content_denied"
	}
	if !hashHexRe.MatchString(sha) || sysSHA256Hex(content) != sha {
		return "hash_mismatch"
	}
	return ""
}

// configHelperTrigger starts the committed, privileged helper unit through
// systemd's manager, passing only the request id. `systemctl start` blocks
// until the oneshot job completes, so the result file is already written when
// it returns. tests replace it.
var configHelperTrigger = func(id string) error {
	out, err := exec.Command("systemctl", "start", configHelperUnitPrefix+id+".service").CombinedOutput()
	if err != nil {
		return fmt.Errorf("start config helper: %v: %s", err, capSysOutput(string(out)))
	}
	return nil
}

// configHelperWrite performs the actual /etc write: an atomic temp-file,
// fsync, rename in the target's directory. It runs ONLY inside the helper
// process (under the helper's sandbox). tests replace it so no real /etc write
// happens. The raw error is returned so the caller can record its errno.
var configHelperWrite = func(path, content string) error {
	return writeFileAtomicSync(path, content, 0o644)
}

// configWriteViaHelper is the agent-side handoff for sys:config write. The
// channel has already verified the lease (which binds target + content hash)
// and applied checkSysConfigPolicy; this re-validates defensively, writes a
// 0600 request the agent owns, triggers the committed helper unit, and reads
// back its result. It never writes /etc itself (the agent's sandbox forbids
// it). Request and result files are removed before returning.
func configWriteViaHelper(target, content, contentSHA string) error {
	if code := configRevalidate(target, content, contentSHA); code != "" {
		return fmt.Errorf("config write refused: %s", code)
	}
	if err := os.MkdirAll(configHelperStateDir, 0o700); err != nil {
		return fmt.Errorf("handoff dir: %w", err)
	}
	idb := make([]byte, 16)
	if _, err := rand.Read(idb); err != nil {
		return err
	}
	id := hex.EncodeToString(idb)
	reqPath := filepath.Join(configHelperStateDir, id+".req")
	resPath := filepath.Join(configHelperStateDir, id+".res")
	defer os.Remove(reqPath)
	defer os.Remove(resPath)

	reqBytes, err := json.Marshal(configHelperReq{Target: target, Content: content, SHA: contentSHA})
	if err != nil {
		return err
	}
	if err := writeHandoffFile(reqPath, reqBytes); err != nil {
		return fmt.Errorf("write request: %w", err)
	}
	if err := configHelperTrigger(id); err != nil {
		return err
	}
	res, err := readConfigResult(resPath)
	if err != nil {
		return fmt.Errorf("config helper result: %w", err)
	}
	if !res.OK {
		code := res.Error
		if code == "" {
			code = "helper_failed"
		}
		if res.Errno != 0 {
			return fmt.Errorf("config helper: %s (errno %d)", code, res.Errno)
		}
		return fmt.Errorf("config helper: %s", code)
	}
	return nil
}

// runConfigHelper is the hidden `__config-helper <id>` subcommand of the agent
// binary, invoked only by the committed helper unit. It reads one request,
// re-validates it independently, performs the write under its own sandbox, and
// writes a result file. It returns 0 whenever it managed to record a result
// (success OR a logical refusal/failure); non-zero only when it could not read
// the request id or write the result at all.
func runConfigHelper(args []string) int {
	if len(args) != 1 || !configHelperIDRE.MatchString(args[0]) {
		fmt.Fprintln(os.Stderr, "config-helper: bad or missing request id")
		return 2
	}
	id := args[0]
	reqPath := filepath.Join(configHelperStateDir, id+".req")
	resPath := filepath.Join(configHelperStateDir, id+".res")
	res := doConfigHelper(reqPath)
	if err := writeConfigResult(resPath, res); err != nil {
		fmt.Fprintf(os.Stderr, "config-helper: write result: %v\n", err)
		return 2
	}
	return 0
}

// doConfigHelper reads the request, re-validates it (not trusting the caller),
// and performs the write. It never panics or exits; it always returns a result.
func doConfigHelper(reqPath string) configHelperRes {
	data, err := readHandoffFile(reqPath, configHandoffMax)
	if err != nil {
		return configHelperRes{Error: "no_request"}
	}
	var req configHelperReq
	if err := json.Unmarshal(data, &req); err != nil {
		return configHelperRes{Error: "bad_request"}
	}
	// Independent re-validation: same rootShapeOk + self-root deny + content
	// hash the channel/agent used. The helper trusts none of this from the
	// caller and fails closed.
	switch configRevalidate(req.Target, req.Content, req.SHA) {
	case "target_denied":
		return configHelperRes{Error: "target_denied"}
	case "content_denied":
		return configHelperRes{Error: "content_denied"}
	case "hash_mismatch":
		return configHelperRes{Error: "hash_mismatch"}
	}
	if err := configHelperWrite(req.Target, req.Content); err != nil {
		return configHelperRes{Error: "write_failed", Errno: errnoOf(err)}
	}
	return configHelperRes{OK: true}
}

func writeConfigResult(path string, res configHelperRes) error {
	data, err := json.Marshal(res)
	if err != nil {
		return err
	}
	return writeHandoffFile(path, data)
}

func readConfigResult(path string) (configHelperRes, error) {
	var res configHelperRes
	data, err := readHandoffFile(path, configHandoffMax)
	if err != nil {
		return res, err
	}
	if err := json.Unmarshal(data, &res); err != nil {
		return res, err
	}
	return res, nil
}

// writeFileAtomicSync writes content to path through a temp file in the SAME
// directory, fsyncs it, renames it over path, and fsyncs the directory so the
// rename is durable. Shared by the config and systemd-override helpers (both
// are independent, fail-closed /etc writers). The temp file is created 0600 by
// CreateTemp and chmod'd to perm before the rename; a leftover temp is removed
// on any error. It does not follow or create a backup — the control plane
// holds the bytes and can re-push.
func writeFileAtomicSync(path, content string, perm os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".systemapi-helper-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	// Remove the temp on any early return; a no-op after a successful rename.
	committed := false
	defer func() {
		if !committed {
			_ = os.Remove(tmpName)
		}
	}()
	if _, err := tmp.WriteString(content); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(perm); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	committed = true
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}
