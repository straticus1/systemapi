// Threats: an unsigned or swapped command, an expired lease, a lease minted
// for another host, and a nonce replayed inside the TTL. Verification
// rejects tampered, expired, wrong-host, wrong-action, and replayed input.
// Does NOT persist the nonce cache across process restarts (TTL cap is 300s).
// Does NOT accept a control public key that changes after the first pin.
// Terminal actions (pty, pty_root, breakglass) sign "<action>\n<session_id>\n
// <deadline_unix>\n<start|renew>", so a renewal lease is bound to one session,
// cannot move its deadline, and cannot be replayed as a start.
// Channel actions (tcp, file, file_root) sign "<action>\n<payload>" too, with
// the payloads of docs/sah-tcp-protocol.md §5 and docs/sah-file-protocol.md
// §7. The agent rebuilds the payload from what it is about to dial or open,
// so a lease for one target, root or mode never verifies for another. The
// builders refuse newlines and control bytes so fields cannot be shifted.
// Xfer actions (xfer, xfer_root) sign "<action>\n<payload>" with the 18-line
// payload of sahxfer docs/plans/2026-10-18-end-to-end-wiring.md ("Frames and
// payloads"), checked against the shared golden vector in testdata.
// An async sysscript job (sysscript_job) signs "sysscript_job\n<job_id>\n
// <deadline_unix>\n<timeout_s>\n<sha256(script)>\n<sha256(canonical
// entitlements v1)>". The agent rebuilds the entitlements text from its own
// parse of the frame (canonicalEntitlements), so entitlements changed in
// transit fail as payload_mismatch; the shared vectors are
// controlplane/testdata/sysscript-job-lease-vectors.json.
// A converge job (converge_job) signs "converge_job\n<job_id>\n
// <deadline_unix>\n<timeout_s>\n<sha256(bundle_json)>\n<sha256(canonical
// entitlements v1)>\n<check|apply>\n<expect_plan_sha256|->", so the mode and
// the approved plan hash cannot be swapped in transit, a check lease cannot
// run an apply, and neither a sysscript_job nor a converge_job lease verifies
// as the other (the action is in the hash). The shared vectors are
// controlplane/testdata/converge-job-lease-vectors.json.
package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"crypto/subtle"
)

const (
	leasePrefix   = "systemapi-lease-v1\n"
	leaseV2Prefix = "systemapi-lease-v2\n"
	leaseMaxTTL = 300 * time.Second
	leaseSkew   = 30 * time.Second
	nonceTTL    = 10 * time.Minute
)

var (
	nonceHexRe = regexp.MustCompile(`^[0-9a-f]{32}$`)
	hashHexRe  = regexp.MustCompile(`^[0-9a-f]{64}$`)

	identityMu     sync.Mutex
	controlPub     ed25519.PublicKey
	enrolledHostID string
	seenNonces     = map[string]time.Time{}
)

// Lease is the signed capability the control plane attaches to exec and PTY.
type Lease struct {
	V           int    `json:"v"`
	HostID      string `json:"host_id"`
	Action      string `json:"action"`
	ExpiresUnix int64  `json:"expires_unix"`
	NonceHex    string `json:"nonce_hex"`
	PayloadSHA  string `json:"payload_sha256"`
	// IntentSHA is set on a systemapi-lease-v2 lease only (intent.go). A v1
	// lease never has it, a v2 lease must.
	IntentSHA string `json:"intent_sha256,omitempty"`
	Signature string `json:"signature"`
}

func canonicalLease(hostID, action string, expiresUnix int64, nonceHex, payloadSHA string) string {
	return leasePrefix + hostID + "\n" + action + "\n" + strconv.FormatInt(expiresUnix, 10) + "\n" + nonceHex + "\n" + payloadSHA + "\n"
}

// canonicalLeaseV2 is the systemapi-lease-v2 text
// (.omc/plans/sah-signed-intent-contract.md 1.4): the v1 lines plus the
// intent hash. The prefix differs, so neither form verifies as the other.
func canonicalLeaseV2(hostID, action string, expiresUnix int64, nonceHex, payloadSHA, intentSHA string) string {
	return leaseV2Prefix + hostID + "\n" + action + "\n" + strconv.FormatInt(expiresUnix, 10) + "\n" + nonceHex + "\n" + payloadSHA + "\n" + intentSHA + "\n"
}

func payloadHash(action, payload string) string {
	sum := sha256.Sum256([]byte(payloadFor(action, payload)))
	return hex.EncodeToString(sum[:])
}

func payloadFor(action, payload string) string {
	if terminalAction(action) || channelAction(action) || xferAction(action) || sysAction(action) || action == "sysscript_job" || action == "converge_job" {
		return action + "\n" + payload
	}
	return payload
}

func terminalAction(action string) bool {
	return action == "pty" || action == "pty_root" || action == "breakglass"
}

// terminalPayload is the signed payload of a terminal lease. phase is
// "start" or "renew", so a renewal lease cannot start a session.
func terminalPayload(sessionID string, deadlineUnix int64, phase string) string {
	return sessionID + "\n" + strconv.FormatInt(deadlineUnix, 10) + "\n" + phase
}

func hashEqual(a, b string) bool {
	if !hashHexRe.MatchString(a) || !hashHexRe.MatchString(b) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

func knownAction(action string) bool {
	return action == "sysscript" || action == "sysscript_job" || action == "converge_job" || terminalAction(action) || channelAction(action) || xferAction(action) || sysAction(action)
}

// sysAction reports the SAH OS-management channel lease actions
// (docs/sah-os-management-design.md).
func sysAction(action string) bool {
	return action == "sys_service" || action == "sys_package" || action == "sys_config" || action == "sys_tweak"
}

// xferAction reports the sahxfer grant lease actions.
func xferAction(action string) bool {
	return action == "xfer" || action == "xfer_root"
}

// channelAction reports the SAH channel lease actions.
func channelAction(action string) bool {
	return action == "tcp" || action == "file" || action == "file_root"
}

var (
	tcpSessionRe  = regexp.MustCompile(`^tcs_[A-Za-z0-9_-]{16,64}$`)
	fileSessionRe = regexp.MustCompile(`^fls_[A-Za-z0-9_-]{16,64}$`)
	tcpLeaseHost  = regexp.MustCompile(`^(local|[0-9A-Fa-f.:]{2,45})$`)
)

func checkLeaseCommon(sessionID string, re *regexp.Regexp, deadlineUnix int64, phase string) error {
	if !re.MatchString(sessionID) {
		return errors.New("bad_session_id")
	}
	if deadlineUnix <= 0 {
		return errors.New("bad_deadline")
	}
	if phase != "start" && phase != "renew" {
		return errors.New("bad_phase")
	}
	return nil
}

// tcpLeasePayload is the signed payload of a tcp lease (TCP §5):
// "<session_id>\n<deadline_unix>\n<start|renew>\n<target.host>\n<port>".
func tcpLeasePayload(sessionID string, deadlineUnix int64, phase, host string, port int) (string, error) {
	if err := checkLeaseCommon(sessionID, tcpSessionRe, deadlineUnix, phase); err != nil {
		return "", err
	}
	if !tcpLeaseHost.MatchString(host) {
		return "", errors.New("bad_target")
	}
	if port < 1 || port > 65535 {
		return "", errors.New("bad_target")
	}
	return sessionID + "\n" + strconv.FormatInt(deadlineUnix, 10) + "\n" + phase + "\n" + host + "\n" + strconv.Itoa(port), nil
}

// fileLeasePayload is the signed payload of a file or file_root lease
// (FILE §7): "<session_id>\n<deadline_unix>\n<start|renew>\n<read|write>\n<root>".
func fileLeasePayload(sessionID string, deadlineUnix int64, phase, mode, root string) (string, error) {
	if err := checkLeaseCommon(sessionID, fileSessionRe, deadlineUnix, phase); err != nil {
		return "", err
	}
	if mode != "read" && mode != "write" {
		return "", errors.New("bad_mode")
	}
	if root == "" || len(root) > 4096 || (root != "~" && root[0] != '/') {
		return "", errors.New("bad_root")
	}
	for i := 0; i < len(root); i++ {
		if root[i] < 0x20 || root[i] == 0x7f {
			return "", errors.New("bad_root")
		}
	}
	return sessionID + "\n" + strconv.FormatInt(deadlineUnix, 10) + "\n" + phase + "\n" + mode + "\n" + root, nil
}

// sysServiceLeasePayload is the signed payload of a sys_service lease
// (docs/sah-os-management-design.md): "<unit>\n<action>". The agent rebuilds
// it from the unit and action it is about to act on, so a lease for one unit
// or verb never authorizes another. action is one of sysServiceActions
// (sys_policy.go), byte-for-byte the server's SERVICE_LEASE_ACTIONS
// (controlplane/lease.js). The unit shape mirrors the server's
// SERVICE_UNIT_RE.
func sysServiceLeasePayload(unit, action string) (string, error) {
	if _, ok := sysServiceActions[action]; !ok {
		return "", errors.New("bad_action")
	}
	if !serviceNameRE.MatchString(unit) {
		return "", errors.New("bad_unit")
	}
	return unit + "\n" + action, nil
}

// sysPackageLeasePayload is the signed payload of a sys_package lease
// (docs/sah-os-management-design.md): "<name>\n<action>". The agent rebuilds
// it from the name and verb it is about to act on, so a lease for one package
// or verb never authorizes another. action is one of sysPackageActions
// (sys_policy.go), byte-for-byte the server's PACKAGE_LEASE_ACTIONS
// (controlplane/lease.js). The name shape mirrors the server's
// PACKAGE_NAME_RE and the agent's packageNameRE (grant.go).
func sysPackageLeasePayload(name, action string) (string, error) {
	if _, ok := sysPackageActions[action]; !ok {
		return "", errors.New("bad_action")
	}
	if !packageNameRE.MatchString(name) {
		return "", errors.New("bad_name")
	}
	return name + "\n" + action, nil
}

// sysConfigLeasePayload is the signed payload of a sys_config lease
// (docs/sah-os-management-design.md), byte-for-byte the server's
// sysConfigPayload (controlplane/lease.js):
//
//	read:   "read\n<path>"
//	write:  "write\n<path>\n<content_sha256>"
//	reload: "reload\n<unit>"
//
// For a write the agent passes contentSHA = sha256hex(content), so a tampered
// body yields a different hash and verifyLease refuses it. read/write target
// an absolute path; reload targets a unit (serviceNameRE).
func sysConfigLeasePayload(action, target, contentSHA string) (string, error) {
	switch action {
	case "reload":
		if !serviceNameRE.MatchString(target) {
			return "", errors.New("bad_unit")
		}
		return "reload\n" + target, nil
	case "read", "write":
		if target == "" || len(target) > 4096 || target == "/" || !strings.HasPrefix(target, "/") || !noControl(target) {
			return "", errors.New("bad_path")
		}
		if action == "read" {
			return "read\n" + target, nil
		}
		if !hashHexRe.MatchString(contentSHA) {
			return "", errors.New("bad_content")
		}
		return "write\n" + target + "\n" + contentSHA, nil
	default:
		return "", errors.New("bad_action")
	}
}

// sysTweakLeasePayload is the signed payload of a sys_tweak lease
// (docs/sah-os-management-design.md), byte-for-byte the server's
// sysTweakPayload (controlplane/lease.js). A unit-override body is bound by
// contentSHA; other verbs' short values ride the payload. Field shapes reuse
// the agent's existing guards (grant.go sysctlKeyOK/sysctlDenied/sysctlValueOK,
// platform_tweak.go resourceLimits/limitValueRE/overrideNameRE).
func sysTweakLeasePayload(verb, key, value, unit, limit, name, contentSHA string) (string, error) {
	sysctlKeyOK := func(k string) bool {
		if sysctlDenied(k) {
			return false
		}
		return sysctlKeyOK(k)
	}
	switch verb {
	case "sysctl-get":
		if !sysctlKeyOK(key) {
			return "", errors.New("bad_key")
		}
		return "sysctl-get\n" + key, nil
	case "sysctl-set":
		if !sysctlKeyOK(key) || !sysctlValueOK(value) {
			return "", errors.New("bad_key")
		}
		return "sysctl-set\n" + key + "\n" + value, nil
	case "resource-limit-set":
		if !serviceNameRE.MatchString(unit) {
			return "", errors.New("bad_unit")
		}
		if _, ok := resourceLimits[limit]; !ok || !limitValueRE.MatchString(value) {
			return "", errors.New("bad_limit")
		}
		return "resource-limit-set\n" + unit + "\n" + limit + "\n" + value, nil
	case "unit-override-set":
		if !serviceNameRE.MatchString(unit) || !overrideNameRE.MatchString(name) {
			return "", errors.New("bad_unit")
		}
		if !hashHexRe.MatchString(contentSHA) {
			return "", errors.New("bad_content")
		}
		return "unit-override-set\n" + unit + "\n" + name + "\n" + contentSHA, nil
	default:
		return "", errors.New("bad_action")
	}
}

const (
	xferMaxSeconds = 3600
	// xferMaxInt is Number.MAX_SAFE_INTEGER, the server's integer bound.
	xferMaxInt = 1<<53 - 1
)

var (
	xferGrantRe    = regexp.MustCompile(`^xfr_[A-Za-z0-9_-]{8,64}$`)
	xferTransferRe = regexp.MustCompile(`^[0-9a-f]{16}$`)
	xferPeerAddrRe = regexp.MustCompile(`^(\[[0-9A-Fa-f:.]+\]|[A-Za-z0-9.-]+):([1-9][0-9]{0,4})$`)
)

// xferLeaseFields are the 18 signed fields of an xfer lease, in line order.
type xferLeaseFields struct {
	GrantID      string
	DeadlineUnix int64
	Phase        string
	Dir          string
	Root         string
	Path         string
	Size         int64
	SHA256       string
	Overwrite    bool
	TransferID   string
	ExpiresUnix  int64
	IdleS        int64
	MaxS         int64
	ByteCap      int64
	Profile      string
	Transport    string
	Peer         string
	Material     string
}

func noControl(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] == 0x7f {
			return false
		}
	}
	return true
}

// xferRootOK is the server's rootShapeOk: absolute, at most 4096 bytes, no
// control byte, no empty, "." or ".." component, no trailing slash.
func xferRootOK(root string) bool {
	if !utf8.ValidString(root) || !strings.HasPrefix(root, "/") || len(root) > 4096 || !noControl(root) {
		return false
	}
	if root == "/" {
		return true
	}
	for _, c := range strings.Split(root[1:], "/") {
		if c == "" || c == "." || c == ".." {
			return false
		}
	}
	return true
}

// xferPathOK is the server's xferPayload path rule: relative, 1 to 4096
// bytes, no control byte or backslash, components non-empty, not "." or
// "..", each at most 255 bytes.
func xferPathOK(path string) bool {
	if !utf8.ValidString(path) || len(path) < 1 || len(path) > 4096 || strings.HasPrefix(path, "/") ||
		!noControl(path) || strings.Contains(path, "\\") {
		return false
	}
	for _, c := range strings.Split(path, "/") {
		if c == "" || c == "." || c == ".." || len(c) > 255 {
			return false
		}
	}
	return true
}

// xferPeerOK accepts "listen" or "dial:<host:port>" (the server's peerAddress).
func xferPeerOK(peer string) bool {
	if peer == "listen" {
		return true
	}
	addr, ok := strings.CutPrefix(peer, "dial:")
	if !ok || addr == "" || len(addr) > 256 || !noControl(addr) || strings.ContainsAny(addr, " \t") {
		return false
	}
	m := xferPeerAddrRe.FindStringSubmatch(addr)
	if m == nil {
		return false
	}
	port, err := strconv.Atoi(m[2])
	return err == nil && port <= 65535
}

func intIn(n, lo, hi int64) bool { return n >= lo && n <= hi }

// xferLeasePayload is the signed payload of an xfer or xfer_root lease. It
// validates every field as the server's controlplane/lease.js xferPayload
// does, so a field the server would never sign is never accepted here.
func xferLeasePayload(f xferLeaseFields) (string, error) {
	if !xferGrantRe.MatchString(f.GrantID) {
		return "", errors.New("bad_grant_id")
	}
	if f.DeadlineUnix <= 0 {
		return "", errors.New("bad_deadline")
	}
	if f.Phase != "start" && f.Phase != "renew" {
		return "", errors.New("bad_phase")
	}
	if f.Dir != "put" && f.Dir != "get" {
		return "", errors.New("bad_dir")
	}
	if !xferRootOK(f.Root) {
		return "", errors.New("bad_root")
	}
	if !xferPathOK(f.Path) {
		return "", errors.New("bad_path")
	}
	if !intIn(f.Size, 0, xferMaxInt) {
		return "", errors.New("bad_size")
	}
	if !hashHexRe.MatchString(f.SHA256) {
		return "", errors.New("bad_sha256")
	}
	if !xferTransferRe.MatchString(f.TransferID) || f.TransferID == "0000000000000000" {
		return "", errors.New("bad_transfer_id")
	}
	if !intIn(f.ExpiresUnix, 1, xferMaxInt) {
		return "", errors.New("bad_expires")
	}
	if !intIn(f.MaxS, 1, xferMaxSeconds) || !intIn(f.IdleS, 1, f.MaxS) {
		return "", errors.New("bad_limits")
	}
	if !intIn(f.ByteCap, f.Size, xferMaxInt) {
		return "", errors.New("bad_byte_cap")
	}
	if f.Profile != "internet" && f.Profile != "dc" {
		return "", errors.New("bad_profile")
	}
	if f.Transport != "udp" {
		return "", errors.New("bad_transport")
	}
	if !xferPeerOK(f.Peer) {
		return "", errors.New("bad_peer")
	}
	if !hashHexRe.MatchString(f.Material) {
		return "", errors.New("bad_material")
	}
	ow := "0"
	if f.Overwrite {
		ow = "1"
	}
	i := func(n int64) string { return strconv.FormatInt(n, 10) }
	return strings.Join([]string{
		f.GrantID, i(f.DeadlineUnix), f.Phase, f.Dir, f.Root, f.Path, i(f.Size), f.SHA256, ow, f.TransferID,
		i(f.ExpiresUnix), i(f.IdleS), i(f.MaxS), i(f.ByteCap), f.Profile, f.Transport, f.Peer, f.Material,
	}, "\n"), nil
}

// xferMaterial is lease line 18: hex SHA-256 of "sahxfer-material-v1\n" ||
// key || route_token over the raw 32 and 16 bytes.
func xferMaterial(key, routeToken []byte) (string, error) {
	if len(key) != 32 || len(routeToken) != 16 {
		return "", errors.New("bad_material")
	}
	h := sha256.New()
	h.Write([]byte("sahxfer-material-v1\n"))
	h.Write(key)
	h.Write(routeToken)
	return hex.EncodeToString(h.Sum(nil)), nil
}

const (
	entitlementsPrefix = "systemapi-entitlements-v1\n"
	// canonicalListMax refuses a list longer than this in the canonical
	// text (path lists are not capped by the parse).
	canonicalListMax = 64
	// sysscriptJobTimeoutMax is the hard cap of a signed timeout_s.
	sysscriptJobTimeoutMax = 3600
)

var sysscriptJobRe = regexp.MustCompile(`^sjb_[A-Za-z0-9_-]{22}$`)

// canonicalEntitlements is the v1 text of parsed entitlements: a header
// line, then one record per field in struct order. A boolean is
// "<name>=true|false"; a list is "<name>#<count>" and one line per item,
// deduplicated and sorted by byte order. An item with "\n" or "\r", or a
// list over canonicalListMax items, is refused (bad_entitlements). nil
// means no entitlements. controlplane/entitlements.js computes the same
// text from the object it sends.
func canonicalEntitlements(e *Entitlements) (string, error) {
	if e == nil {
		e = &Entitlements{}
	}
	var b strings.Builder
	b.WriteString(entitlementsPrefix)
	flag := func(name string, v bool) {
		b.WriteString(name + "=" + strconv.FormatBool(v) + "\n")
	}
	list := func(name string, items []string) error {
		if len(items) > canonicalListMax {
			return errors.New("bad_entitlements")
		}
		seen := make(map[string]struct{}, len(items))
		uniq := make([]string, 0, len(items))
		for _, it := range items {
			if strings.ContainsAny(it, "\n\r") {
				return errors.New("bad_entitlements")
			}
			if _, dup := seen[it]; !dup {
				seen[it] = struct{}{}
				uniq = append(uniq, it)
			}
		}
		sort.Strings(uniq)
		b.WriteString(name + "#" + strconv.Itoa(len(uniq)) + "\n")
		for _, it := range uniq {
			b.WriteString(it + "\n")
		}
		return nil
	}
	for _, f := range []struct {
		name   string
		items  []string
		isBool bool
		v      bool
	}{
		{name: "allow_fs_write", items: e.AllowFSWrite},
		{name: "allow_fs_read", items: e.AllowFSRead},
		{name: "allow_net_outbound", items: e.AllowNetOutbound},
		{name: "allow_exec", isBool: true, v: e.AllowExec},
		{name: "allow_config_write", items: e.AllowConfigWrite},
		{name: "allow_service_reload", items: e.AllowServiceReload},
		{name: "allow_containers", isBool: true, v: e.AllowContainers},
		{name: "allow_k3s", isBool: true, v: e.AllowK3s},
		{name: "allow_linux", isBool: true, v: e.AllowLinux},
		{name: "allow_k8s", isBool: true, v: e.AllowK8s},
		{name: "allow_packages", items: e.AllowPackages},
		{name: "allow_images", items: e.AllowImages},
		{name: "allow_k3s_namespaces", items: e.AllowK3sNamespaces},
		{name: "allow_k8s_namespaces", items: e.AllowK8sNamespaces},
		{name: "allow_net_manage", items: e.AllowNetManage},
		{name: "allow_mount_targets", items: e.AllowMountTargets},
		{name: "allow_sysctl", items: e.AllowSysctl},
	} {
		if f.isBool {
			flag(f.name, f.v)
			continue
		}
		if err := list(f.name, f.items); err != nil {
			return "", err
		}
	}
	return b.String(), nil
}

// sha256Hex is the lowercase hex SHA-256 of s.
func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// sysscriptJobLeasePayload is the signed payload of a sysscript_job lease:
// "<job_id>\n<deadline_unix>\n<timeout_s>\n<script_sha256>\n
// <entitlements_sha256>". It refuses what the server's lease.js
// sysscriptJobPayload would never sign.
func sysscriptJobLeasePayload(jobID string, deadlineUnix int64, timeoutS int, scriptSHA, entsSHA string) (string, error) {
	if !sysscriptJobRe.MatchString(jobID) {
		return "", errors.New("bad_job_id")
	}
	if deadlineUnix <= 0 || timeoutS < 1 || timeoutS > sysscriptJobTimeoutMax {
		return "", errors.New("bad_deadline")
	}
	if !hashHexRe.MatchString(scriptSHA) || !hashHexRe.MatchString(entsSHA) {
		return "", errors.New("bad_payload")
	}
	return jobID + "\n" + strconv.FormatInt(deadlineUnix, 10) + "\n" + strconv.Itoa(timeoutS) + "\n" + scriptSHA + "\n" + entsSHA, nil
}

// convergeModeOK reports whether mode and expectPlan agree: check with "-",
// apply with a 64-hex plan hash.
func convergeModeOK(mode, expectPlan string) bool {
	return (mode == "check" && expectPlan == "-") || (mode == "apply" && hashHexRe.MatchString(expectPlan))
}

// convergeJobLeasePayload is the signed payload of a converge_job lease:
// "<job_id>\n<deadline_unix>\n<timeout_s>\n<bundle_sha256>\n
// <entitlements_sha256>\n<check|apply>\n<expect_plan_sha256|->". It refuses
// what the server's lease.js convergeJobPayload would never sign; a mode and
// plan hash that disagree are bad_mode.
func convergeJobLeasePayload(jobID string, deadlineUnix int64, timeoutS int, bundleSHA, entsSHA, mode, expectPlan string) (string, error) {
	base, err := sysscriptJobLeasePayload(jobID, deadlineUnix, timeoutS, bundleSHA, entsSHA)
	if err != nil {
		return "", err
	}
	if !convergeModeOK(mode, expectPlan) {
		return "", errors.New("bad_mode")
	}
	return base + "\n" + mode + "\n" + expectPlan, nil
}

// verifyLease checks the signature and the time window of a v1 lease. It does
// not record the nonce; authorizeCommand does that after a successful verify.
// A v2 lease, or a v1 lease carrying an intent hash, is malformed here, so an
// agent path that knows nothing of intents never accepts one.
func verifyLease(pub ed25519.PublicKey, lease *Lease, expectedHost, expectedAction, payload string, now time.Time) error {
	if lease == nil || len(pub) != ed25519.PublicKeySize {
		return errors.New("malformed")
	}
	if lease.V != 1 || lease.IntentSHA != "" {
		return errors.New("malformed")
	}
	return verifyLeaseFields(pub, lease, expectedHost, expectedAction, payload, now)
}

// verifyLeaseV2 is verifyLease for a systemapi-lease-v2 lease: the same
// checks over the v2 canonical form, for an action that can carry an intent.
// It returns the lease's intent hash. It does not check the intent itself
// (checkIntentStart) and does not record the nonce.
func verifyLeaseV2(pub ed25519.PublicKey, lease *Lease, expectedHost, expectedAction, payload string, now time.Time) (string, error) {
	if lease == nil || len(pub) != ed25519.PublicKeySize {
		return "", errors.New("malformed")
	}
	if lease.V != 2 || !hashHexRe.MatchString(lease.IntentSHA) {
		return "", errors.New("malformed")
	}
	if !intentLeaseAction(expectedAction) {
		return "", errors.New("bad_action")
	}
	if err := verifyLeaseFields(pub, lease, expectedHost, expectedAction, payload, now); err != nil {
		return "", err
	}
	return lease.IntentSHA, nil
}

func verifyLeaseFields(pub ed25519.PublicKey, lease *Lease, expectedHost, expectedAction, payload string, now time.Time) error {
	if lease.HostID == "" || subtle.ConstantTimeCompare([]byte(lease.HostID), []byte(expectedHost)) != 1 {
		return errors.New("bad_host")
	}
	if !knownAction(lease.Action) || lease.Action != expectedAction {
		return errors.New("bad_action")
	}
	if lease.ExpiresUnix <= 0 {
		return errors.New("bad_expiry")
	}
	if !nonceHexRe.MatchString(lease.NonceHex) {
		return errors.New("bad_nonce")
	}
	nowUnix := now.Unix()
	if lease.ExpiresUnix < nowUnix-int64(leaseSkew.Seconds()) {
		return errors.New("expired")
	}
	if lease.ExpiresUnix > nowUnix+int64(leaseMaxTTL.Seconds()) {
		return errors.New("expiry_too_far")
	}
	expect := payloadHash(expectedAction, payload)
	if !hashEqual(expect, lease.PayloadSHA) {
		return errors.New("payload_mismatch")
	}
	sig, err := base64.StdEncoding.DecodeString(lease.Signature)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return errors.New("bad_signature")
	}
	msg := canonicalLease(lease.HostID, lease.Action, lease.ExpiresUnix, lease.NonceHex, lease.PayloadSHA)
	if lease.V == 2 {
		msg = canonicalLeaseV2(lease.HostID, lease.Action, lease.ExpiresUnix, lease.NonceHex, lease.PayloadSHA, lease.IntentSHA)
	}
	if !ed25519.Verify(pub, []byte(msg), sig) {
		return errors.New("bad_signature")
	}
	return nil
}

func rememberNonce(nonce string, now time.Time) error {
	identityMu.Lock()
	defer identityMu.Unlock()
	cutoff := now.Add(-nonceTTL)
	for k, seen := range seenNonces {
		if seen.Before(cutoff) {
			delete(seenNonces, k)
		}
	}
	if _, ok := seenNonces[nonce]; ok {
		return errors.New("replay")
	}
	seenNonces[nonce] = now
	return nil
}

func resetNonceCache() {
	identityMu.Lock()
	seenNonces = map[string]time.Time{}
	identityMu.Unlock()
}

// authorizeCommand refuses exec and PTY until a control key is pinned, then
// verifies the lease and consumes its nonce.
func authorizeCommand(expectedHost, action, payload string, lease *Lease, now time.Time) error {
	identityMu.Lock()
	pub := controlPub
	host := enrolledHostID
	identityMu.Unlock()
	if len(pub) != ed25519.PublicKeySize || host == "" {
		return errors.New("not_enrolled")
	}
	if subtle.ConstantTimeCompare([]byte(host), []byte(expectedHost)) != 1 {
		return errors.New("bad_host")
	}
	if err := verifyLease(pub, lease, expectedHost, action, payload, now); err != nil {
		return err
	}
	return rememberNonce(lease.NonceHex, now)
}

// enrolledIdentity returns the pinned control key and host, or not_enrolled,
// and refuses another host (authorizeCommand's first checks).
func enrolledIdentity(expectedHost string) (ed25519.PublicKey, error) {
	identityMu.Lock()
	pub := controlPub
	host := enrolledHostID
	identityMu.Unlock()
	if len(pub) != ed25519.PublicKeySize || host == "" {
		return nil, errors.New("not_enrolled")
	}
	if subtle.ConstantTimeCompare([]byte(host), []byte(expectedHost)) != 1 {
		return nil, errors.New("bad_host")
	}
	return pub, nil
}

// authorizeIntentStart is authorizeCommand for an intent-bound START lease
// (contract 1.5): verifyLeaseV2, checkIntentStart against intentText and the
// caller's context, then the nonce. It returns the intent hash the caller
// stores on the session for its renewals.
func authorizeIntentStart(expectedHost, action, payload string, lease *Lease, intentText string, ctx intentCtx, now time.Time) (string, error) {
	pub, err := enrolledIdentity(expectedHost)
	if err != nil {
		return "", err
	}
	sha, err := verifyLeaseV2(pub, lease, expectedHost, action, payload, now)
	if err != nil {
		return "", err
	}
	if _, err := checkIntentStart(intentText, lease, ctx, now); err != nil {
		return "", err
	}
	if err := rememberNonce(lease.NonceHex, now); err != nil {
		return "", err
	}
	return sha, nil
}

// authorizeIntentRenew is authorizeCommand for a v2 RENEW lease of a session
// started with an intent: verifyLeaseV2 and the lease's intent hash equal to
// the stored one (constant time), then the nonce. There is no payload-vs-
// intent check (the intent hashes the START payload) and no use_by check (a
// session approved at minute 14 may run to its deadline).
func authorizeIntentRenew(expectedHost, action, payload string, lease *Lease, storedIntentSHA string, now time.Time) error {
	pub, err := enrolledIdentity(expectedHost)
	if err != nil {
		return err
	}
	sha, err := verifyLeaseV2(pub, lease, expectedHost, action, payload, now)
	if err != nil {
		return err
	}
	if !hashEqual(sha, storedIntentSHA) {
		return errors.New("intent_mismatch")
	}
	return rememberNonce(lease.NonceHex, now)
}

func pinControlPublicKey(b64, hostID string) error {
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return errors.New("bad_control_pubkey")
	}
	identityMu.Lock()
	defer identityMu.Unlock()
	if len(controlPub) == ed25519.PublicKeySize {
		if subtle.ConstantTimeCompare(controlPub, raw) != 1 {
			return errors.New("control_pubkey_changed")
		}
	} else {
		controlPub = ed25519.PublicKey(append([]byte(nil), raw...))
	}
	enrolledHostID = hostID
	sum := sha256.Sum256(raw)
	// Fingerprint only. The raw key is not logged.
	fmt.Printf("[agent] control pubkey sha256:%s\n", hex.EncodeToString(sum[:]))
	return nil
}

func clearIdentity() {
	identityMu.Lock()
	controlPub = nil
	enrolledHostID = ""
	seenNonces = map[string]time.Time{}
	identityMu.Unlock()
}
