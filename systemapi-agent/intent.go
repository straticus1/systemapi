package main

// systemapi-intent-v1, the require-intent host pin and intent receipts
// (.omc/plans/sah-signed-intent-contract.md 1.1-1.6, 2.4, 2.5).
//
// An intent is 13 LF-ended lines naming the request, tenant, host,
// requester, action, the START lease's payload hash, the approval window and
// the session deadline. A systemapi-lease-v2 lease (lease.go) signs the
// intent's SHA-256 beside the usual fields. At a START the agent checks the
// intent text against the lease (hash, host, action, payload), against what
// it knows (the requester, the request id, the frame's deadline) and against
// its own clock (not_before..use_by). The session keeps the intent hash; a
// RENEW must carry the same hash, and a v1 renew on an intent session (or a
// v2 renew on a session without one) is refused.
//
// /etc/systemapi-agent/require-intent lists approval classes for which this
// host refuses a v1 lease (intent_required). It is written by the install
// kit or an out-of-band runbook, never by the control plane, and loaded with
// the helper trust-file rules (trustedNode). A damaged file makes every
// approval-class action refuse, v1 and v2 alike (intent_pin_unavailable).
//
// Every accepted approval-class lease, start or renew, v1 or v2, writes one
// intent_receipt journal line, so a verifier reading the host's journal
// (never through the CP) can find a lease the CP did not record.
//
// Threats: a start lease for an action, host, payload, requester, request or
// deadline other than the approved intent; an intent text with shifted
// fields (embedded newline, space, control byte, reordered lines, a wrong
// domain prefix); an intent used outside its window on this host's clock; a
// renew that swaps in another intent or downgrades to v1; a CP that sends a
// v1 lease for a class this host pins. Does NOT check who approved the
// intent (1B is server side; 1C quorum is phase 4) and does NOT keep a
// durable consumed-request store (phase 4): within the 1.1 window a second
// v2 lease for the same intent with a fresh nonce is accepted. Does NOT
// protect against root on this host, which can edit the pin and the journal.
// Nothing on the control plane sends v2 yet.

import (
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	intentPrefix        = "systemapi-intent-v1"
	intentLines         = 13
	intentMaxBytes      = 2048
	intentWindowMaxS    = 3600
	intentBreakglassMax = 14400
	// intentRootSessionMax is the structural cap for root sessions
	// (PTY_MAX_SECONDS_CAP, fleet.js); the tenant's SYSTEMAPI_PTY_MAX_SECONDS
	// is the control plane's to apply.
	intentRootSessionMax = 7 * 24 * 3600
	// intentMaxInt is Number.MAX_SAFE_INTEGER, the control plane's bound.
	intentMaxInt = 1<<53 - 1

	requireIntentMax = 1024
)

var (
	intentRequestRe = regexp.MustCompile(`^apr_[A-Za-z0-9_-]{22}$`)
	// intentUserRe is the control plane's USER_RE (router.js). It has no
	// colon, so "member:<user_id>" splits one way only.
	intentUserRe    = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._@-]{0,128}$`)
	intentDecimalRe = regexp.MustCompile(`^(0|[1-9][0-9]{0,15})$`)

	intentActions = map[string]bool{
		"breakglass": true, "pty_root": true, "file_root": true, "xfer_root": true,
		"sys_config": true, "sys_tweak": true, "sys_service": true, "sys_package": true,
		"sysscript_job": true, "recovery_sshd": true, "policy_grant": true,
		"approver_admin": true, "tenant_flag": true,
	}

	// requireIntentPath is the require-intent host pin. A var for tests.
	requireIntentPath = "/etc/systemapi-agent/require-intent"

	// intentReceiptSink receives each intent_receipt line. Tests replace it.
	intentReceiptSink = func(line string) { log.Print(line) }
)

// intentClassNames are the four classes a host can pin (contract 2.4).
var intentClassNames = map[string]bool{
	"breakglass": true, "root-session": true, "sys-write": true, "sash-config": true,
}

// intentLeaseAction reports the intent actions that carry a v2 lease.
func intentLeaseAction(action string) bool {
	switch action {
	case "breakglass", "pty_root", "file_root", "xfer_root", "sys_config", "sys_tweak", "sys_service", "sys_package", "sysscript_job":
		return true
	}
	return false
}

// intentSessionAction reports terminal and channel sessions, whose
// max_session_deadline is a real deadline the start frame must match.
func intentSessionAction(action string) bool {
	return action == "breakglass" || action == "pty_root" || action == "file_root" || action == "xfer_root"
}

type intentFields struct {
	RequestID          string
	TenantID           string
	HostID             string
	Requester          string
	Action             string
	PayloadSHA         string
	NotBefore          int64
	UseBy              int64
	MaxSessionDeadline int64
	ReasonSHA          string
	ApproverSetVersion int64
	ThresholdK         int64
}

func intentPrintable(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 0x21 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

// canonicalIntent returns the systemapi-intent-v1 text of f, or
// intent_malformed when any field breaks a 1.1 rule. It refuses, never
// escapes. Byte for byte the control plane's buildIntent (intent.js).
func canonicalIntent(f intentFields) (string, error) {
	bad := errors.New("intent_malformed")
	for _, s := range []string{f.RequestID, f.TenantID, f.HostID, f.Requester, f.Action, f.PayloadSHA, f.ReasonSHA} {
		if !intentPrintable(s) {
			return "", bad
		}
	}
	user, ok := strings.CutPrefix(f.Requester, "member:")
	if !intentRequestRe.MatchString(f.RequestID) || !tenantRe.MatchString(f.TenantID) || !hostIDRe.MatchString(f.HostID) ||
		!ok || !intentUserRe.MatchString(user) || !intentActions[f.Action] ||
		!hashHexRe.MatchString(f.PayloadSHA) || !hashHexRe.MatchString(f.ReasonSHA) {
		return "", bad
	}
	in := func(n int64) bool { return n >= 0 && n <= intentMaxInt }
	if !in(f.NotBefore) || !in(f.UseBy) || !in(f.MaxSessionDeadline) || !in(f.ApproverSetVersion) {
		return "", bad
	}
	if f.NotBefore > f.UseBy || f.UseBy-f.NotBefore > intentWindowMaxS {
		return "", bad
	}
	if intentSessionAction(f.Action) {
		limit := int64(intentRootSessionMax)
		if f.Action == "breakglass" {
			limit = intentBreakglassMax
		}
		if f.MaxSessionDeadline < f.UseBy || f.MaxSessionDeadline-f.NotBefore > limit {
			return "", bad
		}
	} else if f.MaxSessionDeadline != 0 {
		return "", bad
	}
	if f.ApproverSetVersion < 1 || f.ThresholdK < 1 || f.ThresholdK > 9 {
		return "", bad
	}
	i := func(n int64) string { return strconv.FormatInt(n, 10) }
	return strings.Join([]string{
		intentPrefix, f.RequestID, f.TenantID, f.HostID, f.Requester, f.Action, f.PayloadSHA,
		i(f.NotBefore), i(f.UseBy), i(f.MaxSessionDeadline), f.ReasonSHA, i(f.ApproverSetVersion), i(f.ThresholdK),
	}, "\n") + "\n", nil
}

// parseIntent accepts only canonical text: it parses the 13 lines and
// rebuilds them, so two different texts never parse to the same fields.
func parseIntent(text string) (intentFields, error) {
	bad := errors.New("intent_malformed")
	if len(text) > intentMaxBytes || !strings.HasSuffix(text, "\n") {
		return intentFields{}, bad
	}
	lines := strings.Split(strings.TrimSuffix(text, "\n"), "\n")
	if len(lines) != intentLines || lines[0] != intentPrefix {
		return intentFields{}, bad
	}
	nums := make([]int64, 5)
	for k, idx := range []int{7, 8, 9, 11, 12} {
		if !intentDecimalRe.MatchString(lines[idx]) {
			return intentFields{}, bad
		}
		n, err := strconv.ParseInt(lines[idx], 10, 64)
		if err != nil || n > intentMaxInt {
			return intentFields{}, bad
		}
		nums[k] = n
	}
	f := intentFields{
		RequestID: lines[1], TenantID: lines[2], HostID: lines[3], Requester: lines[4], Action: lines[5],
		PayloadSHA: lines[6], NotBefore: nums[0], UseBy: nums[1], MaxSessionDeadline: nums[2],
		ReasonSHA: lines[10], ApproverSetVersion: nums[3], ThresholdK: nums[4],
	}
	canon, err := canonicalIntent(f)
	if err != nil || canon != text {
		return intentFields{}, bad
	}
	return f, nil
}

// intentCtx is what the agent itself knows about a start: the requester
// ("member:" + the frame's actor), the request id when the context names one
// (sash), and the frame's deadline for terminal and channel sessions. The
// helpers pass an empty context (they are one-shot and know only the host).
type intentCtx struct {
	Requester    string
	RequestID    string
	DeadlineUnix int64
	// Session is set by terminal and channel starts: requester and deadline
	// are then always checked, even when empty.
	Session bool
}

// checkIntentStart runs the START checks of contract 1.5 in order, each with
// a stable code. lease has already passed verifyLeaseV2.
func checkIntentStart(intentText string, lease *Lease, ctx intentCtx, now time.Time) (intentFields, error) {
	if lease == nil || !hashEqual(sha256Hex(intentText), lease.IntentSHA) {
		return intentFields{}, errors.New("intent_mismatch")
	}
	f, err := parseIntent(intentText)
	if err != nil {
		return intentFields{}, err
	}
	if f.HostID != lease.HostID || f.Action != lease.Action || !hashEqual(f.PayloadSHA, lease.PayloadSHA) {
		return intentFields{}, errors.New("intent_mismatch")
	}
	if (ctx.Session || ctx.Requester != "") && f.Requester != ctx.Requester {
		return intentFields{}, errors.New("intent_requester")
	}
	if ctx.RequestID != "" && f.RequestID != ctx.RequestID {
		return intentFields{}, errors.New("intent_request")
	}
	skew := int64(leaseSkew.Seconds())
	nowUnix := now.Unix()
	if nowUnix < f.NotBefore-skew || nowUnix > f.UseBy+skew {
		return intentFields{}, errors.New("intent_window")
	}
	if ctx.Session || intentSessionAction(f.Action) {
		if !ctx.Session || ctx.DeadlineUnix != f.MaxSessionDeadline {
			return intentFields{}, errors.New("intent_deadline")
		}
	}
	return f, nil
}

// loadRequireIntent reads the require-intent pin. A missing file is no pin
// (nil, nil). Anything else that is not a trusted, regular file of known
// class names, one per line, at most requireIntentMax bytes, is an error.
func loadRequireIntent() (map[string]bool, error) {
	f, err := os.OpenFile(requireIntentPath, os.O_RDONLY|openNoFollow, 0)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	dirInfo, err := os.Lstat(filepath.Dir(requireIntentPath))
	if err != nil {
		return nil, err
	}
	if !dirInfo.IsDir() {
		return nil, errors.New("pin dir is not a directory")
	}
	if err := trustedNode(dirInfo); err != nil {
		return nil, fmt.Errorf("pin dir: %w", err)
	}
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("pin is not a regular file")
	}
	if err := trustedNode(info); err != nil {
		return nil, fmt.Errorf("pin: %w", err)
	}
	data, err := io.ReadAll(io.LimitReader(f, requireIntentMax+1))
	if err != nil {
		return nil, err
	}
	if len(data) > requireIntentMax {
		return nil, errors.New("pin too large")
	}
	text := string(data)
	classes := map[string]bool{}
	if text == "" {
		return classes, nil
	}
	if !strings.HasSuffix(text, "\n") {
		return nil, errors.New("pin: missing final newline")
	}
	for _, line := range strings.Split(strings.TrimSuffix(text, "\n"), "\n") {
		if !intentClassNames[line] {
			return nil, errors.New("pin: unknown class")
		}
		classes[line] = true
	}
	return classes, nil
}

// requireIntentHeader is the X-SystemAPI-Intent-Pin value: the pinned
// classes sorted and comma-joined, "invalid" for a damaged pin, "" for none.
func requireIntentHeader() string {
	classes, err := loadRequireIntent()
	if err != nil {
		return "invalid"
	}
	names := make([]string, 0, len(classes))
	for c := range classes {
		names = append(names, c)
	}
	sort.Strings(names)
	return strings.Join(names, ",")
}

// sysscriptMutating reports entitlements that make a sysscript root-
// equivalent (contract 5.1): allow_exec or any mutating grant.
func sysscriptMutating(e *Entitlements) bool {
	if e == nil {
		return false
	}
	return e.AllowExec || len(e.AllowConfigWrite) > 0 || len(e.AllowFSWrite) > 0 || len(e.AllowServiceReload) > 0 ||
		len(e.AllowPackages) > 0 || len(e.AllowSysctl) > 0 || len(e.AllowNetManage) > 0 || len(e.AllowMountTargets) > 0
}

// intentClasses names the approval classes (contract 3.1) a lease for
// action+payload belongs to on this agent; nil for an ordinary action.
// sysscript jobs pass their entitlements; converge apply is sys-write.
// sash-config needs the sash origin, which phase 3 adds.
func intentClasses(action, payload string, ents *Entitlements) []string {
	switch action {
	case "breakglass":
		return []string{"breakglass"}
	case "pty_root", "file_root", "xfer_root":
		return []string{"root-session"}
	case "sys_config":
		if strings.HasPrefix(payload, "write\n") {
			return []string{"sys-write"}
		}
	case "sys_tweak":
		if !strings.HasPrefix(payload, "sysctl-get\n") {
			return []string{"sys-write"}
		}
	case "sys_service":
		return []string{"sys-write"}
	case "sys_package":
		if !strings.HasSuffix(payload, "\nquery") {
			return []string{"sys-write"}
		}
	case "sysscript", "sysscript_job":
		if sysscriptMutating(ents) {
			return []string{"sys-write", "root-session"}
		}
	case "converge_job":
		if sysscriptMutating(ents) || strings.Contains(payload, "\napply\n") {
			return []string{"sys-write", "root-session"}
		}
	}
	return nil
}

// pinnedFor returns whether the host pins any of classes. A damaged pin is
// intent_pin_unavailable for every approval-class action.
func pinnedFor(classes []string) (bool, error) {
	if len(classes) == 0 {
		return false, nil
	}
	pin, err := loadRequireIntent()
	if err != nil {
		log.Printf("require-intent pin unreadable or malformed; refusing approval-class leases")
		return false, errors.New("intent_pin_unavailable")
	}
	for _, c := range classes {
		if pin[c] {
			return true, nil
		}
	}
	return false, nil
}

// writeIntentReceipt writes the contract 2.5 receipt line. It carries no
// path, body or actor.
func writeIntentReceipt(phase, action, nonce, intentSHA, requestID, session string) {
	if intentSHA == "" {
		intentSHA = "none"
	}
	if requestID == "" {
		requestID = "none"
	}
	if session == "" {
		session = "-"
	}
	intentReceiptSink(fmt.Sprintf("intent_receipt phase=%s action=%s nonce=%s intent=%s request=%s session=%s",
		phase, action, nonce, intentSHA, requestID, session))
}

// authorizeStart is the lease gate of every start (or one-shot) site that can
// be approval-bound. A v2 lease goes through authorizeIntentStart with
// intentText; a v1 lease through authorizeCommand, refused intent_required
// when the host pins one of classes. It returns the intent hash ("" for v1),
// which a session stores for its renewals. session names the session or
// grant for the receipt ("" for one-shot).
func authorizeStart(host, action, payload string, lease *Lease, intentText string, ctx intentCtx, classes []string, session string, now time.Time) (string, error) {
	pinned, err := pinnedFor(classes)
	if err != nil {
		return "", err
	}
	if lease != nil && lease.V == 2 {
		sha, err := authorizeIntentStart(host, action, payload, lease, intentText, ctx, now)
		if err != nil {
			return "", err
		}
		requestID := ""
		if f, perr := parseIntent(intentText); perr == nil {
			requestID = f.RequestID
		}
		writeIntentReceipt("start", action, lease.NonceHex, sha, requestID, session)
		return sha, nil
	}
	if intentText != "" {
		return "", errors.New("intent_unexpected")
	}
	if pinned {
		return "", errors.New("intent_required")
	}
	if err := authorizeCommand(host, action, payload, lease, now); err != nil {
		return "", err
	}
	if len(classes) > 0 {
		writeIntentReceipt("start", action, lease.NonceHex, "", "", session)
	}
	return "", nil
}

// authorizeRenew is the renew gate for sessions started through
// authorizeStart. storedIntentSHA is the hash the start returned. A v1 renew
// on an intent session is intent_required (downgrade); a v2 renew on a
// session started without an intent is intent_unexpected.
func authorizeRenew(host, action, payload string, lease *Lease, storedIntentSHA string, classes []string, session string, now time.Time) error {
	pinned, err := pinnedFor(classes)
	if err != nil {
		return err
	}
	v2 := lease != nil && lease.V == 2
	switch {
	case storedIntentSHA != "" && !v2:
		return errors.New("intent_required")
	case storedIntentSHA == "" && v2:
		return errors.New("intent_unexpected")
	case storedIntentSHA != "":
		if err := authorizeIntentRenew(host, action, payload, lease, storedIntentSHA, now); err != nil {
			return err
		}
	case pinned:
		return errors.New("intent_required")
	default:
		if err := authorizeCommand(host, action, payload, lease, now); err != nil {
			return err
		}
	}
	if storedIntentSHA != "" || len(classes) > 0 {
		writeIntentReceipt("renew", action, lease.NonceHex, storedIntentSHA, "", session)
	}
	return nil
}
