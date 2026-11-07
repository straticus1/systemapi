package main

// Lease authorization INSIDE the privilege-separated mutation helpers
// (sysctl_helper.go, config_helper.go, systemd_override_helper.go).
//
// The agent writes the helper's request file, so a request is only as
// trustworthy as the agent. Without this check a compromised agent could ask
// a helper to write any shape-valid target with any content and a hash it
// computed itself. So each helper re-authorizes the write on its own:
//
//   - The request carries the original Ed25519-signed lease, exactly as the
//     control plane sent it to the agent.
//   - The helper loads the control-plane public key and this host's id from
//     helperTrustPath, a root-owned file under /etc/systemapi-agent (the same
//     trusted config dir that holds the agent's api-key). Under the agent's
//     ProtectSystem=strict sandbox /etc is read-only to the agent, so a
//     compromised agent cannot swap the key. It is NOT read from the agent's
//     state file (/var/lib/systemapi-agent/agent.json), which the agent can
//     write. The file and its directory must be owned by root, not symlinks,
//     and not group/other writable.
//   - The helper rebuilds the signed payload from the exact action, target and
//     content it is about to write (hashing the content itself) and verifies
//     the lease with verifyLease (lease.go): signature, host, action, expiry
//     within leaseSkew/leaseMaxTTL, payload hash.
//   - The lease nonce is consumed once in a durable store under the helper's
//     own state dir (helperReplayDir), which the agent's sandbox cannot write.
//     One O_EXCL file per nonce holding its expiry, recorded under an
//     exclusive flock; entries past expiry+helperReplayRetain are pruned
//     (such a lease no longer verifies anywhere) and the store refuses
//     once helperReplayMax live entries exist, so it stays bounded. A helper
//     restart keeps the store, so a replay stays refused.
//
// Threats: a forged, re-signed, expired, wrong-host, wrong-action or replayed
// lease, a request whose target or content differs from what was signed, and
// a trust file an unprivileged process could have planted or edited. Every
// failure is a stable error code recorded in the helper's result; nothing
// proceeds on error. Does NOT protect against an attacker who already has root
// outside the agent's sandbox (they can edit the trust file), against a stolen
// control-plane signing key, or against an unhardened agent unit (without
// ProtectSystem=strict the agent can write /etc and the replay store). Nor,
// today, against a compromised agent at all: the agent is root with systemd
// bus access, so it can start an unsandboxed unit of its own and bypass the
// helpers entirely (security review finding 1, an open design decision; see
// docs/sah-os-management-design.md).
// Provisioning helperTrustPath is an install step:
// scripts/provision-helper-trust.sh takes the control key as an out-of-band
// pinned value and refuses if agent.json disagrees (see the helper units).

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

var (
	// helperTrustPath holds {"host_id","control_pubkey"} (control_pubkey is
	// the base64 raw Ed25519 key, the same encoding as the agent state file).
	helperTrustPath = "/etc/systemapi-agent/helper-trust.json"
	// helperTrustOwnerUID is the owner the trust file and its directory must
	// have. A var only so tests (not root) can use their own uid.
	helperTrustOwnerUID uint32 = 0
	// helperHandoffOwnerUID is the owner a helper handoff directory must
	// have (checkHandoffDir). A var only so tests (not root) can use their
	// own uid.
	helperHandoffOwnerUID uint32 = 0
	// helperReplayDir is the durable consumed-nonce store, in the helpers'
	// own StateDirectory (sah-helper), outside the agent's writable paths.
	helperReplayDir = "/var/lib/sah-helper/consumed"
)

const helperTrustMax = 4 * 1024

// helperReplayLockName is the flock file inside helperReplayDir that
// serialises check+prune+record across concurrent helper processes. It is not
// a nonce entry: it is neither counted nor pruned.
const helperReplayLockName = ".lock"

// helperReplayRetain is how long past its lease expiry a consumed nonce is
// kept. verifyLease accepts a lease until expiry+leaseSkew, judged by each
// helper's own clock read before it consumes. Keeping the entry until
// expiry+2*leaseSkew+1m covers that window, a second leaseSkew of clock
// disagreement between helper processes, and up to a minute between one
// helper's verify and its consume, so a prune by a later helper can never
// remove an entry a concurrent helper could still verify and re-consume.
const helperReplayRetain = 2*leaseSkew + time.Minute

// helperReplayMax bounds the live consumed-nonce entries. A var only so tests
// can exercise the full-store refusal without writing thousands of files.
var helperReplayMax = 4096

// helperReplayHook is a no-op test seam called, under the replay lock, just
// before an expired entry is pruned ("prune") and before the nonce is
// recorded ("record"), so tests can assert the flock is held there.
var helperReplayHook = func(stage string) {}

// errReplay marks a nonce that was already consumed.
var errReplay = errors.New("replay")

// helperAuthorize returns "" when lease authorizes action+payload on this
// host and its nonce was not used before (it is consumed now), else a stable
// error code. The caller rebuilds payload from what it is about to write.
// intentText is the intent beside a v2 lease ("" for v1); see helperLeaseCheck.
func helperAuthorize(action, payload string, lease *Lease, intentText string, now time.Time) string {
	if lease == nil {
		return "lease_missing"
	}
	pub, host, err := loadHelperTrust()
	if err != nil {
		return "trust_unavailable"
	}
	if code := helperLeaseCheck(pub, host, action, payload, lease, intentText, now); code != "" {
		return code
	}
	if err := consumeHelperNonce(lease.NonceHex, lease.ExpiresUnix, now); err != nil {
		if errors.Is(err, errReplay) {
			return "replay"
		}
		return "replay_store"
	}
	return ""
}

// helperLeaseCheck is the lease rule shared by helperAuthorize and
// helperPreflight (contract 1.6). A v1 lease with no intent is today's
// check, unless the require-intent pin names the action's class
// (intent_required). A v2 lease is verifyLeaseV2 plus checkIntentStart with
// an empty context (helpers are one-shot and know only the host). A damaged
// pin refuses every approval-class action (intent_pin_unavailable).
func helperLeaseCheck(pub ed25519.PublicKey, host, action, payload string, lease *Lease, intentText string, now time.Time) string {
	pinned, err := pinnedFor(intentClasses(action, payload, nil))
	if err != nil {
		return err.Error()
	}
	if lease.V == 2 {
		if _, err := verifyLeaseV2(pub, lease, host, action, payload, now); err != nil {
			return "lease_" + err.Error()
		}
		if _, err := checkIntentStart(intentText, lease, intentCtx{}, now); err != nil {
			return err.Error()
		}
		return ""
	}
	if intentText != "" {
		return "intent_unexpected"
	}
	if pinned {
		return "intent_required"
	}
	if err := verifyLease(pub, lease, host, action, payload, now); err != nil {
		return "lease_" + err.Error()
	}
	return ""
}

// helperDispatchPrefix keys a helper dispatch in the agent's nonce cache
// (rememberNonce). It is not hex, so it never collides with the entry
// authorizeCommand records for the same nonce at the channel gate.
const helperDispatchPrefix = "helper:"

// helperPreflight is the AGENT-side check every mutation helper handoff runs
// before it writes a request or triggers the privileged unit. It returns ""
// when lease is a lease for exactly action+payload, signed by the agent's
// pinned control key for the enrolled host and inside its time window, and
// this agent has not dispatched a helper for its nonce before; else a stable
// code from the helperAuthorize set. The caller rebuilds payload from what
// the helper will write.
//
// Threats: a caller handing a non-nil lease of the wrong capability (a
// terminal pty/pty_root lease from a sash session), a sys lease for another
// target, content or value, an expired, wrong-host or forged lease, or the
// same lease twice, any of which would otherwise start the root helper unit
// before the helper itself refuses. It does NOT replace the helper's own
// check (helperAuthorize), which stays authoritative against a compromised
// agent.
//
// Nonce handling: this never touches the helper's durable store, so the
// helper consumes the nonce exactly once (no double consume). It records the
// dispatch in the agent's in-memory cache under helperDispatchPrefix, checked
// and recorded under identityMu, so two concurrent handoffs with one lease
// cannot both pass; that entry is separate from the one authorizeCommand
// records, so a lease that passed the channel gate still passes here. A
// restart clears the cache; the helper's durable store still refuses a replay.
func helperPreflight(action, payload string, lease *Lease, intentText string, now time.Time) string {
	if lease == nil {
		return "lease_missing"
	}
	identityMu.Lock()
	pub := controlPub
	host := enrolledHostID
	identityMu.Unlock()
	if len(pub) != ed25519.PublicKeySize || host == "" {
		return "not_enrolled"
	}
	if code := helperLeaseCheck(pub, host, action, payload, lease, intentText, now); code != "" {
		return code
	}
	if err := rememberNonce(helperDispatchPrefix+lease.NonceHex, now); err != nil {
		return "replay"
	}
	return ""
}

// trustedNode checks that info is owned by helperTrustOwnerUID, is not a
// symlink, and is not group/other writable.
func trustedNode(info os.FileInfo) error {
	if info.Mode()&os.ModeSymlink != 0 {
		return errors.New("symlink")
	}
	if info.Mode().Perm()&0o022 != 0 {
		return errors.New("group or other writable")
	}
	uid, _, ok := fileOwnerIDs(info)
	if !ok || uid < 0 || uint32(uid) != helperTrustOwnerUID {
		return errors.New("wrong owner")
	}
	return nil
}

// checkHandoffDir refuses a mutation helper's handoff directory unless it is
// a real directory (Lstat: not a symlink), mode exactly 0700 and owned by
// helperHandoffOwnerUID (root). Both the agent side (after creating it) and the
// helper (before reading a request or writing a result) run it, so neither
// reads or writes request files through a swapped, shared or foreign-owned
// directory.
func checkHandoffDir(dir string) error {
	info, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return errors.New("handoff dir is not a directory")
	}
	if info.Mode().Perm() != 0o700 {
		return errors.New("handoff dir is not mode 0700")
	}
	uid, _, ok := fileOwnerIDs(info)
	if !ok || uid < 0 || uint32(uid) != helperHandoffOwnerUID {
		return errors.New("handoff dir has the wrong owner")
	}
	return nil
}

// loadHelperTrust reads the control public key and host id from
// helperTrustPath, refusing a symlink, a non-regular file, a writable or
// foreign-owned file or directory, and an oversized or malformed body.
// Only the file and its IMMEDIATE directory are checked (Lstat, so that
// directory itself is not a symlink); ancestors such as /etc and / are
// trusted to be root-owned and not group/other writable, and a symlinked
// ancestor is followed. A host where an unprivileged user can rename an
// ancestor can substitute the whole directory.
func loadHelperTrust() (ed25519.PublicKey, string, error) {
	dirInfo, err := os.Lstat(filepath.Dir(helperTrustPath))
	if err != nil {
		return nil, "", err
	}
	if !dirInfo.IsDir() {
		return nil, "", errors.New("trust dir is not a directory")
	}
	if err := trustedNode(dirInfo); err != nil {
		return nil, "", fmt.Errorf("trust dir: %w", err)
	}
	f, err := os.OpenFile(helperTrustPath, os.O_RDONLY|openNoFollow, 0)
	if err != nil {
		return nil, "", err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, "", err
	}
	if !info.Mode().IsRegular() {
		return nil, "", errors.New("trust file is not a regular file")
	}
	if err := trustedNode(info); err != nil {
		return nil, "", fmt.Errorf("trust file: %w", err)
	}
	data, err := io.ReadAll(io.LimitReader(f, helperTrustMax+1))
	if err != nil {
		return nil, "", err
	}
	if len(data) > helperTrustMax {
		return nil, "", errors.New("trust file too large")
	}
	var tf struct {
		HostID        string `json:"host_id"`
		ControlPubKey string `json:"control_pubkey"`
	}
	if err := json.Unmarshal(data, &tf); err != nil {
		return nil, "", err
	}
	if err := validateHostID(tf.HostID); err != nil {
		return nil, "", err
	}
	raw, err := base64.StdEncoding.DecodeString(tf.ControlPubKey)
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return nil, "", errors.New("bad control pubkey")
	}
	return ed25519.PublicKey(raw), tf.HostID, nil
}

// consumeHelperNonce records nonce as used, durably, or returns errReplay if
// it already was. It holds an exclusive flock on helperReplayLockName (opened
// O_NOFOLLOW) for the whole check+prune+record, so concurrent helpers are
// serialised. Entries whose lease expired more than helperReplayRetain ago are
// pruned first; the store refuses when helperReplayMax live entries remain.
func consumeHelperNonce(nonce string, expiresUnix int64, now time.Time) error {
	if !nonceHexRe.MatchString(nonce) {
		return errors.New("bad nonce")
	}
	if err := os.MkdirAll(helperReplayDir, 0o700); err != nil {
		return err
	}
	dirInfo, err := os.Lstat(helperReplayDir)
	if err != nil {
		return err
	}
	if !dirInfo.IsDir() || dirInfo.Mode().Perm()&0o077 != 0 {
		return errors.New("replay dir is not a private directory")
	}
	if err := trustedNode(dirInfo); err != nil {
		return fmt.Errorf("replay dir: %w", err)
	}
	lock, err := os.OpenFile(filepath.Join(helperReplayDir, helperReplayLockName), os.O_RDWR|os.O_CREATE|openNoFollow, 0o600)
	if err != nil {
		return fmt.Errorf("replay lock: %w", err)
	}
	defer lock.Close()
	if info, err := lock.Stat(); err != nil || !info.Mode().IsRegular() {
		return errors.New("replay lock is not a regular file")
	}
	if err := lockFileExclusive(lock); err != nil {
		return fmt.Errorf("replay lock: %w", err)
	}
	// Released by the deferred Close.
	if _, err := os.Lstat(filepath.Join(helperReplayDir, nonce)); err == nil {
		return errReplay
	} else if !os.IsNotExist(err) {
		return err
	}
	entries, err := os.ReadDir(helperReplayDir)
	if err != nil {
		return err
	}
	cutoff := now.Add(-helperReplayRetain).Unix()
	live := 0
	for _, e := range entries {
		name := e.Name()
		if name == helperReplayLockName {
			continue
		}
		p := filepath.Join(helperReplayDir, name)
		b, err := readHandoffFile(p, 32)
		exp, perr := strconv.ParseInt(string(b), 10, 64)
		if err == nil && perr == nil && nonceHexRe.MatchString(name) && exp < cutoff {
			helperReplayHook("prune")
			if err := os.Remove(p); err != nil {
				return err
			}
			continue
		}
		// Unreadable or foreign entries are kept and counted (fail closed).
		live++
	}
	if live >= helperReplayMax {
		return errors.New("replay store full")
	}
	helperReplayHook("record")
	f, err := os.OpenFile(filepath.Join(helperReplayDir, nonce), os.O_WRONLY|os.O_CREATE|os.O_EXCL|openNoFollow, 0o600)
	if err != nil {
		if os.IsExist(err) {
			return errReplay
		}
		return err
	}
	_, werr := f.WriteString(strconv.FormatInt(expiresUnix, 10))
	serr := f.Sync()
	cerr := f.Close()
	if werr != nil || serr != nil || cerr != nil {
		// The id stays recorded (fail closed: the lease is spent).
		return errors.New("replay store write failed")
	}
	d, err := os.Open(helperReplayDir)
	if err != nil {
		return err
	}
	serr = d.Sync()
	cerr = d.Close()
	if serr != nil || cerr != nil {
		return errors.New("replay store sync failed")
	}
	return nil
}
