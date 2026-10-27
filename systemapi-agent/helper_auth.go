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
//     One O_EXCL file per nonce holding its expiry; entries past expiry+skew
//     are pruned (such a lease no longer verifies anyway) and the store refuses
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
// ProtectSystem=strict the agent can write /etc and the replay store).
// Provisioning helperTrustPath is an install step (see the helper units).

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
	"syscall"
	"time"
)

var (
	// helperTrustPath holds {"host_id","control_pubkey"} (control_pubkey is
	// the base64 raw Ed25519 key, the same encoding as the agent state file).
	helperTrustPath = "/etc/systemapi-agent/helper-trust.json"
	// helperTrustOwnerUID is the owner the trust file and its directory must
	// have. A var only so tests (not root) can use their own uid.
	helperTrustOwnerUID uint32 = 0
	// helperReplayDir is the durable consumed-nonce store, in the helpers'
	// own StateDirectory (sah-helper), outside the agent's writable paths.
	helperReplayDir = "/var/lib/sah-helper/consumed"
)

const helperTrustMax = 4 * 1024

// helperReplayMax bounds the live consumed-nonce entries. A var only so tests
// can exercise the full-store refusal without writing thousands of files.
var helperReplayMax = 4096

// errReplay marks a nonce that was already consumed.
var errReplay = errors.New("replay")

// helperAuthorize returns "" when lease authorizes action+payload on this
// host and its nonce was not used before (it is consumed now), else a stable
// error code. The caller rebuilds payload from what it is about to write.
func helperAuthorize(action, payload string, lease *Lease, now time.Time) string {
	if lease == nil {
		return "lease_missing"
	}
	pub, host, err := loadHelperTrust()
	if err != nil {
		return "trust_unavailable"
	}
	if err := verifyLease(pub, lease, host, action, payload, now); err != nil {
		return "lease_" + err.Error()
	}
	if err := consumeHelperNonce(lease.NonceHex, lease.ExpiresUnix, now); err != nil {
		if errors.Is(err, errReplay) {
			return "replay"
		}
		return "replay_store"
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
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != helperTrustOwnerUID {
		return errors.New("wrong owner")
	}
	return nil
}

// loadHelperTrust reads the control public key and host id from
// helperTrustPath, refusing a symlink, a non-regular file, a writable or
// foreign-owned file or directory, and an oversized or malformed body.
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
	f, err := os.OpenFile(helperTrustPath, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
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
// it already was. Entries whose lease expired more than leaseSkew ago are
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
	if _, err := os.Lstat(filepath.Join(helperReplayDir, nonce)); err == nil {
		return errReplay
	} else if !os.IsNotExist(err) {
		return err
	}
	entries, err := os.ReadDir(helperReplayDir)
	if err != nil {
		return err
	}
	cutoff := now.Add(-leaseSkew).Unix()
	live := 0
	for _, e := range entries {
		name := e.Name()
		p := filepath.Join(helperReplayDir, name)
		b, err := readHandoffFile(p, 32)
		exp, perr := strconv.ParseInt(string(b), 10, 64)
		if err == nil && perr == nil && nonceHexRe.MatchString(name) && exp < cutoff {
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
	f, err := os.OpenFile(filepath.Join(helperReplayDir, nonce), os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
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
