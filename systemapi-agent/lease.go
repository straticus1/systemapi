// Threats: an unsigned or swapped command, an expired lease, a lease minted
// for another host, and a nonce replayed inside the TTL. Verification
// rejects tampered, expired, wrong-host, wrong-action, and replayed input.
// Does NOT persist the nonce cache across process restarts (TTL cap is 300s).
// Does NOT accept a control public key that changes after the first pin.
// Terminal actions (pty, pty_root, breakglass) sign "<action>\n<session_id>\n
// <deadline_unix>", so a renewal lease is bound to one session and cannot move
// its deadline.
package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"sync"
	"time"

	"crypto/subtle"
)

const (
	leasePrefix = "systemapi-lease-v1\n"
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
	Signature   string `json:"signature"`
}

func canonicalLease(hostID, action string, expiresUnix int64, nonceHex, payloadSHA string) string {
	return leasePrefix + hostID + "\n" + action + "\n" + strconv.FormatInt(expiresUnix, 10) + "\n" + nonceHex + "\n" + payloadSHA + "\n"
}

func payloadHash(action, payload string) string {
	sum := sha256.Sum256([]byte(payloadFor(action, payload)))
	return hex.EncodeToString(sum[:])
}

func payloadFor(action, payload string) string {
	if terminalAction(action) {
		return action + "\n" + payload
	}
	return payload
}

func terminalAction(action string) bool {
	return action == "pty" || action == "pty_root" || action == "breakglass"
}

// terminalPayload is the signed payload of a terminal lease.
func terminalPayload(sessionID string, deadlineUnix int64) string {
	return sessionID + "\n" + strconv.FormatInt(deadlineUnix, 10)
}

func hashEqual(a, b string) bool {
	if !hashHexRe.MatchString(a) || !hashHexRe.MatchString(b) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

func knownAction(action string) bool {
	return action == "sysscript" || terminalAction(action)
}

// verifyLease checks the signature and the time window. It does not record
// the nonce; authorizeCommand does that after a successful verify.
func verifyLease(pub ed25519.PublicKey, lease *Lease, expectedHost, expectedAction, payload string, now time.Time) error {
	if lease == nil || len(pub) != ed25519.PublicKeySize {
		return errors.New("malformed")
	}
	if lease.V != 1 {
		return errors.New("malformed")
	}
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
