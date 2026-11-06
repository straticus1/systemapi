package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path"
	"strings"
	"time"
)

// Threats: a forged or swapped sash/1 grant, a lease signature presented as a
// grant, a fleet signature on purpose emergency (and the reverse), a "*", an
// expired exp, a relative or unclean file root, identical purpose keys, an
// oversized document, a grant bound to another host, actor, or start lease,
// and a pubkey file that is not exactly 32 raw bytes. Verification fails
// closed before sash is exec'd. Does NOT hold the grant private key. Does
// NOT treat systemapi-lease-v1 as a grant message. Does NOT log key bytes.
// Sign exists for tests; the control plane is the only production signer.

const (
	sashMaxDocument = 64 * 1024
	sashDomain      = "sash-grant-v1\n"

	sashPurposeOpen      = "terminal:open"
	sashPurposeRoot      = "terminal:root"
	sashPurposeEmergency = "emergency"
)

// sashError is a stable status token. Compare it as text. It is not a signature.
type sashError string

func (e sashError) Error() string { return string(e) }

const (
	errSashGrantMissing  sashError = "grant_missing"
	errSashGrantBadShape sashError = "grant_bad_shape"
	errSashGrantStar     sashError = "grant_star"
	errSashGrantBadSig   sashError = "grant_bad_sig"
	errSashGrantExpired  sashError = "grant_expired"
	errSashGrantPurpose  sashError = "grant_purpose"
	errSashGrantBinding  sashError = "grant_binding"
	errSashMissing       sashError = "sash_missing"
)

// sashGrant is the verified sash/1 document. It is not the sys-lease grant.
type sashGrant struct {
	V            string   `json:"v"`
	Actor        string   `json:"actor"`
	Host         string   `json:"host"`
	Purpose      string   `json:"purpose"`
	Exp          int64    `json:"exp"`
	LeaseID      string   `json:"lease_id"`
	Entitlements []string `json:"entitlements"`
	FileRead     []string `json:"file_read"`
	FileWrite    []string `json:"file_write"`
	AllowPrivate bool     `json:"allow_private"`
}

type sashGrantWire struct {
	sashGrant
	Sig string `json:"sig"`
}

// sashBind is the session the grant must name. Empty host, actor, or lease id
// is grant_binding after the purpose check.
type sashBind struct {
	Action  string
	Host    string
	Actor   string
	LeaseID string
	Now     time.Time
}

// sashTargets is the channel policy delivered beside the grant. The grant
// signature does not cover it. An empty list denies that verb.
type sashTargets struct {
	Units      []string `json:"units"`
	Packages   []string `json:"packages"`
	Configs    []string `json:"configs"`
	Sysctls    []string `json:"sysctls"`
	Files      []string `json:"files"`
	FilesWrite []string `json:"files_write"`
}

func sashStatusCode(err error) string {
	var se sashError
	if errors.As(err, &se) {
		return string(se)
	}
	return "pty_start_failed"
}

func sashNorm(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func sashCanonOK(s string) bool {
	for _, r := range s {
		if r < 0x20 || r > 0x7e || r == '<' || r == '>' || r == '&' {
			return false
		}
	}
	return true
}

func sashMessage(g sashGrant) ([]byte, error) {
	body, err := json.Marshal(sashGrant{
		V:            g.V,
		Actor:        g.Actor,
		Host:         g.Host,
		Purpose:      g.Purpose,
		Exp:          g.Exp,
		LeaseID:      g.LeaseID,
		Entitlements: sashNorm(g.Entitlements),
		FileRead:     sashNorm(g.FileRead),
		FileWrite:    sashNorm(g.FileWrite),
		AllowPrivate: g.AllowPrivate,
	})
	if err != nil {
		return nil, errSashGrantBadShape
	}
	out := make([]byte, 0, len(sashDomain)+len(body))
	out = append(out, sashDomain...)
	out = append(out, body...)
	return out, nil
}

// signSashGrant is for tests. Production grants are signed in the control
// plane. It refuses characters whose JSON escaping differs between Go and
// Node. It does not refuse "*"; Verify does, after the signature matches.
func signSashGrant(g sashGrant, priv ed25519.PrivateKey) ([]byte, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return nil, errSashGrantBadSig
	}
	fields := []string{g.V, g.Actor, g.Host, g.Purpose, g.LeaseID}
	fields = append(fields, g.Entitlements...)
	fields = append(fields, g.FileRead...)
	fields = append(fields, g.FileWrite...)
	for _, f := range fields {
		if !sashCanonOK(f) {
			return nil, errSashGrantBadShape
		}
	}
	msg, err := sashMessage(g)
	if err != nil {
		return nil, err
	}
	sig := ed25519.Sign(priv, msg)
	doc, err := json.Marshal(sashGrantWire{
		sashGrant: sashGrant{
			V:            g.V,
			Actor:        g.Actor,
			Host:         g.Host,
			Purpose:      g.Purpose,
			Exp:          g.Exp,
			LeaseID:      g.LeaseID,
			Entitlements: sashNorm(g.Entitlements),
			FileRead:     sashNorm(g.FileRead),
			FileWrite:    sashNorm(g.FileWrite),
			AllowPrivate: g.AllowPrivate,
		},
		Sig: base64.StdEncoding.EncodeToString(sig),
	})
	if err != nil {
		return nil, errSashGrantBadShape
	}
	return doc, nil
}

func sashDistinctKeys(a, b []byte) bool {
	if len(a) != ed25519.PublicKeySize || len(b) != ed25519.PublicKeySize {
		return false
	}
	return subtle.ConstantTimeCompare(a, b) == 0
}

func verifySashGrant(doc, fleet, emergency []byte, now time.Time) (sashGrant, error) {
	if len(doc) == 0 {
		return sashGrant{}, errSashGrantMissing
	}
	if len(doc) > sashMaxDocument {
		return sashGrant{}, errSashGrantBadShape
	}
	g, sig, err := parseSashGrant(doc)
	if err != nil {
		return sashGrant{}, err
	}
	if !sashDistinctKeys(fleet, emergency) {
		return sashGrant{}, errSashGrantBadSig
	}
	key := fleet
	if g.Purpose == sashPurposeEmergency {
		key = emergency
	}
	raw, decErr := base64.StdEncoding.DecodeString(sig)
	if decErr != nil || len(raw) != ed25519.SignatureSize {
		return sashGrant{}, errSashGrantBadSig
	}
	msg, err := sashMessage(g)
	if err != nil {
		return sashGrant{}, errSashGrantBadSig
	}
	if !ed25519.Verify(key, msg, raw) {
		return sashGrant{}, errSashGrantBadSig
	}
	for _, name := range g.Entitlements {
		if name == "*" {
			return sashGrant{}, errSashGrantStar
		}
	}
	if g.Exp < now.Unix() {
		return sashGrant{}, errSashGrantExpired
	}
	return g, nil
}

func parseSashGrant(doc []byte) (sashGrant, string, error) {
	dec := json.NewDecoder(bytes.NewReader(doc))
	dec.DisallowUnknownFields()
	var w sashGrantWire
	if err := dec.Decode(&w); err != nil {
		return sashGrant{}, "", errSashGrantBadShape
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return sashGrant{}, "", errSashGrantBadShape
	}
	if err := sashGrantShape(doc, w); err != nil {
		return sashGrant{}, "", err
	}
	return sashGrant{
		V:            w.V,
		Actor:        w.Actor,
		Host:         w.Host,
		Purpose:      w.Purpose,
		Exp:          w.Exp,
		LeaseID:      w.LeaseID,
		Entitlements: append([]string(nil), w.Entitlements...),
		FileRead:     append([]string(nil), w.FileRead...),
		FileWrite:    append([]string(nil), w.FileWrite...),
		AllowPrivate: w.AllowPrivate,
	}, w.Sig, nil
}

func sashGrantShape(doc []byte, w sashGrantWire) error {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(doc, &raw); err != nil {
		return errSashGrantBadShape
	}
	for _, key := range []string{"v", "actor", "host", "purpose", "exp", "lease_id", "entitlements", "sig"} {
		if _, ok := raw[key]; !ok {
			return errSashGrantBadShape
		}
	}
	if w.V != "sash/1" || w.Actor == "" || w.Host == "" || w.LeaseID == "" || w.Sig == "" {
		return errSashGrantBadShape
	}
	switch w.Purpose {
	case sashPurposeOpen, sashPurposeRoot, sashPurposeEmergency:
	default:
		return errSashGrantBadShape
	}
	if w.Entitlements == nil {
		return errSashGrantBadShape
	}
	for _, name := range w.Entitlements {
		if name == "" {
			return errSashGrantBadShape
		}
	}
	if err := sashRoots(w.FileRead); err != nil {
		return err
	}
	return sashRoots(w.FileWrite)
}

func sashRoots(list []string) error {
	for _, r := range list {
		if path.Clean(r) != r || !strings.HasPrefix(r, "/") {
			return errSashGrantBadShape
		}
	}
	return nil
}

// bindSashGrant verifies doc, then checks purpose against the session action
// and host, actor, and the start lease id. Purpose wins when both are wrong.
func bindSashGrant(doc, fleet, emergency []byte, b sashBind) (sashGrant, error) {
	g, err := verifySashGrant(doc, fleet, emergency, b.Now)
	if err != nil {
		return sashGrant{}, err
	}
	want := ""
	switch b.Action {
	case "pty":
		want = sashPurposeOpen
	case "pty_root":
		want = sashPurposeRoot
	}
	if g.Purpose != want {
		return sashGrant{}, errSashGrantPurpose
	}
	if b.Host == "" || b.Actor == "" || b.LeaseID == "" || g.Host != b.Host || g.Actor != b.Actor || g.LeaseID != b.LeaseID {
		return sashGrant{}, errSashGrantBinding
	}
	return g, nil
}

// readSashPub reads one raw 32-byte public key. Any other length, a missing
// path, or a read error is grant_bad_sig. The error does not contain the path
// or the key bytes.
func readSashPub(path string) ([]byte, error) {
	if path == "" {
		return nil, errSashGrantBadSig
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, errSashGrantBadSig
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, 33))
	if err != nil || len(b) != ed25519.PublicKeySize {
		return nil, errSashGrantBadSig
	}
	return b, nil
}

func copySashTargets(t sashTargets) sashTargets {
	return sashTargets{
		Units:      append([]string(nil), t.Units...),
		Packages:   append([]string(nil), t.Packages...),
		Configs:    append([]string(nil), t.Configs...),
		Sysctls:    append([]string(nil), t.Sysctls...),
		Files:      append([]string(nil), t.Files...),
		FilesWrite: append([]string(nil), t.FilesWrite...),
	}
}

func sashEntitled(g sashGrant, key string) bool {
	for _, name := range g.Entitlements {
		if name == key {
			return true
		}
	}
	return false
}
