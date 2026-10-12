// Threats: a world-readable identity file, a predictable host id, and a
// child process that inherits the API key. The state file is mode 0600 and
// its directory is mode 0700. Host ids and the ed25519 seed come from
// crypto/rand. Does NOT encrypt the seed at rest; the file mode is the
// control. Does NOT log the seed or the API key.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

var (
	tenantRe   = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)
	hostIDRe   = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	hostnameRe = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9.\-]{0,251}[A-Za-z0-9])?$`)
)

type agentState struct {
	HostID        string `json:"host_id"`
	Ed25519Seed   string `json:"ed25519_seed"`
	ControlPubKey string `json:"control_pubkey,omitempty"`
	Tenant        string `json:"tenant"`
}

func validateTenantName(tenant string) error {
	if !tenantRe.MatchString(tenant) {
		return errors.New("bad_tenant")
	}
	return nil
}

func validateHostID(id string) error {
	if !hostIDRe.MatchString(id) {
		return errors.New("bad_host_id")
	}
	return nil
}

func validateHostname(name string) error {
	if len(name) > 253 || !hostnameRe.MatchString(name) {
		return errors.New("bad_hostname")
	}
	return nil
}

func newUUIDv4() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:]), nil
}

func freshState(tenant string) (*agentState, error) {
	id, err := newUUIDv4()
	if err != nil {
		return nil, err
	}
	var seed [32]byte
	if _, err := rand.Read(seed[:]); err != nil {
		return nil, err
	}
	st := &agentState{
		HostID:      id,
		Ed25519Seed: hex.EncodeToString(seed[:]),
		Tenant:      tenant,
	}
	for i := range seed {
		seed[i] = 0
	}
	return st, nil
}

func saveState(path string, st *agentState) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return err
	}
	blob, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, blob, 0o600); err != nil {
		return err
	}
	if err := os.Chmod(tmp, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func loadOrCreateState(path, tenant string) (*agentState, error) {
	if err := validateTenantName(tenant); err != nil {
		return nil, err
	}
	blob, err := os.ReadFile(path)
	if err != nil {
		if !os.IsNotExist(err) {
			return nil, err
		}
		st, err := freshState(tenant)
		if err != nil {
			return nil, err
		}
		if err := saveState(path, st); err != nil {
			return nil, err
		}
		return st, nil
	}
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode().Perm()&0o077 != 0 {
		if err := os.Chmod(path, 0o600); err != nil {
			return nil, fmt.Errorf("state file is group-readable and chmod failed: %w", err)
		}
	}
	var st agentState
	if err := json.Unmarshal(blob, &st); err != nil {
		return nil, err
	}
	if st.Tenant != tenant {
		return nil, errors.New("state tenant does not match --tenant")
	}
	if err := validateHostID(st.HostID); err != nil {
		return nil, err
	}
	raw, err := hex.DecodeString(st.Ed25519Seed)
	if err != nil || len(raw) != ed25519.SeedSize || len(st.Ed25519Seed) != 64 {
		return nil, errors.New("state seed invalid")
	}
	for i := range raw {
		raw[i] = 0
	}
	if st.ControlPubKey != "" {
		pub, err := base64.StdEncoding.DecodeString(st.ControlPubKey)
		if err != nil || len(pub) != ed25519.PublicKeySize {
			return nil, errors.New("state control pubkey invalid")
		}
	}
	return &st, nil
}

func sshEd25519PublicLine(seedHex string) (string, error) {
	raw, err := hex.DecodeString(seedHex)
	if err != nil || len(raw) != ed25519.SeedSize {
		return "", errors.New("bad seed")
	}
	priv := ed25519.NewKeyFromSeed(raw)
	for i := range raw {
		raw[i] = 0
	}
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok || len(pub) != ed25519.PublicKeySize {
		return "", errors.New("bad public key")
	}
	return formatOpenSSHEd25519(pub)
}

func formatOpenSSHEd25519(pub ed25519.PublicKey) (string, error) {
	if len(pub) != ed25519.PublicKeySize {
		return "", errors.New("bad public key")
	}
	buf := make([]byte, 51)
	binary.BigEndian.PutUint32(buf[0:4], 11)
	copy(buf[4:15], "ssh-ed25519")
	binary.BigEndian.PutUint32(buf[15:19], 32)
	copy(buf[19:51], pub)
	return "ssh-ed25519 " + base64.StdEncoding.EncodeToString(buf), nil
}

func refuseAPIKeyURL(raw string) error {
	if strings.Contains(strings.ToLower(raw), "api_key") {
		return errors.New("refusing URL that contains api_key")
	}
	return nil
}

// stripChildEnv drops control-plane credentials before a shell or adssh starts.
func stripChildEnv(base, extra []string) []string {
	out := make([]string, 0, len(base)+len(extra))
	for _, kv := range base {
		name := kv
		if i := strings.IndexByte(kv, '='); i >= 0 {
			name = kv[:i]
		}
		upper := strings.ToUpper(name)
		if strings.HasPrefix(upper, "SYSTEMAPI") || strings.Contains(upper, "API_KEY") || strings.HasPrefix(upper, "ADSTELCO") {
			continue
		}
		out = append(out, kv)
	}
	return append(out, extra...)
}

func fingerprintHex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// acceptEnrolled pins the server key on first use and refuses a later change.
func acceptEnrolled(st *agentState, path, hostID, pubB64 string) error {
	if st == nil || hostID != st.HostID {
		return errors.New("bad_host")
	}
	if st.ControlPubKey != "" && st.ControlPubKey != pubB64 {
		return errors.New("control_pubkey_changed")
	}
	if st.ControlPubKey == "" {
		st.ControlPubKey = pubB64
		if err := saveState(path, st); err != nil {
			return err
		}
	}
	return pinControlPublicKey(pubB64, hostID)
}
