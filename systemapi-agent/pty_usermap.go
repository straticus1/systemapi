// Threats: people who share one Unix account signalling, ptracing or
// planting profile files for each other; a map file that someone other than
// root or the agent user can rewrite; a wildcard or a second identity that
// silently reuses an account; and an identity with no entry falling back to
// --pty-user. --pty-user-map maps each server identity (the actor the server
// sends on pty_start, file_open and xfer_grant) to its own Unix account. When
// a map is configured it is the only source: an unmapped identity is refused
// with account_unmapped, and --pty-user is ignored. Does NOT check that the
// accounts exist at startup (they are looked up per session, and a missing
// one refuses that session), and does NOT authenticate the actor: it rides
// the authenticated control-plane socket, like file_open's.
package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
)

const ptyUserMapMaxBytes = 1 << 20

var (
	mapIdentityRe = regexp.MustCompile(`^[A-Za-z0-9._@:+-]{1,256}$`)
	mapAccountRe  = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}\$?$`)
)

// loadPTYUserMap reads and checks a --pty-user-map file. The file must be a
// regular file of mode 0600 or stricter, owned by root or by euid.
func loadPTYUserMap(path string, euid int) (map[string]string, error) {
	f, err := openAgentConfigFile(path, euid, 0o177, ptyUserMapMaxBytes, "pty user map")
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return parsePTYUserMap(f)
}

// openAgentConfigFile opens a regular file (not a symlink) owned by root or
// euid, with none of the badPerm bits set and at most maxBytes long.
func openAgentConfigFile(path string, euid int, badPerm os.FileMode, maxBytes int64, what string) (*os.File, error) {
	lst, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if lst.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("%s is a symlink", what)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	st, err := f.Stat()
	if err != nil || !os.SameFile(lst, st) {
		f.Close()
		return nil, fmt.Errorf("%s changed while being opened", what)
	}
	if !st.Mode().IsRegular() {
		f.Close()
		return nil, fmt.Errorf("%s is not a regular file", what)
	}
	if st.Mode().Perm()&badPerm != 0 {
		f.Close()
		return nil, fmt.Errorf("%s mode is %04o, which is too open", what, st.Mode().Perm())
	}
	uid, ok := fileOwner(st)
	if !ok || (uid != 0 && int(uid) != euid) {
		f.Close()
		return nil, fmt.Errorf("%s must be owned by root or the agent user", what)
	}
	if st.Size() > maxBytes {
		f.Close()
		return nil, fmt.Errorf("%s is too large", what)
	}
	return f, nil
}

// parsePTYUserMap parses lines "identity = unixuser". Blank lines and lines
// starting with # are skipped. A wildcard, a repeated identity, a root
// account or two identities on one account is an error.
func parsePTYUserMap(r io.Reader) (map[string]string, error) {
	m := map[string]string{}
	owner := map[string]string{}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 4096), 4096)
	n := 0
	for sc.Scan() {
		n++
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		ident, acct, ok := strings.Cut(line, "=")
		if !ok {
			return nil, fmt.Errorf("pty user map line %d: want identity = unixuser", n)
		}
		ident, acct = strings.TrimSpace(ident), strings.TrimSpace(acct)
		if strings.Contains(ident, "*") || strings.Contains(acct, "*") {
			return nil, fmt.Errorf("pty user map line %d: wildcards are not allowed", n)
		}
		if !mapIdentityRe.MatchString(ident) {
			return nil, fmt.Errorf("pty user map line %d: bad identity", n)
		}
		if !mapAccountRe.MatchString(acct) {
			return nil, fmt.Errorf("pty user map line %d: bad account name", n)
		}
		if acct == "root" {
			return nil, fmt.Errorf("pty user map line %d: root is not allowed; use terminal:root", n)
		}
		if _, dup := m[ident]; dup {
			return nil, fmt.Errorf("pty user map line %d: identity %q appears twice", n, ident)
		}
		if prev, dup := owner[acct]; dup {
			return nil, fmt.Errorf("pty user map line %d: account %q is already mapped to %q; one account per identity", n, acct, prev)
		}
		m[ident] = acct
		owner[acct] = ident
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("pty user map line %d: %v", n+1, err)
	}
	if len(m) == 0 {
		return nil, errors.New("pty user map has no entries")
	}
	return m, nil
}

// ptyAccountFor returns the account an identity runs as for terminal:open,
// file and xfer sessions, or a contract error code.
func ptyAccountFor(actor string, cfg ptySettings) (string, string) {
	if cfg.UserMap != nil {
		acct, ok := cfg.UserMap[actor]
		if !ok {
			return "", "account_unmapped"
		}
		return acct, ""
	}
	return cfg.User, ""
}
