package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"unicode/utf8"
)

// Threats: suggestion history is this actor on this host. The key is
// sha256(actor, host) from the verified grant, never an actor, path, or
// argv the child sends. A private session appends the audit file and does
// not read or write the suggestion file; history get then returns no rows.
// A dead lease never reaches this code. An empty root writes nothing.
// A line that is empty, too long, or contains a newline, CR, or NUL is
// rejected and the files stay as they were. A malformed or oversized file
// returns no rows. Does NOT log the line, the actor, the host, or the path.
// Does NOT import sash. Does NOT treat a file in the pty user's home as
// the store.

const (
	sashHistMaxLine = 8192
	sashHistMaxKeep = 200
)

var (
	sashHistoryRoot     string
	sashHistMu          sync.Mutex
	sashHistReadSuggest = sashHistRead
)

func sashHistory(g sashGrant, v sashCall, root string) (sashResult, error) {
	if len(v.Argv) != 1 {
		return sashResult{}, errSashDenied
	}
	switch v.Argv[0] {
	case "get":
		if root == "" || g.AllowPrivate {
			return sashHistEmpty(), nil
		}
		sashHistMu.Lock()
		defer sashHistMu.Unlock()
		sug, _, err := sashHistPaths(root, g.Actor, g.Host)
		if err != nil {
			return sashHistEmpty(), nil
		}
		lines, err := sashHistReadSuggest(sug)
		if err != nil {
			return sashHistEmpty(), nil
		}
		return sashHistRows(lines), nil
	case "append":
		if root == "" || !sashHistLineOK(string(v.Body)) {
			return sashResult{}, errSashDenied
		}
		if err := sashHistAppend(g, root, string(v.Body)); err != nil {
			return sashResult{}, errSashDenied
		}
		return sashResult{Kind: "bytes", Exit: 0}, nil
	default:
		return sashResult{}, errSashDenied
	}
}

func sashHistEmpty() sashResult {
	return sashResult{Kind: "rows", Cols: []string{"line"}, Exit: 0}
}

func sashHistRows(lines []string) sashResult {
	rows := make([]map[string]string, len(lines))
	for i, line := range lines {
		rows[i] = map[string]string{"line": line}
	}
	return sashResult{Kind: "rows", Cols: []string{"line"}, Rows: rows, Exit: 0}
}

func sashHistLineOK(line string) bool {
	if line == "" || len(line) > sashHistMaxLine || !utf8.ValidString(line) {
		return false
	}
	return !strings.ContainsAny(line, "\n\r\x00")
}

func sashHistID(actor, host string) string {
	sum := sha256.Sum256([]byte(actor + "\n" + host))
	return hex.EncodeToString(sum[:])
}

func sashHistPaths(root, actor, host string) (string, string, error) {
	if root == "" {
		return "", "", errors.New("hist root")
	}
	id := sashHistID(actor, host)
	if len(id) != 64 {
		return "", "", errors.New("hist id")
	}
	for _, c := range id {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return "", "", errors.New("hist id")
		}
	}
	dir := filepath.Clean(root)
	sug := filepath.Join(dir, id+".suggest")
	aud := filepath.Join(dir, id+".audit")
	if !sashHistInside(dir, sug) || !sashHistInside(dir, aud) {
		return "", "", errors.New("hist path")
	}
	return sug, aud, nil
}

func sashHistInside(dir, p string) bool {
	rel, err := filepath.Rel(dir, p)
	if err != nil || rel == "." || rel == ".." {
		return false
	}
	return !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

func sashHistAppend(g sashGrant, root, line string) error {
	sashHistMu.Lock()
	defer sashHistMu.Unlock()
	sug, aud, err := sashHistPaths(root, g.Actor, g.Host)
	if err != nil {
		return err
	}
	var sugLines []string
	if !g.AllowPrivate {
		sugLines, err = sashHistReadSuggest(sug)
		if err != nil {
			return err
		}
	}
	audLines, err := sashHistRead(aud)
	if err != nil {
		return err
	}
	audLines = sashHistTrim(append(audLines, line))
	if err := sashHistReplace(aud, audLines); err != nil {
		return err
	}
	if g.AllowPrivate {
		return nil
	}
	sugLines = sashHistTrim(append(sugLines, line))
	return sashHistReplace(sug, sugLines)
}

func sashHistTrim(lines []string) []string {
	if len(lines) <= sashHistMaxKeep {
		return lines
	}
	return append([]string(nil), lines[len(lines)-sashHistMaxKeep:]...)
}

func sashHistRead(path string) (lines []string, err error) {
	f, err := sashHistOpen(path, os.O_RDONLY, 0)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer func() {
		cerr := f.Close()
		if err == nil && cerr != nil {
			err = cerr
		}
	}()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, errors.New("hist file")
	}
	maxFile := int64(sashHistMaxKeep * (sashHistMaxLine*6 + 64))
	if st.Size() > maxFile {
		return nil, errors.New("hist size")
	}
	buf, err := io.ReadAll(io.LimitReader(f, maxFile+1))
	if err != nil {
		return nil, err
	}
	if int64(len(buf)) > maxFile {
		return nil, errors.New("hist size")
	}
	if len(buf) == 0 {
		return nil, nil
	}
	if buf[len(buf)-1] != '\n' {
		return nil, errors.New("hist tail")
	}
	parts := strings.Split(string(buf), "\n")
	parts = parts[:len(parts)-1]
	if len(parts) > sashHistMaxKeep {
		return nil, errors.New("hist count")
	}
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		line, decErr := sashHistDecode(part)
		if decErr != nil {
			return nil, decErr
		}
		out = append(out, line)
	}
	return out, nil
}

func sashHistDecode(raw string) (string, error) {
	dec := json.NewDecoder(strings.NewReader(raw))
	dec.DisallowUnknownFields()
	var row struct {
		Line string `json:"line"`
	}
	if err := dec.Decode(&row); err != nil {
		return "", err
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return "", errors.New("hist json")
	}
	if !sashHistLineOK(row.Line) {
		return "", errors.New("hist line")
	}
	return row.Line, nil
}

func sashHistEncode(lines []string) ([]byte, error) {
	var b strings.Builder
	for _, line := range lines {
		if !sashHistLineOK(line) {
			return nil, errors.New("hist line")
		}
		raw, err := json.Marshal(struct {
			Line string `json:"line"`
		}{Line: line})
		if err != nil {
			return nil, err
		}
		if _, err := b.Write(raw); err != nil {
			return nil, err
		}
		if err := b.WriteByte('\n'); err != nil {
			return nil, err
		}
	}
	return []byte(b.String()), nil
}

func sashHistOpen(path string, flag int, mode os.FileMode) (*os.File, error) {
	if openNoFollow == 0 {
		return nil, errors.New("hist nofollow")
	}
	return os.OpenFile(path, flag|openNoFollow, mode)
}

func sashHistEnsureDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	fi, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if fi.Mode()&os.ModeSymlink != 0 || !fi.IsDir() {
		return errors.New("hist dir")
	}
	return os.Chmod(dir, 0o700)
}

func sashHistReplace(path string, lines []string) error {
	dir := filepath.Dir(path)
	if err := sashHistEnsureDir(dir); err != nil {
		return err
	}
	body, err := sashHistEncode(lines)
	if err != nil {
		return err
	}
	tmp := filepath.Join(dir, "."+filepath.Base(path)+".tmp")
	if !sashHistInside(dir, tmp) {
		return errors.New("hist tmp")
	}
	if err := os.Remove(tmp); err != nil && !os.IsNotExist(err) {
		return err
	}
	f, err := sashHistOpen(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	_, werr := f.Write(body)
	if werr == nil {
		werr = f.Chmod(0o600)
	}
	serr := f.Sync()
	cerr := f.Close()
	if werr != nil || serr != nil || cerr != nil {
		rerr := os.Remove(tmp)
		err := werr
		if err == nil {
			err = serr
		}
		if err == nil {
			err = cerr
		}
		if rerr != nil && !os.IsNotExist(rerr) {
			return errors.Join(err, rerr)
		}
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		if rerr := os.Remove(tmp); rerr != nil && !os.IsNotExist(rerr) {
			return err
		}
		return err
	}
	return nil
}
