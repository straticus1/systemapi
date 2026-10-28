package main

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"go.starlark.net/starlark"
)

// Threats: every sys.fs and sys.config path goes through fsGrantPath. A path
// must be absolute; it is cleaned and checked against the grant list on path
// boundaries (so /srv/app does not grant /srv/app-secrets and
// /srv/data/../app is checked as /srv/app), then its symlinks are resolved
// and the real path is checked again, so a link inside a grant cannot reach
// outside it. The operation then uses the resolved path. Does NOT close the
// race where another local process swaps a directory for a symlink between
// the check and the syscall; chown, which can hand a file to another
// account, closes it on Linux with openat2 (see chownBeneath).
// chown owner names must match a fixed regex before os/user sees them. diff
// reads two regular files under the read policy, each capped at hostFileCap,
// refuses more than diffMaxLines lines in total, an edit distance above
// diffMaxEdits, or more than diffMaxWork search steps, so a crafted pair
// cannot burn CPU or memory.

// diffMaxEdits bounds the Myers search (memory is O(D^2) ints).
const diffMaxEdits = 2000

// diffMaxLines bounds the total line count of both inputs.
const diffMaxLines = 200000

// diffMaxWork bounds the Myers search steps (diagonals plus snake moves).
const diffMaxWork = 20_000_000

// diffContext is the unified diff context line count, as in diff -u.
const diffContext = 3

var ownerNameRE = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9._-]{0,31}\$?$`)

// fsPrefixAllowed reports whether the clean absolute path p is within a
// grant: "*", or a grant prefix on a path boundary. The grant itself is also
// tried with its symlinks resolved (through its nearest existing ancestor
// when it does not exist yet), so a /tmp grant matches /private/tmp on macOS.
func fsPrefixAllowed(allow []string, p string) bool {
	for _, prefix := range allow {
		if prefix == "*" {
			return true
		}
		if prefix == "" || !filepath.IsAbs(prefix) {
			continue
		}
		if pathWithin(prefix, p) {
			return true
		}
		if real, err := resolveExisting(filepath.Clean(prefix)); err == nil && pathWithin(real, p) {
			return true
		}
	}
	return false
}

// fsGrantRoot returns the real path of the grant that holds the resolved
// path p ("/" for "*"), for operations that re-walk from the grant root.
func fsGrantRoot(allow []string, p string) (string, bool) {
	for _, prefix := range allow {
		if prefix == "*" {
			return string(filepath.Separator), true
		}
		if prefix == "" || !filepath.IsAbs(prefix) {
			continue
		}
		real, err := resolveExisting(filepath.Clean(prefix))
		if err != nil {
			continue
		}
		if pathWithin(real, p) {
			return real, true
		}
	}
	return "", false
}

// resolveExisting resolves the symlinks of p. A tail that does not exist yet
// is resolved through its nearest existing ancestor and joined back. A
// dangling symlink fails closed: writing through it would create its target.
func resolveExisting(p string) (string, error) {
	rest := ""
	for {
		real, err := filepath.EvalSymlinks(p)
		if err == nil {
			return filepath.Join(real, rest), nil
		}
		if !errors.Is(err, fs.ErrNotExist) {
			return "", err
		}
		if _, lerr := os.Lstat(p); lerr == nil {
			return "", fmt.Errorf("dangling symlink")
		}
		parent := filepath.Dir(p)
		if parent == p {
			return "", err
		}
		rest = filepath.Join(filepath.Base(p), rest)
		p = parent
	}
}

// fsGrantRootPath is fsGrantPath plus the real grant root that holds the
// resolved path, for the *Beneath helpers.
func fsGrantRootPath(allow []string, path, op string, followFinal bool) (string, string, error) {
	resolved, err := fsGrantPath(allow, path, op, followFinal)
	if err != nil {
		return "", "", err
	}
	root, ok := fsGrantRoot(allow, resolved)
	if !ok {
		return "", "", fmt.Errorf("security exception: %s to %s not granted", op, path)
	}
	return root, resolved, nil
}

// fsGrantPath checks path against allow for op ("read" or "write") and
// returns the resolved path to operate on. followFinal=false resolves only
// the parent, for operations that act on a final symlink itself (rm).
func fsGrantPath(allow []string, path, op string, followFinal bool) (string, error) {
	denied := fmt.Errorf("security exception: %s to %s not granted", op, path)
	if path == "" || strings.ContainsRune(path, 0) || !filepath.IsAbs(path) {
		return "", denied
	}
	cleaned := filepath.Clean(path)
	if !fsPrefixAllowed(allow, cleaned) {
		return "", denied
	}
	var resolved string
	if followFinal {
		r, err := resolveExisting(cleaned)
		if err != nil {
			return "", denied
		}
		resolved = r
	} else {
		dir, err := resolveExisting(filepath.Dir(cleaned))
		if err != nil {
			return "", denied
		}
		resolved = filepath.Join(dir, filepath.Base(cleaned))
	}
	if !fsPrefixAllowed(allow, resolved) {
		return "", denied
	}
	return resolved, nil
}

// resolveOwnerID turns a user or group name, or a numeric id, into an id.
// "" means unchanged (-1).
func resolveOwnerID(s string, group bool) (int, error) {
	if s == "" {
		return -1, nil
	}
	if n, err := strconv.ParseUint(s, 10, 32); err == nil {
		if n > math.MaxInt32 {
			return 0, fmt.Errorf("invalid id %q", s)
		}
		return int(n), nil
	}
	if !ownerNameRE.MatchString(s) {
		return 0, fmt.Errorf("invalid name %q", s)
	}
	var id string
	if group {
		g, err := user.LookupGroup(s)
		if err != nil {
			return 0, fmt.Errorf("unknown group %q", s)
		}
		id = g.Gid
	} else {
		u, err := user.Lookup(s)
		if err != nil {
			return 0, fmt.Errorf("unknown user %q", s)
		}
		id = u.Uid
	}
	n, err := strconv.Atoi(id)
	if err != nil {
		return 0, fmt.Errorf("non-numeric id for %q", s)
	}
	return n, nil
}

// sys.fs.chown(path, user, group) - user/group are names or numeric ids; ""
// leaves that id unchanged
func (engine *SysscriptEngine) fsChown(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var path, owner, group string
	if err := starlark.UnpackArgs("chown", args, kwargs, "path", &path, "user", &owner, "group", &group); err != nil {
		return starlark.None, err
	}
	root, resolved, err := fsGrantRootPath(engine.Entitlements.AllowFSWrite, path, "write", true)
	if err != nil {
		return starlark.None, err
	}
	if owner == "" && group == "" {
		return starlark.None, fmt.Errorf("fs.chown: user or group required")
	}
	uid, err := resolveOwnerID(owner, false)
	if err != nil {
		return starlark.None, fmt.Errorf("fs.chown: %w", err)
	}
	gid, err := resolveOwnerID(group, true)
	if err != nil {
		return starlark.None, fmt.Errorf("fs.chown: %w", err)
	}
	if err := chownBeneath(root, resolved, uid, gid); err != nil {
		return starlark.None, fmt.Errorf("fs.chown: %w", err)
	}
	return starlark.True, nil
}

// sys.fs.diff(path_a, path_b) - unified diff string, "" when equal
func (engine *SysscriptEngine) fsDiff(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var pathA, pathB string
	if err := starlark.UnpackArgs("diff", args, kwargs, "path_a", &pathA, "path_b", &pathB); err != nil {
		return starlark.None, err
	}
	realA, err := fsGrantPath(engine.Entitlements.AllowFSRead, pathA, "read", true)
	if err != nil {
		return starlark.None, err
	}
	realB, err := fsGrantPath(engine.Entitlements.AllowFSRead, pathB, "read", true)
	if err != nil {
		return starlark.None, err
	}
	a, err := readFileCapped(realA, hostFileCap)
	if err != nil {
		return starlark.None, fmt.Errorf("fs.diff: %w", err)
	}
	bb, err := readFileCapped(realB, hostFileCap)
	if err != nil {
		return starlark.None, fmt.Errorf("fs.diff: %w", err)
	}
	out, err := unifiedDiff(pathA, pathB, a, bb)
	if err != nil {
		return starlark.None, fmt.Errorf("fs.diff: %w", err)
	}
	return starlark.String(out), nil
}

// readFileCapped reads a regular file of at most max bytes. It lstats first
// so a FIFO or device is refused before open, opens non-blocking, and checks
// the opened file is the one it lstat'ed.
func readFileCapped(path string, max int) (string, error) {
	return readFileCappedLinks(path, max, false)
}

// readFileCappedLinks is readFileCapped; singleLink also refuses a file with
// more than one hard link (checked on the opened file), so a hard link
// planted beside a config cannot pull a secret into a readable copy.
func readFileCappedLinks(path string, max int, singleLink bool) (string, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("%s is not a regular file", path)
	}
	if info.Size() > int64(max) {
		return "", fmt.Errorf("%s exceeds %d bytes", path, max)
	}
	f, err := os.OpenFile(path, os.O_RDONLY|openNonBlock, 0)
	if err != nil {
		return "", err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil {
		return "", err
	}
	if !os.SameFile(info, opened) {
		return "", fmt.Errorf("%s changed while opening", path)
	}
	if singleLink && fileNlink(opened) > 1 {
		return "", fmt.Errorf("%s has more than one hard link", path)
	}
	data, err := io.ReadAll(io.LimitReader(f, int64(max)+1))
	if err != nil {
		return "", err
	}
	if len(data) > max {
		return "", fmt.Errorf("%s exceeds %d bytes", path, max)
	}
	return string(data), nil
}

// splitDiffLines splits text into lines that keep their "\n", so a last line
// without a newline differs from the same line with one, as in GNU diff.
func splitDiffLines(s string) []string {
	if s == "" {
		return nil
	}
	lines := strings.SplitAfter(s, "\n")
	if lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	return lines
}

// diffOp is one line of an edit script: ' ' keep, '-' delete, '+' insert.
type diffOp struct {
	kind byte
	line string
}

// myersDiff returns the shortest edit script from a to b, or an error when it
// needs more than maxEdits edits or more than maxWork search steps. Common prefix and suffix are trimmed first.
func myersDiff(a, b []string, maxEdits, maxWork int) ([]diffOp, error) {
	pre := 0
	for pre < len(a) && pre < len(b) && a[pre] == b[pre] {
		pre++
	}
	suf := 0
	for suf < len(a)-pre && suf < len(b)-pre && a[len(a)-1-suf] == b[len(b)-1-suf] {
		suf++
	}
	ma, mb := a[pre:len(a)-suf], b[pre:len(b)-suf]

	var ops []diffOp
	for _, l := range a[:pre] {
		ops = append(ops, diffOp{' ', l})
	}
	mid, err := myersCore(ma, mb, maxEdits, maxWork)
	if err != nil {
		return nil, err
	}
	ops = append(ops, mid...)
	for _, l := range a[len(a)-suf:] {
		ops = append(ops, diffOp{' ', l})
	}
	return ops, nil
}

func myersCore(a, b []string, maxEdits, maxWork int) ([]diffOp, error) {
	n, m := len(a), len(b)
	if n == 0 && m == 0 {
		return nil, nil
	}
	max := n + m
	if max > maxEdits {
		max = maxEdits
	}
	// v[k+offset] is the furthest x on diagonal k. trace[d] keeps the
	// window [-d, d] of v after step d, for the backtrack.
	offset := max + 1
	v := make([]int32, 2*max+3)
	var trace [][]int32
	found := -1
	work := 0
	for d := 0; d <= max && found < 0; d++ {
		for k := -d; k <= d; k += 2 {
			work++
			var x int
			if k == -d || (k != d && v[k-1+offset] < v[k+1+offset]) {
				x = int(v[k+1+offset])
			} else {
				x = int(v[k-1+offset]) + 1
			}
			y := x - k
			for x < n && y < m && a[x] == b[y] {
				x++
				y++
				work++
			}
			if work > maxWork {
				return nil, fmt.Errorf("diff exceeds %d search steps", maxWork)
			}
			v[k+offset] = int32(x)
			if x >= n && y >= m {
				found = d
				break
			}
		}
		snap := make([]int32, 2*d+1)
		copy(snap, v[offset-d:offset+d+1])
		trace = append(trace, snap)
	}
	if found < 0 {
		return nil, fmt.Errorf("files differ by more than %d lines", maxEdits)
	}

	// Backtrack from (n, m) through the saved windows.
	var rev []diffOp
	x, y := n, m
	for d := found; d > 0; d-- {
		prev := trace[d-1]
		get := func(k int) int { return int(prev[k+d-1]) }
		k := x - y
		var pk int
		if k == -d || (k != d && get(k-1) < get(k+1)) {
			pk = k + 1
		} else {
			pk = k - 1
		}
		px := get(pk)
		py := px - pk
		for x > px && y > py {
			x--
			y--
			rev = append(rev, diffOp{' ', a[x]})
		}
		if x == px {
			y--
			rev = append(rev, diffOp{'+', b[y]})
		} else {
			x--
			rev = append(rev, diffOp{'-', a[x]})
		}
	}
	for x > 0 && y > 0 {
		x--
		y--
		rev = append(rev, diffOp{' ', a[x]})
	}
	ops := make([]diffOp, len(rev))
	for i := range rev {
		ops[i] = rev[len(rev)-1-i]
	}
	return ops, nil
}

// unifiedDiff renders a diff -u style patch with diffContext lines of
// context. Equal inputs give "".
func unifiedDiff(nameA, nameB, a, b string) (string, error) {
	la, lb := splitDiffLines(a), splitDiffLines(b)
	if len(la)+len(lb) > diffMaxLines {
		return "", fmt.Errorf("files exceed %d lines in total", diffMaxLines)
	}
	ops, err := myersDiff(la, lb, diffMaxEdits, diffMaxWork)
	if err != nil {
		return "", err
	}
	changed := false
	for _, op := range ops {
		if op.kind != ' ' {
			changed = true
			break
		}
	}
	if !changed {
		return "", nil
	}

	var sb strings.Builder
	fmt.Fprintf(&sb, "--- %s\n+++ %s\n", nameA, nameB)
	i := 0
	for i < len(ops) {
		// Find the next change, then grow the hunk while changes are
		// within 2*diffContext lines of each other.
		for i < len(ops) && ops[i].kind == ' ' {
			i++
		}
		if i == len(ops) {
			break
		}
		start := i - diffContext
		if start < 0 {
			start = 0
		}
		end := i
		for end < len(ops) {
			if ops[end].kind != ' ' {
				end++
				continue
			}
			run := end
			for run < len(ops) && ops[run].kind == ' ' {
				run++
			}
			if run == len(ops) || run-end > 2*diffContext {
				end += diffContext
				if end > len(ops) {
					end = len(ops)
				}
				break
			}
			end = run
		}
		writeHunk(&sb, ops, start, end)
		i = end
	}
	return sb.String(), nil
}

func writeHunk(sb *strings.Builder, ops []diffOp, start, end int) {
	// Line numbers of the hunk start in each file (1-based).
	la, lb := 1, 1
	for _, op := range ops[:start] {
		if op.kind != '+' {
			la++
		}
		if op.kind != '-' {
			lb++
		}
	}
	ca, cb := 0, 0
	for _, op := range ops[start:end] {
		if op.kind != '+' {
			ca++
		}
		if op.kind != '-' {
			cb++
		}
	}
	fmt.Fprintf(sb, "@@ -%s +%s @@\n", hunkRange(la, ca), hunkRange(lb, cb))
	for _, op := range ops[start:end] {
		sb.WriteByte(op.kind)
		sb.WriteString(op.line)
		if !strings.HasSuffix(op.line, "\n") {
			sb.WriteString("\n\\ No newline at end of file\n")
		}
	}
}

// hunkRange formats "start,count" the way diff -u does: count 1 is omitted
// and an empty range points at the line before.
func hunkRange(start, count int) string {
	switch count {
	case 0:
		return fmt.Sprintf("%d,0", start-1)
	case 1:
		return strconv.Itoa(start)
	default:
		return fmt.Sprintf("%d,%d", start, count)
	}
}
