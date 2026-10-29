package main

// Desired-state providers (.omc/plans/convergence-drift.md §4.3). Each v1
// resource kind (file, directory, absent, package, service, sysctl) is a
// Checker and an Applier. Check reads facts through a ReadOnlyHost and
// returns the difference from the desired state; Apply changes the host
// through a WriteHost; verify is Check again after Apply.
//
// Threats: a resource is declared by a bundle or a sysscript, so its path,
// name, key and content are untrusted. Every grant is checked in the host
// views, before any backend call, for Check and for Apply alike: a file path
// must be absolute and clean and pass fsGrantPath against allow_config_write
// or allow_fs_write (directory and absent: allow_fs_write only), packages and
// services need an exact grant ("*" never matches), a sysctl needs
// allow_sysctl and allow_linux. File operations then go through the *Beneath
// helpers, which re-walk from the grant root without following a symlink
// (openat2 on Linux). Check reads file content under a write grant: holding
// the right to write a path implies reading it for comparison; a file with
// more than one hard link is not read, so a planted link cannot pull another
// file into a report or diff. A sensitive file reports only whether it
// matches: no hash, size or diff. Backups go to stateBackupDir, outside every
// target directory, which must not overlap a write grant.
//
// Read-only is structural. ReadOnlyHost is a struct whose backend
// (hostReads) has no write method, so a Checker cannot type-assert it to a
// WriteHost (a compile error) or to hostWrites (the backend does not
// implement it). WriteHost is built only by newWriteHost, which only the
// apply drivers call. state_providers_readonly_test.go checks this, and that
// no Check body names a write helper. Does NOT stop code elsewhere in package
// main calling a write helper directly; review and that test are the guard.

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const (
	// statePathMax bounds a resource path.
	statePathMax = 4096
	// stateContentMax bounds one file resource's content and the current
	// file a Check reads to compare with it.
	stateContentMax = hostFileCap
	// stateErrorMax bounds one resource's error text.
	stateErrorMax = 1024
	// packageVersionMax bounds a package version string.
	packageVersionMax = 128
)

// Resource statuses. conflict is set by the server only.
const (
	statusOK      = "ok"
	statusDrift   = "drift"
	statusChanged = "changed"
	statusFailed  = "failed"
	statusDenied  = "denied"
	statusSkipped = "skipped"
)

// errStateDenied marks a resource outside the run's grants.
var errStateDenied = errors.New("denied")

// codedError is a resource failure with a stable code, reported as
// "code: detail".
type codedError struct {
	code   string
	detail string
}

func (e *codedError) Error() string {
	if e.detail == "" {
		return e.code
	}
	return e.code + ": " + e.detail
}

// stateGrant selects the grant lists a path is checked against.
type stateGrant int

const (
	grantFileWrite stateGrant = iota // allow_config_write or allow_fs_write
	grantFSWrite                     // allow_fs_write only
)

// Facts are the canonical, JSON-encodable facts of a resource.
type Facts map[string]any

// Diff is the difference Check found. Fields name the facts that differ, in
// a fixed order; Text is a unified content diff (never for sensitive files).
type Diff struct {
	Fields []string
	Text   string
	// before is the provider's typed view of the current state, for Apply.
	before any
}

// Empty reports whether the resource is in its desired state.
func (d Diff) Empty() bool { return len(d.Fields) == 0 }

// Checker checks one resource. It receives only a read-only view.
type Checker interface {
	Key() string
	Kind() string
	Sensitive() bool
	Desired() Facts
	Check(ctx context.Context, ro ReadOnlyHost) (Facts, Diff, error)
}

// Applier also converges the resource. Apply receives the Diff its own
// Check returned.
type Applier interface {
	Checker
	Apply(ctx context.Context, rw WriteHost, d Diff) error
}

// pathFacts are the lstat facts of a path. Mode holds the permission bits
// including setuid, setgid and sticky (0o7777). UID and GID are -1 when the
// OS does not report them or the path does not exist.
type pathFacts struct {
	Exists bool
	Type   string // "file", "dir", "symlink" or "other"
	Mode   uint32
	UID    int
	GID    int
	Size   int64
}

var missingPath = pathFacts{UID: -1, GID: -1}

// pathFactsOf converts an lstat result.
func pathFactsOf(fi os.FileInfo) pathFacts {
	pf := pathFacts{Exists: true, UID: -1, GID: -1, Size: fi.Size()}
	switch {
	case fi.Mode().IsRegular():
		pf.Type = "file"
	case fi.IsDir():
		pf.Type = "dir"
	case fi.Mode()&os.ModeSymlink != 0:
		pf.Type = "symlink"
	default:
		pf.Type = "other"
	}
	pf.Mode = uint32(fi.Mode().Perm())
	if fi.Mode()&os.ModeSetuid != 0 {
		pf.Mode |= 0o4000
	}
	if fi.Mode()&os.ModeSetgid != 0 {
		pf.Mode |= 0o2000
	}
	if fi.Mode()&os.ModeSticky != 0 {
		pf.Mode |= 0o1000
	}
	if uid, gid, ok := fileOwnerIDs(fi); ok {
		pf.UID, pf.GID = uid, gid
	}
	return pf
}

// hostReads is the read-only backend. Its paths have passed the grant
// check in ReadOnlyHost. It has no write method by design.
type hostReads interface {
	stat(root, target string) (pathFacts, error)
	readFile(root, target string, max int) ([]byte, error)
	packageQuery(ctx context.Context, name string, allow []string) (bool, string, error)
	serviceState(ctx context.Context, name string) (active, enabled bool, err error)
	sysctlGet(key string, allow []string) (string, error)
}

// hostWrites is the mutating backend. Its paths have passed the grant
// check in WriteHost.
type hostWrites interface {
	backup(root, target string) (string, error)
	replaceFile(root, target string, data []byte, mode os.FileMode, uid, gid int) error
	mkdirAll(root, target string, mode os.FileMode) error
	chmod(root, target string, mode os.FileMode) error
	chown(root, target string, uid, gid int) error
	remove(root, target string) error
	packageChange(ctx context.Context, verb, name string, allow []string) error
	serviceAction(ctx context.Context, verb, name string) error
	sysctlSet(key, value string, allow []string) error
}

// hostBackend pairs the read backend with a constructor for the write
// backend. A check run never calls newWrites.
type hostBackend struct {
	reads     hostReads
	newWrites func() hostWrites
}

// osHostBackend is the real host.
func osHostBackend() hostBackend {
	return hostBackend{reads: osHostReads{}, newWrites: func() hostWrites { return osHostWrites{} }}
}

// ReadOnlyHost is the only view a Check receives: grant checks, then reads.
type ReadOnlyHost struct {
	ents *Entitlements
	r    hostReads
}

func newReadOnlyHost(ents *Entitlements, r hostReads) ReadOnlyHost {
	if ents == nil {
		ents = &Entitlements{}
	}
	return ReadOnlyHost{ents: ents, r: r}
}

// Stat lstat's a granted path.
func (ro ReadOnlyHost) Stat(path string, g stateGrant) (pathFacts, error) {
	root, target, err := stateGrantPath(ro.ents, path, g)
	if err != nil {
		return pathFacts{}, err
	}
	return ro.r.stat(root, target)
}

// ReadFile reads a granted regular file with a single link, at most max
// bytes.
func (ro ReadOnlyHost) ReadFile(path string, g stateGrant, max int) ([]byte, error) {
	root, target, err := stateGrantPath(ro.ents, path, g)
	if err != nil {
		return nil, err
	}
	return ro.r.readFile(root, target, max)
}

// Package reports whether a granted package is installed and its version.
func (ro ReadOnlyHost) Package(ctx context.Context, name string) (bool, string, error) {
	if !packageStateGranted(ro.ents, name) {
		return false, "", fmt.Errorf("%w: package %s not granted", errStateDenied, name)
	}
	return ro.r.packageQuery(ctx, name, ro.ents.AllowPackages)
}

// Service reports whether a granted service is active and enabled.
func (ro ReadOnlyHost) Service(ctx context.Context, name string) (bool, bool, error) {
	if !serviceStateGranted(ro.ents, name) {
		return false, false, fmt.Errorf("%w: service %s not granted", errStateDenied, name)
	}
	return ro.r.serviceState(ctx, name)
}

// Sysctl reads a granted sysctl.
func (ro ReadOnlyHost) Sysctl(key string) (string, error) {
	if !sysctlStateGranted(ro.ents, key) {
		return "", fmt.Errorf("%w: sysctl %s not granted", errStateDenied, key)
	}
	return ro.r.sysctlGet(key, ro.ents.AllowSysctl)
}

// WriteHost is the view Apply receives. Only newWriteHost builds one.
type WriteHost struct {
	ents *Entitlements
	w    hostWrites
	// backupID receives the basename of a backup taken by this Apply.
	backupID *string
}

// newWriteHost is called only by the apply drivers (applyChecked).
func newWriteHost(ents *Entitlements, w hostWrites) WriteHost {
	if ents == nil {
		ents = &Entitlements{}
	}
	return WriteHost{ents: ents, w: w}
}

// ReplaceFile atomically replaces a granted path with data, mode and owner,
// backing up the current regular file first when backup is set.
func (rw WriteHost) ReplaceFile(path string, g stateGrant, backup bool, data []byte, mode os.FileMode, uid, gid int) error {
	root, target, err := stateGrantPath(rw.ents, path, g)
	if err != nil {
		return err
	}
	if backup {
		if err := rw.backup(root, target); err != nil {
			return err
		}
	}
	return rw.w.replaceFile(root, target, data, mode, uid, gid)
}

// Mkdir creates a granted directory and its missing parents.
func (rw WriteHost) Mkdir(path string, mode os.FileMode) error {
	root, target, err := stateGrantPath(rw.ents, path, grantFSWrite)
	if err != nil {
		return err
	}
	return rw.w.mkdirAll(root, target, mode)
}

// Chmod sets the mode of a granted path.
func (rw WriteHost) Chmod(path string, g stateGrant, mode os.FileMode) error {
	root, target, err := stateGrantPath(rw.ents, path, g)
	if err != nil {
		return err
	}
	return rw.w.chmod(root, target, mode)
}

// Chown sets the owner of a granted path (-1 leaves an id unchanged).
func (rw WriteHost) Chown(path string, g stateGrant, uid, gid int) error {
	root, target, err := stateGrantPath(rw.ents, path, g)
	if err != nil {
		return err
	}
	return rw.w.chown(root, target, uid, gid)
}

// Remove removes a granted path (a file, a link or an empty directory),
// backing up a regular file first when backup is set.
func (rw WriteHost) Remove(path string, backup bool) error {
	root, target, err := stateGrantPath(rw.ents, path, grantFSWrite)
	if err != nil {
		return err
	}
	if backup {
		if err := rw.backup(root, target); err != nil {
			return err
		}
	}
	return rw.w.remove(root, target)
}

// Package installs or removes a granted package.
func (rw WriteHost) Package(ctx context.Context, verb, name string) error {
	if !packageStateGranted(rw.ents, name) {
		return fmt.Errorf("%w: package %s not granted", errStateDenied, name)
	}
	return rw.w.packageChange(ctx, verb, name, rw.ents.AllowPackages)
}

// Service runs a verb on a granted service.
func (rw WriteHost) Service(ctx context.Context, verb, name string) error {
	if !serviceStateGranted(rw.ents, name) {
		return fmt.Errorf("%w: service %s not granted", errStateDenied, name)
	}
	return rw.w.serviceAction(ctx, verb, name)
}

// Sysctl sets a granted sysctl.
func (rw WriteHost) Sysctl(key, value string) error {
	if !sysctlStateGranted(rw.ents, key) {
		return fmt.Errorf("%w: sysctl %s not granted", errStateDenied, key)
	}
	return rw.w.sysctlSet(key, value, rw.ents.AllowSysctl)
}

// backup refuses a backup dir that overlaps a write grant, then copies the
// current file there.
func (rw WriteHost) backup(root, target string) error {
	dir := filepath.Clean(stateBackupDir)
	if !filepath.IsAbs(dir) || writeGrantOverlaps(rw.ents.AllowFSWrite, dir) || writeGrantOverlaps(rw.ents.AllowConfigWrite, dir) {
		return fmt.Errorf("backup: backup dir overlaps a write grant")
	}
	id, err := rw.w.backup(root, target)
	if err != nil {
		return fmt.Errorf("backup: %w", err)
	}
	if rw.backupID != nil {
		*rw.backupID = id
	}
	return nil
}

// statePathOK accepts an absolute, clean path other than the root.
func statePathOK(p string) bool {
	return p != "" && len(p) <= statePathMax && filepath.IsAbs(p) && filepath.Clean(p) == p &&
		p != string(filepath.Separator) && !strings.ContainsAny(p, "\x00\n\r")
}

// stateGrantPath checks path against the grant lists of g with
// fsGrantRootPath. The final component is not followed: a symlink there is
// a fact to report or replace, never a way out.
func stateGrantPath(ents *Entitlements, path string, g stateGrant) (string, string, error) {
	denied := fmt.Errorf("%w: write to %s not granted", errStateDenied, path)
	if ents == nil || !statePathOK(path) {
		return "", "", denied
	}
	lists := [][]string{ents.AllowFSWrite}
	if g == grantFileWrite {
		lists = [][]string{ents.AllowConfigWrite, ents.AllowFSWrite}
	}
	for _, allow := range lists {
		if root, target, err := fsGrantRootPath(allow, path, "write", false); err == nil {
			return root, target, nil
		}
	}
	return "", "", denied
}

func packageStateGranted(ents *Entitlements, name string) bool {
	return ents != nil && packageNameRE.MatchString(name) && exactGrant(ents.AllowPackages, name)
}

func serviceStateGranted(ents *Entitlements, name string) bool {
	return ents != nil && serviceNameRE.MatchString(name) && exactGrant(ents.AllowServiceReload, name)
}

func sysctlStateGranted(ents *Entitlements, key string) bool {
	return ents != nil && ents.AllowLinux && sysctlGranted(ents.AllowSysctl, key)
}

// --- helpers ---

func fmtMode(m uint32) string { return fmt.Sprintf("%04o", m) }

// parseStateMode parses an octal mode of at most 0777 (no setuid, setgid or
// sticky bit).
func parseStateMode(s string) (uint32, error) {
	if s == "" || len(s) > 4 {
		return 0, fmt.Errorf("invalid mode %q", s)
	}
	n, err := strconv.ParseUint(s, 8, 32)
	if err != nil || n > 0o777 {
		return 0, fmt.Errorf("invalid mode %q (octal, at most 0777)", s)
	}
	return uint32(n), nil
}

// ownerSpecOK accepts "", a numeric id or a name matching ownerNameRE.
func ownerSpecOK(s string) bool {
	if s == "" {
		return true
	}
	if n, err := strconv.ParseUint(s, 10, 32); err == nil {
		return n <= 1<<31-1
	}
	return ownerNameRE.MatchString(s)
}

// resolveOwners turns owner and group into ids (-1 when not managed).
func resolveOwners(owner, group string) (int, int, error) {
	uid, err := resolveOwnerID(owner, false)
	if err != nil {
		return 0, 0, err
	}
	gid, err := resolveOwnerID(group, true)
	if err != nil {
		return 0, 0, err
	}
	return uid, gid, nil
}

func pathFactsMap(pf pathFacts) Facts {
	f := Facts{"exists": pf.Exists}
	if !pf.Exists {
		return f
	}
	f["type"] = pf.Type
	f["mode"] = fmtMode(pf.Mode)
	f["uid"] = int64(pf.UID)
	f["gid"] = int64(pf.GID)
	return f
}

// ownerFields appends "owner" and "group" when a managed id differs.
func ownerFields(fields []string, pf pathFacts, uid, gid int) []string {
	if uid >= 0 && pf.UID != uid {
		fields = append(fields, "owner")
	}
	if gid >= 0 && pf.GID != gid {
		fields = append(fields, "group")
	}
	return fields
}

func hasField(fields []string, name string) bool {
	for _, f := range fields {
		if f == name {
			return true
		}
	}
	return false
}

// factsDigest is the sha256 of the canonical JSON of f (map keys sorted).
func factsDigest(f Facts) string {
	if f == nil {
		return "-"
	}
	b, err := json.Marshal(f)
	if err != nil {
		return "-"
	}
	return sha256Hex(string(b))
}

// --- file ---

// fileResource is state.file(path, content, mode, owner, group, sensitive).
type fileResource struct {
	path         string
	content      string
	mode         uint32
	owner, group string
	sensitive    bool
}

func (f *fileResource) Key() string     { return "file:" + f.path }
func (f *fileResource) Kind() string    { return "file" }
func (f *fileResource) Sensitive() bool { return f.sensitive }

func (f *fileResource) Desired() Facts {
	d := Facts{"exists": true, "type": "file", "mode": fmtMode(f.mode)}
	if !f.sensitive {
		d["sha256"] = sha256Hex(f.content)
		d["size"] = int64(len(f.content))
	}
	if f.owner != "" {
		d["owner"] = f.owner
	}
	if f.group != "" {
		d["group"] = f.group
	}
	return d
}

func (f *fileResource) Check(ctx context.Context, ro ReadOnlyHost) (Facts, Diff, error) {
	uid, gid, err := resolveOwners(f.owner, f.group)
	if err != nil {
		return nil, Diff{}, err
	}
	pf, err := ro.Stat(f.path, grantFileWrite)
	if err != nil {
		return nil, Diff{}, err
	}
	before := pathFactsMap(pf)
	var fields []string
	var current []byte
	switch {
	case !pf.Exists:
		fields = append(fields, "exists")
	case pf.Type != "file":
		fields = append(fields, "type")
	default:
		matches := false
		if pf.Size <= stateContentMax {
			current, err = ro.ReadFile(f.path, grantFileWrite, stateContentMax)
			if err != nil {
				return nil, Diff{}, err
			}
			have, want := sha256.Sum256(current), sha256.Sum256([]byte(f.content))
			matches = subtle.ConstantTimeCompare(have[:], want[:]) == 1
		}
		if f.sensitive {
			before["matches"] = matches
		} else {
			before["size"] = pf.Size
			if current != nil || pf.Size == 0 {
				before["sha256"] = sha256Hex(string(current))
			}
		}
		if !matches {
			fields = append(fields, "content")
		}
		if pf.Mode != f.mode {
			fields = append(fields, "mode")
		}
		fields = ownerFields(fields, pf, uid, gid)
	}
	d := Diff{Fields: fields, before: pf}
	if !f.sensitive && (hasField(fields, "exists") || hasField(fields, "content")) && pf.Size <= stateContentMax {
		if text, err := unifiedDiff(f.path, f.path, string(current), f.content); err == nil {
			d.Text = text
		}
	}
	return before, d, nil
}

func (f *fileResource) Apply(ctx context.Context, rw WriteHost, d Diff) error {
	pf, _ := d.before.(pathFacts)
	uid, gid, err := resolveOwners(f.owner, f.group)
	if err != nil {
		return err
	}
	if hasField(d.Fields, "exists") || hasField(d.Fields, "type") || hasField(d.Fields, "content") {
		if pf.Exists && pf.Type == "dir" {
			return fmt.Errorf("%s is a directory", f.path)
		}
		isFile := pf.Exists && pf.Type == "file"
		// An unmanaged owner keeps the replaced file's.
		if uid < 0 && isFile {
			uid = pf.UID
		}
		if gid < 0 && isFile {
			gid = pf.GID
		}
		return rw.ReplaceFile(f.path, grantFileWrite, isFile, []byte(f.content), os.FileMode(f.mode), uid, gid)
	}
	if hasField(d.Fields, "mode") {
		if err := rw.Chmod(f.path, grantFileWrite, os.FileMode(f.mode)); err != nil {
			return err
		}
	}
	if hasField(d.Fields, "owner") || hasField(d.Fields, "group") {
		return rw.Chown(f.path, grantFileWrite, uid, gid)
	}
	return nil
}

// --- directory ---

// dirResource is state.directory(path, mode, owner, group).
type dirResource struct {
	path         string
	mode         uint32
	owner, group string
}

func (r *dirResource) Key() string     { return "dir:" + r.path }
func (r *dirResource) Kind() string    { return "directory" }
func (r *dirResource) Sensitive() bool { return false }

func (r *dirResource) Desired() Facts {
	d := Facts{"exists": true, "type": "dir", "mode": fmtMode(r.mode)}
	if r.owner != "" {
		d["owner"] = r.owner
	}
	if r.group != "" {
		d["group"] = r.group
	}
	return d
}

func (r *dirResource) Check(ctx context.Context, ro ReadOnlyHost) (Facts, Diff, error) {
	uid, gid, err := resolveOwners(r.owner, r.group)
	if err != nil {
		return nil, Diff{}, err
	}
	pf, err := ro.Stat(r.path, grantFSWrite)
	if err != nil {
		return nil, Diff{}, err
	}
	var fields []string
	switch {
	case !pf.Exists:
		fields = append(fields, "exists")
	case pf.Type != "dir":
		fields = append(fields, "type")
	default:
		if pf.Mode != r.mode {
			fields = append(fields, "mode")
		}
		fields = ownerFields(fields, pf, uid, gid)
	}
	return pathFactsMap(pf), Diff{Fields: fields, before: pf}, nil
}

func (r *dirResource) Apply(ctx context.Context, rw WriteHost, d Diff) error {
	pf, _ := d.before.(pathFacts)
	uid, gid, err := resolveOwners(r.owner, r.group)
	if err != nil {
		return err
	}
	if pf.Exists && pf.Type != "dir" {
		return fmt.Errorf("%s exists and is not a directory", r.path)
	}
	if !pf.Exists {
		if err := rw.Mkdir(r.path, os.FileMode(r.mode)); err != nil {
			return err
		}
	}
	// mkdir is subject to the umask, so the mode is set explicitly.
	if !pf.Exists || hasField(d.Fields, "mode") {
		if err := rw.Chmod(r.path, grantFSWrite, os.FileMode(r.mode)); err != nil {
			return err
		}
	}
	if uid >= 0 || gid >= 0 {
		if !pf.Exists || hasField(d.Fields, "owner") || hasField(d.Fields, "group") {
			return rw.Chown(r.path, grantFSWrite, uid, gid)
		}
	}
	return nil
}

// --- absent ---

// absentResource is state.absent(path). It shares the file: key space.
type absentResource struct {
	path string
}

func (r *absentResource) Key() string     { return "file:" + r.path }
func (r *absentResource) Kind() string    { return "absent" }
func (r *absentResource) Sensitive() bool { return false }
func (r *absentResource) Desired() Facts  { return Facts{"exists": false} }

func (r *absentResource) Check(ctx context.Context, ro ReadOnlyHost) (Facts, Diff, error) {
	pf, err := ro.Stat(r.path, grantFSWrite)
	if err != nil {
		return nil, Diff{}, err
	}
	var fields []string
	if pf.Exists {
		fields = append(fields, "exists")
	}
	return pathFactsMap(pf), Diff{Fields: fields, before: pf}, nil
}

func (r *absentResource) Apply(ctx context.Context, rw WriteHost, d Diff) error {
	pf, _ := d.before.(pathFacts)
	return rw.Remove(r.path, pf.Type == "file")
}

// --- package ---

// packageResource is state.package(name, present, version). version is
// check-only in v1.
type packageResource struct {
	name    string
	present bool
	version string
}

func (r *packageResource) Key() string     { return "package:" + r.name }
func (r *packageResource) Kind() string    { return "package" }
func (r *packageResource) Sensitive() bool { return false }

func (r *packageResource) Desired() Facts {
	d := Facts{"installed": r.present}
	if r.version != "" {
		d["version"] = r.version
	}
	return d
}

func (r *packageResource) Check(ctx context.Context, ro ReadOnlyHost) (Facts, Diff, error) {
	installed, version, err := ro.Package(ctx, r.name)
	if err != nil {
		return nil, Diff{}, err
	}
	before := Facts{"installed": installed}
	if installed {
		before["version"] = version
	}
	var fields []string
	if installed != r.present {
		fields = append(fields, "installed")
	} else if installed && r.version != "" && version != r.version {
		fields = append(fields, "version")
	}
	return before, Diff{Fields: fields}, nil
}

func (r *packageResource) Apply(ctx context.Context, rw WriteHost, d Diff) error {
	if r.version != "" {
		return &codedError{code: "version_pin_unsupported", detail: "package version is check-only"}
	}
	verb := "install"
	if !r.present {
		verb = "remove"
	}
	return rw.Package(ctx, verb, r.name)
}

// --- service ---

// serviceResource is state.service(name, running, enabled, restart_on).
// restart_on is acted on by the converge engine, not by Apply.
type serviceResource struct {
	name      string
	running   bool
	enabled   bool
	restartOn []string
}

func (r *serviceResource) Key() string     { return "service:" + r.name }
func (r *serviceResource) Kind() string    { return "service" }
func (r *serviceResource) Sensitive() bool { return false }
func (r *serviceResource) Desired() Facts {
	return Facts{"active": r.running, "enabled": r.enabled}
}

func (r *serviceResource) Check(ctx context.Context, ro ReadOnlyHost) (Facts, Diff, error) {
	active, enabled, err := ro.Service(ctx, r.name)
	if err != nil {
		return nil, Diff{}, err
	}
	var fields []string
	if enabled != r.enabled {
		fields = append(fields, "enabled")
	}
	if active != r.running {
		fields = append(fields, "active")
	}
	return Facts{"active": active, "enabled": enabled}, Diff{Fields: fields}, nil
}

func (r *serviceResource) Apply(ctx context.Context, rw WriteHost, d Diff) error {
	if hasField(d.Fields, "enabled") {
		verb := "disable"
		if r.enabled {
			verb = "enable"
		}
		if err := rw.Service(ctx, verb, r.name); err != nil {
			return err
		}
	}
	if hasField(d.Fields, "active") {
		verb := "stop"
		if r.running {
			verb = "start"
		}
		return rw.Service(ctx, verb, r.name)
	}
	return nil
}

// --- sysctl ---

// sysctlResource is state.sysctl(key, value). Values compare with runs of
// whitespace folded, as the kernel prints multi-value keys with tabs.
type sysctlResource struct {
	key   string
	value string
}

func normalizeSysctl(v string) string { return strings.Join(strings.Fields(v), " ") }

func (r *sysctlResource) Key() string     { return "sysctl:" + r.key }
func (r *sysctlResource) Kind() string    { return "sysctl" }
func (r *sysctlResource) Sensitive() bool { return false }
func (r *sysctlResource) Desired() Facts  { return Facts{"value": normalizeSysctl(r.value)} }

func (r *sysctlResource) Check(ctx context.Context, ro ReadOnlyHost) (Facts, Diff, error) {
	v, err := ro.Sysctl(r.key)
	if err != nil {
		return nil, Diff{}, err
	}
	cur := normalizeSysctl(v)
	var fields []string
	if cur != normalizeSysctl(r.value) {
		fields = append(fields, "value")
	}
	return Facts{"value": cur}, Diff{Fields: fields}, nil
}

func (r *sysctlResource) Apply(ctx context.Context, rw WriteHost, d Diff) error {
	return rw.Sysctl(r.key, r.value)
}

// --- drivers ---

// resourceResult is one resource's outcome.
type resourceResult struct {
	Key       string
	Kind      string
	Status    string
	Sensitive bool
	Before    Facts
	Desired   Facts
	After     Facts
	Diff      string
	Error     string
	BackupID  string
	diff      Diff
}

func stateErrText(err error) string { return capText(err.Error(), stateErrorMax) }

// checkResource runs Check and classifies it as ok, drift, failed or denied
// (skipped once ctx has ended).
func checkResource(ctx context.Context, c Checker, ro ReadOnlyHost) resourceResult {
	res := resourceResult{Key: c.Key(), Kind: c.Kind(), Sensitive: c.Sensitive(), Desired: c.Desired()}
	if ctx.Err() != nil {
		res.Status, res.Error = statusSkipped, jobCtxReason(ctx)
		return res
	}
	before, d, err := c.Check(ctx, ro)
	res.Before, res.diff = before, d
	switch {
	case errors.Is(err, errStateDenied):
		res.Status, res.Error = statusDenied, stateErrText(err)
	case err != nil:
		res.Status, res.Error = statusFailed, stateErrText(err)
	case d.Empty():
		res.Status = statusOK
	default:
		res.Status = statusDrift
		if !c.Sensitive() {
			res.Diff = d.Text
		}
	}
	return res
}

// applyChecked applies a resource whose check drifted, then verifies it
// with a fresh Check: an unchanged diff is failed[non_idempotent]. Other
// statuses are returned as they are.
func applyChecked(ctx context.Context, a Applier, ro ReadOnlyHost, rw WriteHost, res resourceResult) resourceResult {
	if res.Status != statusDrift {
		return res
	}
	if ctx.Err() != nil {
		res.Status, res.Error = statusSkipped, jobCtxReason(ctx)
		return res
	}
	var backupID string
	rw.backupID = &backupID
	err := a.Apply(ctx, rw, res.diff)
	res.BackupID = backupID
	if err != nil {
		res.Status, res.Error = statusFailed, stateErrText(err)
		if errors.Is(err, errStateDenied) {
			res.Status = statusDenied
		}
		return res
	}
	after, d, err := a.Check(ctx, ro)
	res.After = after
	switch {
	case err != nil:
		res.Status, res.Error = statusFailed, stateErrText(fmt.Errorf("verify: %w", err))
	case !d.Empty():
		res.Status = statusFailed
		res.Error = (&codedError{code: "non_idempotent", detail: strings.Join(d.Fields, ",") + " still differ"}).Error()
	default:
		res.Status = statusChanged
	}
	return res
}

// --- real host backends ---

// osHostReads reads the real host. It has no write method.
type osHostReads struct{}

func (osHostReads) stat(root, target string) (pathFacts, error) { return statBeneath(root, target) }

func (osHostReads) readFile(root, target string, max int) ([]byte, error) {
	return readBeneath(root, target, max)
}

func (osHostReads) packageQuery(ctx context.Context, name string, allow []string) (bool, string, error) {
	return queryPackage(ctx, name, allow)
}

func (osHostReads) serviceState(ctx context.Context, name string) (bool, bool, error) {
	svc := currentPlatform().Services
	st, err := svc.Status(ctx, name)
	if err != nil {
		return false, false, err
	}
	enabled, err := svc.IsEnabled(ctx, name)
	if err != nil {
		return false, false, err
	}
	return st.Active, enabled, nil
}

func (osHostReads) sysctlGet(key string, allow []string) (string, error) {
	return currentPlatform().Tweaks.SysctlGet(key, allow)
}

// osHostWrites changes the real host.
type osHostWrites struct{}

func (osHostWrites) backup(root, target string) (string, error) {
	data, err := readBeneath(root, target, hostFileCap)
	if err != nil {
		return "", err
	}
	return backupOutside(target, data)
}

func (osHostWrites) replaceFile(root, target string, data []byte, mode os.FileMode, uid, gid int) error {
	return atomicReplaceMode(root, target, data, mode, uid, gid)
}

func (osHostWrites) mkdirAll(root, target string, mode os.FileMode) error {
	return mkdirBeneath(root, target, mode)
}

func (osHostWrites) chmod(root, target string, mode os.FileMode) error {
	return chmodBeneath(root, target, mode)
}

func (osHostWrites) chown(root, target string, uid, gid int) error {
	return chownBeneath(root, target, uid, gid)
}

func (osHostWrites) remove(root, target string) error { return removeBeneath(root, target) }

func (osHostWrites) packageChange(ctx context.Context, verb, name string, allow []string) error {
	return changePackage(ctx, verb, name, allow)
}

func (osHostWrites) serviceAction(ctx context.Context, verb, name string) error {
	out, err := currentPlatform().Services.Action(ctx, verb, name)
	if err != nil {
		return fmt.Errorf("service %s %s: %v: %s", verb, name, err, capText(strings.TrimSpace(out), installErrCap))
	}
	return nil
}

func (osHostWrites) sysctlSet(key, value string, allow []string) error {
	return currentPlatform().Tweaks.SysctlSet(key, value, allow)
}
