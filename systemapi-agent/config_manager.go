package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"text/template"
	"time"
)

//go:embed templates/*.tmpl
var embeddedTemplates embed.FS

// ConfigManager handles atomic config writes, backups, and template rendering.
type ConfigManager struct{}

// Threats: path is a resolved path the caller checked against a grant, in
// a directory scripts or local users may also write. Nothing here writes or
// reads through a name someone could plant first: the temp file is
// os.CreateTemp in the target's directory (random name, O_EXCL, so a planted
// symlink fails the create), backups are created O_CREAT|O_EXCL|O_NOFOLLOW,
// the target is replaced by rename (which replaces a final symlink rather
// than following it), and a file is only read when it is a regular file
// (readFileCapped: Lstat first, size cap) with a single hard link. A
// replaced file keeps its mode and owner. Restore takes only names that
// match path.bak.<digits> and are regular files. Does NOT stop a parent
// directory being swapped for a symlink between the caller's check and these
// calls.

// backupSuffixRE matches the timestamp of a backup name written by
// newBackupName (unix nanoseconds) or by older agents (unix seconds).
var backupSuffixRE = regexp.MustCompile(`^[0-9]{1,19}$`)

// stateBackupDir holds the desired-state file backups, outside every target
// directory: <dir>/<sha256(path)>/<unix_ns>, dirs 0700, files 0600. It must
// not overlap a write grant (WriteHost refuses a backup otherwise). A var so
// tests can point it at a temp dir.
var stateBackupDir = "/var/lib/systemapi/backups"

// configureStateBackupDir sets stateBackupDir from --state-backup-dir at
// startup. An explicit value (set) must pass checkStateBackupDir, or the
// agent does not start; on Windows, where owners cannot be checked, an
// explicit value is refused. The default is not worth an outage: when it
// fails the check (or on Windows) backups are disabled with a warning, and
// a file change that needs a backup then fails with a clear error. Nothing
// else in the agent depends on it.
func configureStateBackupDir(value string, set bool, goos string) error {
	if goos == "windows" {
		if set {
			return fmt.Errorf("not supported on windows")
		}
		stateBackupDir = ""
		return nil
	}
	dir, err := checkStateBackupDir(value)
	if err != nil {
		if set {
			return err
		}
		log.Printf("WARNING: desired-state backups disabled: default backup dir %s: %v (file changes that need a backup will fail; set --state-backup-dir)", value, err)
		stateBackupDir = ""
		return nil
	}
	stateBackupDir = dir
	return nil
}

// checkStateBackupDir validates --state-backup-dir at startup and returns
// the path to use, its symlinks resolved so backups never go through a link
// someone could later repoint. On unix, every existing component of both
// the given and the resolved path must be a directory owned by root and not
// writable by group or other; a symlink is accepted only inside such a
// directory (as /var is on macOS). Components that do not exist yet are
// created 0700 by the first backup. The agent runs as root in production.
func checkStateBackupDir(dir string) (string, error) {
	if !statePathOK(dir) {
		return "", fmt.Errorf("must be an absolute, clean path other than /")
	}
	if err := checkRootOnlyPath(dir); err != nil {
		return "", err
	}
	real, err := resolveExisting(dir)
	if err != nil {
		return "", fmt.Errorf("resolve %s: %w", dir, err)
	}
	if err := checkRootOnlyPath(real); err != nil {
		return "", err
	}
	return real, nil
}

// checkRootOnlyPath walks the existing prefixes of p from the root, so each
// one's parent was checked before it.
func checkRootOnlyPath(p string) error {
	var prefixes []string
	for q := p; ; q = filepath.Dir(q) {
		prefixes = append([]string{q}, prefixes...)
		if filepath.Dir(q) == q {
			break
		}
	}
	for _, q := range prefixes {
		fi, err := os.Lstat(q)
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		if fi.Mode()&os.ModeSymlink != 0 {
			continue // its parent is root-only (checked), so is the link
		}
		if !fi.IsDir() {
			return fmt.Errorf("%s is not a directory", q)
		}
		if uid, _, ok := fileOwnerIDs(fi); ok {
			if uid != 0 {
				return fmt.Errorf("%s is not owned by root", q)
			}
			if fi.Mode().Perm()&0o022 != 0 {
				return fmt.Errorf("%s is writable by group or other", q)
			}
		}
	}
	return nil
}

// stateBackupKeep is how many backups are kept per path.
const stateBackupKeep = 5

// atomicReplaceMode replaces path, which fsGrantPath resolved under the
// grant root root, with data, mode and owner (-1 leaves an id as created):
// a fresh temp file in the same directory, opened beneath root, renamed over
// path (replaceBeneath). Unlike atomicReplace it sets the mode and owner it
// is given instead of keeping the old file's. mode may not carry setuid,
// setgid or sticky bits. Nothing is written beside path except the temp file,
// which is gone on success and on failure.
func atomicReplaceMode(root, path string, data []byte, mode os.FileMode, uid, gid int) error {
	if mode&^os.ModePerm != 0 {
		return fmt.Errorf("atomic replace: mode %v not allowed", mode)
	}
	if err := replaceBeneath(root, path, data, mode, uid, gid); err != nil {
		return fmt.Errorf("atomic replace: %w", err)
	}
	return nil
}

// replaceTempName is a random hidden temp name beside base.
func replaceTempName(base string) (string, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("temp name: %w", err)
	}
	return "." + base + ".systemapi-" + hex.EncodeToString(b[:]) + ".tmp", nil
}

// backupOutside stores data, the current content of path, as
// stateBackupDir/<sha256(path)>/<unix_ns> (created O_EXCL|O_NOFOLLOW, 0600)
// and keeps the newest stateBackupKeep there. It returns the basename.
func backupOutside(path string, data []byte) (string, error) {
	sum := sha256.Sum256([]byte(path))
	dir := filepath.Join(filepath.Clean(stateBackupDir), hex.EncodeToString(sum[:]))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	fi, err := os.Lstat(dir)
	if err != nil {
		return "", err
	}
	if !fi.IsDir() {
		return "", fmt.Errorf("backup dir is not a directory")
	}
	if fi.Mode().Perm() != 0o700 {
		if err := os.Chmod(dir, 0o700); err != nil {
			return "", err
		}
	}
	ts := time.Now().UnixNano()
	for i := int64(0); i < 16; i++ {
		name := strconv.FormatInt(ts+i, 10)
		dst := filepath.Join(dir, name)
		f, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL|openNoFollow, 0o600)
		if errors.Is(err, fs.ErrExist) {
			continue
		}
		if err != nil {
			return "", err
		}
		if _, err := f.Write(data); err != nil {
			_ = f.Close()
			_ = os.Remove(dst)
			return "", err
		}
		if err := f.Sync(); err != nil {
			_ = f.Close()
			_ = os.Remove(dst)
			return "", err
		}
		if err := f.Close(); err != nil {
			_ = os.Remove(dst)
			return "", err
		}
		if err := pruneBackups(dir, stateBackupKeep); err != nil {
			return "", fmt.Errorf("prune: %w", err)
		}
		return name, nil
	}
	return "", fmt.Errorf("no free backup name")
}

// pruneBackups removes all but the newest keep backups (regular files named
// by digits) in dir.
func pruneBackups(dir string, keep int) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	type stamped struct {
		name string
		ts   int64
	}
	var all []stamped
	for _, e := range entries {
		if !e.Type().IsRegular() || !backupSuffixRE.MatchString(e.Name()) {
			continue
		}
		ts, err := strconv.ParseInt(e.Name(), 10, 64)
		if err != nil {
			continue
		}
		all = append(all, stamped{e.Name(), ts})
	}
	sort.Slice(all, func(i, j int) bool { return all[i].ts < all[j].ts })
	for len(all) > keep {
		if err := os.Remove(filepath.Join(dir, all[0].name)); err != nil {
			return err
		}
		all = all[1:]
	}
	return nil
}

// AtomicWrite safely replaces path with content:
//  1. Write content to a new random temp file beside path
//  2. If original exists: copy it to path + ".bak." + unix-nanoseconds
//  3. os.Rename(tmp, path) - atomic on same filesystem
//  4. On any failure: remove tmp, return error (backup preserved)
func (cm *ConfigManager) AtomicWrite(path, content string) error {
	if _, err := os.Lstat(path); err == nil {
		if _, err := cm.BackupConfig(path); err != nil {
			return fmt.Errorf("atomic write: backup: %w", err)
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("atomic write: %w", err)
	}
	if err := atomicReplace(path, []byte(content)); err != nil {
		return fmt.Errorf("atomic write: %w", err)
	}
	return nil
}

// atomicReplace writes data to a fresh temp file beside path and renames it
// over path. The new file keeps the mode and owner of the regular file it
// replaces (a new file, or one replacing a symlink, is 0644 and owned by the
// agent), so restoring a 0600 secret does not make it readable.
func atomicReplace(path string, data []byte) error {
	mode := os.FileMode(0o644)
	uid, gid, chown := 0, 0, false
	if fi, err := os.Lstat(path); err == nil && fi.Mode().IsRegular() {
		mode = fi.Mode().Perm()
		uid, gid, chown = fileOwnerIDs(fi)
	} else if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".systemapi-*.tmp")
	if err != nil {
		return fmt.Errorf("create tmp: %w", err)
	}
	tmp := f.Name()
	fail := func(err error) error {
		_ = f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if chown {
		if err := f.Chown(uid, gid); err != nil {
			return fail(fmt.Errorf("chown tmp: %w", err))
		}
	}
	if err := f.Chmod(mode); err != nil {
		return fail(fmt.Errorf("chmod tmp: %w", err))
	}
	if _, err := f.Write(data); err != nil {
		return fail(fmt.Errorf("write tmp: %w", err))
	}
	if err := f.Sync(); err != nil {
		return fail(fmt.Errorf("sync tmp: %w", err))
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("close tmp: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("rename: %w", err)
	}
	return nil
}

// BackupConfig copies path to path + ".bak." + unix-nanoseconds. Returns the
// backup path.
func (cm *ConfigManager) BackupConfig(path string) (string, error) {
	backupPath := fmt.Sprintf("%s.bak.%d", path, time.Now().UnixNano())
	if err := copyFile(path, backupPath); err != nil {
		return "", err
	}
	return backupPath, nil
}

// RestoreConfig restores the newest path.bak.<digits> regular file over path
// with atomicReplace. A newest candidate that is not a regular file refuses.
func (cm *ConfigManager) RestoreConfig(path string) error {
	dir, base := filepath.Dir(path), filepath.Base(path)+".bak."
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("restore: %w", err)
	}
	latest, latestTS := "", int64(-1)
	for _, e := range entries {
		suffix, ok := strings.CutPrefix(e.Name(), base)
		if !ok || !backupSuffixRE.MatchString(suffix) {
			continue
		}
		ts, err := strconv.ParseInt(suffix, 10, 64)
		if err != nil {
			continue
		}
		if len(suffix) <= 10 { // seconds from an older agent
			ts *= int64(time.Second)
		}
		if ts > latestTS {
			latest, latestTS = e.Name(), ts
		}
	}
	if latest == "" {
		return fmt.Errorf("restore: no backup found for %s", path)
	}
	data, err := readFileCappedLinks(filepath.Join(dir, latest), hostFileCap, true)
	if err != nil {
		return fmt.Errorf("restore: read backup: %w", err)
	}
	if err := atomicReplace(path, []byte(data)); err != nil {
		return fmt.Errorf("restore: %w", err)
	}
	return nil
}

// RenderTemplate renders a named embedded template with the given vars map.
// name must match a file in templates/ without the .tmpl extension.
// The "default" function is provided via FuncMap since text/template has no built-in default.
func (cm *ConfigManager) RenderTemplate(name string, vars map[string]interface{}) (string, error) {
	tmplPath := "templates/" + name + ".tmpl"
	data, err := embeddedTemplates.ReadFile(tmplPath)
	if err != nil {
		return "", fmt.Errorf("template %q not found: %w", name, err)
	}

	tmpl, err := template.New(name).
		Funcs(template.FuncMap{
			"default": func(def, val interface{}) interface{} {
				if val == nil || val == "" || val == 0 {
					return def
				}
				return val
			},
			// toYAMLList renders a []interface{} as inline YAML list: ["a", "b"]
			"toYAMLList": func(v interface{}) string {
				items, ok := v.([]interface{})
				if !ok || len(items) == 0 {
					return "[]"
				}
				var b bytes.Buffer
				b.WriteString("[")
				for i, item := range items {
					if i > 0 {
						b.WriteString(", ")
					}
					b.WriteString(fmt.Sprintf("%q", fmt.Sprintf("%v", item)))
				}
				b.WriteString("]")
				return b.String()
			},
		}).
		Option("missingkey=zero").
		Parse(string(data))
	if err != nil {
		return "", fmt.Errorf("template parse error: %w", err)
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, vars); err != nil {
		return "", fmt.Errorf("template render error: %w", err)
	}
	return buf.String(), nil
}

// copyFile copies the regular file src (capped at hostFileCap) to a new
// file dst, created O_EXCL|O_NOFOLLOW with mode 0600 so a planted name is
// never written through.
func copyFile(src, dst string) error {
	data, err := readFileCappedLinks(src, hostFileCap, true)
	if err != nil {
		return err
	}
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL|openNoFollow, 0o600)
	if err != nil {
		return err
	}
	if _, err := out.WriteString(data); err != nil {
		_ = out.Close()
		_ = os.Remove(dst)
		return err
	}
	return out.Close()
}
