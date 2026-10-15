// Interrupted file-channel uploads (docs/sah-file-protocol.md §6 "Resume").
// A record per upload lives in the agent's state directory
// (<state dir>/file-uploads/<upload_id>.json, 0600 in a 0700 directory),
// never in the target tree; the bytes stay in the upload's reserved
// .sahsync-<upload_id>.part temp file beside the target, which §5.5 places in
// the target's parent directory so the commit can be an atomic rename.
// Records are keyed by actor (hashed), host (this agent), canonical root,
// path, size and sha256, and expire after 24 h: an expired record's temp file
// is unlinked and the record deleted.
// Threats: one actor resuming another actor's upload (the key includes the
// actor, which the server sends on file_open), two sessions writing one temp
// file (an upload in use by a live session is not resumable), a crafted
// record file steering a deletion (records are size-capped, every field is
// re-validated, and deletion resolves the root and parent like a helper and
// unlinks only the reserved temp name), and unbounded growth (24 h expiry,
// swept at every file session start and hourly; at most 16 live uploads per
// actor and root; a write that fails through the client's fault discards its
// temp file and record instead of keeping them for resume). Does NOT encrypt records (they hold
// paths and hashes, no content) and does NOT survive the state directory
// being deleted (the temp files then expire only by hand).
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
	"time"
)

const (
	uploadTTL       = 24 * time.Hour
	uploadRecordMax = 16 * 1024
	uploadDirName   = "file-uploads"
	// uploadsPerActorRoot caps the live uploads (interrupted or open) one
	// actor may hold under one root; a new write_open past it gets no_space.
	uploadsPerActorRoot = 16
)

// uploadSweepEvery is how often the running agent sweeps expired uploads, in
// addition to every file session start.
var uploadSweepEvery = time.Hour

type uploadRecord struct {
	UploadID    string `json:"upload_id"`
	ActorKey    string `json:"actor_key"`
	Root        string `json:"root"`
	Path        string `json:"path"`
	Size        int64  `json:"size"`
	SHA256      string `json:"sha256"`
	CreatedUnix int64  `json:"created_unix"`
}

var (
	uploadsMu     sync.Mutex
	activeUploads = map[string]bool{}
)

func actorKey(actor string) string {
	sum := sha256.Sum256([]byte("systemapi-file-actor\n" + actor))
	return hex.EncodeToString(sum[:])
}

func uploadsDir(stateDir string) string {
	return filepath.Join(stateDir, uploadDirName)
}

func (r *uploadRecord) valid() bool {
	return uploadIDRe.MatchString(r.UploadID) && sha256HexRe.MatchString(r.ActorKey) &&
		(r.Root == "/" || strings.HasPrefix(r.Root, "/")) && checkFilePath(r.Path) == "" && r.Path != "." &&
		r.Size >= 0 && sha256HexRe.MatchString(r.SHA256) && r.CreatedUnix > 0
}

func saveUpload(stateDir string, rec uploadRecord) error {
	if !rec.valid() {
		return errors.New("bad_record")
	}
	dir := uploadsDir(stateDir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return err
	}
	raw, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	final := filepath.Join(dir, rec.UploadID+".json")
	tmp := final + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(raw); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, final)
}

func deleteUpload(stateDir, id string) {
	if !uploadIDRe.MatchString(id) {
		return
	}
	_ = os.Remove(filepath.Join(uploadsDir(stateDir), id+".json"))
}

func loadUploads(stateDir string) []uploadRecord {
	dir := uploadsDir(stateDir)
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []uploadRecord
	for _, e := range ents {
		name := e.Name()
		if !e.Type().IsRegular() || !strings.HasSuffix(name, ".json") {
			continue
		}
		f, err := os.Open(filepath.Join(dir, name))
		if err != nil {
			continue
		}
		raw, err := io.ReadAll(io.LimitReader(f, uploadRecordMax+1))
		_ = f.Close()
		if err != nil || len(raw) > uploadRecordMax {
			continue
		}
		var rec uploadRecord
		if json.Unmarshal(raw, &rec) != nil || !rec.valid() || name != rec.UploadID+".json" {
			continue
		}
		out = append(out, rec)
	}
	return out
}

// claimUpload marks an upload in use by a live session; false when another
// session holds it.
func claimUpload(id string) bool {
	uploadsMu.Lock()
	defer uploadsMu.Unlock()
	if activeUploads[id] {
		return false
	}
	activeUploads[id] = true
	return true
}

func unclaimUpload(id string) {
	uploadsMu.Lock()
	delete(activeUploads, id)
	uploadsMu.Unlock()
}

// findUpload returns a live, unclaimed upload with this exact key, claimed
// for the caller, or nil.
func findUpload(stateDir, actor, root, path string, size int64, sha string, now time.Time) *uploadRecord {
	key := actorKey(actor)
	for _, rec := range loadUploads(stateDir) {
		if !hashEqual(rec.ActorKey, key) || rec.Root != root || rec.Path != path || rec.Size != size || !hashEqual(rec.SHA256, sha) {
			continue
		}
		if now.Sub(time.Unix(rec.CreatedUnix, 0)) >= uploadTTL {
			continue
		}
		if !claimUpload(rec.UploadID) {
			continue
		}
		r := rec
		return &r
	}
	return nil
}

// countUploads returns how many live (unexpired) upload records this actor
// holds under this root, claimed or not.
func countUploads(stateDir, actor, root string, now time.Time) int {
	key := actorKey(actor)
	n := 0
	for _, rec := range loadUploads(stateDir) {
		if hashEqual(rec.ActorKey, key) && rec.Root == root && now.Sub(time.Unix(rec.CreatedUnix, 0)) < uploadTTL {
			n++
		}
	}
	return n
}

var (
	uploadSweeperOnce sync.Once
	// uploadSweeperRun is the sweeper loop; a test swaps it to count starts.
	uploadSweeperRun = runUploadSweeper
)

// startUploadSweeper sweeps expired uploads every uploadSweepEvery for the
// life of the process, so temp files of an agent that sees no new file
// session still expire. It runs once per process.
func startUploadSweeper(stateDir string) {
	if stateDir == "" {
		return
	}
	uploadSweeperOnce.Do(func() {
		go uploadSweeperRun(stateDir, uploadSweepEvery, nil, removeUploadTemp)
	})
}

func runUploadSweeper(stateDir string, every time.Duration, stop <-chan struct{}, remove func(root, path, id string) error) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case now := <-t.C:
			sweepUploads(stateDir, now, remove)
		}
	}
}

// sweepUploads deletes every expired, unclaimed upload: its temp file
// (through remove) and then its record. A record whose temp file cannot be
// removed is kept for the next sweep unless the root itself is gone.
func sweepUploads(stateDir string, now time.Time, remove func(root, path, id string) error) int {
	n := 0
	for _, rec := range loadUploads(stateDir) {
		if now.Sub(time.Unix(rec.CreatedUnix, 0)) < uploadTTL {
			continue
		}
		if !claimUpload(rec.UploadID) {
			continue
		}
		err := remove(rec.Root, rec.Path, rec.UploadID)
		if err == nil || errors.Is(err, errFileUnsupported) || err.Error() == "root_invalid" || err.Error() == "not_found" || err.Error() == "bad_record" {
			deleteUpload(stateDir, rec.UploadID)
			n++
		}
		unclaimUpload(rec.UploadID)
	}
	return n
}
