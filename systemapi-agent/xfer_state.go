// Xfer state records (sahxfer end-to-end plan, step 6 and "Agent restart
// mid-transfer"). One record per running recv, written (and its directory
// fsynced) before the spawn and removed once the result has been written to
// a connection, so a restarted agent knows which temp files to sweep and
// which grants to report. Threats: a record that leaks the transfer key (it
// holds only the grant id, transfer id, action, root, path, size, the
// grant's sha256, identity and, once known, the result payload; never the
// key, the route token or the material hash), a record readable by other
// users (directory 0700, files 0600), a record naming another file (the
// sweep passes only root, path and grant id to `recv --sweep`, which removes
// the one temp name fixed by the grant id), and a record whose identity no
// longer matches the configuration (the sweep runs only as the identity
// resolveFileIdentity gives today for the record's actor, and only when it
// equals the record's).
// A restarted agent reports ok only when `recv --sweep --report` finds the
// target holding the grant's size and hash, aborted agent_restart with
// committed false when the target is absent or different, and nothing at
// all when the check cannot run, so the server's tombstone records the
// grant as unknown rather than unchanged. Delivery is at most once per
// connection: a frame written to a socket that then dies is lost and the
// server records unknown; a result re-sent after a restart reaches a server
// that ignores grant ids it no longer holds, so it must stay idempotent on
// grant_id. Does NOT authenticate records: the state directory is the
// agent's own.
package main

import (
	"encoding/json"
	"errors"
	"io"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type xferRecordIdentity struct {
	Name   string   `json:"name"`
	UID    uint32   `json:"uid"`
	GID    uint32   `json:"gid"`
	Groups []uint32 `json:"groups,omitempty"`
	Home   string   `json:"home"`
	Drop   bool     `json:"drop"`
}

type xferRecord struct {
	GrantID     string                 `json:"grant_id"`
	TransferID  string                 `json:"transfer_id"`
	Action      string                 `json:"action"`
	Root        string                 `json:"root"`
	Path        string                 `json:"path"`
	Size        int64                  `json:"size"`
	SHA256      string                 `json:"sha256"`
	Identity    xferRecordIdentity     `json:"identity"`
	Actor       string                 `json:"actor,omitempty"`
	CreatedUnix int64                  `json:"created_unix"`
	Result      map[string]interface{} `json:"result,omitempty"`
}

func recordIdentity(id *ptyIdentity) xferRecordIdentity {
	return xferRecordIdentity{Name: id.name, UID: id.uid, GID: id.gid, Groups: id.groups, Home: id.home, Drop: id.drop}
}

func (r xferRecordIdentity) identity() *ptyIdentity {
	return &ptyIdentity{name: r.Name, uid: r.UID, gid: r.GID, groups: r.Groups, home: r.Home, drop: r.Drop}
}

func xferRecordsDir(stateDir string) string { return filepath.Join(stateDir, "xfer") }

func xferRecordPath(stateDir, gid string) string {
	return filepath.Join(xferRecordsDir(stateDir), gid+".json")
}

func saveXferRecord(stateDir string, rec xferRecord) error {
	if stateDir == "" || !xferGrantRe.MatchString(rec.GrantID) {
		return errors.New("bad_record")
	}
	dir := xferRecordsDir(stateDir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return err
	}
	blob, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	path := xferRecordPath(stateDir, rec.GrantID)
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(blob); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	return syncDir(dir)
}

// syncDir makes a rename or unlink in dir durable.
func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

func loadXferRecord(stateDir, gid string) (xferRecord, error) {
	var rec xferRecord
	blob, err := os.ReadFile(xferRecordPath(stateDir, gid))
	if err != nil {
		return rec, err
	}
	if err := json.Unmarshal(blob, &rec); err != nil {
		return rec, err
	}
	if rec.GrantID != gid {
		return rec, errors.New("bad_record")
	}
	return rec, nil
}

// saveXferResult adds the result payload to an existing record.
func saveXferResult(stateDir, gid string, payload map[string]interface{}) error {
	rec, err := loadXferRecord(stateDir, gid)
	if err != nil {
		return err
	}
	rec.Result = payload
	return saveXferRecord(stateDir, rec)
}

func removeXferRecord(stateDir, gid string) {
	if stateDir == "" || !xferGrantRe.MatchString(gid) {
		return
	}
	if err := os.Remove(xferRecordPath(stateDir, gid)); err != nil {
		if !os.IsNotExist(err) {
			log.Printf("xfer %s: state record not removed: %v", gid, err)
		}
		return
	}
	_ = syncDir(xferRecordsDir(stateDir))
}

// loadXferRecords lists the well-formed records in stateDir.
func loadXferRecords(stateDir string) []xferRecord {
	entries, err := os.ReadDir(xferRecordsDir(stateDir))
	if err != nil {
		return nil
	}
	var out []xferRecord
	for _, e := range entries {
		gid, ok := strings.CutSuffix(e.Name(), ".json")
		if !ok || !e.Type().IsRegular() || !xferGrantRe.MatchString(gid) {
			continue
		}
		rec, err := loadXferRecord(stateDir, gid)
		if err != nil || !xferRootOK(rec.Root) || !xferPathOK(rec.Path) {
			log.Printf("xfer %s: unreadable state record skipped", gid)
			continue
		}
		out = append(out, rec)
	}
	return out
}

// sweepXferRecords runs once at startup, in the background: a record with
// a result is reported as is; any other means recv was interrupted, so
// `recv --sweep --report` removes its temp file as the record's identity
// and reports the target, and the grant is reported ok (the target holds
// the grant's size and hash) or aborted agent_restart committed false. A
// record that cannot be checked is kept, retried on the next start, and not
// reported, so the server's tombstone records it as unknown. Results found
// before the first connection enrolls wait in the queue; later ones go out
// at once.
func (m *xferManager) sweepXferRecords() {
	stateDir := m.recordDir("")
	if stateDir == "" {
		return
	}
	for _, rec := range loadXferRecords(stateDir) {
		if rec.Result != nil {
			m.deliver(xferQueued{grantID: rec.GrantID, payload: rec.Result, recordDir: stateDir})
			continue
		}
		payload, err := checkInterrupted(rec)
		if err != nil {
			log.Printf("xfer %s: interrupted transfer not checked (%v); kept for the next start, outcome unknown", rec.GrantID, err)
			continue
		}
		log.Printf("xfer %s: reporting %v after restart", rec.GrantID, payload["status"])
		m.deliver(xferQueued{grantID: rec.GrantID, payload: payload, recordDir: stateDir})
	}
}

// checkInterrupted sweeps one record and decides its result.
func checkInterrupted(rec xferRecord) (map[string]interface{}, error) {
	if !xferAvailable() {
		return nil, errors.New("xfer is not configured")
	}
	if !hashHexRe.MatchString(rec.SHA256) || rec.Size < 0 {
		return nil, errors.New("record has no grant hash")
	}
	id, err := sweepIdentity(rec)
	if err != nil {
		return nil, err
	}
	target, err := runXferSweep(rec, xferCfg.bin, id)
	if err != nil {
		return nil, err
	}
	if target != nil && target.Bytes == rec.Size && target.SHA256 == rec.SHA256 {
		return map[string]interface{}{"status": "ok", "reason": "agent_restart", "bytes": rec.Size,
			"sha256": rec.SHA256, "committed": true}, nil
	}
	return map[string]interface{}{"status": "aborted", "reason": "agent_restart", "bytes": 0, "committed": false}, nil
}

// sweepIdentity resolves the identity the record's action runs as today
// and requires it to equal the recorded one.
func sweepIdentity(rec xferRecord) (*ptyIdentity, error) {
	action := ""
	switch rec.Action {
	case "xfer":
		action = "file"
	case "xfer_root":
		action = "file_root"
	default:
		return nil, errors.New("record has a bad action")
	}
	id, code := resolveFileIdentity(action, rec.Actor, ptyCfg, agentEUID())
	if code != "" {
		return nil, errors.New("identity: " + code)
	}
	r := rec.Identity
	if id.uid != r.UID || id.gid != r.GID || id.drop != r.Drop || !sameGroups(id.groups, r.Groups) {
		return nil, errors.New("the recorded identity differs from the configured one")
	}
	return id, nil
}

func sameGroups(a, b []uint32) bool {
	if len(a) != len(b) {
		return false
	}
	x := append([]uint32(nil), a...)
	y := append([]uint32(nil), b...)
	sort.Slice(x, func(i, j int) bool { return x[i] < x[j] })
	sort.Slice(y, func(i, j int) bool { return y[i] < y[j] })
	for i := range x {
		if x[i] != y[i] {
			return false
		}
	}
	return true
}

// xferSweepTarget is the line `recv --sweep --report` writes for a target
// that is a regular file.
type xferSweepTarget struct {
	Ev     string `json:"ev"`
	Bytes  int64  `json:"bytes"`
	SHA256 string `json:"sha256"`
}

// runXferSweep starts `recv --sweep --report --ctl-fd 3 --event-fd 4` as id,
// hands it {root, path, grant_id}, and returns the target it reports (nil
// when absent). Any failure is an error: the outcome is then unknown.
func runXferSweep(rec xferRecord, bin string, id *ptyIdentity) (*xferSweepTarget, error) {
	exe, release, err := openXferBin(bin, os.Geteuid())
	if err != nil {
		return nil, err
	}
	defer release()
	cmd, err := startXferProc(id, exe, "recv", "--sweep", "--report", "--ctl-fd", "3", "--event-fd", "4")
	if err != nil {
		return nil, err
	}
	cmd.Args[0] = "sahxfer"
	cmd.WaitDelay = xferWaitDelay
	ctlR, ctlW, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	evR, evW, err := os.Pipe()
	if err != nil {
		closeAll(ctlR, ctlW)
		return nil, err
	}
	defer evR.Close()
	cmd.ExtraFiles = []*os.File{ctlR, evW}
	if err := cmd.Start(); err != nil {
		closeAll(ctlR, ctlW, evW)
		return nil, err
	}
	closeAll(ctlR, evW)
	line, _ := json.Marshal(map[string]string{"root": rec.Root, "path": rec.Path, "grant_id": rec.GrantID})
	_ = ctlW.SetWriteDeadline(time.Now().Add(xferCtlTimeout))
	_, _ = ctlW.Write(append(line, '\n'))
	ctlW.Close()
	type read struct {
		b   []byte
		err error
	}
	got := make(chan read, 1)
	go func() {
		b, err := io.ReadAll(io.LimitReader(evR, 4096))
		got <- read{b, err}
	}()
	waited := make(chan error, 1)
	go func() { waited <- cmd.Wait() }()
	var werr error
	select {
	case werr = <-waited:
	case <-time.After(xferSweepTimeout):
		_ = cmd.Process.Kill()
		<-waited
		return nil, errors.New("sweep timed out")
	}
	if werr != nil {
		return nil, werr
	}
	var out read
	select {
	case out = <-got:
	case <-time.After(xferEventDrain):
		_ = evR.SetReadDeadline(time.Now())
		<-got
		return nil, errors.New("sweep fd 4 held open")
	}
	if out.err != nil {
		return nil, out.err
	}
	text := strings.TrimSpace(string(out.b))
	if text == "" {
		return nil, nil
	}
	var t xferSweepTarget
	dec := json.NewDecoder(strings.NewReader(text))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&t); err != nil || dec.More() || t.Ev != "target" || t.Bytes < 0 || !hashHexRe.MatchString(t.SHA256) {
		return nil, errors.New("bad sweep report")
	}
	return &t, nil
}
