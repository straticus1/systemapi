// Threats: a terminal session whose input or output is not recorded, a
// recording edited after the fact, and a recorder that silently drops bytes
// when it falls behind. Each session gets its own append-only file in a
// directory owned by the agent (mode 0700). Every line carries an
// HMAC-SHA256 over the previous line's MAC and its own fields, keyed by a
// 32-byte CSPRNG key in a 0600 file only the agent can read, so an edit,
// deletion or reorder breaks the chain. The final MAC (the digest) goes to
// the control plane in pty_exit and lands in the audit chain. Writes are
// queued with a byte cap; a full queue or a failed write ends the session
// (fail closed). A session is capped at --pty-record-max-bytes recorded bytes
// (ended with record_error recording_size_limit), and a session does not
// start when the recording filesystem has less than --pty-record-min-free. Does NOT protect against the agent's own user (root, or the
// agent user when --pty-allow-agent-user is set), who holds the key; does
// NOT set the filesystem append-only attribute.
package main

import (
	"bufio"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

const recordingKeyFile = "recording.key"

const (
	recordMaxBytesDefault = int64(1) << 30
	recordMinFreeDefault  = uint64(1) << 30

	recordErrFailed    = "recording_failed"
	recordErrSizeLimit = "recording_size_limit"
)

var (
	// recordQueueMax caps bytes waiting to be written to one recording.
	recordQueueMax = 4 * 1024 * 1024

	recKeyMu sync.Mutex
	recKey   []byte
)

type recEntry struct {
	kind string
	t    int64
	data []byte
}

type recLine struct {
	Seq  uint64 `json:"seq"`
	T    int64  `json:"t"`
	Kind string `json:"k"`
	B64  string `json:"b64"`
	MAC  string `json:"mac"`
}

type recorder struct {
	key  []byte
	path string
	f    *os.File
	ch   chan recEntry
	done chan struct{}

	mu       sync.Mutex
	queued   int
	closed   bool
	failed   bool
	bytesIn  int64
	bytesOut int64
	maxBytes int64
	onFail   func(code string)

	// Owned by the writer goroutine until done is closed.
	prev string
	seq  uint64
	err  error
}

// loadRecordingKey reads, or creates once, the agent's recording key. The
// file must be a regular 0600 file owned by the agent's uid.
func loadRecordingKey(stateDir string) ([]byte, error) {
	recKeyMu.Lock()
	defer recKeyMu.Unlock()
	if recKey != nil {
		return recKey, nil
	}
	path := filepath.Join(stateDir, recordingKeyFile)
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err == nil {
		key := make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			_ = f.Close()
			_ = os.Remove(path)
			return nil, err
		}
		_, werr := f.WriteString(hex.EncodeToString(key) + "\n")
		cerr := f.Close()
		if werr != nil || cerr != nil {
			_ = os.Remove(path)
			return nil, errors.New("recording_key_write_failed")
		}
		recKey = key
		return key, nil
	}
	if !os.IsExist(err) {
		return nil, err
	}
	key, err := readRecordingKey(path)
	if err != nil {
		return nil, err
	}
	recKey = key
	return key, nil
}

// readRecordingKey reads a recording key file that must be a 0600 regular
// file owned by the caller's uid.
func readRecordingKey(path string) ([]byte, error) {
	if err := checkPrivateFile(path, uint32(os.Geteuid())); err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	key, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil || len(key) != 32 {
		return nil, errors.New("recording_key_malformed")
	}
	return key, nil
}

func resetRecordingKeyCache() {
	recKeyMu.Lock()
	recKey = nil
	recKeyMu.Unlock()
}

func recordingSeed(key []byte, sessionID string) string {
	m := hmac.New(sha256.New, key)
	m.Write([]byte("systemapi-recording-v1\n" + sessionID))
	return hex.EncodeToString(m.Sum(nil))
}

func recordingMAC(key []byte, prev string, seq uint64, t int64, kind, b64 string) string {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(prev + "\n" + strconv.FormatUint(seq, 10) + "\n" + strconv.FormatInt(t, 10) + "\n" + kind + "\n" + b64))
	return hex.EncodeToString(m.Sum(nil))
}

// openRecorder creates <dir>/<session_id>.rec and writes the header line
// synchronously, so a session never starts with a recording that cannot be
// written.
// maxBytes caps the session's recorded bytes; minFree is the free space the
// recording filesystem must have at start.
func openRecorder(dir, sessionID string, key []byte, header map[string]interface{}, maxBytes int64, minFree uint64, onFail func(code string)) (*recorder, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	if err := checkRealDir(dir, uint32(os.Geteuid())); err != nil {
		return nil, err
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return nil, err
	}
	free, err := freeBytes(dir)
	if err != nil {
		return nil, err
	}
	if free < minFree {
		return nil, errors.New("recording_disk_low")
	}
	path := filepath.Join(dir, sessionID+".rec")
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|os.O_APPEND, 0o600)
	if err != nil {
		return nil, err
	}
	r := &recorder{
		key:      key,
		path:     path,
		f:        f,
		ch:       make(chan recEntry, 8192),
		done:     make(chan struct{}),
		prev:     recordingSeed(key, sessionID),
		maxBytes: maxBytes,
		onFail:   onFail,
	}
	meta, _ := json.Marshal(header)
	if err := r.writeLine(recEntry{kind: "start", t: time.Now().UnixMilli(), data: meta}); err != nil {
		_ = f.Close()
		return nil, err
	}
	go r.loop()
	return r, nil
}

func (r *recorder) writeLine(e recEntry) error {
	r.seq++
	b64 := base64.StdEncoding.EncodeToString(e.data)
	mac := recordingMAC(r.key, r.prev, r.seq, e.t, e.kind, b64)
	line, err := json.Marshal(recLine{Seq: r.seq, T: e.t, Kind: e.kind, B64: b64, MAC: mac})
	if err != nil {
		return err
	}
	if _, err := r.f.Write(append(line, '\n')); err != nil {
		return err
	}
	r.prev = mac
	return nil
}

func (r *recorder) loop() {
	defer close(r.done)
	for e := range r.ch {
		if r.err == nil {
			if err := r.writeLine(e); err != nil {
				r.err = err
				r.fail(recordErrFailed)
			}
		}
		r.mu.Lock()
		r.queued -= len(e.data)
		r.mu.Unlock()
	}
}

func (r *recorder) fail(code string) {
	r.mu.Lock()
	first := !r.failed
	r.failed = true
	cb := r.onFail
	r.mu.Unlock()
	if first && cb != nil {
		cb(code)
	}
}

// add queues bytes without blocking. kind is "i" (input) or "o" (output).
// It returns false, and ends the session through onFail, when the queue is
// full; bytes are never dropped silently.
func (r *recorder) add(kind string, data []byte) bool {
	if len(data) == 0 {
		return true
	}
	r.mu.Lock()
	if r.closed || r.failed {
		r.mu.Unlock()
		return false
	}
	if r.queued+len(data) > recordQueueMax {
		r.mu.Unlock()
		r.fail(recordErrFailed)
		return false
	}
	if r.bytesIn+r.bytesOut+int64(len(data)) > r.maxBytes {
		r.mu.Unlock()
		r.fail(recordErrSizeLimit)
		return false
	}
	e := recEntry{kind: kind, t: time.Now().UnixMilli(), data: append([]byte(nil), data...)}
	select {
	case r.ch <- e:
	default:
		r.mu.Unlock()
		r.fail(recordErrFailed)
		return false
	}
	r.queued += len(data)
	if kind == "i" {
		r.bytesIn += int64(len(data))
	} else {
		r.bytesOut += int64(len(data))
	}
	r.mu.Unlock()
	return true
}

type recSummary struct {
	Path     string `json:"path"`
	Digest   string `json:"digest"`
	BytesIn  int64  `json:"bytes_in"`
	BytesOut int64  `json:"bytes_out"`
}

// finish drains the queue, writes the end line, and returns the final MAC.
func (r *recorder) finish(meta map[string]interface{}) (recSummary, error) {
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return recSummary{}, errors.New("recorder_closed")
	}
	r.closed = true
	r.mu.Unlock()
	close(r.ch)
	<-r.done
	err := r.err
	if err == nil {
		raw, _ := json.Marshal(meta)
		err = r.writeLine(recEntry{kind: "end", t: time.Now().UnixMilli(), data: raw})
	}
	if err == nil {
		err = r.f.Sync()
	}
	if cerr := r.f.Close(); err == nil {
		err = cerr
	}
	r.mu.Lock()
	sum := recSummary{Path: r.path, Digest: r.prev, BytesIn: r.bytesIn, BytesOut: r.bytesOut}
	failed := r.failed
	r.mu.Unlock()
	if err == nil && failed {
		err = errors.New(recordErrFailed)
	}
	return sum, err
}

// verifyRecording replays the chain of one recording and returns its final
// MAC. Any edit, deletion, insertion or reorder is an error, and so is a file
// that does not start with the session's start line or end with an end line
// (a truncated or still-open recording).
func verifyRecording(path string, key []byte, sessionID string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	prev := recordingSeed(key, sessionID)
	var seq uint64
	last := ""
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	for sc.Scan() {
		var l recLine
		if err := json.Unmarshal(sc.Bytes(), &l); err != nil {
			return "", errors.New("recording_malformed")
		}
		seq++
		if l.Seq != seq {
			return "", errors.New("recording_sequence_broken")
		}
		want := recordingMAC(key, prev, l.Seq, l.T, l.Kind, l.B64)
		if !hmac.Equal([]byte(want), []byte(l.MAC)) {
			return "", errors.New("recording_mac_mismatch")
		}
		if seq == 1 {
			if l.Kind != "start" {
				return "", errors.New("recording_no_start")
			}
			raw, err := base64.StdEncoding.DecodeString(l.B64)
			var meta struct {
				SessionID string `json:"session_id"`
			}
			if err != nil || json.Unmarshal(raw, &meta) != nil || meta.SessionID != sessionID {
				return "", errors.New("recording_session_mismatch")
			}
		} else if last == "end" {
			return "", errors.New("recording_data_after_end")
		}
		prev = l.MAC
		last = l.Kind
	}
	if err := sc.Err(); err != nil {
		return "", err
	}
	if seq == 0 {
		return "", errors.New("recording_empty")
	}
	if last != "end" {
		return "", errors.New("recording_truncated")
	}
	return prev, nil
}

// runVerifyRecording implements `systemapi-agent verify-recording <file>
// [--digest HEX] [--key PATH]`. It returns the process exit code: 0 when the
// chain is valid, complete, and matches --digest if given; 1 otherwise; 2 on
// bad usage.
func runVerifyRecording(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("verify-recording", flag.ContinueOnError)
	fs.SetOutput(stderr)
	digest := fs.String("digest", "", "expected final digest (hex), e.g. from the terminal_end audit row")
	keyPath := fs.String("key", "", "recording key (default: beside --state, else ~/.systemapi/"+recordingKeyFile+")")
	statePath := fs.String("state", "", "the agent's --state file; the key is "+recordingKeyFile+" in the same directory")
	var file string
	rest := args
	for {
		if err := fs.Parse(rest); err != nil {
			return 2
		}
		if fs.NArg() == 0 {
			break
		}
		if file != "" {
			fmt.Fprintln(stderr, "usage: systemapi-agent verify-recording <file> [--digest HEX] [--key PATH | --state PATH]")
			return 2
		}
		file = fs.Arg(0)
		rest = fs.Args()[1:]
	}
	if file == "" {
		fmt.Fprintln(stderr, "usage: systemapi-agent verify-recording <file> [--digest HEX] [--key PATH | --state PATH]")
		return 2
	}
	if *keyPath != "" && *statePath != "" {
		fmt.Fprintln(stderr, "usage: pass --key or --state, not both")
		return 2
	}
	if *keyPath == "" && *statePath != "" {
		*keyPath = filepath.Join(filepath.Dir(*statePath), recordingKeyFile)
	}
	if *keyPath == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			fmt.Fprintf(stderr, "FAIL: %v\n", err)
			return 1
		}
		*keyPath = filepath.Join(home, ".systemapi", recordingKeyFile)
	}
	key, err := readRecordingKey(*keyPath)
	if err != nil {
		fmt.Fprintf(stderr, "FAIL: recording key: %v\n", err)
		return 1
	}
	sessionID := strings.TrimSuffix(filepath.Base(file), ".rec")
	if !sessionIDRe.MatchString(sessionID) {
		fmt.Fprintln(stderr, "FAIL: file name is not <session_id>.rec")
		return 1
	}
	got, err := verifyRecording(file, key, sessionID)
	if err != nil {
		fmt.Fprintf(stderr, "FAIL: %v\n", err)
		return 1
	}
	if *digest != "" {
		want := strings.ToLower(strings.TrimSpace(*digest))
		if !hashHexRe.MatchString(want) || subtle.ConstantTimeCompare([]byte(want), []byte(got)) != 1 {
			fmt.Fprintf(stderr, "FAIL: digest mismatch: recording %s\n", got)
			return 1
		}
	}
	fmt.Fprintf(stdout, "ok %s digest=%s\n", sessionID, got)
	return 0
}
