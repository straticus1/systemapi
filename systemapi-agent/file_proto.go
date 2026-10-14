// File channel shared rules (docs/sah-file-protocol.md): the §5.1 path
// shape, reserved temp names, the write mode rule, and the internal framing
// between the agent and its file-helper child process.
// Threats: traversal and absolute escape through a request path (every path
// is checked here before any syscall: no leading "/", no empty, "." or ".."
// component, no NUL, C0, DEL or "\", valid UTF-8, 1-4096 bytes, components
// 1-255 bytes; nothing is decoded or normalized), a client addressing the
// agent's own temp files (.sahsync-*.part gives reserved_name), a mode that
// sets setuid, setgid or sticky (only 0600-0777 are accepted), and a helper
// or parent that sends an oversized frame to grow the other's memory (frames
// over helperFrameMax are refused and end the helper). Does NOT resolve
// anything on disk: symlinks and the root are the helper's job (§5.3-5.5).
package main

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

const (
	filePathMax       = 4096
	fileComponentMax  = 255
	fileChunkMax      = 1 << 20 // chunk_max
	fileReadMax       = 8 << 20 // read_max
	fileListMax       = 1000    // list_max
	fileListDefault   = 500
	fileWriteWindow   = 8
	fileReservedStart = ".sahsync-"
	fileReservedEnd   = ".part"
	// helperFrameMax bounds one frame on the helper pipes: a chunk, or a
	// list result of fileListMax entries.
	helperFrameMax = 4 << 20
)

var (
	fileModeRe         = regexp.MustCompile(`^0[67][0-7]{2}$`)
	uploadIDRe         = regexp.MustCompile(`^upl_[A-Za-z0-9_-]{16,64}$`)
	requestIDRe        = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
	sha256HexRe        = regexp.MustCompile(`^[0-9a-f]{64}$`)
	errFrameSize       = errors.New("frame_too_large")
	errFileUnsupported = errors.New("agent_unsupported")
)

// fileMutatingOps are refused on a read lease (read_only).
var fileMutatingOps = map[string]bool{
	"write_open": true, "write_chunk": true, "write_commit": true, "write_abort": true,
	"mkdir": true, "remove": true,
}

// fileKnownOps is every op of FILE §4.
var fileKnownOps = map[string]bool{
	"stat": true, "list": true, "read": true, "hash": true,
	"write_open": true, "write_chunk": true, "write_commit": true, "write_abort": true,
	"mkdir": true, "remove": true,
}

// reservedName reports a component of the form .sahsync-*.part.
func reservedName(c string) bool {
	return len(c) >= len(fileReservedStart)+len(fileReservedEnd) &&
		strings.HasPrefix(c, fileReservedStart) && strings.HasSuffix(c, fileReservedEnd)
}

// checkFilePath applies FILE §5.1 and §5.2 to a request path. It returns ""
// when the path is acceptable, else "bad_path" or "reserved_name". "." alone
// is the root.
func checkFilePath(p string) string {
	if len(p) == 0 || len(p) > filePathMax || !utf8.ValidString(p) {
		return "bad_path"
	}
	if p == "." {
		return ""
	}
	if p[0] == '/' {
		return "bad_path"
	}
	for i := 0; i < len(p); i++ {
		b := p[i]
		if b < 0x20 || b == 0x7f || b == '\\' {
			return "bad_path"
		}
	}
	reserved := false
	for _, c := range strings.Split(p, "/") {
		if c == "" || c == "." || c == ".." || len(c) > fileComponentMax {
			return "bad_path"
		}
		if reservedName(c) {
			reserved = true
		}
	}
	if reserved {
		return "reserved_name"
	}
	return ""
}

// splitFilePath returns the parent components and the final component of
// a checked path other than ".".
func splitFilePath(p string) ([]string, string) {
	parts := strings.Split(p, "/")
	return parts[:len(parts)-1], parts[len(parts)-1]
}

// parseFileMode parses an optional octal mode string "0600"-"0777".
// ok is false for anything else (setuid, setgid and sticky never parse).
func parseFileMode(s *string) (uint32, bool, bool) {
	if s == nil {
		return 0, false, true
	}
	if !fileModeRe.MatchString(*s) {
		return 0, false, false
	}
	v, err := strconv.ParseUint(*s, 8, 32)
	if err != nil {
		return 0, false, false
	}
	return uint32(v), true, true
}

func formatFileMode(perm uint32) string {
	s := strconv.FormatUint(uint64(perm&0o7777), 8)
	for len(s) < 4 {
		s = "0" + s
	}
	return s
}

// fileEntry is the entry shape of FILE §4.
type fileEntry struct {
	Name    string `json:"name"`
	Type    string `json:"type"`
	Size    int64  `json:"size"`
	Mode    string `json:"mode"`
	MtimeNS int64  `json:"mtime_ns"`
}

// fileIfMatch is the optional if_match of read and hash.
type fileIfMatch struct {
	Size    *int64 `json:"size"`
	MtimeNS *int64 `json:"mtime_ns"`
}

// fileReq is one request as the agent passes it to the helper. The server
// already checked the request shape; the helper checks it again.
type fileReq struct {
	Op        string       `json:"op"`
	RequestID string       `json:"request_id,omitempty"`
	Path      string       `json:"path,omitempty"`
	Cursor    *string      `json:"cursor,omitempty"`
	Limit     *int         `json:"limit,omitempty"`
	Offset    *int64       `json:"offset,omitempty"`
	Length    *int64       `json:"length,omitempty"`
	IfMatch   *fileIfMatch `json:"if_match,omitempty"`
	Size      *int64       `json:"size,omitempty"`
	SHA256    string       `json:"sha256,omitempty"`
	Overwrite *bool        `json:"overwrite,omitempty"`
	Mode      *string      `json:"mode,omitempty"`
	Resume    *bool        `json:"resume,omitempty"`
	Parents   *bool        `json:"parents,omitempty"`

	// Set by the agent, never by the server.
	UploadID string `json:"upload_id,omitempty"`
	ResumeID string `json:"resume_id,omitempty"`
	Root     string `json:"root,omitempty"`
	Home     string `json:"home,omitempty"`
	FileMax  int64  `json:"file_max,omitempty"`
}

// fileResp is the helper's answer; Fields are the ok-response fields.
type fileResp struct {
	Error  string                 `json:"error,omitempty"`
	Fields map[string]interface{} `json:"fields,omitempty"`
}

// Helper wire: [1 byte kind 'J' or 'B'][4 byte big-endian length][payload].
const (
	frameJSON   = 'J'
	frameBinary = 'B'
)

func writeHelperFrame(w io.Writer, kind byte, payload []byte) error {
	if len(payload) > helperFrameMax {
		return errFrameSize
	}
	var hdr [5]byte
	hdr[0] = kind
	binary.BigEndian.PutUint32(hdr[1:], uint32(len(payload)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}

func writeHelperJSON(w io.Writer, v interface{}) error {
	raw, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return writeHelperFrame(w, frameJSON, raw)
}

func readHelperFrame(r io.Reader) (byte, []byte, error) {
	var hdr [5]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return 0, nil, err
	}
	n := binary.BigEndian.Uint32(hdr[1:])
	if n > helperFrameMax || (hdr[0] != frameJSON && hdr[0] != frameBinary) {
		return 0, nil, errFrameSize
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return 0, nil, err
	}
	return hdr[0], buf, nil
}
