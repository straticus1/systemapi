//go:build linux

// The file-helper child process (docs/sah-file-protocol.md §5, §7): every
// file operation of one session runs here, under the session's dropped
// identity (uid, gid and supplementary groups set by the parent with
// SysProcAttr.Credential, as for PTY shells), never in the agent itself.
// Threats: symlink escape and TOCTOU (the root is opened once with
// openat2(RESOLVE_NO_SYMLINKS) and held; every path then resolves through
// that fd with RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS|RESOLVE_NO_MAGICLINKS;
// the final component is acted on through its parent dirfd with lstat and
// unlinkat semantics, so no symlink below the root is ever followed), a FIFO
// or device hanging or poking the agent (read and hash lstat first and open
// only regular files, with O_NONBLOCK, then fstat and compare the inode), a
// partial or corrupt file at the target (writes go to an O_EXCL|O_NOFOLLOW
// 0600 temp file in the parent dirfd, fsync, re-read from disk and hash,
// then renameat2(RENAME_NOREPLACE) or renameat onto a regular file only, and
// fsync of the parent), a mode with setuid, setgid or sticky (refused), and
// operations running with the agent's privileges (the parent drops them
// before exec). Does NOT detect a hard link inside the root to a file outside
// it (§5.6: the kernel's permissions for this identity bound what it can
// reach), and does NOT stop a concurrent writer on the host changing a file
// between hash and use.
package main

import (
	"bufio"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"sort"
	"strings"
	"sync"
	"unicode/utf8"

	"golang.org/x/sys/unix"
)

const (
	fileResolve     = unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS
	fileReadBuf     = 256 * 1024
	fileListNameCap = 1_000_000
)

var (
	openat2Once sync.Once
	openat2OK   bool
)

func init() {
	registerCapability("file", openat2Available)
}

// openat2Available probes the kernel once: without openat2 (Linux < 5.6, or
// a seccomp filter that refuses it) the file capability is not advertised
// and file_open answers agent_unsupported (§5.4, no fallback).
func openat2Available() bool {
	openat2Once.Do(func() {
		fd, err := unix.Openat2(unix.AT_FDCWD, "/", &unix.OpenHow{
			Flags:   unix.O_PATH | unix.O_DIRECTORY | unix.O_CLOEXEC,
			Resolve: unix.RESOLVE_NO_SYMLINKS,
		})
		if err == nil {
			_ = unix.Close(fd)
			openat2OK = true
		}
	})
	return openat2OK
}

// openat2 retries EAGAIN (a concurrent rename or mount under
// RESOLVE_BENEATH) a few times.
func openat2(dirfd int, path string, flags uint64, resolve uint64) (int, error) {
	var err error
	for i := 0; i < 8; i++ {
		var fd int
		fd, err = unix.Openat2(dirfd, path, &unix.OpenHow{Flags: flags | unix.O_CLOEXEC, Resolve: resolve})
		if err == nil {
			return fd, nil
		}
		if !errors.Is(err, unix.EAGAIN) && !errors.Is(err, unix.EINTR) {
			return -1, err
		}
	}
	return -1, err
}

// fileErrCode maps an errno to a FILE §8 operation code.
func fileErrCode(err error) string {
	var en unix.Errno
	if !errors.As(err, &en) {
		return "io_error"
	}
	switch en {
	case unix.ENOENT:
		return "not_found"
	case unix.ELOOP, unix.EXDEV:
		// RESOLVE_NO_SYMLINKS reports a symlink as ELOOP; RESOLVE_BENEATH
		// reports an escape as EXDEV.
		return "symlink_refused"
	case unix.ENOTDIR:
		return "not_a_dir"
	case unix.EACCES, unix.EPERM, unix.EROFS:
		return "permission_denied"
	case unix.ENOSPC, unix.EDQUOT:
		return "no_space"
	case unix.EFBIG:
		return "too_large"
	case unix.EEXIST:
		return "exists"
	case unix.ENOTEMPTY:
		return "not_empty"
	case unix.ENAMETOOLONG:
		return "bad_path"
	case unix.EISDIR:
		return "not_a_file"
	}
	return "io_error"
}

// rootShapeOK is the absolute-root rule of FILE §2.
func rootShapeOK(root string) bool {
	if root == "" || len(root) > filePathMax || root[0] != '/' || !utf8.ValidString(root) {
		return false
	}
	for i := 0; i < len(root); i++ {
		if root[i] < 0x20 || root[i] == 0x7f {
			return false
		}
	}
	if root == "/" {
		return true
	}
	if strings.HasSuffix(root, "/") {
		return false
	}
	for _, c := range strings.Split(root[1:], "/") {
		if c == "" || c == "." || c == ".." {
			return false
		}
	}
	return true
}

// openFileRoot opens a session root (§5.3). A symlink anywhere in it, a
// missing root or a non-directory is root_invalid; no openat2 is
// agent_unsupported.
func openFileRoot(root string) (int, string) {
	if !rootShapeOK(root) {
		return -1, "root_invalid"
	}
	fd, err := openat2(unix.AT_FDCWD, root, unix.O_PATH|unix.O_DIRECTORY, unix.RESOLVE_NO_SYMLINKS)
	if err != nil {
		if errors.Is(err, unix.ENOSYS) {
			return -1, "agent_unsupported"
		}
		return -1, "root_invalid"
	}
	return fd, ""
}

func entryFromStat(name string, st *unix.Stat_t) fileEntry {
	typ := "other"
	switch st.Mode & unix.S_IFMT {
	case unix.S_IFREG:
		typ = "file"
	case unix.S_IFDIR:
		typ = "dir"
	case unix.S_IFLNK:
		typ = "symlink"
	}
	return fileEntry{
		Name:    name,
		Type:    typ,
		Size:    st.Size,
		Mode:    formatFileMode(st.Mode & 0o7777),
		MtimeNS: st.Mtim.Sec*1_000_000_000 + st.Mtim.Nsec,
	}
}

func mtimeNS(st *unix.Stat_t) int64 {
	return st.Mtim.Sec*1_000_000_000 + st.Mtim.Nsec
}

// fileHelper is the state of one helper process: the held root fd and the
// open write, if any.
type fileHelper struct {
	rootFD  int
	root    string
	fileMax int64
	w       *bufio.Writer
	write   *helperWrite
}

type helperWrite struct {
	uploadID  string
	path      string
	dirFD     int
	name      string
	tmp       string
	fd        int
	size      int64
	sha       string
	overwrite bool
	mode      uint32
	hasMode   bool
	offset    int64
}

// runFileHelper is "systemapi-agent file-helper": it serves the parent over
// stdin/stdout until stdin closes, then releases any open write (fsync,
// keep the temp file for resume) and exits.
func runFileHelper(in io.Reader, out io.Writer) int {
	unix.Umask(0)
	r := bufio.NewReaderSize(in, 64*1024)
	h := &fileHelper{rootFD: -1, w: bufio.NewWriterSize(out, 64*1024)}
	defer h.release()
	for {
		kind, payload, err := readHelperFrame(r)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return 0
			}
			return 1
		}
		if kind != frameJSON {
			return 1
		}
		var req fileReq
		if err := json.Unmarshal(payload, &req); err != nil {
			return 1
		}
		var data []byte
		if req.Op == "write_chunk" {
			kind, data, err = readHelperFrame(r)
			if err != nil || kind != frameBinary {
				return 1
			}
		}
		resp := h.do(req, data)
		if err := writeHelperJSON(h.w, resp); err != nil {
			return 1
		}
		if err := h.w.Flush(); err != nil {
			return 1
		}
	}
}

func helperFail(code string) fileResp { return fileResp{Error: code} }

func okResp(fields map[string]interface{}) fileResp { return fileResp{Fields: fields} }

func (h *fileHelper) do(req fileReq, data []byte) fileResp {
	if req.Op == "init" {
		return h.init(req)
	}
	if h.rootFD < 0 {
		return helperFail("internal")
	}
	switch req.Op {
	case "write_chunk":
		return h.writeChunk(req, data)
	case "write_commit":
		return h.writeCommit()
	case "write_abort":
		return h.writeAbort()
	case "write_release":
		h.release()
		return okResp(nil)
	case "write_discard":
		h.discard()
		return okResp(nil)
	}
	if code := checkFilePath(req.Path); code != "" {
		return helperFail(code)
	}
	switch req.Op {
	case "stat":
		return h.stat(req.Path)
	case "list":
		return h.list(req)
	case "read":
		return h.read(req)
	case "hash":
		return h.hash(req)
	case "write_open":
		return h.writeOpen(req)
	case "mkdir":
		return h.mkdir(req)
	case "remove":
		return h.remove(req.Path)
	}
	return helperFail("bad_request")
}

func (h *fileHelper) init(req fileReq) fileResp {
	if h.rootFD >= 0 {
		return helperFail("internal")
	}
	root := req.Root
	if root == "~" {
		root = req.Home
	}
	fd, code := openFileRoot(root)
	if code != "" {
		return helperFail(code)
	}
	h.rootFD, h.root, h.fileMax = fd, root, req.FileMax
	return okResp(map[string]interface{}{"root": root, "uid": os.Geteuid()})
}

// openParent resolves the parent directory of a checked path (not ".")
// beneath the root and returns an O_PATH dirfd and the final component.
func (h *fileHelper) openParent(path string) (int, string, string) {
	parents, name := splitFilePath(path)
	dir := "."
	if len(parents) > 0 {
		dir = strings.Join(parents, "/")
	}
	fd, err := openat2(h.rootFD, dir, unix.O_PATH|unix.O_DIRECTORY, fileResolve)
	if err != nil {
		return -1, "", fileErrCode(err)
	}
	return fd, name, ""
}

func (h *fileHelper) stat(path string) fileResp {
	var st unix.Stat_t
	if path == "." {
		if err := unix.Fstat(h.rootFD, &st); err != nil {
			return helperFail(fileErrCode(err))
		}
		return okResp(map[string]interface{}{"entry": entryFromStat(".", &st)})
	}
	dirfd, name, code := h.openParent(path)
	if code != "" {
		return helperFail(code)
	}
	defer unix.Close(dirfd)
	if err := unix.Fstatat(dirfd, name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return helperFail(fileErrCode(err))
	}
	return okResp(map[string]interface{}{"entry": entryFromStat(name, &st)})
}

func (h *fileHelper) list(req fileReq) fileResp {
	limit := fileListDefault
	if req.Limit != nil {
		limit = *req.Limit
	}
	if limit < 1 || limit > fileListMax {
		return helperFail("bad_request")
	}
	after := ""
	if req.Cursor != nil {
		raw, err := base64.RawURLEncoding.DecodeString(*req.Cursor)
		if err != nil || len(raw) == 0 || len(raw) > fileComponentMax {
			return helperFail("bad_request")
		}
		after = string(raw)
	}
	var fd int
	var err error
	if req.Path == "." {
		fd, err = unix.Openat(h.rootFD, ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	} else {
		fd, err = openat2(h.rootFD, req.Path, unix.O_RDONLY|unix.O_DIRECTORY, fileResolve)
	}
	if err != nil {
		return helperFail(fileErrCode(err))
	}
	dir := os.NewFile(uintptr(fd), "dir")
	defer dir.Close()
	var names []string
	for {
		batch, err := dir.Readdirnames(4096)
		for _, n := range batch {
			// Temp files are the agent's own; names that are not UTF-8
			// cannot be addressed by any request (§5.1).
			if reservedName(n) || !utf8.ValidString(n) {
				continue
			}
			names = append(names, n)
		}
		if len(names) > fileListNameCap {
			return helperFail("too_large")
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return helperFail(fileErrCode(err))
		}
		if len(batch) == 0 {
			break
		}
	}
	sort.Strings(names)
	start := 0
	if after != "" {
		start = sort.Search(len(names), func(i int) bool { return names[i] > after })
	}
	entries := []fileEntry{}
	i := start
	for ; i < len(names) && len(entries) < limit; i++ {
		var st unix.Stat_t
		if err := unix.Fstatat(int(dir.Fd()), names[i], &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			if errors.Is(err, unix.ENOENT) {
				continue
			}
			return helperFail(fileErrCode(err))
		}
		entries = append(entries, entryFromStat(names[i], &st))
	}
	var next interface{}
	if i < len(names) && len(entries) > 0 {
		next = base64.RawURLEncoding.EncodeToString([]byte(entries[len(entries)-1].Name))
	}
	return okResp(map[string]interface{}{"entries": entries, "next_cursor": next})
}

// openRegular opens the final component of a checked path for reading,
// only when it is a regular file: lstat first (a FIFO or device is never
// opened), then open with O_NONBLOCK|O_NOFOLLOW and confirm the same inode.
func (h *fileHelper) openRegular(path string) (int, *unix.Stat_t, string) {
	if path == "." {
		return -1, nil, "not_a_file"
	}
	dirfd, name, code := h.openParent(path)
	if code != "" {
		return -1, nil, code
	}
	defer unix.Close(dirfd)
	var pre unix.Stat_t
	if err := unix.Fstatat(dirfd, name, &pre, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return -1, nil, fileErrCode(err)
	}
	switch pre.Mode & unix.S_IFMT {
	case unix.S_IFLNK:
		return -1, nil, "symlink_refused"
	case unix.S_IFREG:
	default:
		return -1, nil, "not_a_file"
	}
	fd, err := openat2(dirfd, name, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_NOFOLLOW, fileResolve)
	if err != nil {
		return -1, nil, fileErrCode(err)
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		_ = unix.Close(fd)
		return -1, nil, fileErrCode(err)
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Dev != pre.Dev || st.Ino != pre.Ino {
		_ = unix.Close(fd)
		return -1, nil, "not_a_file"
	}
	return fd, &st, ""
}

func ifMatchFails(m *fileIfMatch, st *unix.Stat_t) bool {
	if m == nil {
		return false
	}
	if m.Size != nil && *m.Size != st.Size {
		return true
	}
	return m.MtimeNS != nil && *m.MtimeNS != mtimeNS(st)
}

func validIfMatch(m *fileIfMatch) bool {
	return m == nil || (m.Size != nil && m.MtimeNS != nil && *m.Size >= 0)
}

func (h *fileHelper) read(req fileReq) fileResp {
	if req.Offset == nil || req.Length == nil || *req.Offset < 0 || *req.Length < 1 || *req.Length > fileReadMax || !validIfMatch(req.IfMatch) {
		return helperFail("bad_request")
	}
	fd, st, code := h.openRegular(req.Path)
	if code != "" {
		return helperFail(code)
	}
	defer unix.Close(fd)
	if ifMatchFails(req.IfMatch, st) {
		return helperFail("changed")
	}
	off, want := *req.Offset, *req.Length
	buf := make([]byte, fileReadBuf)
	var got int64
	for got < want {
		n := int64(len(buf))
		if want-got < n {
			n = want - got
		}
		m, err := unix.Pread(fd, buf[:n], off+got)
		if err != nil {
			if errors.Is(err, unix.EINTR) {
				continue
			}
			return helperFail(fileErrCode(err))
		}
		if m == 0 {
			break
		}
		if err := writeHelperFrame(h.w, frameBinary, buf[:m]); err != nil {
			return helperFail("internal")
		}
		got += int64(m)
	}
	return okResp(map[string]interface{}{
		"bytes":    got,
		"eof":      off+got >= st.Size,
		"size":     st.Size,
		"mtime_ns": mtimeNS(st),
	})
}

// hashFD returns the sha256 of the first n bytes of fd (n < 0: all).
func hashFD(fd int, n int64) (string, error) {
	sum := sha256.New()
	buf := make([]byte, fileReadBuf)
	var off int64
	for n < 0 || off < n {
		want := int64(len(buf))
		if n >= 0 && n-off < want {
			want = n - off
		}
		m, err := unix.Pread(fd, buf[:want], off)
		if err != nil {
			if errors.Is(err, unix.EINTR) {
				continue
			}
			return "", err
		}
		if m == 0 {
			if n >= 0 {
				return "", io.ErrUnexpectedEOF
			}
			break
		}
		sum.Write(buf[:m])
		off += int64(m)
	}
	return hex.EncodeToString(sum.Sum(nil)), nil
}

func (h *fileHelper) hash(req fileReq) fileResp {
	if !validIfMatch(req.IfMatch) {
		return helperFail("bad_request")
	}
	fd, st, code := h.openRegular(req.Path)
	if code != "" {
		return helperFail(code)
	}
	defer unix.Close(fd)
	if ifMatchFails(req.IfMatch, st) {
		return helperFail("changed")
	}
	sum, err := hashFD(fd, -1)
	if err != nil {
		return helperFail(fileErrCode(err))
	}
	if req.IfMatch != nil {
		var after unix.Stat_t
		if err := unix.Fstat(fd, &after); err != nil || ifMatchFails(req.IfMatch, &after) {
			return helperFail("changed")
		}
	}
	return okResp(map[string]interface{}{"sha256": sum, "size": st.Size, "mtime_ns": mtimeNS(st)})
}

func tempName(uploadID string) string {
	return fileReservedStart + uploadID + fileReservedEnd
}

func (h *fileHelper) writeOpen(req fileReq) fileResp {
	if h.write != nil {
		return helperFail("bad_request")
	}
	if req.Path == "." {
		return helperFail("not_a_file")
	}
	if req.Size == nil || *req.Size < 0 || !sha256HexRe.MatchString(req.SHA256) || req.Overwrite == nil || !uploadIDRe.MatchString(req.UploadID) {
		return helperFail("bad_request")
	}
	if req.ResumeID != "" && !uploadIDRe.MatchString(req.ResumeID) {
		return helperFail("bad_request")
	}
	mode, hasMode, ok := parseFileMode(req.Mode)
	if !ok {
		return helperFail("bad_request")
	}
	if h.fileMax > 0 && *req.Size > h.fileMax {
		return helperFail("too_large")
	}
	dirfd, name, code := h.openParent(req.Path)
	if code != "" {
		return helperFail(code)
	}
	var st unix.Stat_t
	if err := unix.Fstatat(dirfd, name, &st, unix.AT_SYMLINK_NOFOLLOW); err == nil {
		if !*req.Overwrite {
			_ = unix.Close(dirfd)
			return helperFail("exists")
		}
		if st.Mode&unix.S_IFMT != unix.S_IFREG {
			_ = unix.Close(dirfd)
			return helperFail("not_a_file")
		}
	} else if !errors.Is(err, unix.ENOENT) {
		_ = unix.Close(dirfd)
		return helperFail(fileErrCode(err))
	}
	w := &helperWrite{
		path: req.Path, dirFD: dirfd, name: name, fd: -1, size: *req.Size, sha: req.SHA256,
		overwrite: *req.Overwrite, mode: mode, hasMode: hasMode,
	}
	fields := map[string]interface{}{}
	if req.ResumeID != "" {
		if prefix, ok := h.resumeTemp(w, req.ResumeID); ok {
			fields["prefix_sha256"] = prefix
		}
	}
	if w.fd < 0 {
		w.uploadID, w.tmp, w.offset = req.UploadID, tempName(req.UploadID), 0
		fd, err := unix.Openat(dirfd, w.tmp, unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_WRONLY|unix.O_CLOEXEC, 0o600)
		if err != nil {
			_ = unix.Close(dirfd)
			return helperFail(fileErrCode(err))
		}
		w.fd = fd
		delete(fields, "prefix_sha256")
	}
	h.write = w
	fields["upload_id"] = w.uploadID
	fields["offset"] = w.offset
	if w.offset == 0 {
		delete(fields, "prefix_sha256")
	}
	return okResp(fields)
}

// resumeTemp reopens an interrupted upload's temp file: a regular file with
// one link, owned by this identity. It is lstat'ed first and opened only when
// regular, with O_NONBLOCK, then fstat'ed and compared by inode, as
// openRegular does, so a FIFO or device planted at the temp name never
// blocks or is written. The durable offset is its length after fsync;
// prefix_sha256 lets the client check those bytes (§6).
func (h *fileHelper) resumeTemp(w *helperWrite, id string) (string, bool) {
	tmp := tempName(id)
	var pre unix.Stat_t
	if err := unix.Fstatat(w.dirFD, tmp, &pre, unix.AT_SYMLINK_NOFOLLOW); err != nil || pre.Mode&unix.S_IFMT != unix.S_IFREG {
		return "", false
	}
	fd, err := unix.Openat(w.dirFD, tmp, unix.O_WRONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return "", false
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Dev != pre.Dev || st.Ino != pre.Ino ||
		st.Nlink != 1 || int(st.Uid) != os.Geteuid() {
		_ = unix.Close(fd)
		return "", false
	}
	offset := st.Size
	if offset > w.size {
		if err := unix.Ftruncate(fd, w.size); err != nil {
			_ = unix.Close(fd)
			return "", false
		}
		offset = w.size
	}
	if err := unix.Fsync(fd); err != nil {
		_ = unix.Close(fd)
		return "", false
	}
	prefix := ""
	if offset > 0 {
		rfd, ok := reopenForRead(w.dirFD, tmp, &st)
		if !ok {
			_ = unix.Close(fd)
			return "", false
		}
		prefix, err = hashFD(rfd, offset)
		_ = unix.Close(rfd)
		if err != nil {
			_ = unix.Close(fd)
			return "", false
		}
	}
	w.uploadID, w.tmp, w.fd, w.offset = id, tmp, fd, offset
	return prefix, true
}

// reopenForRead opens the temp file again read-only and checks it is the
// same inode as want.
func reopenForRead(dirfd int, tmp string, want *unix.Stat_t) (int, bool) {
	rfd, err := unix.Openat(dirfd, tmp, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, false
	}
	var st unix.Stat_t
	if err := unix.Fstat(rfd, &st); err != nil || st.Dev != want.Dev || st.Ino != want.Ino {
		_ = unix.Close(rfd)
		return -1, false
	}
	return rfd, true
}

func (h *fileHelper) writeChunk(req fileReq, data []byte) fileResp {
	w := h.write
	if w == nil {
		return helperFail("upload_not_found")
	}
	if req.Offset == nil || *req.Offset != w.offset {
		return helperFail("offset_mismatch")
	}
	if len(data) == 0 || len(data) > fileChunkMax {
		return helperFail("bad_request")
	}
	if w.offset+int64(len(data)) > w.size {
		return helperFail("too_large")
	}
	for written := 0; written < len(data); {
		n, err := unix.Pwrite(w.fd, data[written:], w.offset+int64(written))
		if err != nil {
			if errors.Is(err, unix.EINTR) {
				continue
			}
			return helperFail(fileErrCode(err))
		}
		written += n
	}
	w.offset += int64(len(data))
	return okResp(map[string]interface{}{"offset": w.offset})
}

// writeCommit is §6 "Commit": offset == size, fsync, re-read and hash,
// mode, rename, fsync of the parent. A hash mismatch or a commit before the
// last byte (offset_mismatch, the client's fault) deletes the temp file; any
// other failure keeps it for resume.
func (h *fileHelper) writeCommit() fileResp {
	w := h.write
	if w == nil {
		return helperFail("upload_not_found")
	}
	if w.offset != w.size {
		h.discard()
		return helperFail("offset_mismatch")
	}
	if err := unix.Fsync(w.fd); err != nil {
		h.release()
		return helperFail(fileErrCode(err))
	}
	var st unix.Stat_t
	if err := unix.Fstat(w.fd, &st); err != nil {
		h.release()
		return helperFail(fileErrCode(err))
	}
	rfd, ok := reopenForRead(w.dirFD, w.tmp, &st)
	if !ok {
		h.release()
		return helperFail("io_error")
	}
	sum, err := hashFD(rfd, w.size)
	_ = unix.Close(rfd)
	if err != nil {
		h.release()
		return helperFail("io_error")
	}
	if subtle.ConstantTimeCompare([]byte(sum), []byte(w.sha)) != 1 {
		h.discard()
		return helperFail("sha256_mismatch")
	}
	mode := uint32(0o644)
	var cur unix.Stat_t
	curErr := unix.Fstatat(w.dirFD, w.name, &cur, unix.AT_SYMLINK_NOFOLLOW)
	if w.hasMode {
		mode = w.mode
	} else if curErr == nil && cur.Mode&unix.S_IFMT == unix.S_IFREG {
		mode = cur.Mode & 0o777
	}
	if err := unix.Fchmod(w.fd, mode); err != nil {
		h.release()
		return helperFail(fileErrCode(err))
	}
	dirRD, err := unix.Openat(w.dirFD, ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		h.release()
		return helperFail(fileErrCode(err))
	}
	defer unix.Close(dirRD)
	if !w.overwrite {
		if err := unix.Renameat2(w.dirFD, w.tmp, w.dirFD, w.name, unix.RENAME_NOREPLACE); err != nil {
			h.release()
			return helperFail(fileErrCode(err))
		}
	} else {
		if curErr == nil && cur.Mode&unix.S_IFMT != unix.S_IFREG {
			h.release()
			return helperFail("not_a_file")
		}
		if err := unix.Renameat(w.dirFD, w.tmp, w.dirFD, w.name); err != nil {
			h.release()
			if errors.Is(err, unix.EISDIR) || errors.Is(err, unix.ENOTDIR) || errors.Is(err, unix.ENOTEMPTY) || errors.Is(err, unix.EEXIST) {
				return helperFail("not_a_file")
			}
			return helperFail(fileErrCode(err))
		}
	}
	if err := unix.Fsync(dirRD); err != nil {
		h.closeWrite()
		return helperFail("io_error")
	}
	path, size := w.path, w.size
	h.closeWrite()
	return okResp(map[string]interface{}{"sha256": sum, "size": size, "path": path})
}

func (h *fileHelper) writeAbort() fileResp {
	if h.write == nil {
		return helperFail("upload_not_found")
	}
	h.discard()
	return okResp(nil)
}

// discard deletes the temp file and forgets the write.
func (h *fileHelper) discard() {
	w := h.write
	if w == nil {
		return
	}
	_ = unix.Unlinkat(w.dirFD, w.tmp, 0)
	h.closeWrite()
}

// release keeps the temp file (fsynced) for resume and forgets the write.
func (h *fileHelper) release() {
	w := h.write
	if w == nil {
		return
	}
	_ = unix.Fsync(w.fd)
	h.closeWrite()
}

func (h *fileHelper) closeWrite() {
	w := h.write
	if w == nil {
		return
	}
	if w.fd >= 0 {
		_ = unix.Close(w.fd)
	}
	_ = unix.Close(w.dirFD)
	h.write = nil
}

func (h *fileHelper) mkdir(req fileReq) fileResp {
	mode, hasMode, ok := parseFileMode(req.Mode)
	if !ok {
		return helperFail("bad_request")
	}
	if !hasMode {
		mode = 0o755
	}
	parents := req.Parents != nil && *req.Parents
	var st unix.Stat_t
	if req.Path == "." {
		if !parents {
			return helperFail("exists")
		}
		if err := unix.Fstat(h.rootFD, &st); err != nil {
			return helperFail(fileErrCode(err))
		}
		return okResp(map[string]interface{}{"entry": entryFromStat(".", &st)})
	}
	if !parents {
		dirfd, name, code := h.openParent(req.Path)
		if code != "" {
			return helperFail(code)
		}
		defer unix.Close(dirfd)
		if err := unix.Mkdirat(dirfd, name, mode); err != nil {
			return helperFail(fileErrCode(err))
		}
		if err := unix.Fstatat(dirfd, name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			return helperFail(fileErrCode(err))
		}
		return okResp(map[string]interface{}{"entry": entryFromStat(name, &st)})
	}
	cur, err := openat2(h.rootFD, ".", unix.O_PATH|unix.O_DIRECTORY, fileResolve)
	if err != nil {
		return helperFail(fileErrCode(err))
	}
	parts := strings.Split(req.Path, "/")
	for _, c := range parts {
		if err := unix.Mkdirat(cur, c, mode); err != nil && !errors.Is(err, unix.EEXIST) {
			_ = unix.Close(cur)
			return helperFail(fileErrCode(err))
		}
		next, err := openat2(cur, c, unix.O_PATH|unix.O_DIRECTORY, fileResolve)
		_ = unix.Close(cur)
		if err != nil {
			return helperFail(fileErrCode(err))
		}
		cur = next
	}
	defer unix.Close(cur)
	if err := unix.Fstat(cur, &st); err != nil {
		return helperFail(fileErrCode(err))
	}
	return okResp(map[string]interface{}{"entry": entryFromStat(parts[len(parts)-1], &st)})
}

// remove deletes one regular file, one symlink (the link itself) or one
// empty directory; never recursive.
func (h *fileHelper) remove(path string) fileResp {
	if path == "." {
		return helperFail("bad_path")
	}
	dirfd, name, code := h.openParent(path)
	if code != "" {
		return helperFail(code)
	}
	defer unix.Close(dirfd)
	err := unix.Unlinkat(dirfd, name, 0)
	if errors.Is(err, unix.EISDIR) {
		err = unix.Unlinkat(dirfd, name, unix.AT_REMOVEDIR)
		if errors.Is(err, unix.ENOTEMPTY) || errors.Is(err, unix.EEXIST) {
			return helperFail("not_empty")
		}
	}
	if err != nil {
		return helperFail(fileErrCode(err))
	}
	return okResp(nil)
}

// removeUploadTemp deletes an expired upload's temp file, resolving the
// root and the parent exactly as a helper does. Unlinking only ever removes
// the name itself, never what a link points to.
func removeUploadTemp(root, path, uploadID string) error {
	if checkFilePath(path) != "" || path == "." || !uploadIDRe.MatchString(uploadID) {
		return errors.New("bad_record")
	}
	fd, code := openFileRoot(root)
	if code != "" {
		return errors.New(code)
	}
	h := &fileHelper{rootFD: fd}
	defer unix.Close(fd)
	dirfd, _, code := h.openParent(path)
	if code != "" {
		return errors.New(code)
	}
	defer unix.Close(dirfd)
	err := unix.Unlinkat(dirfd, tempName(uploadID), 0)
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	return err
}
