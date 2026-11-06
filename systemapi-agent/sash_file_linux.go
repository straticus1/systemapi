//go:build linux

package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log"
	"os"
)

// Threats: sash asking the agent to open or replace a path the grant did
// not name, a helper that returns a secret after a failed status, a nil
// identity reaching the credential drop, and a write that keeps its temp
// file after a failed commit. file.read and file.write go through the
// existing file helper (write_open, write_chunk, write_commit, write_abort).
// A failed spawn, a bad path, or a transport error returns denied and no
// bytes. An operational helper error is exit 1 and does not return the
// path or the body. Does NOT os.Open the request path. Does NOT shell out.
// Does NOT call Wait unless Start succeeded. Does NOT use the file-channel
// upload registry.

func sashFileDefault(id *ptyIdentity, op, root, rel string) (sashResult, error) {
	if id == nil || checkFilePath(rel) != "" {
		return sashResult{}, errSashDenied
	}
	helperOp := ""
	switch op {
	case "cat", "<":
		helperOp = "read"
	case "ls":
		helperOp = "list"
	case "stat":
		helperOp = "stat"
	default:
		return sashResult{}, errSashDenied
	}
	return sashFileRun(id, root, func(w *bufio.Writer, r *bufio.Reader) (sashResult, error) {
		switch helperOp {
		case "read":
			return sashFileRead(w, r, rel)
		case "list":
			return sashFileList(w, r, rel)
		case "stat":
			return sashFileStat(w, r, rel)
		default:
			return sashResult{}, errSashDenied
		}
	})
}

// sashFileWriteDefault replaces one file under root. rel "." is the
// directory itself and is refused before the helper starts. An empty body
// is a real write. Shell ">" overwrites.
func sashFileWriteDefault(id *ptyIdentity, root, rel string, body []byte) (sashResult, error) {
	if id == nil || rel == "." || checkFilePath(rel) != "" || len(body) > fileReadMax {
		return sashResult{}, errSashDenied
	}
	uploadID, err := newUploadID()
	if err != nil {
		log.Printf("sash file write id failed")
		return sashResult{}, errSashDenied
	}
	sum := sha256.Sum256(body)
	hexSum := hex.EncodeToString(sum[:])
	size := int64(len(body))
	overwrite := true
	return sashFileRun(id, root, func(w *bufio.Writer, r *bufio.Reader) (sashResult, error) {
		opened, err := sashHelperResp(w, r, fileReq{
			Op: "write_open", Path: rel, Size: &size, SHA256: hexSum,
			Overwrite: &overwrite, UploadID: uploadID,
		})
		if err != nil {
			return sashResult{}, errSashDenied
		}
		if opened.Error != "" {
			return sashResult{Kind: "bytes", Exit: 1}, nil
		}
		off := int64(0)
		for off < size {
			n := int64(fileChunkMax)
			if remain := size - off; remain < n {
				n = remain
			}
			chunk := body[off : off+n]
			chunkOff := off
			if err := writeHelperJSON(w, fileReq{Op: "write_chunk", Offset: &chunkOff}); err != nil {
				return sashAbortDenied(w, r)
			}
			if err := writeHelperFrame(w, frameBinary, chunk); err != nil {
				return sashAbortDenied(w, r)
			}
			if err := w.Flush(); err != nil {
				return sashAbortDenied(w, r)
			}
			resp, err := sashReadHelperResp(r)
			if err != nil {
				return sashAbortDenied(w, r)
			}
			if resp.Error != "" {
				return sashAbortExit(w, r)
			}
			off += n
		}
		committed, err := sashHelperResp(w, r, fileReq{Op: "write_commit"})
		if err != nil {
			return sashAbortDenied(w, r)
		}
		if committed.Error != "" {
			return sashAbortExit(w, r)
		}
		return sashResult{Kind: "bytes", Exit: 0}, nil
	})
}

// sashAbortDenied tries to drop the temp file, then fails closed.
func sashAbortDenied(w *bufio.Writer, r *bufio.Reader) (sashResult, error) {
	if _, err := sashHelperResp(w, r, fileReq{Op: "write_abort"}); err != nil {
		return sashResult{}, errSashDenied
	}
	return sashResult{}, errSashDenied
}

// sashAbortExit tries to drop the temp file, then reports the helper's
// operational failure. An abort response that names an error is ignored.
// An abort that cannot be sent fails closed.
func sashAbortExit(w *bufio.Writer, r *bufio.Reader) (sashResult, error) {
	if _, err := sashHelperResp(w, r, fileReq{Op: "write_abort"}); err != nil {
		return sashResult{}, errSashDenied
	}
	return sashResult{Kind: "bytes", Exit: 1}, nil
}

// sashFileRun starts the file helper, inits it, runs fn, then closes the
// pipes and Wait. A nil identity never reaches the credential drop. Wait
// runs only after Start. A non-zero Wait after a successful op fails closed.
func sashFileRun(id *ptyIdentity, root string, fn func(w *bufio.Writer, r *bufio.Reader) (sashResult, error)) (sashResult, error) {
	if id == nil {
		return sashResult{}, errSashDenied
	}
	cmd, err := startFileHelperProc(id)
	if err != nil {
		return sashResult{}, errSashDenied
	}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return sashResult{}, errSashDenied
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		sashFileClose(stdin)
		return sashResult{}, errSashDenied
	}
	if err := cmd.Start(); err != nil {
		sashFileClose(stdin)
		sashFileClose(stdout)
		return sashResult{}, errSashDenied
	}
	w := bufio.NewWriter(stdin)
	r := bufio.NewReader(stdout)
	var res sashResult
	opErr := sashFileInit(w, r, id, root)
	if opErr == nil {
		res, opErr = fn(w, r)
	}
	cerr := sashFileClose(stdin)
	oerr := sashFileClose(stdout)
	werr := cmd.Wait()
	if opErr != nil {
		return sashResult{}, opErr
	}
	if sashFileCloseBad(cerr) || sashFileCloseBad(oerr) || werr != nil {
		return sashResult{}, errSashDenied
	}
	return res, nil
}

func sashFileInit(w *bufio.Writer, r *bufio.Reader, id *ptyIdentity, root string) error {
	if err := writeHelperJSON(w, fileReq{Op: "init", Root: root, Home: id.home, FileMax: fileReadMax}); err != nil {
		return errSashDenied
	}
	if err := w.Flush(); err != nil {
		return errSashDenied
	}
	resp, err := sashReadHelperResp(r)
	if err != nil || resp.Error != "" {
		return errSashDenied
	}
	return nil
}

func sashFileCloseBad(err error) bool {
	return err != nil && !errors.Is(err, os.ErrClosed)
}

func sashFileClose(c io.Closer) error {
	if c == nil {
		return nil
	}
	err := c.Close()
	if sashFileCloseBad(err) {
		log.Printf("sash file pipe close failed")
	}
	return err
}

func sashHelperCall(w *bufio.Writer, req fileReq) error {
	if err := writeHelperJSON(w, req); err != nil {
		return err
	}
	return w.Flush()
}

func sashHelperResp(w *bufio.Writer, r *bufio.Reader, req fileReq) (fileResp, error) {
	if err := sashHelperCall(w, req); err != nil {
		return fileResp{}, err
	}
	return sashReadHelperResp(r)
}

func sashReadHelperResp(r *bufio.Reader) (fileResp, error) {
	kind, payload, err := readHelperFrame(r)
	if err != nil || kind != frameJSON {
		return fileResp{}, errSashDenied
	}
	return decodeFileResp(payload)
}

func decodeFileResp(payload []byte) (fileResp, error) {
	dec := json.NewDecoder(bytesReader(payload))
	dec.UseNumber()
	var resp fileResp
	if err := dec.Decode(&resp); err != nil {
		return fileResp{}, err
	}
	return resp, nil
}

func sashFileRead(w *bufio.Writer, r *bufio.Reader, rel string) (sashResult, error) {
	off := int64(0)
	length := int64(fileReadMax)
	if err := sashHelperCall(w, fileReq{Op: "read", Path: rel, Offset: &off, Length: &length}); err != nil {
		return sashResult{}, errSashDenied
	}
	var acc []byte
	for {
		kind, payload, err := readHelperFrame(r)
		if err != nil {
			return sashResult{}, errSashDenied
		}
		if kind == frameBinary {
			if len(payload) > fileReadMax || len(acc) > fileReadMax-len(payload) {
				return sashResult{}, errSashDenied
			}
			acc = append(acc, payload...)
			continue
		}
		if kind != frameJSON {
			return sashResult{}, errSashDenied
		}
		resp, err := decodeFileResp(payload)
		if err != nil {
			return sashResult{}, errSashDenied
		}
		if resp.Error != "" {
			return sashResult{Kind: "bytes", Exit: 1}, nil
		}
		return sashResult{Kind: "bytes", Bytes: acc, Exit: 0}, nil
	}
}

func sashFileList(w *bufio.Writer, r *bufio.Reader, rel string) (sashResult, error) {
	limit := fileListMax
	if err := sashHelperCall(w, fileReq{Op: "list", Path: rel, Limit: &limit}); err != nil {
		return sashResult{}, errSashDenied
	}
	resp, err := sashReadHelperResp(r)
	if err != nil {
		return sashResult{}, errSashDenied
	}
	cols := []string{"name", "type", "size", "mode"}
	if resp.Error != "" {
		return sashResult{Kind: "rows", Cols: cols, Exit: 1}, nil
	}
	raw, ok := resp.Fields["entries"]
	if !ok || raw == nil {
		return sashResult{}, errSashDenied
	}
	arr, ok := raw.([]any)
	if !ok {
		return sashResult{}, errSashDenied
	}
	rows := make([]map[string]string, 0, len(arr))
	for _, item := range arr {
		m, ok := item.(map[string]any)
		if !ok {
			return sashResult{}, errSashDenied
		}
		rows = append(rows, map[string]string{
			"name": sashFieldString(m["name"]),
			"type": sashFieldString(m["type"]),
			"size": sashFieldString(m["size"]),
			"mode": sashFieldString(m["mode"]),
		})
	}
	return sashResult{Kind: "rows", Rows: rows, Cols: cols, Exit: 0}, nil
}

func sashFileStat(w *bufio.Writer, r *bufio.Reader, rel string) (sashResult, error) {
	if err := sashHelperCall(w, fileReq{Op: "stat", Path: rel}); err != nil {
		return sashResult{}, errSashDenied
	}
	resp, err := sashReadHelperResp(r)
	if err != nil {
		return sashResult{}, errSashDenied
	}
	if resp.Error != "" {
		return sashResult{Kind: "bytes", Exit: 1}, nil
	}
	raw, ok := resp.Fields["entry"].(map[string]any)
	if !ok {
		return sashResult{}, errSashDenied
	}
	exit := 1
	if sashFieldString(raw["type"]) == "dir" {
		exit = 0
	}
	return sashResult{Kind: "bytes", Exit: exit}, nil
}

func sashFieldString(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case json.Number:
		return t.String()
	default:
		return ""
	}
}

func bytesReader(b []byte) io.Reader {
	return &sashByteReader{b: b}
}

type sashByteReader struct {
	b []byte
}

func (r *sashByteReader) Read(p []byte) (int, error) {
	if len(r.b) == 0 {
		return 0, io.EOF
	}
	n := copy(p, r.b)
	r.b = r.b[n:]
	return n, nil
}
