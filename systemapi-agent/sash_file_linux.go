//go:build linux

package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"io"
	"log"
	"os"
	"os/exec"
)

// Threats: sash asking the agent to open a path the grant did not name, a
// helper that returns a secret after a failed status, and a nil identity
// reaching the credential drop. file.read goes through the existing file
// helper. A failed spawn or a bad path returns denied and no bytes. Does
// NOT os.Open the request path. Does NOT shell out. Does NOT call Wait
// unless Start succeeded.

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
	res, opErr := sashFileOps(stdin, stdout, id, helperOp, root, rel)
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

func sashFileOps(stdin io.Writer, stdout io.Reader, id *ptyIdentity, helperOp, root, rel string) (sashResult, error) {
	w := bufio.NewWriter(stdin)
	r := bufio.NewReader(stdout)
	if err := writeHelperJSON(w, fileReq{Op: "init", Root: root, Home: id.home, FileMax: fileReadMax}); err != nil {
		return sashResult{}, errSashDenied
	}
	if err := w.Flush(); err != nil {
		return sashResult{}, errSashDenied
	}
	kind, payload, err := readHelperFrame(r)
	if err != nil || kind != frameJSON {
		return sashResult{}, errSashDenied
	}
	initResp, err := decodeFileResp(payload)
	if err != nil || initResp.Error != "" {
		return sashResult{}, errSashDenied
	}
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
}

func sashHelperCall(w *bufio.Writer, req fileReq) error {
	if err := writeHelperJSON(w, req); err != nil {
		return err
	}
	return w.Flush()
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
	kind, payload, err := readHelperFrame(r)
	if err != nil || kind != frameJSON {
		return sashResult{}, errSashDenied
	}
	resp, err := decodeFileResp(payload)
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
	kind, payload, err := readHelperFrame(r)
	if err != nil || kind != frameJSON {
		return sashResult{}, errSashDenied
	}
	resp, err := decodeFileResp(payload)
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

// bytesReader exists so decodeFileResp does not import bytes under a name
// the file helper already uses loosely. strings is not required.
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

// Keep exec imported for the file's build: startFileHelperProc returns *exec.Cmd.
var _ = exec.ErrNotFound
