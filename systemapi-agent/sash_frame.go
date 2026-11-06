package main

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
)

// Threats: a verb frame larger than 8 MiB, a trailing or unknown JSON field,
// and a result that base64-expands past the frame cap. A too-large length is
// rejected before the body is read, which poisons the stream. Does NOT exec
// a helper. The dispatcher does that after the grant re-check.

const sashMaxFrame = 8 << 20

type sashCall struct {
	Key  string
	Argv []string
	Path string
	Body []byte
}

type sashResult struct {
	Kind  string
	Bytes []byte
	Rows  []map[string]string
	Cols  []string
	Exit  int
}

type sashFrameReq struct {
	Key  string   `json:"key"`
	Argv []string `json:"argv"`
	Path string   `json:"path"`
	Body string   `json:"body"`
}

type sashFrameResp struct {
	Kind  string              `json:"kind"`
	Bytes string              `json:"bytes,omitempty"`
	Rows  []map[string]string `json:"rows,omitempty"`
	Cols  []string            `json:"cols,omitempty"`
	Exit  int                 `json:"exit"`
	Error string              `json:"error,omitempty"`
}

func sashWriteFrame(w io.Writer, body []byte) error {
	if len(body) > sashMaxFrame {
		return errors.New("frame too large")
	}
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(len(body)))
	if _, err := w.Write(n[:]); err != nil {
		return err
	}
	_, err := w.Write(body)
	return err
}

func sashReadFrame(r io.Reader, v any) error {
	var n [4]byte
	if _, err := io.ReadFull(r, n[:]); err != nil {
		return err
	}
	size := binary.BigEndian.Uint32(n[:])
	if size > sashMaxFrame {
		return errors.New("frame too large")
	}
	body := make([]byte, size)
	if _, err := io.ReadFull(r, body); err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return errors.New("frame body")
	}
	return nil
}

func sashErrorFrame(msg string) ([]byte, error) {
	return json.Marshal(struct {
		Error string `json:"error"`
	}{Error: msg})
}

func sashWriteResult(w io.Writer, res sashResult, callErr error) error {
	if callErr != nil {
		body, err := sashErrorFrame(callErr.Error())
		if err != nil {
			return err
		}
		return sashWriteFrame(w, body)
	}
	resp := sashFrameResp{Kind: res.Kind, Cols: res.Cols, Rows: res.Rows, Exit: res.Exit}
	if resp.Kind == "" {
		resp.Kind = "bytes"
	}
	if len(res.Bytes) > 0 {
		resp.Bytes = base64.StdEncoding.EncodeToString(res.Bytes)
	}
	body, err := json.Marshal(resp)
	if err != nil {
		return err
	}
	if len(body) > sashMaxFrame {
		body, err = sashErrorFrame("result_too_large")
		if err != nil {
			return err
		}
	}
	return sashWriteFrame(w, body)
}

// sashServe reads verbs until the header hits EOF. A length above the cap
// returns. A bad body writes one error frame and continues.
func sashServe(rw io.ReadWriter, h func(sashCall) (sashResult, error)) error {
	for {
		var req sashFrameReq
		err := sashReadFrame(rw, &req)
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil && err.Error() == "frame too large" {
			return err
		}
		if err != nil {
			if errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF) {
				return err
			}
			if werr := sashWriteResult(rw, sashResult{}, errors.New("frame body")); werr != nil {
				return werr
			}
			continue
		}
		call := sashCall{Key: req.Key, Argv: append([]string(nil), req.Argv...), Path: req.Path}
		if req.Body != "" {
			b, decErr := base64.StdEncoding.DecodeString(req.Body)
			if decErr != nil {
				if werr := sashWriteResult(rw, sashResult{}, errors.New("frame body")); werr != nil {
					return werr
				}
				continue
			}
			call.Body = b
		}
		res, callErr := h(call)
		if err := sashWriteResult(rw, res, callErr); err != nil {
			return err
		}
	}
}
