package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
)

func TestSashReadFrameTooLargeLeavesBody(t *testing.T) {
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(sashMaxFrame+1))
	r := io.MultiReader(bytes.NewReader(n[:]), strings.NewReader("SECRET"))
	err := sashReadFrame(r, &sashFrameReq{})
	if err == nil || err.Error() != "frame too large" {
		t.Fatalf("err %v", err)
	}
	rest, readErr := io.ReadAll(r)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(rest) != "SECRET" {
		t.Fatalf("body %q", rest)
	}
}

func TestSashReadFrameRejectsTrailingJSON(t *testing.T) {
	var buf bytes.Buffer
	if err := sashWriteFrame(&buf, []byte(`{"key":"ps"}{"x":1}`)); err != nil {
		t.Fatal(err)
	}
	err := sashReadFrame(&buf, &sashFrameReq{})
	if err == nil || err.Error() != "frame body" {
		t.Fatalf("err %v", err)
	}
}

func TestSashWriteResultErrorOmitsBytes(t *testing.T) {
	var buf bytes.Buffer
	err := sashWriteResult(&buf, sashResult{Kind: "bytes", Bytes: []byte("SECRET"), Exit: 0}, errors.New("denied"))
	if err != nil {
		t.Fatal(err)
	}
	body := readSashTestFrame(t, &buf)
	if bytes.Contains(body, []byte("SECRET")) || bytes.Contains(body, []byte(`"bytes"`)) {
		t.Fatalf("leaked %s", body)
	}
	if string(body) != `{"error":"denied"}` {
		t.Fatalf("frame %s", body)
	}
}

func TestSashWriteResultTooLarge(t *testing.T) {
	var buf bytes.Buffer
	res := sashResult{Kind: "bytes", Bytes: bytes.Repeat([]byte{'A'}, 6<<20), Exit: 0}
	if err := sashWriteResult(&buf, res, nil); err != nil {
		t.Fatal(err)
	}
	body := readSashTestFrame(t, &buf)
	if string(body) != `{"error":"result_too_large"}` {
		t.Fatalf("frame %s", body)
	}
	var decoded map[string]any
	if err := json.Unmarshal(body, &decoded); err != nil {
		t.Fatal(err)
	}
	if _, ok := decoded["bytes"]; ok {
		t.Fatal("bytes field")
	}
}

func readSashTestFrame(t *testing.T, r io.Reader) []byte {
	t.Helper()
	var n [4]byte
	if _, err := io.ReadFull(r, n[:]); err != nil {
		t.Fatal(err)
	}
	size := binary.BigEndian.Uint32(n[:])
	body := make([]byte, size)
	if _, err := io.ReadFull(r, body); err != nil {
		t.Fatal(err)
	}
	return body
}
