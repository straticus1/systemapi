package main

// Frames that carry script output (command_result today) are encoded here.
//
// Threats: one oversized frame closing the control-plane socket (the
// server's 4 MiB limit answers 1009 and every terminal and channel on the
// host ends with it), and output that grows when JSON-escaped (1 MiB of
// '<' or of control bytes) slipping past a cap on the raw text. Output is
// made valid UTF-8, HTML escaping is off so '<' '>' '&' stay one byte, and
// the ENCODED frame is held to jobFrameMax by cutting the output and
// encoding again; output_truncated says so. Error text is capped
// separately. Does NOT chunk: the cut output is lost.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
)

const (
	// jobFrameMax caps one encoded output frame, far under the server's
	// 4 MiB agent frame limit (playground/fleet.js AGENT_FRAME_MAX).
	jobFrameMax = 1 << 20
	// frameErrMax caps the error text in an output frame.
	frameErrMax = 16 << 10
	// frameSlack is kept free for the frame's other fields when the output
	// is cut to fit.
	frameSlack = 4 << 10
	// framePasses bounds how often the output is cut and re-encoded before
	// it is dropped.
	framePasses = 4
)

// encodeFrame marshals v as JSON without HTML escaping or a trailing newline.
func encodeFrame(v interface{}) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}

// frameText makes s valid UTF-8 and cuts it to max bytes. It reports
// whether it cut.
func frameText(s string, max int) (string, bool) {
	s = strings.ToValidUTF8(s, "�")
	if len(s) <= max {
		return s, false
	}
	return truncateUTF8(s, max), true
}

// encodeOutputFrame encodes build(output, truncated) so the encoded frame is
// at most jobFrameMax bytes. The output is capped at scriptOutputMax raw,
// then cut in proportion to the overshoot and encoded again, at most
// framePasses times, after which it is dropped. truncated is set whenever
// output was cut.
func encodeOutputFrame(build func(output string, truncated bool) interface{}, output string, truncated bool) ([]byte, error) {
	out, cut := frameText(output, scriptOutputMax)
	truncated = truncated || cut
	for pass := 0; pass < framePasses; pass++ {
		b, err := encodeFrame(build(out, truncated))
		if err != nil {
			return nil, err
		}
		if len(b) <= jobFrameMax {
			return b, nil
		}
		n := int(int64(len(out)) * int64(jobFrameMax-frameSlack) / int64(len(b)))
		if n >= len(out) {
			n = len(out) - 1
		}
		if n < 0 {
			n = 0
		}
		out = truncateUTF8(out, n)
		truncated = true
	}
	b, err := encodeFrame(build("", true))
	if err != nil {
		return nil, err
	}
	if len(b) > jobFrameMax {
		return nil, fmt.Errorf("frame exceeds %d bytes without output", jobFrameMax)
	}
	return b, nil
}

// commandResultPayload is the legacy command_result payload. Its wire shape
// is unchanged: output_truncated appears only when output was cut.
type commandResultPayload struct {
	Error           string `json:"error"`
	Output          string `json:"output"`
	OutputTruncated bool   `json:"output_truncated,omitempty"`
}
