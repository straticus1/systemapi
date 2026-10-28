package main

import (
	"encoding/json"
	"strings"
	"testing"
)

// rawOut keeps the exact bytes of each text frame.
type rawOut struct{ texts [][]byte }

func (r *rawOut) WriteJSON(v interface{}) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	r.texts = append(r.texts, b)
	return nil
}
func (r *rawOut) WriteBinary(b []byte) error { return nil }
func (r *rawOut) WriteText(b []byte) error {
	r.texts = append(r.texts, append([]byte(nil), b...))
	return nil
}

func decodeResult(t *testing.T, b []byte) (string, map[string]interface{}) {
	t.Helper()
	var m struct {
		Type      string                 `json:"type"`
		RequestID string                 `json:"request_id"`
		Payload   map[string]interface{} `json:"payload"`
	}
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("frame is not JSON: %v", err)
	}
	if m.Type != "command_result" || m.RequestID != "req-1" {
		t.Fatalf("frame=%s", b[:min(len(b), 200)])
	}
	return m.Type, m.Payload
}

func TestCommandResultFrameCap(t *testing.T) {
	cases := []struct {
		name      string
		output    string
		truncated bool
	}{
		{"1 MiB of <", strings.Repeat("<", 1<<20), true},
		{"1 MiB of \\x01", strings.Repeat("\x01", 1<<20), true},
		// A run of invalid bytes becomes one U+FFFD, so nothing is cut.
		{"invalid utf8", "a" + strings.Repeat("\xff", 1<<20), false},
		{"small", "hello <b>&</b>\n", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := &rawOut{}
			writeCommandResult(out, "req-1", "", tc.output, false)
			if len(out.texts) != 1 {
				t.Fatalf("frames=%d", len(out.texts))
			}
			b := out.texts[0]
			if len(b) > jobFrameMax {
				t.Fatalf("encoded frame %d > %d", len(b), jobFrameMax)
			}
			_, p := decodeResult(t, b)
			got, _ := p["output_truncated"].(bool)
			if got != tc.truncated {
				t.Fatalf("output_truncated=%v want %v", got, tc.truncated)
			}
			if !tc.truncated {
				if p["output"] != strings.ToValidUTF8(tc.output, "\uFFFD") {
					t.Fatalf("output=%q", p["output"])
				}
				if _, present := p["output_truncated"]; present {
					t.Fatal("output_truncated present on an uncut result")
				}
				if strings.Contains(tc.output, "<b>") && !strings.Contains(string(b), "<b>&</b>") {
					t.Fatalf("HTML was escaped: %s", b)
				}
			} else if len(p["output"].(string)) == 0 {
				t.Fatal("all output dropped when a cut would fit")
			}
		})
	}
}

func TestCommandResultCapsErrorText(t *testing.T) {
	out := &rawOut{}
	writeCommandResult(out, "req-1", strings.Repeat("e", 1<<20), strings.Repeat("o", 1<<20), false)
	b := out.texts[0]
	if len(b) > jobFrameMax {
		t.Fatalf("encoded frame %d", len(b))
	}
	_, p := decodeResult(t, b)
	if n := len(p["error"].(string)); n != frameErrMax {
		t.Fatalf("error length %d", n)
	}
}

func TestScriptOutputCapped(t *testing.T) {
	engine := newTestEngine(&Entitlements{})
	out, err := engine.Execute("def f():\n  s = '<' * 4096\n  for i in range(300):\n    print(s)\nf()\n")
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != scriptOutputMax || !engine.outputTruncated {
		t.Fatalf("len=%d truncated=%v", len(out), engine.outputTruncated)
	}
	engine = newTestEngine(&Entitlements{})
	if _, err := engine.Execute("print('x')\n"); err != nil || engine.outputTruncated {
		t.Fatalf("err=%v truncated=%v", err, engine.outputTruncated)
	}
}
