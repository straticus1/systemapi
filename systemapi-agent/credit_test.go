package main

import (
	"bytes"
	"encoding/json"
	"sync"
	"testing"
	"time"
)

// recordingOut captures frames written to the agent socket.
type recordingOut struct {
	mu     sync.Mutex
	binary [][]byte
	json   []map[string]interface{}
}

func (r *recordingOut) WriteJSON(v interface{}) error {
	b, _ := json.Marshal(v)
	var m map[string]interface{}
	_ = json.Unmarshal(b, &m)
	r.mu.Lock()
	r.json = append(r.json, m)
	r.mu.Unlock()
	return nil
}

func (r *recordingOut) WriteBinary(b []byte) error {
	r.mu.Lock()
	r.binary = append(r.binary, append([]byte(nil), b...))
	r.mu.Unlock()
	return nil
}

func (r *recordingOut) frames() [][]byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([][]byte(nil), r.binary...)
}

func creditWait(t *testing.T, what string, fn func() bool) {
	t.Helper()
	end := time.Now().Add(3 * time.Second)
	for !fn() {
		if time.Now().After(end) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

func frameID(f []byte) (string, []byte) {
	n := int(f[0])
	return string(f[1 : 1+n]), f[1+n:]
}

func TestCreditWindowSizes(t *testing.T) {
	if tcpCreditWindow != 256*1024 || fileCreditWindow != 8*1024*1024 || creditMaxTurn != 64*1024 {
		t.Fatal("window constants drifted from the contracts")
	}
}

func TestCreditSenderStopsAtWindowAndResumesOnGrant(t *testing.T) {
	out := &recordingOut{}
	m := newCreditMux(out)
	defer m.Stop()
	const id = "tcs_aaaaaaaaaaaaaaaa"
	if err := m.Open(id, "tcp", 4096); err != nil {
		t.Fatal(err)
	}
	if err := m.Open(id, "tcp", 4096); err != errStreamExists {
		t.Fatalf("duplicate open: %v", err)
	}
	data := bytes.Repeat([]byte("x"), 10000)
	wrote := make(chan error, 1)
	go func() { wrote <- m.Write(id, data) }()
	creditWait(t, "window sent", func() bool {
		total := 0
		for _, f := range out.frames() {
			_, b := frameID(f)
			total += len(b)
		}
		return total == 4096
	})
	time.Sleep(20 * time.Millisecond)
	total := 0
	for _, f := range out.frames() {
		_, b := frameID(f)
		total += len(b)
	}
	if total != 4096 {
		t.Fatalf("sent %d bytes with a 4096 window", total)
	}
	// All 10000 bytes fit in the queue (64 KiB), so Write may already have
	// returned; what matters is that nothing past the window was sent.
	if err := m.Grant(id, 4096); err != nil {
		t.Fatal(err)
	}
	sent := func() int {
		total := 0
		for _, f := range out.frames() {
			_, b := frameID(f)
			total += len(b)
		}
		return total
	}
	creditWait(t, "second window", func() bool { return sent() == 8192 })
	if err := m.Grant(id, 4096); err != nil {
		t.Fatal(err)
	}
	creditWait(t, "all bytes", func() bool {
		total := 0
		for _, f := range out.frames() {
			_, b := frameID(f)
			total += len(b)
		}
		return total == 10000
	})
	if err := <-wrote; err != nil {
		t.Fatal(err)
	}
}

func TestCreditWriteBlocksWhileNoCredit(t *testing.T) {
	out := &recordingOut{}
	m := newCreditMux(out)
	defer m.Stop()
	const id = "tcs_bbbbbbbbbbbbbbbb"
	if err := m.Open(id, "tcp", 1024); err != nil {
		t.Fatal(err)
	}
	// 1024 sent + 64 KiB queued; the rest must block the producer.
	done := make(chan error, 1)
	go func() { done <- m.Write(id, make([]byte, 1024+creditMaxTurn+1)) }()
	select {
	case err := <-done:
		t.Fatalf("Write returned with no credit: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	m.Close(id)
	select {
	case err := <-done:
		if err != errStreamClosed {
			t.Fatalf("closed stream: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not unblock the writer")
	}
}

func TestCreditRoundRobinCapsTurnAt64KiB(t *testing.T) {
	out := &recordingOut{}
	m := newCreditMux(out)
	const bulk = "fls_bulkbulkbulkbulk"
	const small = "tcs_smallsmallsmall0"
	if err := m.Open(bulk, "file", fileCreditWindow); err != nil {
		t.Fatal(err)
	}
	if err := m.Open(small, "tcp", tcpCreditWindow); err != nil {
		t.Fatal(err)
	}
	go func() { _ = m.Write(bulk, make([]byte, 1<<20)) }()
	creditWait(t, "bulk started", func() bool { return len(out.frames()) > 0 })
	if err := m.Write(small, []byte("ping")); err != nil {
		t.Fatal(err)
	}
	creditWait(t, "small sent", func() bool {
		for _, f := range out.frames() {
			if id, _ := frameID(f); id == small {
				return true
			}
		}
		return false
	})
	m.Stop()
	frames := out.frames()
	bulkBefore := 0
	for _, f := range frames {
		id, b := frameID(f)
		if len(b) > creditMaxTurn {
			t.Fatalf("frame of %d bytes exceeds one turn", len(b))
		}
		if id == small {
			break
		}
		bulkBefore++
	}
	// The small stream waits at most one bulk turn after it has data; the
	// bulk producer may have been ahead by the frames already written.
	if bulkBefore > 20 {
		t.Fatalf("small stream waited behind %d bulk frames", bulkBefore)
	}
}

func TestCreditOverrunAndOverflowAreViolations(t *testing.T) {
	out := &recordingOut{}
	m := newCreditMux(out)
	defer m.Stop()
	const id = "tcs_cccccccccccccccc"
	if err := m.Open(id, "tcp", 1000); err != nil {
		t.Fatal(err)
	}
	if err := m.Receive(id, 1000); err != nil {
		t.Fatal(err)
	}
	if err := m.Receive(id, 1); err != errCreditOverrun {
		t.Fatalf("overrun: %v", err)
	}
	if err := m.Grant(id, 1); err != errCreditOverflow {
		t.Fatalf("credit past the window: %v", err)
	}
	if err := m.Grant(id, 0); err != errCreditOverflow {
		t.Fatalf("zero credit: %v", err)
	}
	if err := m.Receive("unknown", 1<<30); err != nil {
		t.Fatalf("unknown stream: %v", err)
	}
}

func TestCreditDrainedReturnsBatchedCredit(t *testing.T) {
	out := &recordingOut{}
	m := newCreditMux(out)
	defer m.Stop()
	const id = "fls_dddddddddddddddd"
	if err := m.Open(id, "file", 1000); err != nil {
		t.Fatal(err)
	}
	if err := m.Receive(id, 1000); err != nil {
		t.Fatal(err)
	}
	_ = m.Drained(id, 100)
	if len(out.json) != 0 {
		t.Fatal("credit returned before a quarter window drained")
	}
	_ = m.Drained(id, 200)
	if len(out.json) != 1 || out.json[0]["type"] != "file_credit" || out.json[0]["session_id"] != id || out.json[0]["bytes"] != float64(300) {
		t.Fatalf("credit frame: %+v", out.json)
	}
	// The returned credit is reusable; more than that is still an overrun.
	if err := m.Receive(id, 300); err != nil {
		t.Fatal(err)
	}
	if err := m.Receive(id, 1); err != errCreditOverrun {
		t.Fatalf("overrun after return: %v", err)
	}
}

func TestCreditBytesParse(t *testing.T) {
	for _, c := range []struct {
		v  interface{}
		ok bool
	}{{float64(10), true}, {float64(0), false}, {float64(-1), false}, {1.5, false}, {"10", false}, {nil, false}, {float64(1 << 41), false}} {
		if _, ok := creditBytes(c.v); ok != c.ok {
			t.Fatalf("%v: %v", c.v, ok)
		}
	}
}

func TestCreditStopUnblocksWriters(t *testing.T) {
	m := newCreditMux(&recordingOut{})
	const id = "tcs_eeeeeeeeeeeeeeee"
	_ = m.Open(id, "tcp", 1)
	done := make(chan error, 1)
	go func() { done <- m.Write(id, make([]byte, 2*creditMaxTurn)) }()
	time.Sleep(20 * time.Millisecond)
	m.Stop()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("Write succeeded after Stop")
		}
	case <-time.After(time.Second):
		t.Fatal("Stop did not unblock the writer")
	}
	if err := m.Open("tcs_ffffffffffffffff", "tcp", 1); err != errMuxStopped {
		t.Fatalf("open after stop: %v", err)
	}
}
