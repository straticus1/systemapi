// Threats: one SAH channel stream (TCP forward or file session) growing the
// agent's or the server's memory without bound, or starving the PTY and the
// other streams on the shared control-plane socket. Each stream has a credit
// window per direction (docs/sah-tcp-protocol.md §6: 256 KiB;
// docs/sah-file-protocol.md §6: 8 MiB per session). The sender is a single
// round-robin goroutine that writes at most 64 KiB per stream per turn and
// releases the socket's write lock between frames, so bulk data cannot hold
// the socket. A producer (the reader of a TCP target or a file) blocks in
// Write while its stream has no credit, so the agent stops reading the
// target. A server that sends past the window it was given, or returns more
// credit than it could owe, is a fatal violation (errCreditOverrun /
// errCreditOverflow): the caller drops the connection. Not used by PTY.
// Does NOT pace a peer that stays inside its window.
package main

import (
	"errors"
	"sync"
)

const (
	tcpCreditWindow  int64 = 256 * 1024
	fileCreditWindow int64 = 8 * 1024 * 1024
	creditMaxTurn          = 64 * 1024
)

var (
	errCreditOverrun  = errors.New("credit_overrun")
	errCreditOverflow = errors.New("credit_overflow")
	errStreamExists   = errors.New("stream_exists")
	errStreamClosed   = errors.New("stream_closed")
	errMuxStopped     = errors.New("mux_stopped")
)

type creditStream struct {
	id       string
	kind     string // "tcp" or "file": the credit frame is "<kind>_credit"
	window   int64
	returnAt int64

	sendCredit int64  // bytes the agent may still send to the server
	pending    []byte // queued for sending, at most creditMaxTurn
	inflight   int    // frames taken from pending but not yet written
	closed     bool

	inWindow          int64 // bytes the server sent that the agent has not credited back
	drainedUnreturned int64
}

// creditMux multiplexes channel streams onto the shared agent socket.
type creditMux struct {
	out     ptyOut
	mu      sync.Mutex
	cond    *sync.Cond
	streams map[string]*creditStream
	ring    []string
	next    int
	stopped bool
	done    chan struct{}
}

func newCreditMux(out ptyOut) *creditMux {
	m := &creditMux{out: out, streams: map[string]*creditStream{}, done: make(chan struct{})}
	m.cond = sync.NewCond(&m.mu)
	go m.run()
	return m
}

// Open registers a stream. window is per direction.
func (m *creditMux) Open(id, kind string, window int64) error {
	if id == "" || len(id) > 255 || window <= 0 {
		return errors.New("bad_stream")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.stopped {
		return errMuxStopped
	}
	if _, ok := m.streams[id]; ok {
		return errStreamExists
	}
	returnAt := window / 4
	if returnAt < 1 {
		returnAt = 1
	}
	m.streams[id] = &creditStream{id: id, kind: kind, window: window, returnAt: returnAt, sendCredit: window}
	m.ring = append(m.ring, id)
	return nil
}

// Close forgets a stream and unblocks its writers. Queued data is dropped
// only because the stream itself is over.
func (m *creditMux) Close(id string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.streams[id]
	if !ok {
		return
	}
	s.closed = true
	delete(m.streams, id)
	for i, r := range m.ring {
		if r == id {
			m.ring = append(m.ring[:i], m.ring[i+1:]...)
			if m.next > i {
				m.next--
			}
			break
		}
	}
	m.cond.Broadcast()
}

// Stop ends the sender and unblocks every writer.
func (m *creditMux) Stop() {
	m.mu.Lock()
	if !m.stopped {
		m.stopped = true
		for _, s := range m.streams {
			s.closed = true
		}
		m.cond.Broadcast()
	}
	m.mu.Unlock()
	<-m.done
}

// Write queues p for the stream, blocking while the stream's queue is full
// (that is, while it has no credit to drain the queue). It returns once all
// of p is queued, or an error when the stream or mux is closed.
func (m *creditMux) Write(id string, p []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for len(p) > 0 {
		s, ok := m.streams[id]
		if m.stopped {
			return errMuxStopped
		}
		if !ok || s.closed {
			return errStreamClosed
		}
		space := creditMaxTurn - len(s.pending)
		if space <= 0 {
			m.cond.Wait()
			continue
		}
		if space > len(p) {
			space = len(p)
		}
		s.pending = append(s.pending, p[:space]...)
		p = p[space:]
		m.cond.Broadcast()
	}
	return nil
}

// Flush blocks until every byte queued for the stream so far has been
// written to the socket, so a control frame sent next (tcp_eof, tcp_closed)
// cannot overtake the stream's data. It returns an error when the stream or
// the mux closes first.
func (m *creditMux) Flush(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for {
		if m.stopped {
			return errMuxStopped
		}
		s, ok := m.streams[id]
		if !ok || s.closed {
			return errStreamClosed
		}
		if len(s.pending) == 0 && s.inflight == 0 {
			return nil
		}
		m.cond.Wait()
	}
}

// Grant applies a "<kind>_credit" frame from the server. A non-positive
// amount or credit past the window is a violation.
func (m *creditMux) Grant(id string, n int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.streams[id]
	if !ok {
		return nil
	}
	if n <= 0 || s.sendCredit+n > s.window {
		return errCreditOverflow
	}
	s.sendCredit += n
	m.cond.Broadcast()
	return nil
}

// Receive accounts n bytes of data from the server. Past the window is a
// violation. Data for an unknown stream (just closed) is ignored.
func (m *creditMux) Receive(id string, n int) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.streams[id]
	if !ok {
		return nil
	}
	if n < 0 || s.inWindow+int64(n) > s.window {
		return errCreditOverrun
	}
	s.inWindow += int64(n)
	return nil
}

// Drained reports that n received bytes were written onward (to the target
// or the file). Credit goes back in batches of a quarter window; a server
// with no credit has a full window in flight, so batching cannot stall it.
func (m *creditMux) Drained(id string, n int) error {
	m.mu.Lock()
	s, ok := m.streams[id]
	if !ok || n <= 0 {
		m.mu.Unlock()
		return nil
	}
	s.drainedUnreturned += int64(n)
	if s.drainedUnreturned > s.inWindow {
		s.drainedUnreturned = s.inWindow
	}
	if s.drainedUnreturned < s.returnAt {
		m.mu.Unlock()
		return nil
	}
	ret := s.drainedUnreturned
	s.inWindow -= ret
	s.drainedUnreturned = 0
	kind := s.kind
	m.mu.Unlock()
	return m.out.WriteJSON(map[string]interface{}{"type": kind + "_credit", "session_id": id, "bytes": ret})
}

// pick returns the next stream, in ring order after the last one served,
// that has data and credit. Caller holds mu.
func (m *creditMux) pick() *creditStream {
	n := len(m.ring)
	for i := 0; i < n; i++ {
		idx := (m.next + i) % n
		s := m.streams[m.ring[idx]]
		if s != nil && len(s.pending) > 0 && s.sendCredit > 0 {
			m.next = (idx + 1) % n
			return s
		}
	}
	return nil
}

func (m *creditMux) run() {
	defer close(m.done)
	m.mu.Lock()
	for {
		if m.stopped {
			m.mu.Unlock()
			return
		}
		s := m.pick()
		if s == nil {
			m.cond.Wait()
			continue
		}
		take := len(s.pending)
		if int64(take) > s.sendCredit {
			take = int(s.sendCredit)
		}
		if take > creditMaxTurn {
			take = creditMaxTurn
		}
		frame := make([]byte, 0, 1+len(s.id)+take)
		frame = append(frame, byte(len(s.id)))
		frame = append(frame, s.id...)
		frame = append(frame, s.pending[:take]...)
		s.pending = append(s.pending[:0], s.pending[take:]...)
		s.sendCredit -= int64(take)
		s.inflight++
		m.cond.Broadcast()
		m.mu.Unlock()
		// The socket lock is taken per frame, so PTY frames interleave.
		_ = m.out.WriteBinary(frame)
		m.mu.Lock()
		s.inflight--
		m.cond.Broadcast()
	}
}

// creditBytes parses the "bytes" field of a decoded credit frame: a
// positive whole JSON number. Anything else is malformed.
func creditBytes(v interface{}) (int64, bool) {
	n, ok := v.(float64)
	if !ok || n <= 0 || n > 1<<40 || n != float64(int64(n)) {
		return 0, false
	}
	return int64(n), true
}
