// TCP-forward channel, agent side (docs/sah-tcp-protocol.md).
// Threats: a stream dialing something the lease did not sign (the target is
// part of the signed payload; the agent dials only the signed host and port,
// by IP, never a name), an SSRF pivot (tcp_policy.go: the local --tcp-allow
// list, deny by default, and the always-refused classes, checked on the exact
// address dialed), a stream outliving its lease or deadline (a watcher ends
// it at the lease expiry, the deadline, the idle timeout or the byte cap
// sent in tcp_open), one stream starving the others or the agent's memory
// (credit.go: the agent stops reading the target while its credit is zero;
// bytes from the server are bounded by the credit window and a server that
// overruns it drops the whole connection), and a slow target blocking the
// agent (each stream has its own writer goroutine; a write to the target
// blocks only that stream). At most 64 streams per connection, separate from
// the PTY slots. Does NOT inspect or record content (TCP §9), and does NOT
// verify idle_s and max_bytes (they ride the authenticated control-plane
// socket, not the lease).
package main

import (
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	tcpMaxStreams  = 64
	tcpMaxDeadline = 7*24*time.Hour + time.Minute
	tcpReadBuf     = 32 * 1024
)

var (
	// tcpAllowRules is the parsed --tcp-allow flag. Empty refuses everything.
	tcpAllowRules []tcpAllowRule
	// tcpDialTimeout is TCP §5's 10 s; tests shorten it.
	tcpDialTimeout = 10 * time.Second
	// tcpWatchEvery is how often a stream checks its lease, deadline and idle time.
	tcpWatchEvery = 200 * time.Millisecond
	// tcpDial dials one IP address; tests replace it to simulate failures.
	tcpDial = func(ap netip.AddrPort, timeout time.Duration) (net.Conn, error) {
		network := "tcp4"
		if ap.Addr().Is6() {
			network = "tcp6"
		}
		return (&net.Dialer{Timeout: timeout}).Dial(network, ap.String())
	}
)

func init() {
	registerCapability("tcp", func() bool { return true })
}

// channelConn is the channel state of one control-plane connection: the
// credit mux and the live TCP streams. It ends with the connection.
type channelConn struct {
	out    ptyOut
	hostID string
	mux    *creditMux

	// stateDir holds interrupted file uploads (file_uploads.go); empty in
	// tests that do not resume.
	stateDir string

	mu     sync.Mutex
	tcp    map[string]*tcpStream
	files  map[string]*fileSession
	closed bool
}

func newChannelConn(out ptyOut, hostID string) *channelConn {
	return &channelConn{out: out, hostID: hostID, mux: newCreditMux(out), tcp: map[string]*tcpStream{}, files: map[string]*fileSession{}}
}

type tcpOpenMsg struct {
	Type      string `json:"type"`
	SessionID string `json:"session_id"`
	Target    struct {
		Host string `json:"host"`
		Port int    `json:"port"`
	} `json:"target"`
	DeadlineUnix int64       `json:"deadline_unix"`
	IdleS        int64       `json:"idle_s"`
	MaxBytes     int64       `json:"max_bytes"`
	Lease        *Lease      `json:"lease"`
	Bytes        interface{} `json:"bytes"`
}

// handle processes a channel frame. It reports whether the type was a
// channel frame, and returns an error only for a fatal violation (the
// caller drops the connection).
func (c *channelConn) handle(typ string, message []byte) (bool, error) {
	if handled, err := c.handleFile(typ, message); handled {
		return true, err
	}
	switch typ {
	case "tcp_open", "tcp_renew", "tcp_eof", "tcp_stop", "tcp_credit":
	default:
		return false, nil
	}
	var msg tcpOpenMsg
	if err := json.Unmarshal(message, &msg); err != nil {
		log.Printf("rejected malformed %s", typ)
		return true, nil
	}
	now := time.Now()
	switch typ {
	case "tcp_open":
		c.openTCP(msg, now)
	case "tcp_renew":
		if err := c.renewTCP(msg.SessionID, msg.Lease, now); err != nil {
			log.Printf("tcp_renew refused: %s", err.Error())
		}
	case "tcp_eof":
		if s := c.lookup(msg.SessionID); s != nil {
			s.queueEOF()
		}
	case "tcp_stop":
		if s := c.lookup(msg.SessionID); s != nil {
			s.end("stopped")
		}
	case "tcp_credit":
		n, ok := creditBytes(msg.Bytes)
		if !ok {
			if c.lookup(msg.SessionID) != nil {
				return true, errCreditOverflow
			}
			return true, nil
		}
		if err := c.mux.Grant(msg.SessionID, n); err != nil {
			return true, err
		}
	}
	return true, nil
}

// data handles a binary frame from the server: [1-byte id length][id][bytes].
// Bytes past the stream's credit window are a fatal violation.
func (c *channelConn) data(frame []byte) error {
	if len(frame) < 1 || int(frame[0]) == 0 || len(frame) < 1+int(frame[0]) {
		return nil
	}
	n := int(frame[0])
	sid := string(frame[1 : 1+n])
	payload := frame[1+n:]
	if err := c.mux.Receive(sid, len(payload)); err != nil {
		return err
	}
	if strings.HasPrefix(sid, "fls_") {
		c.fileData(sid, payload)
		return nil
	}
	if s := c.lookup(sid); s != nil {
		s.queueData(payload)
	}
	return nil
}

func (c *channelConn) lookup(id string) *tcpStream {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.tcp[id]
}

// close ends every stream with reason (best effort tcp_closed) and stops
// the mux. Safe to call more than once.
func (c *channelConn) close(reason string) {
	c.mu.Lock()
	c.closed = true
	live := make([]*tcpStream, 0, len(c.tcp))
	for _, s := range c.tcp {
		live = append(live, s)
	}
	files := make([]*fileSession, 0, len(c.files))
	for _, s := range c.files {
		files = append(files, s)
	}
	c.mu.Unlock()
	for _, s := range live {
		s.end(reason)
	}
	for _, s := range files {
		s.end(reason)
	}
	c.mux.Stop()
}

func tcpStatusError(out ptyOut, sid, code string) {
	_ = out.WriteJSON(ResponseMessage{Type: "tcp_status", SessionID: sid, Payload: map[string]string{"error": code}})
}

// openTCP authorizes a tcp_open and dials in the background. Every refusal
// is a tcp_status error with a contract code.
func (c *channelConn) openTCP(msg tcpOpenMsg, now time.Time) {
	sid := msg.SessionID
	if !tcpSessionRe.MatchString(sid) {
		log.Printf("tcp_open refused: bad session id")
		tcpStatusError(c.out, "", "internal")
		return
	}
	host, port := msg.Target.Host, msg.Target.Port
	deadline := time.Unix(msg.DeadlineUnix, 0)
	if !deadline.After(now) || deadline.Sub(now) > tcpMaxDeadline {
		tcpStatusError(c.out, sid, "lease_required")
		return
	}
	payload, err := tcpLeasePayload(sid, msg.DeadlineUnix, "start", host, port)
	if err != nil {
		tcpStatusError(c.out, sid, "lease_required")
		return
	}
	// The lease signs the target: the agent dials only what was signed.
	if err := authorizeCommand(c.hostID, "tcp", payload, msg.Lease, now); err != nil {
		log.Printf("tcp refused: %s", err.Error())
		tcpStatusError(c.out, sid, "lease_required")
		return
	}
	if msg.IdleS <= 0 || msg.MaxBytes <= 0 {
		tcpStatusError(c.out, sid, "internal")
		return
	}
	addr, local, code := tcpTargetAddr(host)
	if code != "" {
		log.Printf("tcp refused: target in a refused class")
		tcpStatusError(c.out, sid, code)
		return
	}
	if !tcpAllowed(tcpAllowRules, addr, local, port) {
		log.Printf("tcp refused: target not in --tcp-allow")
		tcpStatusError(c.out, sid, "target_denied_agent")
		return
	}
	leaseExp := time.Unix(msg.Lease.ExpiresUnix, 0)
	if leaseExp.After(deadline) {
		leaseExp = deadline
	}
	s := &tcpStream{
		c:            c,
		id:           sid,
		host:         host,
		port:         port,
		deadline:     deadline,
		idle:         time.Duration(msg.IdleS) * time.Second,
		maxBytes:     msg.MaxBytes,
		leaseExp:     leaseExp,
		lastActivity: now,
		done:         make(chan struct{}),
		watchEvery:   tcpWatchEvery,
		dialFn:       tcpDial,
		dialWait:     tcpDialTimeout,
	}
	s.wcond = sync.NewCond(&s.mu)
	c.mu.Lock()
	if c.closed || c.tcp[sid] != nil || len(c.tcp) >= tcpMaxStreams {
		c.mu.Unlock()
		log.Printf("tcp refused: duplicate session or no free stream")
		tcpStatusError(c.out, sid, "cap_reached")
		return
	}
	c.tcp[sid] = s
	c.mu.Unlock()
	go s.dial(netip.AddrPortFrom(addr, uint16(port)))
}

func (c *channelConn) renewTCP(sid string, lease *Lease, now time.Time) error {
	s := c.lookup(sid)
	if s == nil {
		return errors.New("unknown_session")
	}
	payload, err := tcpLeasePayload(sid, s.deadline.Unix(), "renew", s.host, s.port)
	if err != nil {
		return err
	}
	if err := authorizeCommand(c.hostID, "tcp", payload, lease, now); err != nil {
		return err
	}
	exp := time.Unix(lease.ExpiresUnix, 0)
	if exp.After(s.deadline) {
		exp = s.deadline
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ended {
		return errors.New("session_ended")
	}
	if exp.After(s.leaseExp) {
		s.leaseExp = exp
	}
	return nil
}

// dialErrorCode maps a dial failure to a TCP §7 code.
func dialErrorCode(err error) string {
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return "connect_timeout"
	}
	if errors.Is(err, syscall.ECONNREFUSED) {
		return "connect_refused"
	}
	if errors.Is(err, syscall.EHOSTUNREACH) || errors.Is(err, syscall.ENETUNREACH) {
		return "host_unreachable"
	}
	return "internal"
}

type tcpStream struct {
	c        *channelConn
	id       string
	host     string
	port     int
	deadline time.Time
	idle     time.Duration
	maxBytes int64
	// Captured from the package settings when the stream opens.
	watchEvery time.Duration
	dialFn     func(netip.AddrPort, time.Duration) (net.Conn, error)
	dialWait   time.Duration

	mu           sync.Mutex
	wcond        *sync.Cond
	conn         net.Conn
	leaseExp     time.Time
	lastActivity time.Time
	bytesIn      int64 // target -> client (read from the target)
	bytesOut     int64 // client -> target (accepted from the server)
	wq           [][]byte
	eofQueued    bool
	targetEOF    bool // the target sent FIN and tcp_eof went out
	serverEOF    bool // the client's FIN was applied with shutdown(SHUT_WR)
	ended        bool
	reason       string
	done         chan struct{}
}

func (s *tcpStream) dial(ap netip.AddrPort) {
	conn, err := s.dialFn(ap, s.dialWait)
	if err != nil {
		code := dialErrorCode(err)
		log.Printf("tcp %s dial failed: %s", s.id, code)
		s.c.mu.Lock()
		if s.c.tcp[s.id] == s {
			delete(s.c.tcp, s.id)
		}
		s.c.mu.Unlock()
		s.mu.Lock()
		stopped := s.ended
		s.ended = true
		s.mu.Unlock()
		if stopped {
			s.sendClosed()
			return
		}
		tcpStatusError(s.c.out, s.id, code)
		return
	}
	s.mu.Lock()
	if s.ended {
		s.mu.Unlock()
		_ = conn.Close()
		s.finish()
		return
	}
	if err := s.c.mux.Open(s.id, "tcp", tcpCreditWindow); err != nil {
		s.mu.Unlock()
		_ = conn.Close()
		s.end("stopped")
		return
	}
	s.conn = conn
	s.lastActivity = time.Now()
	s.mu.Unlock()
	_ = s.c.out.WriteJSON(ResponseMessage{Type: "tcp_status", SessionID: s.id, Payload: map[string]string{
		"status": "connected",
		"peer":   ap.String(),
	}})
	go s.readLoop()
	go s.writeLoop()
	go s.watch()
}

// readLoop reads the target. mux.Write blocks while the stream has no
// credit, so the agent stops reading the target.
func (s *tcpStream) readLoop() {
	buf := make([]byte, tcpReadBuf)
	for {
		n, err := s.conn.Read(buf)
		if n > 0 {
			s.mu.Lock()
			if s.bytesIn+s.bytesOut+int64(n) > s.maxBytes {
				s.mu.Unlock()
				s.end("byte_cap")
				return
			}
			s.bytesIn += int64(n)
			s.lastActivity = time.Now()
			s.mu.Unlock()
			if werr := s.c.mux.Write(s.id, buf[:n]); werr != nil {
				return
			}
		}
		if err == nil {
			continue
		}
		if errors.Is(err, io.EOF) {
			// Every byte read so far reaches the server before tcp_eof.
			if s.c.mux.Flush(s.id) != nil {
				return
			}
			s.mu.Lock()
			if s.ended {
				s.mu.Unlock()
				return
			}
			s.targetEOF = true
			s.mu.Unlock()
			_ = s.c.out.WriteJSON(ResponseMessage{Type: "tcp_eof", SessionID: s.id})
			s.maybeClosed()
			return
		}
		s.end("reset")
		return
	}
}

// writeLoop is the only writer to the target, so a target that stops
// reading blocks this goroutine and nothing else.
func (s *tcpStream) writeLoop() {
	for {
		s.mu.Lock()
		for len(s.wq) == 0 && !s.eofQueued && !s.ended {
			s.wcond.Wait()
		}
		if s.ended {
			s.mu.Unlock()
			return
		}
		if len(s.wq) == 0 && s.eofQueued {
			s.eofQueued = false
			s.mu.Unlock()
			if tc, ok := s.conn.(interface{ CloseWrite() error }); ok {
				if err := tc.CloseWrite(); err != nil {
					s.end("reset")
					return
				}
			}
			s.mu.Lock()
			s.serverEOF = true
			s.mu.Unlock()
			s.maybeClosed()
			continue
		}
		data := s.wq[0]
		s.wq = s.wq[1:]
		s.mu.Unlock()
		if _, err := s.conn.Write(data); err != nil {
			s.end("reset")
			return
		}
		_ = s.c.mux.Drained(s.id, len(data))
	}
}

// watch ends the stream at the lease expiry, the deadline or the idle limit.
func (s *tcpStream) watch() {
	t := time.NewTicker(s.watchEvery)
	defer t.Stop()
	for {
		select {
		case <-s.done:
			return
		case now := <-t.C:
			s.mu.Lock()
			reason := ""
			switch {
			case !now.Before(s.deadline):
				reason = "max_duration"
			case !now.Before(s.leaseExp):
				reason = "stopped"
			case now.Sub(s.lastActivity) >= s.idle:
				reason = "idle_timeout"
			}
			s.mu.Unlock()
			if reason != "" {
				log.Printf("tcp %s ending: %s", s.id, reason)
				s.end(reason)
				return
			}
		}
	}
}

// queueData accepts bytes from the server for the target. The credit
// window (mux.Receive) bounds what can be queued.
func (s *tcpStream) queueData(p []byte) {
	if len(p) == 0 {
		return
	}
	s.mu.Lock()
	if s.ended || s.conn == nil {
		s.mu.Unlock()
		return
	}
	if s.eofQueued || s.serverEOF {
		s.mu.Unlock()
		log.Printf("tcp %s: bytes after tcp_eof ignored", s.id)
		return
	}
	if s.bytesIn+s.bytesOut+int64(len(p)) > s.maxBytes {
		s.mu.Unlock()
		s.end("byte_cap")
		return
	}
	s.bytesOut += int64(len(p))
	s.lastActivity = time.Now()
	s.wq = append(s.wq, append([]byte(nil), p...))
	s.wcond.Broadcast()
	s.mu.Unlock()
}

// queueEOF applies the client's FIN after every byte queued before it.
func (s *tcpStream) queueEOF() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ended || s.conn == nil || s.eofQueued || s.serverEOF {
		return
	}
	s.eofQueued = true
	s.wcond.Broadcast()
}

func (s *tcpStream) maybeClosed() {
	s.mu.Lock()
	both := s.targetEOF && s.serverEOF
	s.mu.Unlock()
	if both {
		s.end("closed")
	}
}

// end stops the stream once: closes the target, forgets the credit stream
// and reports tcp_closed with the agent's byte counts.
func (s *tcpStream) end(reason string) {
	s.mu.Lock()
	if s.ended {
		s.mu.Unlock()
		return
	}
	s.ended = true
	s.reason = reason
	conn := s.conn
	s.wq = nil
	s.wcond.Broadcast()
	s.mu.Unlock()
	if conn == nil {
		// Still dialing: dial() sees ended and reports tcp_closed.
		return
	}
	_ = conn.Close()
	s.finish()
}

// finish forgets the stream and sends tcp_closed.
func (s *tcpStream) finish() {
	select {
	case <-s.done:
	default:
		close(s.done)
	}
	s.c.mux.Close(s.id)
	s.c.mu.Lock()
	if s.c.tcp[s.id] == s {
		delete(s.c.tcp, s.id)
	}
	s.c.mu.Unlock()
	s.sendClosed()
}

func (s *tcpStream) sendClosed() {
	s.mu.Lock()
	reason := s.reason
	if reason == "" {
		reason = "stopped"
	}
	in, out := s.bytesIn, s.bytesOut
	s.mu.Unlock()
	log.Printf("tcp %s closed: %s in=%s out=%s", s.id, reason, strconv.FormatInt(in, 10), strconv.FormatInt(out, 10))
	_ = s.c.out.WriteJSON(ResponseMessage{Type: "tcp_closed", SessionID: s.id, Payload: map[string]interface{}{
		"reason":    reason,
		"bytes_in":  in,
		"bytes_out": out,
	}})
}
