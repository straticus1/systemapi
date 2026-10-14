// Threats: an agent that silently stops managing its host after a network
// blip, a reconnect storm against the control plane, and an agent that keeps
// retrying with a rejected key or a changed control key. The agent redials
// with jittered exponential backoff (1 s doubling to 60 s), ends every
// terminal session when a connection drops, and exits non-zero only on a
// fatal error: a rejected API key (HTTP 401/403), a permanent enrollment
// refusal, or a changed control public key. Channel streams (tcp.go, file.go) are
// per connection and end with it; a control plane that overruns a stream's
// credit window gets its connection dropped.
package main

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"path/filepath"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// fatalError stops the reconnect loop.
type fatalError struct{ err error }

func (f fatalError) Error() string { return f.err.Error() }
func (f fatalError) Unwrap() error { return f.err }

func isFatal(err error) bool {
	var f fatalError
	return errors.As(err, &f)
}

// transientEnrollErrors are server-side conditions worth retrying.
var transientEnrollErrors = map[string]bool{
	"signer_unavailable": true,
	"enroll_required":    true,
	"enroll_failed":      true,
}

type agentConn struct {
	url            string
	header         http.Header
	dialer         websocket.Dialer
	st             *agentState
	statePath      string
	hostname       string
	telemetryEvery time.Duration
	enrollTimeout  time.Duration
	minBackoff     time.Duration
	maxBackoff     time.Duration
	// telemetry is gatherTelemetry outside tests.
	telemetry func(hostname string) (TelemetryPayload, error)
}

// jittered returns a delay in [d/2, d].
func jittered(d time.Duration) time.Duration {
	half := int64(d / 2)
	if half <= 0 {
		return d
	}
	n, err := rand.Int(rand.Reader, big.NewInt(half+1))
	if err != nil {
		return d
	}
	return time.Duration(half + n.Int64())
}

// run serves connections until stop closes (returns nil) or a fatal error.
func (a *agentConn) run(stop <-chan struct{}) error {
	backoff := a.minBackoff
	for {
		enrolled, err := a.runOnce(stop)
		stopAllSessions("agent_disconnected", 3*time.Second)
		if err != nil && isFatal(err) {
			return err
		}
		select {
		case <-stop:
			return nil
		default:
		}
		if enrolled {
			backoff = a.minBackoff
		}
		wait := jittered(backoff)
		log.Printf("control plane connection lost (%v); reconnecting in %s", err, wait.Round(time.Millisecond))
		select {
		case <-stop:
			return nil
		case <-time.After(wait):
		}
		backoff *= 2
		if backoff > a.maxBackoff {
			backoff = a.maxBackoff
		}
	}
}

// runOnce dials, enrolls and serves one connection. It reports whether the
// connection enrolled.
func (a *agentConn) runOnce(stop <-chan struct{}) (bool, error) {
	log.Printf("dialing control plane host_id=%s", a.st.HostID)
	c, resp, err := a.dialer.Dial(a.url, a.header)
	if err != nil {
		if resp != nil && (resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden) {
			return false, fatalError{fmt.Errorf("control plane rejected the API key (HTTP %d)", resp.StatusCode)}
		}
		return false, err
	}
	defer c.Close()
	c.SetReadLimit(256 * 1024)
	out := &wsWriter{c: c}
	// Channel streams (TCP forward) live and die with this connection.
	ch := newChannelConn(out, a.st.HostID)
	ch.stateDir = filepath.Dir(a.statePath)
	defer ch.close("agent_disconnected")

	enrolled := make(chan error, 1)
	var enrollOnce sync.Once
	signalEnroll := func(err error) {
		enrollOnce.Do(func() { enrolled <- err })
	}
	done := make(chan struct{})
	stateDir := filepath.Dir(a.statePath)

	go func() {
		defer close(done)
		for {
			mt, message, err := c.ReadMessage()
			if err != nil {
				signalEnroll(err)
				return
			}
			if mt == websocket.BinaryMessage {
				// Channel data. A server past a stream's credit window is a
				// fatal violation: drop the connection.
				if err := ch.data(message); err != nil {
					log.Printf("channel credit violation (%v); dropping the connection", err)
					_ = c.Close()
				}
				continue
			}
			var peek struct {
				Type          string `json:"type"`
				Error         string `json:"error"`
				HostID        string `json:"host_id"`
				ControlPubKey string `json:"control_pubkey"`
			}
			if err := json.Unmarshal(message, &peek); err != nil {
				log.Printf("rejected malformed message")
				continue
			}
			switch peek.Type {
			case "enrolled":
				if err := acceptEnrolled(a.st, a.statePath, peek.HostID, peek.ControlPubKey); err != nil {
					log.Printf("enroll pin failed: %v", err)
					signalEnroll(fatalError{err})
					return
				}
				signalEnroll(nil)
			case "enroll_error":
				log.Printf("enroll rejected: %s", peek.Error)
				err := fmt.Errorf("enroll_error:%s", peek.Error)
				if !transientEnrollErrors[peek.Error] {
					err = fatalError{err}
				}
				signalEnroll(err)
				return
			default:
				handled, err := ch.handle(peek.Type, message)
				if err != nil {
					log.Printf("channel credit violation (%v); dropping the connection", err)
					_ = c.Close()
					continue
				}
				if !handled {
					processIncomingMessage(out, a.st.HostID, stateDir, message)
				}
			}
		}
	}()

	telemetryTicker := time.NewTicker(a.telemetryEvery)
	defer telemetryTicker.Stop()
	enrollTimer := time.NewTimer(a.enrollTimeout)
	defer enrollTimer.Stop()
	enrolledOK := false

	for {
		select {
		case err := <-enrolled:
			if err != nil {
				return false, err
			}
			enrolledOK = true
			log.Printf("enrolled host_id=%s", a.st.HostID)
		case <-enrollTimer.C:
			if !enrolledOK {
				return false, errors.New("enrollment timed out")
			}
		case <-done:
			select {
			case err := <-enrolled:
				if err != nil {
					return enrolledOK, err
				}
			default:
			}
			return enrolledOK, errors.New("connection closed")
		case <-telemetryTicker.C:
			if !enrolledOK {
				continue
			}
			stats, err := a.telemetry(a.hostname)
			if err != nil {
				log.Printf("telemetry: %v", err)
				continue
			}
			if err := out.WriteJSON(ResponseMessage{Type: "telemetry", Payload: stats}); err != nil {
				return enrolledOK, err
			}
		case <-stop:
			log.Println("signal received, stopping terminal sessions and disconnecting")
			stopAllSessions("stopped", 3*time.Second)
			ch.close("stopped")
			_ = out.WriteClose()
			select {
			case <-done:
			case <-time.After(time.Second):
			}
			return enrolledOK, nil
		}
	}
}
