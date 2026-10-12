package main

import (
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// CommandMessage is an incoming WebSocket message from the control plane.
type CommandMessage struct {
	Type         string        `json:"type"`
	Script       string        `json:"script"`
	Entitlements *Entitlements `json:"entitlements"`
	RequestID    string        `json:"request_id"`
	Data         string        `json:"data,omitempty"`
	Rows         int           `json:"rows,omitempty"`
	Cols         int           `json:"cols,omitempty"`
	Action       string        `json:"action,omitempty"`
	Lease        *Lease        `json:"lease,omitempty"`
}

// ResponseMessage is an outgoing WebSocket message.
type ResponseMessage struct {
	Type      string      `json:"type"`
	Payload   interface{} `json:"payload"`
	RequestID string      `json:"request_id,omitempty"`
}

func main() {
	serverURL := flag.String("server", "ws://localhost:3003/api/v1/systems/stream", "WebSocket stream URL")
	apiKeyFlag := flag.String("api-key", "", "API key; prefer the SYSTEMAPI_API_KEY environment variable")
	tenantFlag := flag.String("tenant", "", "tenant name (required)")
	hostnameFlag := flag.String("hostname", "", "hostname (default: this machine)")
	stateFlag := flag.String("state", "", "state file (default: ~/.systemapi/agent.json)")
	flag.Parse()

	apiKey := *apiKeyFlag
	if apiKey == "" {
		apiKey = os.Getenv("SYSTEMAPI_API_KEY")
	}
	if apiKey == "" {
		fmt.Fprintln(os.Stderr, "Error: set SYSTEMAPI_API_KEY or pass --api-key")
		os.Exit(2)
	}
	if *tenantFlag == "" {
		fmt.Fprintln(os.Stderr, "Error: --tenant is required")
		os.Exit(2)
	}
	hostname := *hostnameFlag
	if hostname == "" {
		var err error
		hostname, err = os.Hostname()
		if err != nil {
			log.Fatalf("hostname: %v", err)
		}
	}
	if err := validateHostname(hostname); err != nil {
		log.Fatalf("hostname rejected: %v", err)
	}
	statePath := *stateFlag
	if statePath == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			log.Fatalf("home: %v", err)
		}
		statePath = filepath.Join(home, ".systemapi", "agent.json")
	}

	st, err := loadOrCreateState(statePath, *tenantFlag)
	if err != nil {
		log.Fatalf("state: %v", err)
	}
	pubLine, err := sshEd25519PublicLine(st.Ed25519Seed)
	if err != nil {
		log.Fatalf("ssh identity: %v", err)
	}
	if err := refuseAPIKeyURL(*serverURL); err != nil {
		log.Fatal("refusing to dial: URL contains api_key")
	}
	u, err := url.Parse(*serverURL)
	if err != nil {
		log.Fatalf("invalid server URL: %v", err)
	}
	if err := refuseAPIKeyURL(u.String()); err != nil {
		log.Fatal("refusing to dial: URL contains api_key")
	}

	header := http.Header{}
	header.Set("Authorization", "Bearer "+apiKey)
	header.Set("X-SystemAPI-Tenant", st.Tenant)
	header.Set("X-SystemAPI-Host-ID", st.HostID)
	header.Set("X-SystemAPI-Hostname", hostname)
	header.Set("X-SystemAPI-SSH-PubKey", pubLine)

	log.Printf("dialing control plane %s host_id=%s", u.Host, st.HostID)
	dialer := *websocket.DefaultDialer
	dialer.HandshakeTimeout = 10 * time.Second
	dialer.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS13}
	c, _, err := dialer.Dial(u.String(), header)
	if err != nil {
		log.Fatalf("dial error: %v", err)
	}
	defer c.Close()
	c.SetReadLimit(256 * 1024)

	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, os.Interrupt)

	enrolled := make(chan error, 1)
	var enrollOnce sync.Once
	signalEnroll := func(err error) {
		enrollOnce.Do(func() { enrolled <- err })
	}
	done := make(chan struct{})
	stateDir := filepath.Dir(statePath)

	go func() {
		defer close(done)
		for {
			_, message, err := c.ReadMessage()
			if err != nil {
				log.Printf("read error: %v", err)
				signalEnroll(err)
				return
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
				if err := acceptEnrolled(st, statePath, peek.HostID, peek.ControlPubKey); err != nil {
					log.Printf("enroll pin failed: %v", err)
					signalEnroll(err)
					return
				}
				signalEnroll(nil)
			case "enroll_error":
				log.Printf("enroll rejected: %s", peek.Error)
				signalEnroll(fmt.Errorf("enroll_error:%s", peek.Error))
				return
			default:
				processIncomingMessage(c, st.HostID, stateDir, message)
			}
		}
	}()

	telemetryTicker := time.NewTicker(5 * time.Second)
	defer telemetryTicker.Stop()
	enrollTimer := time.NewTimer(10 * time.Second)
	defer enrollTimer.Stop()
	enrolledOK := false

	for {
		select {
		case err := <-enrolled:
			if err != nil {
				log.Fatalf("enrollment failed: %v", err)
			}
			enrolledOK = true
			log.Printf("enrolled host_id=%s", st.HostID)
		case <-enrollTimer.C:
			if !enrolledOK {
				log.Fatal("enrollment timed out")
			}
		case <-done:
			select {
			case err := <-enrolled:
				if err != nil {
					log.Fatalf("enrollment failed: %v", err)
				}
			default:
			}
			if !enrolledOK {
				log.Fatal("connection closed before enrollment")
			}
			return
		case <-telemetryTicker.C:
			stats, err := gatherTelemetry()
			if err != nil {
				log.Printf("telemetry: %v", err)
				continue
			}
			response := ResponseMessage{Type: "telemetry", Payload: stats}
			if err := c.WriteJSON(response); err != nil {
				log.Printf("write telemetry: %v", err)
				return
			}
		case <-interrupt:
			log.Println("interrupt received, disconnecting")
			_ = c.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
			select {
			case <-done:
			case <-time.After(time.Second):
			}
			return
		}
	}
}

func processIncomingMessage(c *websocket.Conn, hostID, stateDir string, message []byte) {
	var cmd CommandMessage
	if err := json.Unmarshal(message, &cmd); err != nil {
		log.Printf("rejected command: %v", err)
		return
	}

	switch cmd.Type {
	case "sysscript":
		if len(cmd.Script) > scriptMaxBytes {
			writeCommandResult(c, cmd.RequestID, "script_too_large", "")
			return
		}
		if err := authorizeCommand(hostID, "sysscript", cmd.Script, cmd.Lease, time.Now()); err != nil {
			log.Printf("sysscript refused: %s", err.Error())
			writeCommandResult(c, cmd.RequestID, err.Error(), "")
			return
		}
		log.Printf("sysscript %s", cmd.RequestID)
		engine := NewSysscriptEngine(cmd.Entitlements)
		output, err := engine.Execute(cmd.Script)
		errText := ""
		if err != nil {
			errText = err.Error()
		}
		writeCommandResult(c, cmd.RequestID, errText, output)

	case "pty_start":
		action := cmd.Action
		if action == "" {
			action = "pty"
		}
		if err := authorizeCommand(hostID, action, action, cmd.Lease, time.Now()); err != nil {
			log.Printf("pty refused: %s", err.Error())
			_ = c.WriteJSON(ResponseMessage{
				Type:      "pty_status",
				RequestID: cmd.RequestID,
				Payload:   map[string]string{"error": err.Error()},
			})
			return
		}
		expires := int64(0)
		if cmd.Lease != nil {
			expires = cmd.Lease.ExpiresUnix
		}
		log.Printf("pty_start %s action=%s", cmd.RequestID, action)
		HandlePTYStart(c, cmd.RequestID, action, expires, stateDir)

	case "pty_input":
		HandlePTYInput([]byte(cmd.Data))

	case "pty_resize":
		HandlePTYResize(uint16(cmd.Rows), uint16(cmd.Cols))

	case "pty_stop":
		log.Printf("pty_stop")
		HandlePTYStop()
	}
}

func writeCommandResult(c *websocket.Conn, requestID, errText, output string) {
	_ = c.WriteJSON(ResponseMessage{
		Type:      "command_result",
		RequestID: requestID,
		Payload:   map[string]string{"error": errText, "output": output},
	})
}
