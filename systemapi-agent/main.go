package main

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
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
	DataB64      string        `json:"data_b64,omitempty"`
	SessionID    string        `json:"session_id,omitempty"`
	DeadlineUnix int64         `json:"deadline_unix,omitempty"`
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
	SessionID string      `json:"session_id,omitempty"`
}

func main() {
	serverURL := flag.String("server", "ws://localhost:3003/api/v1/systems/stream", "WebSocket stream URL")
	apiKeyFlag := flag.String("api-key", "", "API key (visible in the process list); prefer SYSTEMAPI_API_KEY or --api-key-file")
	apiKeyFileFlag := flag.String("api-key-file", "", "file holding the API key (mode 0600)")
	tenantFlag := flag.String("tenant", "", "tenant name (required)")
	hostnameFlag := flag.String("hostname", "", "hostname (default: this machine)")
	stateFlag := flag.String("state", "", "state file (default: ~/.systemapi/agent.json)")
	ptyUserFlag := flag.String("pty-user", "", "account for terminal:open shells; required when the agent runs as root")
	ptyAllowAgentUserFlag := flag.Bool("pty-allow-agent-user", false, "let a non-root agent run terminal:open shells as its own user (the shell can read the agent's key and state; recording is user_owned)")
	ptyRecordFlag := flag.Bool("pty-record", true, "record every terminal session in an HMAC-chained file")
	ptyRecordDirFlag := flag.String("pty-record-dir", "", "terminal recordings (default: "+ptyRootRecordDir+" as root, else <state dir>/recordings)")
	flag.Parse()
	ptyCfg = ptySettings{User: *ptyUserFlag, AllowAgentUser: *ptyAllowAgentUserFlag, Record: *ptyRecordFlag, RecordDir: *ptyRecordDirFlag}
	if !ptyCfg.Record {
		log.Printf("WARNING: terminal recording is OFF (--pty-record=false)")
	}
	if ptyCfg.AllowAgentUser {
		log.Printf("WARNING: --pty-allow-agent-user: terminal shells run as the agent's own user and can read its API key and state")
	}

	apiKey, warn, err := resolveAPIKey(*apiKeyFlag, *apiKeyFileFlag)
	if warn != "" {
		log.Printf("WARNING: %s", warn)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
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
	out := &wsWriter{c: c}
	// Every return from here ends all terminal sessions first.
	defer stopAllSessions(3 * time.Second)

	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, os.Interrupt, syscall.SIGTERM)

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
				processIncomingMessage(out, st.HostID, stateDir, message)
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
			if err := out.WriteJSON(response); err != nil {
				log.Printf("write telemetry: %v", err)
				return
			}
		case <-interrupt:
			log.Println("signal received, stopping terminal sessions and disconnecting")
			stopAllSessions(3 * time.Second)
			_ = out.WriteClose()
			select {
			case <-done:
			case <-time.After(time.Second):
			}
			return
		}
	}
}

func processIncomingMessage(out ptyOut, hostID, stateDir string, message []byte) {
	var cmd CommandMessage
	if err := json.Unmarshal(message, &cmd); err != nil {
		log.Printf("rejected command: %v", err)
		return
	}

	switch cmd.Type {
	case "sysscript":
		if len(cmd.Script) > scriptMaxBytes {
			writeCommandResult(out, cmd.RequestID, "script_too_large", "")
			return
		}
		if err := authorizeCommand(hostID, "sysscript", cmd.Script, cmd.Lease, time.Now()); err != nil {
			log.Printf("sysscript refused: %s", err.Error())
			writeCommandResult(out, cmd.RequestID, err.Error(), "")
			return
		}
		log.Printf("sysscript %s", cmd.RequestID)
		engine := NewSysscriptEngine(cmd.Entitlements)
		output, err := engine.Execute(cmd.Script)
		errText := ""
		if err != nil {
			errText = err.Error()
		}
		writeCommandResult(out, cmd.RequestID, errText, output)

	case "pty_start":
		log.Printf("pty_start %s action=%s", cmd.SessionID, cmd.Action)
		startPTYSession(out, hostID, stateDir, ptyStartRequest{
			SessionID:    cmd.SessionID,
			Action:       cmd.Action,
			Rows:         cmd.Rows,
			Cols:         cmd.Cols,
			DeadlineUnix: cmd.DeadlineUnix,
			Lease:        cmd.Lease,
		}, time.Now())

	case "pty_renew":
		if err := renewPTYSession(hostID, cmd.SessionID, cmd.Lease, time.Now()); err != nil {
			log.Printf("pty_renew refused: %s", err.Error())
			_ = out.WriteJSON(ResponseMessage{
				Type:      "pty_renew_rejected",
				SessionID: cmd.SessionID,
				Payload:   map[string]string{"error": err.Error()},
			})
		}

	case "pty_input":
		data, err := decodePTYInput(cmd.DataB64, cmd.Data)
		if err != nil {
			log.Printf("pty_input rejected: bad base64")
			return
		}
		handlePTYInput(cmd.SessionID, data)

	case "pty_eof":
		handlePTYEOF(cmd.SessionID)

	case "pty_resize":
		handlePTYResize(cmd.SessionID, cmd.Rows, cmd.Cols)

	case "pty_stop":
		log.Printf("pty_stop %s", cmd.SessionID)
		handlePTYStop(cmd.SessionID)
	}
}

func writeCommandResult(out ptyOut, requestID, errText, output string) {
	_ = out.WriteJSON(ResponseMessage{
		Type:      "command_result",
		RequestID: requestID,
		Payload:   map[string]string{"error": errText, "output": output},
	})
}

// resolveAPIKey takes the key from --api-key-file, then SYSTEMAPI_API_KEY,
// then --api-key, and removes SYSTEMAPI_API_KEY from the process environment
// so no child can inherit it. A key on argv is visible in the process list,
// so it returns a warning.
func resolveAPIKey(flagKey, keyFile string) (string, string, error) {
	envKey := os.Getenv("SYSTEMAPI_API_KEY")
	if err := os.Unsetenv("SYSTEMAPI_API_KEY"); err != nil {
		return "", "", err
	}
	warn := ""
	if flagKey != "" {
		warn = "--api-key is visible in the process list; use SYSTEMAPI_API_KEY or --api-key-file"
	}
	if keyFile != "" {
		if err := checkPrivateFile(keyFile, uint32(os.Geteuid())); err != nil {
			return "", warn, fmt.Errorf("api key file: %v", err)
		}
		raw, err := os.ReadFile(keyFile)
		if err != nil {
			return "", warn, fmt.Errorf("api key file: %v", err)
		}
		if key := strings.TrimSpace(string(raw)); key != "" {
			return key, warn, nil
		}
		return "", warn, errors.New("api key file is empty")
	}
	if envKey != "" {
		return envKey, warn, nil
	}
	if flagKey != "" {
		return flagKey, warn, nil
	}
	return "", warn, errors.New("set SYSTEMAPI_API_KEY, --api-key-file, or --api-key")
}
