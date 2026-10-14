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
	if len(os.Args) > 1 && os.Args[1] == "verify-recording" {
		os.Exit(runVerifyRecording(os.Args[2:], os.Stdout, os.Stderr))
	}
	if len(os.Args) > 1 && os.Args[1] == "file-helper" {
		// The per-session file child (file_helper_linux.go); the parent
		// agent starts it with the session's identity already dropped.
		os.Exit(runFileHelper(os.Stdin, os.Stdout))
	}
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
	ptyRecordMaxFlag := flag.Int64("pty-record-max-bytes", recordMaxBytesDefault, "end a terminal session once it has recorded this many bytes")
	tcpAllowFlag := flag.String("tcp-allow", "", "TCP-forward targets this agent may dial, e.g. local:5432,10.0.0.0/24:3389,10.0.0.0/24:8000-8099 (default: none)")
	ptyRecordMinFreeFlag := flag.Uint64("pty-record-min-free", recordMinFreeDefault, "refuse a terminal session when the recording filesystem has less free space (bytes)")
	flag.Parse()
	if *ptyRecordMaxFlag <= 0 || *ptyRecordMinFreeFlag == 0 {
		fmt.Fprintln(os.Stderr, "Error: --pty-record-max-bytes and --pty-record-min-free must be positive")
		os.Exit(2)
	}
	rules, err := parseTCPAllow(*tcpAllowFlag)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(2)
	}
	tcpAllowRules = rules
	ptyCfg = ptySettings{
		User:           *ptyUserFlag,
		AllowAgentUser: *ptyAllowAgentUserFlag,
		Record:         *ptyRecordFlag,
		RecordDir:      *ptyRecordDirFlag,
		RecordMaxBytes: *ptyRecordMaxFlag,
		RecordMinFree:  *ptyRecordMinFreeFlag,
	}
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
	if caps := capabilitiesHeaderValue(); caps != "" {
		header.Set(capabilitiesHeader, caps)
	}

	dialer := *websocket.DefaultDialer
	dialer.HandshakeTimeout = 10 * time.Second
	dialer.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS13}

	stop := make(chan struct{})
	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-interrupt
		close(stop)
	}()

	conn := &agentConn{
		url:            u.String(),
		header:         header,
		dialer:         dialer,
		st:             st,
		statePath:      statePath,
		hostname:       hostname,
		telemetryEvery: 5 * time.Second,
		enrollTimeout:  10 * time.Second,
		minBackoff:     time.Second,
		maxBackoff:     60 * time.Second,
		telemetry:      gatherTelemetry,
	}
	if err := conn.run(stop); err != nil {
		log.Printf("fatal: %v", err)
		os.Exit(1)
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
