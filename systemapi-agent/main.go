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
	"runtime"
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
	JobID        string        `json:"job_id,omitempty"`
	TimeoutS     int           `json:"timeout_s,omitempty"`
	Data         string        `json:"data,omitempty"`
	DataB64      string        `json:"data_b64,omitempty"`
	SessionID    string        `json:"session_id,omitempty"`
	DeadlineUnix int64         `json:"deadline_unix,omitempty"`
	Rows         int           `json:"rows,omitempty"`
	Cols         int           `json:"cols,omitempty"`
	Action       string        `json:"action,omitempty"`
	Lease        *Lease        `json:"lease,omitempty"`
	Actor        string        `json:"actor,omitempty"`
	WatchID      string        `json:"watch_id,omitempty"`
	Mode         string        `json:"mode,omitempty"`
	Reason       string        `json:"reason,omitempty"`
	Override     bool          `json:"override,omitempty"`
	// A sysscript_job frame with kind "converge" carries the bundle and,
	// in Mode, check or apply; ExpectPlan is "-" for check.
	Kind       string `json:"kind,omitempty"`
	BundleJSON string `json:"bundle_json,omitempty"`
	ExpectPlan string `json:"expect_plan_sha256,omitempty"`
}

// ResponseMessage is an outgoing WebSocket message.
type ResponseMessage struct {
	Type      string      `json:"type"`
	Payload   interface{} `json:"payload"`
	RequestID string      `json:"request_id,omitempty"`
	SessionID string      `json:"session_id,omitempty"`
	JobID     string      `json:"job_id,omitempty"`
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
	ptyUserMapFlag := flag.String("pty-user-map", "", "file of 'identity = unixuser' lines (mode 0600, owned by root or the agent user); each identity runs as its own account and an unmapped identity is refused; overrides --pty-user")
	ptyNoticeFlag := flag.String("pty-notice", "", "file holding the monitoring notice shown at the start of every terminal session (owned by root or the agent user, not group or other writable); the tenant name is always appended, and the notice cannot be turned off")
	ptyAllowAgentUserFlag := flag.Bool("pty-allow-agent-user", false, "let a non-root agent run terminal:open shells as its own user (the shell can read the agent's key and state; recording is user_owned)")
	ptyRecordFlag := flag.Bool("pty-record", true, "record every terminal session in an HMAC-chained file")
	ptyRecordDirFlag := flag.String("pty-record-dir", "", "terminal recordings (default: "+ptyRootRecordDir+" as root, else <state dir>/recordings)")
	ptyRecordMaxFlag := flag.Int64("pty-record-max-bytes", recordMaxBytesDefault, "end a terminal session once it has recorded this many bytes")
	tcpAllowFlag := flag.String("tcp-allow", "", "TCP-forward targets this agent may dial, e.g. local:5432,10.0.0.0/24:3389,10.0.0.0/24:8000-8099 (default: none)")
	xferBinFlag := flag.String("xfer-bin", "", "absolute path of the sahxfer binary started for xfer grants (owned by root or the agent user, not group or other writable)")
	xferListenFlag := flag.String("xfer-udp-listen", "", "address recv binds for listen-mode grants: ip:port or ip:lo-hi (unset refuses listen mode)")
	xferAdvertiseFlag := flag.String("xfer-udp-advertise", "", "IP reported to the server in place of the bound one (a published port behind NAT or Docker)")
	xferAllowDarwinFlag := flag.Bool("xfer-allow-darwin", false, "advertise xfer on macOS (development only: no openat2, no Pdeathsig)")
	ptyRecordMinFreeFlag := flag.Uint64("pty-record-min-free", recordMinFreeDefault, "refuse a terminal session when the recording filesystem has less free space (bytes)")
	sysscriptWorkersFlag := flag.Int("sysscript-workers", jobWorkersDefault, fmt.Sprintf("sysscripts run at once (1..%d); %d more may wait, then agent_busy", jobWorkersMax, jobPendingMax))
	sysscriptLegacyFlag := flag.Int("sysscript-legacy-seconds", jobLegacyDefaultSec, fmt.Sprintf("whole-script deadline of a legacy sysscript frame (1..%d, at most --sysscript-max-seconds)", jobMaxSecondsMax))
	sysscriptJobsFlag := flag.Bool("sysscript-jobs", true, "advertise async sysscript jobs (sysscript_jobs, Linux and macOS only); =false makes the server send this host's scripts the legacy way")
	convergeFlag := flag.Bool("converge", false, "advertise desired-state converge jobs (converge, Linux and macOS only, needs --sysscript-jobs); enable only after every server replica runs the converge wiring")
	sysscriptMaxFlag := flag.Int("sysscript-max-seconds", jobMaxSecondsMax, fmt.Sprintf("ceiling for any sysscript deadline (1..%d)", jobMaxSecondsMax))
	stateBackupDirFlag := flag.String("state-backup-dir", stateBackupDir, "directory for desired-state file backups (absolute, root-only; must not overlap any write grant, or file changes that need a backup fail)")
	flag.Parse()
	backupDirSet := false
	flag.Visit(func(f *flag.Flag) { backupDirSet = backupDirSet || f.Name == "state-backup-dir" })
	if err := configureStateBackupDir(*stateBackupDirFlag, backupDirSet, runtime.GOOS); err != nil {
		fmt.Fprintf(os.Stderr, "Error: --state-backup-dir: %v\n", err)
		os.Exit(2)
	}
	sysscriptJobsOn = *sysscriptJobsFlag
	convergeOn = *convergeFlag
	jc, err := parseJobFlags(*sysscriptWorkersFlag, *sysscriptLegacyFlag, *sysscriptMaxFlag)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(2)
	}
	jobCfg = jc
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
		Tenant:         *tenantFlag,
	}
	if *ptyUserMapFlag != "" {
		m, err := loadPTYUserMap(*ptyUserMapFlag, os.Geteuid())
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: --pty-user-map: %v\n", err)
			os.Exit(2)
		}
		ptyCfg.UserMap = m
		log.Printf("terminal, file and xfer sessions run as per-identity accounts from --pty-user-map (%d identities)", len(m))
		if ptyCfg.User != "" {
			log.Printf("WARNING: --pty-user is ignored because --pty-user-map is set")
		}
	} else if ptyCfg.User != "" {
		log.Printf("WARNING: --pty-user maps every identity to the one account %s; people sharing it can signal, ptrace and plant files for each other (use --pty-user-map)", ptyCfg.User)
	}
	if *ptyNoticeFlag != "" {
		text, err := loadPTYNotice(*ptyNoticeFlag, os.Geteuid())
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: --pty-notice: %v\n", err)
			os.Exit(2)
		}
		ptyCfg.Notice = text
	}
	if !ptyCfg.Record {
		log.Printf("WARNING: terminal recording is OFF (--pty-record=false)")
	}
	if ptyCfg.AllowAgentUser {
		log.Printf("WARNING: --pty-allow-agent-user: terminal shells run as the agent's own user and can read its API key and state")
	}
	xcfg, err := parseXferFlags(*xferBinFlag, *xferListenFlag, *xferAdvertiseFlag, *xferAllowDarwinFlag, os.Geteuid())
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(2)
	}
	xferCfg = xcfg
	if xferCfg.allowDarwin {
		log.Printf("WARNING: --xfer-allow-darwin: xfer on macOS has no openat2 and no Pdeathsig; development only")
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
	// Interrupted transfers from a previous run: sweep their temp files and
	// report them. This runs in the background, since a sweep may hash a
	// large target: results found before the first connection enrolls wait
	// in the queue, later ones go out on the live connection. The server
	// ignores a result for a grant id it no longer holds, so a result sent
	// again after another restart is harmless.
	xferMgr().setStateDir(filepath.Dir(statePath))
	go xferMgr().sweepXferRecords()
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
	caps := capabilitiesHeaderValue()
	log.Printf("advertised capabilities=%q", caps)
	if caps != "" {
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
	err = conn.run(stop)
	// Graceful shutdown: each xfer child gets cancel and deletes its temp
	// file; results not sent stay in their records for the next start.
	xferMgr().stopAll("stopped", xferStopTimeout)
	// Scripts still running end as agent_stopped (a no-op when the
	// connection's stop already did it).
	jobMgr().stopAll(jobKillGrace + jobStopMargin)
	if err != nil {
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
		if len(cmd.RequestID) > requestIDMaxBytes {
			log.Printf("sysscript refused: request_id too long")
			writeCommandResult(out, "", "bad_request", "", false)
			return
		}
		if len(cmd.Script) > scriptMaxBytes {
			writeCommandResult(out, cmd.RequestID, "script_too_large", "", false)
			return
		}
		if err := authorizeCommand(hostID, "sysscript", cmd.Script, cmd.Lease, time.Now()); err != nil {
			log.Printf("sysscript refused: %s", err.Error())
			writeCommandResult(out, cmd.RequestID, err.Error(), "", false)
			return
		}
		log.Printf("sysscript %s", cmd.RequestID)
		// Off the read loop: a worker runs it and writes command_result.
		jobMgr().submitLegacy(out, cmd.RequestID, cmd.Script, cmd.Entitlements, jobCfg.Legacy)

	case "sysscript_job":
		// Checked here (id, size, entitlements, lease, nonce, duplicate,
		// deadline) and queued; a worker runs it.
		jobMgr().startJob(hostID, &cmd, time.Now())

	case "sysscript_job_cancel":
		jobMgr().cancelJob(cmd.JobID, cmd.Reason)

	case "sysscript_job_ack":
		jobMgr().ackJob(cmd.JobID)

	case "pty_start":
		log.Printf("pty_start %s action=%s", cmd.SessionID, cmd.Action)
		startPTYSession(out, hostID, stateDir, ptyStartRequest{
			SessionID:    cmd.SessionID,
			Action:       cmd.Action,
			Rows:         cmd.Rows,
			Cols:         cmd.Cols,
			DeadlineUnix: cmd.DeadlineUnix,
			Actor:        cmd.Actor,
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
		if cmd.WatchID != "" {
			handleWatcherInput(cmd.SessionID, cmd.WatchID, data)
			return
		}
		handlePTYInput(cmd.SessionID, data)

	case "pty_eof":
		handlePTYEOF(cmd.SessionID)

	case "pty_resize":
		handlePTYResize(cmd.SessionID, cmd.Rows, cmd.Cols)

	case "watch_request":
		log.Printf("watch_request %s mode=%s", cmd.SessionID, cmd.Mode)
		handleWatchRequest(out, hostID, watchRequest{
			SessionID: cmd.SessionID,
			WatchID:   cmd.WatchID,
			Mode:      cmd.Mode,
			Actor:     cmd.Actor,
			Reason:    cmd.Reason,
			Override:  cmd.Override,
			Lease:     cmd.Lease,
		}, time.Now())

	case "watch_stop":
		handleWatchStop(cmd.SessionID, cmd.WatchID)

	case "pty_stop":
		log.Printf("pty_stop %s", cmd.SessionID)
		handlePTYStop(cmd.SessionID)
	}
}

// requestIDMaxBytes caps the request_id echoed back in command_result and
// alert frames.
const requestIDMaxBytes = 256

// writeCommandResult sends the legacy command_result frame, its encoded size
// capped at jobFrameMax (encodeOutputFrame).
func writeCommandResult(out ptyOut, requestID, errText, output string, truncated bool) {
	b, err := commandResultFrame(requestID, errText, output, truncated)
	if err != nil {
		log.Printf("command_result %s not encoded: %v", requestID, err)
		return
	}
	if err := out.WriteText(b); err != nil {
		log.Printf("command_result %s not sent: %v", requestID, err)
	}
}

// commandResultFrame encodes the legacy command_result frame.
func commandResultFrame(requestID, errText, output string, truncated bool) ([]byte, error) {
	errText, _ = frameText(errText, frameErrMax)
	return encodeOutputFrame(func(o string, tr bool) interface{} {
		return ResponseMessage{
			Type:      "command_result",
			RequestID: requestID,
			Payload:   commandResultPayload{Error: errText, Output: o, OutputTruncated: tr},
		}
	}, output, truncated)
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
