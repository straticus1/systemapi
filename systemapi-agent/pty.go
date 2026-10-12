package main

import (
	"errors"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"syscall"
	"time"

	"github.com/creack/pty"
	"github.com/gorilla/websocket"
)

type PTYSession struct {
	PtyFile *os.File
	Cmd     *exec.Cmd
	Mutex   sync.Mutex
	timer   *time.Timer
}

var (
	ptyMu     sync.Mutex
	activePTY *PTYSession
)

const scriptMaxBytes = 64 * 1024

func loginShell() string {
	shell := "bash"
	if runtime.GOOS == "windows" {
		return "powershell.exe"
	}
	if runtime.GOOS == "darwin" {
		if _, err := os.Stat("/bin/zsh"); err == nil {
			return "zsh"
		}
	}
	return shell
}

// breakglassCommand resolves adssh and refuses to fall open to a login shell.
// It does not pass -r. Authorization is the control-plane lease.
func breakglassCommand() (string, []string, error) {
	path, err := exec.LookPath("adssh")
	if err != nil {
		return "", nil, errors.New("adssh_missing")
	}
	return path, nil, nil
}

func writeBreakglassPolicy(dir string) (string, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return "", err
	}
	path := filepath.Join(dir, "breakglass.rego")
	body := []byte("package adssh.authz\n\ndefault allow = true\n")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		return "", err
	}
	return path, nil
}

func ptyStatus(c *websocket.Conn, requestID string, payload map[string]string) {
	_ = c.WriteJSON(ResponseMessage{Type: "pty_status", RequestID: requestID, Payload: payload})
}

// HandlePTYStart starts a leased PTY. action "pty" is the login shell.
// action "breakglass" is adssh with no restricted flag, or a refusal.
func HandlePTYStart(c *websocket.Conn, requestID, action string, expiresUnix int64, stateDir string) {
	if action != "pty" && action != "breakglass" {
		ptyStatus(c, requestID, map[string]string{"error": "bad_action"})
		return
	}
	if expiresUnix <= time.Now().Unix() {
		ptyStatus(c, requestID, map[string]string{"error": "lease_expired"})
		return
	}

	var argv0 string
	var args []string
	extra := []string{"TERM=xterm-256color"}
	if action == "breakglass" {
		path, cmdArgs, err := breakglassCommand()
		if err != nil {
			ptyStatus(c, requestID, map[string]string{"error": "adssh_missing"})
			return
		}
		policy, err := writeBreakglassPolicy(stateDir)
		if err != nil {
			ptyStatus(c, requestID, map[string]string{"error": "policy_write_failed"})
			return
		}
		argv0 = path
		args = cmdArgs
		extra = append(extra,
			"ADSSH_POLICY="+policy,
			"ADSSH_AUDIT_LOG="+filepath.Join(stateDir, "breakglass-audit.log"),
		)
	} else {
		argv0 = loginShell()
	}

	ptyStatus(c, requestID, map[string]string{"status": "starting", "shell": filepath.Base(argv0)})

	cmd := exec.Command(argv0, args...)
	cmd.Env = stripChildEnv(os.Environ(), extra)
	ptmx, err := pty.Start(cmd)
	if err != nil {
		log.Printf("Failed to start PTY: %v", err)
		ptyStatus(c, requestID, map[string]string{"error": "pty_start_failed"})
		return
	}

	session := &PTYSession{PtyFile: ptmx, Cmd: cmd}
	session.timer = time.AfterFunc(time.Until(time.Unix(expiresUnix, 0)), func() {
		log.Printf("lease expired; stopping pty %s", requestID)
		HandlePTYStop()
	})

	ptyMu.Lock()
	if activePTY != nil {
		stopSession(activePTY)
	}
	activePTY = session
	ptyMu.Unlock()

	go func() {
		defer ptmx.Close()
		_ = cmd.Wait()
		ptyMu.Lock()
		if activePTY == session {
			if session.timer != nil {
				session.timer.Stop()
			}
			activePTY = nil
		}
		ptyMu.Unlock()
		ptyStatus(c, requestID, map[string]string{"status": "exited"})
	}()

	go func() {
		buf := make([]byte, 1024)
		for {
			n, err := ptmx.Read(buf)
			if err != nil {
				return
			}
			_ = c.WriteMessage(websocket.BinaryMessage, buf[:n])
		}
	}()
}

func stopSession(s *PTYSession) {
	if s == nil {
		return
	}
	if s.timer != nil {
		s.timer.Stop()
	}
	if s.Cmd != nil && s.Cmd.Process != nil {
		_ = s.Cmd.Process.Signal(syscall.SIGKILL)
	}
	if s.PtyFile != nil {
		_ = s.PtyFile.Close()
	}
}

func HandlePTYInput(data []byte) {
	ptyMu.Lock()
	s := activePTY
	ptyMu.Unlock()
	if s != nil && s.PtyFile != nil {
		s.Mutex.Lock()
		_, _ = s.PtyFile.Write(data)
		s.Mutex.Unlock()
	}
}

func HandlePTYResize(rows uint16, cols uint16) {
	ptyMu.Lock()
	s := activePTY
	ptyMu.Unlock()
	if s != nil && s.PtyFile != nil {
		_ = pty.Setsize(s.PtyFile, &pty.Winsize{Rows: rows, Cols: cols})
	}
}

func HandlePTYStop() {
	ptyMu.Lock()
	s := activePTY
	activePTY = nil
	ptyMu.Unlock()
	stopSession(s)
}
