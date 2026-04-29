package main

import (
	"log"
	"os"
	"os/exec"
	"runtime"
	"sync"
	"syscall"

	"github.com/creack/pty"
	"github.com/gorilla/websocket"
)

type PTYSession struct {
	PtyFile *os.File
	Cmd     *exec.Cmd
	Mutex   sync.Mutex
}

// Global active PTY session
var activePTY *PTYSession

// SetupPTY initializes a new pseudo-terminal process and pipes it over WebSocket
func HandlePTYStart(c *websocket.Conn, requestID string) {
	if activePTY != nil {
		activePTY.PtyFile.Close()
		if activePTY.Cmd.Process != nil {
			activePTY.Cmd.Process.Kill()
		}
	}

	shell := "bash"
	if runtime.GOOS == "windows" {
		shell = "powershell.exe"
	}
	
	// Try ZSH on mac
	if runtime.GOOS == "darwin" {
		if _, err := os.Stat("/bin/zsh"); err == nil {
			shell = "zsh"
		}
	}

	c.WriteJSON(ResponseMessage{
		Type:      "pty_status",
		RequestID: requestID,
		Payload:   map[string]string{"status": "starting", "shell": shell},
	})

	cmd := exec.Command(shell)
	
	// Add environment variables
	cmd.Env = append(os.Environ(), "TERM=xterm-256color")

	// Start the command with a pty.
	ptmx, err := pty.Start(cmd)
	if err != nil {
		log.Printf("Failed to start PTY: %v", err)
		c.WriteJSON(ResponseMessage{Type: "pty_status", RequestID: requestID, Payload: map[string]string{"error": err.Error()}})
		return
	}

	activePTY = &PTYSession{
		PtyFile: ptmx,
		Cmd:     cmd,
	}

	// Wait for process to exit and cleanup
	go func() {
		defer ptmx.Close()
		cmd.Wait()
		activePTY = nil
		c.WriteJSON(ResponseMessage{Type: "pty_status", Payload: map[string]string{"status": "exited"}})
	}()

	// Loop to read from the PTY and pump to the WebSocket
	go func() {
		buf := make([]byte, 1024)
		for {
			n, err := ptmx.Read(buf)
			if err != nil {
				return
			}
			
			// Send binary raw TTY data
			c.WriteMessage(websocket.BinaryMessage, buf[:n])
		}
	}()
}

// HandlePTYInput writes raw keystrokes/data from the dashboard into the active TTY
func HandlePTYInput(data []byte) {
	if activePTY != nil && activePTY.PtyFile != nil {
		activePTY.Mutex.Lock()
		activePTY.PtyFile.Write(data)
		activePTY.Mutex.Unlock()
	}
}

// HandlePTYResize resizes the pseudo-terminal window to match the dashboard's xterm.js
func HandlePTYResize(rows uint16, cols uint16) {
	if activePTY != nil && activePTY.PtyFile != nil {
		pty.Setsize(activePTY.PtyFile, &pty.Winsize{
			Rows: rows,
			Cols: cols,
		})
	}
}

// HandlePTYStop gracefully shuts down the PTY
func HandlePTYStop() {
	if activePTY != nil && activePTY.PtyFile != nil {
		// Send interrupt signals
		if activePTY.Cmd != nil && activePTY.Cmd.Process != nil {
			activePTY.Cmd.Process.Signal(syscall.SIGINT)
			activePTY.Cmd.Process.Signal(syscall.SIGKILL)
		}
		activePTY.PtyFile.Close()
		activePTY = nil
	}
}
