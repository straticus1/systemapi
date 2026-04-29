package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/url"
	"os"
	"os/signal"
	"time"

	"github.com/gorilla/websocket"
)

// CommandMessage represents an incoming WebSocket message from the dashboard
type CommandMessage struct {
	Type         string        `json:"type"`          // "sysscript", "pty_start", "pty_input", "pty_resize", "pty_stop"
	Script       string        `json:"script"`        // The Starlark source code
	Entitlements *Entitlements `json:"entitlements"`  // Security manifest
	RequestID    string        `json:"request_id"`
	Data         string        `json:"data,omitempty"` // For pty_input (keystrokes)
	Rows         int           `json:"rows,omitempty"` // For pty_resize
	Cols         int           `json:"cols,omitempty"` // For pty_resize
}

// ResponseMessage represents an outgoing WebSocket message to the dashboard
type ResponseMessage struct {
	Type      string      `json:"type"` // "telemetry" or "command_result"
	Payload   interface{} `json:"payload"`
	RequestID string      `json:"request_id,omitempty"`
}

func main() {
	serverURL := flag.String("server", "ws://localhost:3003/api/v1/systems/stream", "WebSocket stream URL")
	apiKey := flag.String("api-key", "", "SystemAPI.io API Key (ak_live_...)")
	flag.Parse()

	if *apiKey == "" {
		fmt.Println("Error: --api-key is required.")
		fmt.Printf("Usage: %s --api-key ak_live_xxxx.yyyy\n", os.Args[0])
		os.Exit(1)
	}

	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, os.Interrupt)

	u, err := url.Parse(*serverURL)
	if err != nil {
		log.Fatalf("Invalid server URL: %v", err)
	}
	
	// Appending API key to URL simply for the demo; in prod this should be an HTTP header
	q := u.Query()
	q.Set("api_key", *apiKey)
	u.RawQuery = q.Encode()

	log.Printf("Connecting to %s", u.String())

	// Connect to WebSocket
	c, _, err := websocket.DefaultDialer.Dial(u.String(), nil)
	if err != nil {
		log.Fatalf("Fatal: dial error: %v (Is the server running?)", err)
	}
	defer c.Close()

	done := make(chan struct{})

	// Read pump - listen for incoming Sysscripts to run
	go func() {
		defer close(done)
		for {
			_, message, err := c.ReadMessage()
			if err != nil {
				log.Println("read error:", err)
				return
			}
			processIncomingMessage(c, message)
		}
	}()

	telemetryTicker := time.NewTicker(5 * time.Second)
	defer telemetryTicker.Stop()

	for {
		select {
		case <-done:
			return
		case <-telemetryTicker.C:
			// Gather health stats and send
			stats, err := gatherTelemetry()
			if err != nil {
				log.Println("Error gathering telemetry:", err)
				continue
			}

			response := ResponseMessage{
				Type:    "telemetry",
				Payload: stats,
			}

			if err := c.WriteJSON(response); err != nil {
				log.Println("write telemetry error:", err)
				return
			}
		case <-interrupt:
			log.Println("Interrupt received, disconnecting...")
			err := c.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
			if err != nil {
				log.Println("write close:", err)
			}
			select {
			case <-done:
			case <-time.After(time.Second):
			}
			return
		}
	}
}

func processIncomingMessage(c *websocket.Conn, message []byte) {
	var cmd CommandMessage
	if err := json.Unmarshal(message, &cmd); err != nil {
		log.Printf("Failed to unmarshal command: %v\n", err)
		return
	}

	switch cmd.Type {
	case "sysscript":
		log.Printf("Received Sysscript Execution Request [%s]\n", cmd.RequestID)
		
		engine := NewSysscriptEngine(cmd.Entitlements)
		output, err := engine.Execute(cmd.Script)
		
		var resultPayload map[string]string
		if err != nil {
			resultPayload = map[string]string{"error": err.Error(), "output": output}
		} else {
			resultPayload = map[string]string{"error": "", "output": output}
		}

		response := ResponseMessage{
			Type:      "command_result",
			RequestID: cmd.RequestID,
			Payload:   resultPayload,
		}
		
		if err := c.WriteJSON(response); err != nil {
			log.Println("write command_result error:", err)
		}
	
	case "pty_start":
		log.Printf("Starting Web PTY Session [%s]\n", cmd.RequestID)
		HandlePTYStart(c, cmd.RequestID)
	
	case "pty_input":
		HandlePTYInput([]byte(cmd.Data))
	
	case "pty_resize":
		HandlePTYResize(uint16(cmd.Rows), uint16(cmd.Cols))
	
	case "pty_stop":
		log.Printf("Stopping Web PTY Session\n")
		HandlePTYStop()
	}
}
