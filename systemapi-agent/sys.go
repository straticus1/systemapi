// Service-management channel, agent side (docs/sah-os-management-design.md
// Phase 1), modelled on tcp.go. Unlike the TCP forward this is one
// request/response: restart one unit, then read its status to confirm. The
// server relays the client's request as a sys_service frame and the agent
// answers with one sys_result frame.
//
// Threats: service restart is root-equivalent. The lease signs "<unit>\n
// <action>" and the agent rebuilds that payload from the unit and action in
// the frame, so a lease minted for one unit can never restart another, and a
// tampered or expired lease is refused by verifyLease (lease.go). The agent
// then applies its own fail-closed gate (sys_policy.go): the host must
// advertise the service capability, the verb must be in the closed set, and
// the unit must pass the shape guard. The command runs through the Phase 0
// ServiceManager (platform_service.go), which uses fixed argv and no shell, so
// a unit name can never inject a command. Command output is capped before it
// is returned and is never logged. Every refusal is a sys_result with an error
// code, never a dropped connection. Does NOT persist across a reconnect: a
// request whose connection drops is simply retried by the caller.
package main

import (
	"encoding/json"
	"log"
	"regexp"
	"time"
)

// sysRequestRe matches a server-minted request id (playground/sys.js).
var sysRequestRe = regexp.MustCompile(`^sys_[A-Za-z0-9_-]{16,64}$`)

// sysOutputMax caps the bytes of command output returned to the server.
const sysOutputMax = 8 * 1024

// sysServices returns the host's ServiceManager; tests replace it.
var sysServices = func() ServiceManager { return currentPlatform().Services }

// sysServiceMsg is the server's sys_service request frame.
type sysServiceMsg struct {
	Type      string `json:"type"`
	RequestID string `json:"request_id"`
	Unit      string `json:"unit"`
	Action    string `json:"action"`
	Lease     *Lease `json:"lease"`
}

// handleSys dispatches the sys channel frames. It reports whether typ was a
// sys frame. A refusal is a sys_result error, never a fatal connection error.
func (c *channelConn) handleSys(typ string, message []byte) bool {
	if typ != "sys_service" {
		return false
	}
	var msg sysServiceMsg
	if err := json.Unmarshal(message, &msg); err != nil {
		log.Printf("rejected malformed sys_service")
		return true
	}
	c.sysService(msg, time.Now())
	return true
}

func capSysOutput(s string) string {
	if len(s) > sysOutputMax {
		return s[:sysOutputMax]
	}
	return s
}

func sysResultError(out ptyOut, rid, code string) {
	_ = out.WriteJSON(ResponseMessage{Type: "sys_result", RequestID: rid, Payload: map[string]interface{}{
		"ok":    false,
		"error": code,
	}})
}

// sysService verifies the lease, applies the agent's own gate, then restarts
// the unit and reads its status to confirm.
func (c *channelConn) sysService(msg sysServiceMsg, now time.Time) {
	rid := msg.RequestID
	if !sysRequestRe.MatchString(rid) {
		log.Printf("sys_service refused: bad request id")
		sysResultError(c.out, "", "internal")
		return
	}
	// The lease signs the exact unit and action; rebuild the payload from what
	// we are about to act on so a lease for one unit never acts on another.
	payload, err := sysServiceLeasePayload(msg.Unit, msg.Action)
	if err != nil {
		log.Printf("sys_service refused: %s", err.Error())
		sysResultError(c.out, rid, "lease_required")
		return
	}
	if err := authorizeCommand(c.hostID, "sys_service", payload, msg.Lease, now); err != nil {
		log.Printf("sys_service refused: %s", err.Error())
		sysResultError(c.out, rid, "lease_required")
		return
	}
	// The agent's own fail-closed gate, independent of the lease.
	if err := checkSysServicePolicy(msg.Unit, msg.Action); err != nil {
		log.Printf("sys_service refused: %s", err.Error())
		sysResultError(c.out, rid, err.Error())
		return
	}
	svc := sysServices()
	output, actErr := svc.Action(msg.Action, msg.Unit)
	result := map[string]interface{}{
		"ok":     actErr == nil,
		"unit":   msg.Unit,
		"action": msg.Action,
		"output": capSysOutput(output),
	}
	if actErr != nil {
		result["error"] = "action_failed"
	}
	// Status is the confirm read (same unit, no separate lease).
	if status, statusErr := svc.Status(msg.Unit); statusErr == nil {
		result["active"] = status.Active
		result["state"] = status.State
		result["status_output"] = capSysOutput(status.Output)
	}
	_ = c.out.WriteJSON(ResponseMessage{Type: "sys_result", RequestID: rid, Payload: result})
	log.Printf("sys_service %s unit=%s action=%s ok=%t", rid, msg.Unit, msg.Action, actErr == nil)
}
