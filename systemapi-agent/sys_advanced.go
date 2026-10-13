package main

import (
	"fmt"
	"log"

	"go.starlark.net/starlark"
)

// --- sys.alerts ---

// sys.alerts.push(severity, message) writes the alert to the agent log only.
// Nothing forwards it to the control plane yet, so it returns False to tell
// the script the alert was not delivered.
func (engine *SysscriptEngine) alertsPush(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var severity, message string
	if err := starlark.UnpackArgs("push", args, kwargs, "severity", &severity, "message", &message); err != nil {
		return starlark.None, err
	}
	log.Printf("[sysscript alert, not forwarded] severity=%s message=%s", severity, message)
	return starlark.False, nil
}

// --- sys.security and sys.events ---
// These names are reserved but have no implementation. They fail so a script
// never mistakes a missing scanner for a clean result.

func notImplemented(name string) error {
	return fmt.Errorf("%s is not implemented in this agent", name)
}

// sys.security.yara_scan(path)
func (engine *SysscriptEngine) securityYaraScan(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	return starlark.None, notImplemented("sys.security.yara_scan")
}

// sys.security.scan_memory(pid)
func (engine *SysscriptEngine) securityScanMemory(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	return starlark.None, notImplemented("sys.security.scan_memory")
}

// sys.events.listen(event_type, callback)
func (engine *SysscriptEngine) eventsListen(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	return starlark.None, notImplemented("sys.events.listen")
}
