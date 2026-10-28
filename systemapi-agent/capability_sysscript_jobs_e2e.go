//go:build sysscript_jobs_e2e

// Test-only: npm run test:agent (scripts/test-agent.sh) builds the agent
// with -tags sysscript_jobs_e2e so it advertises sysscript_jobs before that
// capability is registered for every build. A build without the tag (every
// release build) does not advertise it.
// Threats: none; see capabilities.go.
package main

func init() {
	registerCapability("sysscript_jobs", func() bool { return true })
}
