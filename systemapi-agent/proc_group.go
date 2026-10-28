package main

// jobCommand runs a child for a sysscript builtin, bound to the job context.
//
// Threats: a script deadline or cancel that leaves the child, or the
// children it forked, running (an apt that keeps going after the server
// gave up, a `sleep 600 &` that holds the output pipe open), and a group
// signal that lands on an unrelated process after the leader's pid was
// reused. On linux and darwin the child leads its own process group; when
// the context ends the whole group gets SIGTERM, then SIGKILL after
// jobKillGrace (sooner once the leader has exited and the agent's output
// pipes are closed). Setsid is refused, as it would leave that group. The leader is not
// reaped until that escalation is over, so its pid, which is the group id,
// cannot be reused while the group is signalled. Output written to a
// non-file Stdout/Stderr goes through pipes the agent owns, and the leader
// is reaped only after they reach EOF or the context ends. Does NOT reach a
// grandchild that moved itself into another group or session (setsid); with
// the shipped unit's KillMode=control-group, stopping the service still does.
// Elsewhere (windows, the BSDs) only the direct child is killed.

import (
	"bytes"
	"context"
	"os/exec"
	"time"
)

// jobKillGrace is the time between SIGTERM and SIGKILL to a job's group.
const jobKillGrace = 10 * time.Second

// jobCmd is an *exec.Cmd whose Start, Wait, Run, Output and CombinedOutput
// apply the job context. Set Stdin, Stdout, Stderr, Env and Dir on the
// embedded Cmd as usual; StdoutPipe also works.
type jobCmd struct {
	*exec.Cmd
	ctx context.Context
	grp *procGroup // platform state, set by Start
}

// jobCommand is exec.Command bound to ctx. It never consults ctx before
// Start, which refuses an already ended context.
func jobCommand(ctx context.Context, name string, args ...string) *jobCmd {
	return &jobCmd{Cmd: exec.Command(name, args...), ctx: ctx}
}

// Run starts the command and waits for it.
func (c *jobCmd) Run() error {
	if err := c.Start(); err != nil {
		return err
	}
	return c.Wait()
}

// Output runs the command and returns its stdout, capped at hostFileCap.
// Stderr is discarded unless the caller set it.
func (c *jobCmd) Output() ([]byte, error) {
	out := &capWriter{max: hostFileCap}
	c.Stdout = out
	err := c.Run()
	return bytes.Clone(out.buf.Bytes()), err
}

// CombinedOutput runs the command and returns stdout and stderr together,
// capped at hostFileCap.
func (c *jobCmd) CombinedOutput() ([]byte, error) {
	out := &capWriter{max: hostFileCap}
	c.Stdout = out
	c.Stderr = out
	err := c.Run()
	return bytes.Clone(out.buf.Bytes()), err
}
