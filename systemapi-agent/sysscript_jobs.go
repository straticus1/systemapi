package main

// jobManager runs sysscripts off the connection's read goroutine.
//
// Threats: a long script stalling the read loop (no pong, so the server's
// stale-agent probe displaces a live agent; no PTY input; no channel
// credit), an unbounded number of concurrent scripts, and a panicking
// builtin taking the agent down. The read loop only checks size and the
// lease (unchanged) and hands the script to a bounded pool: a fixed number
// of workers and a small queue; when both are full the script is refused at
// once with agent_busy. Each script has its own context, created on receipt,
// with its whole-script deadline; a panic in one script ends only that
// script (error "internal"). On shutdown every script is cancelled with the
// cause agent_stopped and the workers get the TERM->KILL grace plus a
// margin to report. Does NOT survive an agent restart: a running script dies
// with the process. Does NOT bound memory or CPU inside a script beyond the
// deadline and output caps.

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sync"
	"time"
)

const (
	jobWorkersDefault   = 4
	jobWorkersMax       = 16
	jobPendingMax       = 8 // scripts waiting for a worker
	jobLegacyDefaultSec = 300
	jobMaxSecondsMax    = 3600
	// jobStopMargin is added to jobKillGrace when shutdown waits for the
	// workers to report.
	jobStopMargin = 3 * time.Second
)

var (
	// errAgentBusy refuses a script when every worker and queue slot is
	// taken.
	errAgentBusy = errors.New("agent_busy")
	// errAgentStopped is the cancel cause for scripts ended by shutdown.
	errAgentStopped = errors.New("agent_stopped")
)

// jobConfig comes from the agent flags --sysscript-workers,
// --sysscript-legacy-seconds and --sysscript-max-seconds.
type jobConfig struct {
	Workers int
	// Legacy is the whole-script deadline of a legacy "sysscript" frame.
	Legacy time.Duration
	// Max is the agent's ceiling for any script deadline.
	Max time.Duration
}

var jobCfg = jobConfig{
	Workers: jobWorkersDefault,
	Legacy:  jobLegacyDefaultSec * time.Second,
	Max:     jobMaxSecondsMax * time.Second,
}

// parseJobFlags validates the sysscript flags. The legacy deadline is
// clamped to the ceiling.
func parseJobFlags(workers, legacySec, maxSec int) (jobConfig, error) {
	if workers < 1 || workers > jobWorkersMax {
		return jobConfig{}, fmt.Errorf("--sysscript-workers must be 1..%d", jobWorkersMax)
	}
	if legacySec < 1 || legacySec > jobMaxSecondsMax {
		return jobConfig{}, fmt.Errorf("--sysscript-legacy-seconds must be 1..%d", jobMaxSecondsMax)
	}
	if maxSec < 1 || maxSec > jobMaxSecondsMax {
		return jobConfig{}, fmt.Errorf("--sysscript-max-seconds must be 1..%d", jobMaxSecondsMax)
	}
	if legacySec > maxSec {
		legacySec = maxSec
	}
	return jobConfig{
		Workers: workers,
		Legacy:  time.Duration(legacySec) * time.Second,
		Max:     time.Duration(maxSec) * time.Second,
	}, nil
}

// sysscriptJob is one script queued or running.
type sysscriptJob struct {
	id      string // the legacy request_id
	script  string
	ents    *Entitlements
	ctx     context.Context
	cancel  context.CancelCauseFunc
	alerts  func(v interface{}) error
	started time.Time
	// finish reports the outcome. It is called exactly once, from a worker.
	finish func(output string, truncated bool, err error)
}

type jobManager struct {
	mu      sync.Mutex
	live    map[*sysscriptJob]struct{}
	stopped bool
	pending chan *sysscriptJob
	workers sync.WaitGroup
}

var (
	jobMgrMu   sync.Mutex
	jobMgrInst *jobManager
)

// jobMgr is the agent's job manager, started on first use with jobCfg.
func jobMgr() *jobManager {
	jobMgrMu.Lock()
	defer jobMgrMu.Unlock()
	if jobMgrInst == nil {
		jobMgrInst = newJobManager(jobCfg.Workers, jobPendingMax)
	}
	return jobMgrInst
}

func newJobManager(workers, queue int) *jobManager {
	m := &jobManager{
		live:    map[*sysscriptJob]struct{}{},
		pending: make(chan *sysscriptJob, queue),
	}
	for i := 0; i < workers; i++ {
		m.workers.Add(1)
		go m.worker()
	}
	return m
}

func (m *jobManager) worker() {
	defer m.workers.Done()
	for j := range m.pending {
		m.run(j)
	}
}

// submit queues j or refuses it at once: errAgentBusy when the pool and the
// queue are full, errAgentStopped after stopAll. It never blocks.
func (m *jobManager) submit(j *sysscriptJob) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.stopped {
		return errAgentStopped
	}
	select {
	case m.pending <- j:
		m.live[j] = struct{}{}
		return nil
	default:
		return errAgentBusy
	}
}

// run executes one job; a panic ends that job as "internal".
func (m *jobManager) run(j *sysscriptJob) {
	output, truncated, err := "", false, error(nil)
	defer func() {
		if r := recover(); r != nil {
			log.Printf("sysscript %s panicked: %v", j.id, r)
			output, truncated, err = "", false, errors.New("internal")
		}
		j.cancel(nil)
		m.mu.Lock()
		delete(m.live, j)
		m.mu.Unlock()
		status := "succeeded"
		if err != nil {
			status = "failed"
		}
		log.Printf("sysscript %s ended status=%s dur=%s", j.id, status, time.Since(j.started).Round(time.Millisecond))
		j.finish(output, truncated, err)
	}()
	if errors.Is(context.Cause(j.ctx), errAgentStopped) {
		err = errAgentStopped
		return
	}
	engine := NewSysscriptEngine(j.ctx, j.ents)
	engine.alerts = &alertSink{send: j.alerts, scriptID: j.id}
	output, err = engine.Execute(j.script)
	truncated = engine.outputTruncated
	if err != nil && errors.Is(context.Cause(j.ctx), errAgentStopped) {
		err = errAgentStopped
	}
}

// stopAll cancels every queued and running job with the cause
// errAgentStopped, refuses new ones, and waits up to wait for the workers
// to report. It reports whether they all finished.
func (m *jobManager) stopAll(wait time.Duration) bool {
	m.mu.Lock()
	if !m.stopped {
		m.stopped = true
		for j := range m.live {
			j.cancel(errAgentStopped)
		}
		close(m.pending)
	}
	m.mu.Unlock()
	done := make(chan struct{})
	go func() {
		m.workers.Wait()
		close(done)
	}()
	select {
	case <-done:
		return true
	case <-time.After(wait):
		log.Printf("sysscript workers still running after %s at shutdown", wait)
		return false
	}
}

// submitLegacy runs a legacy "sysscript" frame (already size-checked and
// authorized) on the pool, with the legacy whole-script deadline counted
// from receipt. The result goes back as command_result on out, the
// connection the frame came on; if that connection is gone the result is
// lost, as before. A full pool answers agent_busy at once.
func (m *jobManager) submitLegacy(out ptyOut, requestID, script string, ents *Entitlements, legacy time.Duration) {
	base, cancel := context.WithCancelCause(context.Background())
	ctx, stopTimer := context.WithTimeout(base, legacy)
	j := &sysscriptJob{
		id:      requestID,
		script:  script,
		ents:    ents,
		ctx:     ctx,
		alerts:  out.WriteJSON,
		started: time.Now(),
	}
	j.cancel = func(cause error) {
		cancel(cause)
		stopTimer()
	}
	j.finish = func(output string, truncated bool, err error) {
		errText := ""
		if err != nil {
			errText = err.Error()
		}
		writeCommandResult(out, requestID, errText, output, truncated)
	}
	if err := m.submit(j); err != nil {
		j.cancel(err)
		log.Printf("sysscript %s refused: %s", requestID, err.Error())
		writeCommandResult(out, requestID, err.Error(), "", false)
	}
}
