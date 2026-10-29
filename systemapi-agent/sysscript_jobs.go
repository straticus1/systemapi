package main

// jobManager runs sysscripts off the connection's read goroutine.
//
// Threats: a long script stalling the read loop (no pong, so the server's
// stale-agent probe displaces a live agent; no PTY input; no channel
// credit), an unbounded number of concurrent scripts, and a panicking
// builtin taking the agent down. The read loop only checks size and the
// lease and hands the script to a bounded pool: a fixed number of workers
// and a small queue; when both are full the script is refused at once with
// agent_busy. Each script has its own context, created on receipt, with its
// whole-script deadline; a panic in one script ends only that script (error
// "internal"). On shutdown every script is cancelled with the cause
// agent_stopped and the workers get the TERM->KILL grace plus a margin to
// report. Does NOT survive an agent restart: a running script dies with the
// process. Does NOT bound memory or CPU inside a script beyond the deadline
// and output caps.
//
// Async jobs ("sysscript_job" frames) also guard against: a start frame
// replayed or retargeted (the sysscript_job lease binds the job id,
// deadline, timeout, script hash and canonical entitlements hash, the nonce
// is consumed, and a job id seen in the last 10 minutes is refused as
// duplicate_job), a deadline stretched by wall-clock skew (the effective
// deadline is the earliest of the signed deadline_unix, receipt + the signed
// timeout_s and receipt + the agent's ceiling, measured on the monotonic
// clock from receipt), and a result lost on a socket drop (a finished result
// is kept until the server acks it, listed in sysscript_job_sync and sent
// again on every new connection; at most jobDoneMax results or
// jobDoneBytesMax bytes are kept, the oldest dropped first). Every frame
// the manager emits goes through one ordered queue and one writer
// goroutine, so the read loop never writes, a job's frames are never
// reordered, and the sync of a new connection precedes every later frame.
// Two lanes share that queue: control frames (sync, accepted, running,
// rejections) are written before bulk frames (results, alerts, legacy
// frames), so a large backlog of results cannot delay a new job's
// accepted. The queue is capped at jobQueueMax frames and jobQueueMaxBytes;
// a frame for the current connection over the cap closes that connection
// (the next connection's sync restores the state), and a legacy frame over
// the cap is dropped; both are logged and counted. A status or rejection
// emitted while the agent is not connected, or still queued when the
// connection drops, is dropped: the server learns of an accepted or running
// job from the next sync and of a refusal only by its own ack timeout. A
// start frame repeated for a job the agent still holds (duplicate id or a
// replayed lease) is answered with that job's current status or kept
// result, not a rejection.
// Cancel and ack are unsigned: cancel can only shorten work and ack only
// frees memory; ids the agent does not hold are ignored.
// A converge job is a sysscript_job frame with kind "converge"
// (.omc/plans/convergence-drift.md §7): it carries bundle_json, mode and
// expect_plan_sha256 instead of a script, under a converge_job lease that
// binds the bundle hash, the canonical entitlements hash, the mode and the
// plan hash, so a check cannot be turned into an apply or pointed at another
// plan. It is refused as converge_unsupported unless --converge is on, as
// bad_mode unless mode=apply goes with a plan hash and mode=check with "-",
// and as bundle_too_large over the bundle cap. convergeRun's capped report
// rides in the result frame next to the capped output. Any other kind is
// bad_kind.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"sort"
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
	// workers to report; the queued frames then get as long again.
	jobStopMargin = 3 * time.Second
	// jobDoneMax and jobDoneBytesMax cap the finished results kept for the
	// server's ack.
	jobDoneMax      = 64
	jobDoneBytesMax = 16 << 20
	// jobRecentTTL is how long a job id stays a duplicate.
	jobRecentTTL = 10 * time.Minute
	// jobQueueMax and jobQueueMaxBytes cap the frames waiting for the
	// writer: room for every kept result plus margin.
	jobQueueMax      = 512
	jobQueueMaxBytes = jobDoneBytesMax + 8<<20
)

var (
	// errAgentBusy refuses a script when every worker and queue slot is
	// taken.
	errAgentBusy = errors.New("agent_busy")
	// errAgentStopped is the cancel cause for scripts ended by shutdown.
	errAgentStopped = errors.New("agent_stopped")
	// errJobCancelled is the cancel cause of a sysscript_job_cancel frame.
	errJobCancelled = errors.New("cancel requested")
	// errNoConnection drops a frame emitted while the agent is not
	// connected.
	errNoConnection = errors.New("no connection")
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
	id      string // the legacy request_id or the job id
	job     bool   // an async job (sysscript_job frame)
	script  string
	ents    *Entitlements
	ctx     context.Context
	cancel  context.CancelCauseFunc
	alerts  func(v interface{}) error
	started time.Time
	// deadline is an async job's effective deadline; runAt is when a worker
	// picked it up (zero while queued). Both are read under jobManager.mu.
	deadline time.Time
	runAt    time.Time
	// running, when set, is called as a worker picks the job up.
	running func()
	// conv, when set, makes this a converge job: run calls convergeRun and
	// leaves its report in report before finish.
	conv   *convergeRequest
	report json.RawMessage
	// finish reports the outcome. It is called exactly once, from a worker.
	finish func(output string, truncated bool, err error)
}

// jobFrame is one encoded frame waiting for the writer. pin sends it on
// that connection only (legacy frames answer on the connection they came
// on); nil means the current connection.
type jobFrame struct {
	b   []byte
	pin ptyOut
}

// jobDone is a finished async job's result, kept until acked.
type jobDone struct {
	id     string
	status string
	frame  []byte
}

type jobManager struct {
	mu     sync.Mutex
	cond   *sync.Cond // signals queue and writing changes
	live   map[*sysscriptJob]struct{}
	jobs   map[string]*sysscriptJob // async jobs queued or running
	done   []jobDone                // finished async results, finish order
	doneB  int
	recent map[string]time.Time // async job ids accepted, for duplicate_job
	out    ptyOut               // the enrolled connection; nil while down
	// closeOut closes out; it is called once when out's frames overflow.
	closeOut func()
	ctl      []jobFrame // control lane, written first
	bulk     []jobFrame // bulk lane
	queueB   int        // bytes in both lanes
	overflow int        // frames dropped over the queue cap
	writing  bool
	stopped  bool
	pending  chan *sysscriptJob
	workers  sync.WaitGroup
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
		jobs:    map[string]*sysscriptJob{},
		recent:  map[string]time.Time{},
		pending: make(chan *sysscriptJob, queue),
	}
	m.cond = sync.NewCond(&m.mu)
	for i := 0; i < workers; i++ {
		m.workers.Add(1)
		go m.worker()
	}
	go m.writer()
	return m
}

func (m *jobManager) worker() {
	defer m.workers.Done()
	for j := range m.pending {
		m.run(j)
	}
}

// writer sends queued frames in order, one at a time, without holding mu
// during the write. A failed write drops the frame: a broken connection is
// replaced, and kept results go out again after the next sync.
func (m *jobManager) writer() {
	m.mu.Lock()
	for {
		for len(m.ctl) == 0 && len(m.bulk) == 0 {
			m.cond.Wait()
		}
		lane := &m.ctl
		if len(m.ctl) == 0 {
			lane = &m.bulk
		}
		f := (*lane)[0]
		(*lane)[0] = jobFrame{}
		*lane = (*lane)[1:]
		m.queueB -= len(f.b)
		target := f.pin
		if target == nil {
			target = m.out
		}
		m.writing = true
		m.mu.Unlock()
		if target != nil {
			if err := target.WriteText(f.b); err != nil {
				log.Printf("sysscript frame not sent: %v", err)
			}
		}
		m.mu.Lock()
		m.writing = false
		m.cond.Broadcast()
	}
}

// enqueueLocked queues a frame for the writer on the control or bulk lane.
// Over the queue cap the frame is dropped; a frame for the current
// connection also closes it, so detach clears the queue and the next sync
// restores the state. m.mu is held.
func (m *jobManager) enqueueLocked(f jobFrame, ctl bool) {
	if len(m.ctl)+len(m.bulk) >= jobQueueMax || m.queueB+len(f.b) > jobQueueMaxBytes {
		m.overflow++
		if f.pin != nil {
			log.Printf("sysscript frame dropped: writer queue full (%d dropped)", m.overflow)
			return
		}
		log.Printf("sysscript frame dropped: writer queue full (%d dropped); closing the connection", m.overflow)
		if m.closeOut != nil {
			go m.closeOut()
			m.closeOut = nil
		}
		return
	}
	if ctl {
		m.ctl = append(m.ctl, f)
	} else {
		m.bulk = append(m.bulk, f)
	}
	m.queueB += len(f.b)
	m.cond.Broadcast()
}

// dropUnpinnedLocked drops the queued frames meant for the current
// connection. m.mu is held.
func (m *jobManager) dropUnpinnedLocked() {
	for _, lane := range []*[]jobFrame{&m.ctl, &m.bulk} {
		keep := (*lane)[:0]
		for _, f := range *lane {
			if f.pin != nil {
				keep = append(keep, f)
			} else {
				m.queueB -= len(f.b)
			}
		}
		for i := len(keep); i < len(*lane); i++ {
			(*lane)[i] = jobFrame{}
		}
		*lane = keep
	}
}

// sendFrame queues v on the bulk lane for the current connection. With no
// connection the frame is dropped and errNoConnection is returned.
func (m *jobManager) sendFrame(v interface{}) error {
	b, err := encodeFrame(v)
	if err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.out == nil {
		return errNoConnection
	}
	m.enqueueLocked(jobFrame{b: b}, false)
	return nil
}

// sendFrameTo queues an encoded frame on the bulk lane for out only.
func (m *jobManager) sendFrameTo(out ptyOut, b []byte) {
	m.mu.Lock()
	m.enqueueLocked(jobFrame{b: b, pin: out}, false)
	m.mu.Unlock()
}

// flush waits up to wait for the queue to drain. It reports whether it did.
func (m *jobManager) flush(wait time.Duration) bool {
	timedOut := false
	timer := time.AfterFunc(wait, func() {
		m.mu.Lock()
		timedOut = true
		m.cond.Broadcast()
		m.mu.Unlock()
	})
	defer timer.Stop()
	m.mu.Lock()
	defer m.mu.Unlock()
	for (len(m.ctl) > 0 || len(m.bulk) > 0 || m.writing) && !timedOut {
		m.cond.Wait()
	}
	return len(m.ctl) == 0 && len(m.bulk) == 0 && !m.writing
}

type jobSyncEntry struct {
	JobID  string `json:"job_id"`
	Status string `json:"status"`
}

type jobSyncPayload struct {
	Active  []string       `json:"active"`
	Unacked []jobSyncEntry `json:"unacked"`
}

// attach makes out the connection job frames go to. Under one lock it drops
// frames queued for the previous connection (kept results are in done),
// then queues sysscript_job_sync and every unacked result in finish order.
// A frame emitted afterwards queues behind them, so nothing overtakes the
// sync. The sync is on the control lane and the results on the bulk lane,
// so the sync is written first. closeOut closes out; it is used if out's
// frames overflow the queue. The agent calls attach once a connection has
// enrolled.
func (m *jobManager) attach(out ptyOut, closeOut func()) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.out = out
	m.closeOut = closeOut
	m.dropUnpinnedLocked()
	sync := jobSyncPayload{Active: make([]string, 0, len(m.jobs)), Unacked: make([]jobSyncEntry, 0, len(m.done))}
	for id := range m.jobs {
		sync.Active = append(sync.Active, id)
	}
	sort.Strings(sync.Active)
	for _, d := range m.done {
		sync.Unacked = append(sync.Unacked, jobSyncEntry{JobID: d.id, Status: d.status})
	}
	b, err := encodeFrame(ResponseMessage{Type: "sysscript_job_sync", Payload: sync})
	if err != nil {
		log.Printf("sysscript_job_sync not encoded: %v", err)
		return
	}
	m.enqueueLocked(jobFrame{b: b}, true)
	for _, d := range m.done {
		m.enqueueLocked(jobFrame{b: d.frame}, false)
	}
}

// detach forgets out if it is still the current connection, with the frames
// queued for it. Jobs keep running.
func (m *jobManager) detach(out ptyOut) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.out != out {
		return
	}
	m.out = nil
	m.closeOut = nil
	m.dropUnpinnedLocked()
}

// submit queues j or refuses it at once: errAgentBusy when the pool and the
// queue are full, errAgentStopped after stopAll. It never blocks.
func (m *jobManager) submit(j *sysscriptJob) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.submitLocked(j)
}

func (m *jobManager) submitLocked(j *sysscriptJob) error {
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
		status, _ := jobOutcome(err)
		log.Printf("sysscript %s ended status=%s dur=%s", j.id, status, time.Since(j.started).Round(time.Millisecond))
		j.finish(output, truncated, err)
	}()
	if errors.Is(context.Cause(j.ctx), errAgentStopped) {
		err = errAgentStopped
		return
	}
	if j.ctx.Err() != nil {
		// Cancelled or timed out while queued: no running, no engine.
		err = scriptCtxErr(j.ctx)
		return
	}
	if j.running != nil {
		j.running()
	}
	if j.conv != nil {
		res := convergeRun(j.ctx, *j.conv, convergeBackend())
		output, truncated, j.report = res.Output, res.OutputTruncated, res.Report
		err = convergeJobErr(res)
	} else {
		engine := NewSysscriptEngine(j.ctx, j.ents)
		engine.alerts = &alertSink{send: j.alerts, scriptID: j.id, job: j.job}
		output, err = engine.Execute(j.script)
		truncated = engine.outputTruncated
	}
	if err != nil && errors.Is(context.Cause(j.ctx), errAgentStopped) {
		err = errAgentStopped
	}
}

// stopAll cancels every queued and running job with the cause
// errAgentStopped, refuses new ones, and waits up to wait for the workers
// to report, then up to jobStopMargin for their frames to be written. It
// reports whether the workers all finished.
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
	finished := true
	select {
	case <-done:
	case <-time.After(wait):
		log.Printf("sysscript workers still running after %s at shutdown", wait)
		finished = false
	}
	if !m.flush(jobStopMargin) {
		log.Printf("sysscript frames still queued after %s at shutdown", jobStopMargin)
	}
	return finished
}

// submitLegacy runs a legacy "sysscript" frame (already size-checked and
// authorized) on the pool, with the legacy whole-script deadline counted
// from receipt. Its alerts and its command_result go back on out, the
// connection the frame came on, through the ordered writer; if that
// connection is gone they are lost, as before. A full pool answers
// agent_busy at once.
func (m *jobManager) submitLegacy(out ptyOut, requestID, script string, ents *Entitlements, legacy time.Duration) {
	base, cancel := context.WithCancelCause(context.Background())
	ctx, stopTimer := context.WithTimeout(base, legacy)
	j := &sysscriptJob{
		id:     requestID,
		script: script,
		ents:   ents,
		ctx:    ctx,
		alerts: func(v interface{}) error {
			b, err := encodeFrame(v)
			if err != nil {
				return err
			}
			m.sendFrameTo(out, b)
			return nil
		},
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
		b, encErr := commandResultFrame(requestID, errText, output, truncated)
		if encErr != nil {
			log.Printf("command_result %s not encoded: %v", requestID, encErr)
			return
		}
		m.sendFrameTo(out, b)
	}
	if err := m.submit(j); err != nil {
		j.cancel(err)
		log.Printf("sysscript %s refused: %s", requestID, err.Error())
		j.finish("", false, err)
	}
}

// jobStatusPayload is the payload of sysscript_job_status.
type jobStatusPayload struct {
	Status       string `json:"status"`
	DeadlineUnix int64  `json:"deadline_unix,omitempty"`
	Queued       bool   `json:"queued,omitempty"`
	StartedUnix  int64  `json:"started_unix,omitempty"`
}

// jobResultPayload is the payload of sysscript_job_result. Report is a
// converge job's report (absent for a script).
type jobResultPayload struct {
	Status          string          `json:"status"`
	Error           string          `json:"error"`
	Output          string          `json:"output"`
	OutputTruncated bool            `json:"output_truncated"`
	DurationMS      int64           `json:"duration_ms"`
	Report          json.RawMessage `json:"report,omitempty"`
}

// jobResultFrame encodes a sysscript_job_result, its encoded size capped at
// jobFrameMax (encodeOutputFrame): the output is cut to fit; the report is
// already capped at convergeReportMax, far under the frame cap.
func jobResultFrame(id, status, errText, output string, truncated bool, dur time.Duration, report json.RawMessage) ([]byte, error) {
	errText, _ = frameText(errText, frameErrMax)
	return encodeOutputFrame(func(o string, tr bool) interface{} {
		return ResponseMessage{
			Type:  "sysscript_job_result",
			JobID: id,
			Payload: jobResultPayload{
				Status: status, Error: errText, Output: o, OutputTruncated: tr, DurationMS: dur.Milliseconds(), Report: report,
			},
		}
	}, output, truncated)
}

// convergeBackend is the host converge jobs run against; tests replace it.
var convergeBackend = osHostBackend

// convergeJobError carries a converge run's (already masked) error text and
// the sentinel jobOutcome maps to the job status.
type convergeJobError struct {
	text string
	kind error
}

func (e *convergeJobError) Error() string { return e.text }
func (e *convergeJobError) Unwrap() error { return e.kind }

// convergeJobErr maps a converge result to the error jobOutcome reads: nil
// when it succeeded, timed_out and cancelled to their sentinels, and a run
// that failed only because resources failed or were denied to
// resources_failed.
func convergeJobErr(res convergeResult) error {
	if res.Status == "succeeded" {
		return nil
	}
	e := &convergeJobError{text: res.Error}
	if e.text == "" {
		e.text = res.ErrorCode
	}
	if e.text == "" {
		e.text = "resources_failed"
	}
	switch res.ErrorCode {
	case "timed_out":
		e.kind = errScriptTimedOut
	case "cancelled":
		e.kind = errScriptCancelled
	}
	return e
}

// jobOutcome maps a script's end to a job status and error text.
func jobOutcome(err error) (string, string) {
	switch {
	case err == nil:
		return "succeeded", ""
	case errors.Is(err, errAgentStopped):
		return "failed", errAgentStopped.Error()
	case errors.Is(err, errScriptTimedOut):
		return "timed_out", err.Error()
	case errors.Is(err, errScriptCancelled):
		return "cancelled", err.Error()
	default:
		return "failed", err.Error()
	}
}

// rejectJob answers a sysscript_job frame that was not accepted. The job id
// is echoed only when it is well formed.
func (m *jobManager) rejectJob(id, code string) {
	if !sysscriptJobRe.MatchString(id) {
		id = ""
	}
	log.Printf("sysscript job %s rejected: %s", id, code)
	b, err := jobResultFrame(id, "rejected", code, "", false, 0, nil)
	if err != nil {
		log.Printf("sysscript job %s rejection not encoded: %v", id, err)
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.out == nil {
		return
	}
	m.enqueueLocked(jobFrame{b: b}, true)
}

// startJob checks a sysscript_job frame on the read loop and queues it:
// job id, kind, script or bundle size (and, for converge, the capability and
// the mode and plan pairing), canonical entitlements, the lease (which binds
// the job id, deadline, timeout, script or bundle and entitlements, and for
// converge the mode and plan hash) and its nonce, then duplicate id, timeout
// and deadline. A refusal is answered as
// sysscript_job_result{status:rejected}. now is the receipt time; it must
// carry a monotonic reading (time.Now).
func (m *jobManager) startJob(hostID string, cmd *CommandMessage, now time.Time) {
	id := cmd.JobID
	if !sysscriptJobRe.MatchString(id) {
		m.rejectJob(id, "bad_job_id")
		return
	}
	var conv *convergeRequest
	switch cmd.Kind {
	case "", "sysscript":
		if len(cmd.Script) > scriptMaxBytes {
			m.rejectJob(id, "script_too_large")
			return
		}
	case "converge":
		switch {
		case !convergeCapable():
			m.rejectJob(id, "converge_unsupported")
			return
		case cmd.Script != "":
			m.rejectJob(id, "bad_payload")
			return
		case len(cmd.BundleJSON) > convergeBundleMax:
			m.rejectJob(id, "bundle_too_large")
			return
		case !convergeModeOK(cmd.Mode, cmd.ExpectPlan):
			m.rejectJob(id, "bad_mode")
			return
		}
		conv = &convergeRequest{BundleJSON: cmd.BundleJSON, Ents: cmd.Entitlements, Mode: cmd.Mode, ExpectPlan: cmd.ExpectPlan}
	default:
		m.rejectJob(id, "bad_kind")
		return
	}
	canon, err := canonicalEntitlements(cmd.Entitlements)
	if err != nil {
		m.rejectJob(id, err.Error())
		return
	}
	action, payload := "sysscript_job", ""
	if conv != nil {
		action = "converge_job"
		payload, err = convergeJobLeasePayload(id, cmd.DeadlineUnix, cmd.TimeoutS, sha256Hex(cmd.BundleJSON), sha256Hex(canon), cmd.Mode, cmd.ExpectPlan)
	} else {
		payload, err = sysscriptJobLeasePayload(id, cmd.DeadlineUnix, cmd.TimeoutS, sha256Hex(cmd.Script), sha256Hex(canon))
	}
	if err != nil {
		m.rejectJob(id, err.Error())
		return
	}
	if err := authorizeCommand(hostID, action, payload, cmd.Lease, now); err != nil {
		if err.Error() == "replay" && m.answerHeld(id) {
			return
		}
		m.rejectJob(id, err.Error())
		return
	}
	// The effective deadline: the earliest of the signed wall-clock
	// deadline, receipt + the signed timeout and receipt + the ceiling. It is
	// measured from receipt on the monotonic clock, so skew only shortens it.
	limit := time.Unix(cmd.DeadlineUnix, 0).Sub(now)
	if limit <= 0 {
		m.rejectJob(id, "bad_deadline")
		return
	}
	if t := time.Duration(cmd.TimeoutS) * time.Second; t < limit {
		limit = t
	}
	if jobCfg.Max < limit {
		limit = jobCfg.Max
	}
	deadline := now.Add(limit)
	base, cancel := context.WithCancelCause(context.Background())
	ctx, stopTimer := context.WithDeadline(base, deadline)
	j := &sysscriptJob{id: id, job: true, script: cmd.Script, ents: cmd.Entitlements, conv: conv, ctx: ctx, started: now, deadline: deadline}
	j.cancel = func(cause error) {
		cancel(cause)
		stopTimer()
	}
	j.alerts = m.sendFrame
	j.running = func() {
		m.mu.Lock()
		defer m.mu.Unlock()
		j.runAt = time.Now()
		m.statusLocked(j)
	}
	j.finish = func(output string, truncated bool, err error) {
		status, errText := jobOutcome(err)
		b, encErr := jobResultFrame(id, status, errText, output, truncated, time.Since(j.started), j.report)
		if encErr != nil {
			log.Printf("sysscript job %s result not encoded: %v", id, encErr)
			b, _ = jobResultFrame(id, "failed", "internal", "", false, time.Since(j.started), nil)
			status = "failed"
		}
		m.finishJob(id, status, b)
	}
	m.mu.Lock()
	code := m.admitLocked(j, now)
	switch code {
	case "":
		// Queued under the same lock as the hand-off to the pool, so
		// "accepted" precedes the worker's "running".
		m.statusLocked(j)
	case "duplicate_job":
		if m.answerHeldLocked(id) {
			code = "held"
		}
	}
	m.mu.Unlock()
	if code == "held" {
		j.cancel(errors.New("duplicate_job"))
		return
	}
	if code != "" {
		j.cancel(errors.New(code))
		m.rejectJob(id, code)
		return
	}
	log.Printf("sysscript job %s accepted deadline=%s", id, limit.Round(time.Second))
}

// statusLocked queues j's current status (accepted while queued, running
// once picked up) on the control lane. m.mu is held.
func (m *jobManager) statusLocked(j *sysscriptJob) {
	if m.out == nil {
		return
	}
	p := jobStatusPayload{Status: "accepted", DeadlineUnix: j.deadline.Unix(), Queued: true}
	if !j.runAt.IsZero() {
		p = jobStatusPayload{Status: "running", StartedUnix: j.runAt.Unix()}
	}
	b, err := encodeFrame(ResponseMessage{Type: "sysscript_job_status", JobID: j.id, Payload: p})
	if err != nil {
		log.Printf("sysscript job %s status not encoded: %v", j.id, err)
		return
	}
	m.enqueueLocked(jobFrame{b: b}, true)
}

// answerHeld answers a repeated start frame for a job the agent holds with
// its current status, or its kept result. It reports whether it did.
func (m *jobManager) answerHeld(id string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.answerHeldLocked(id)
}

func (m *jobManager) answerHeldLocked(id string) bool {
	if j, ok := m.jobs[id]; ok {
		m.statusLocked(j)
		return true
	}
	for _, d := range m.done {
		if d.id == id {
			if m.out != nil {
				m.enqueueLocked(jobFrame{b: d.frame}, false)
			}
			return true
		}
	}
	return false
}

// admitLocked refuses a duplicate id, then hands j to the pool. It returns
// the refusal code, or "" once j is queued. m.mu is held.
func (m *jobManager) admitLocked(j *sysscriptJob, now time.Time) string {
	for id, at := range m.recent {
		if now.Sub(at) > jobRecentTTL {
			delete(m.recent, id)
		}
	}
	if _, ok := m.jobs[j.id]; ok {
		return "duplicate_job"
	}
	if _, ok := m.recent[j.id]; ok {
		return "duplicate_job"
	}
	for _, d := range m.done {
		if d.id == j.id {
			return "duplicate_job"
		}
	}
	if err := m.submitLocked(j); err != nil {
		return err.Error()
	}
	m.jobs[j.id] = j
	m.recent[j.id] = now
	return ""
}

// finishJob moves a job from live to done in one step, so a sync lists it in
// exactly one of active and unacked, and sends its result if connected.
func (m *jobManager) finishJob(id, status string, frame []byte) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.jobs, id)
	m.recent[id] = time.Now()
	m.done = append(m.done, jobDone{id: id, status: status, frame: frame})
	m.doneB += len(frame)
	for len(m.done) > 0 && (len(m.done) > jobDoneMax || m.doneB > jobDoneBytesMax) {
		old := m.done[0]
		log.Printf("sysscript job %s result dropped unacked (over %d results or %d bytes)", old.id, jobDoneMax, jobDoneBytesMax)
		m.doneB -= len(old.frame)
		m.done[0] = jobDone{}
		m.done = m.done[1:]
	}
	if m.out != nil {
		m.enqueueLocked(jobFrame{b: frame}, false)
	}
}

// ackJob frees a kept result once the server has stored it.
func (m *jobManager) ackJob(id string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i, d := range m.done {
		if d.id == id {
			m.doneB -= len(d.frame)
			copy(m.done[i:], m.done[i+1:])
			m.done[len(m.done)-1] = jobDone{}
			m.done = m.done[:len(m.done)-1]
			return
		}
	}
}

// cancelJob cancels a queued or running async job; the worker reports it as
// cancelled. reason is the server's, for the log only.
func (m *jobManager) cancelJob(id, reason string) {
	m.mu.Lock()
	j := m.jobs[id]
	m.mu.Unlock()
	if j == nil {
		return
	}
	log.Printf("sysscript job %s cancel requested reason=%q", id, capText(reason, 64))
	j.cancel(errJobCancelled)
}
