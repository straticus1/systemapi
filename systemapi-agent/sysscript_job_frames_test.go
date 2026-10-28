package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

func newJobID(t *testing.T) string {
	t.Helper()
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return "sjb_" + base64.RawURLEncoding.EncodeToString(b)
}

// jobStart is a signed sysscript_job frame for host.
func jobStart(t *testing.T, priv ed25519.PrivateKey, host, id, script string, ents map[string]interface{}, deadline int64, timeoutS int) map[string]interface{} {
	t.Helper()
	raw, err := json.Marshal(ents)
	if err != nil {
		t.Fatal(err)
	}
	payload := jobPayloadOf(t, id, deadline, timeoutS, script, raw)
	return map[string]interface{}{
		"type": "sysscript_job", "job_id": id, "script": script, "entitlements": ents,
		"deadline_unix": deadline, "timeout_s": timeoutS,
		"lease": signLease(t, priv, host, "sysscript_job", payload, time.Now().Add(time.Minute).Unix()),
	}
}

type jobSrvFrame struct {
	n int64
	m map[string]interface{}
}

// jobServer is a fake control plane that serves every connection the agent
// makes (while gate is open) and tags the agent's frames with the
// connection number.
type jobServer struct {
	mu     sync.Mutex
	conn   *websocket.Conn
	n      int64
	gate   atomic.Bool
	stall  atomic.Bool // stop reading the agent's frames
	frames chan jobSrvFrame
}

func (s *jobServer) write(t *testing.T, v interface{}) {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.conn.WriteJSON(v); err != nil {
		t.Errorf("server write: %v", err)
	}
}

// drop closes the current connection.
func (s *jobServer) drop() {
	s.mu.Lock()
	defer s.mu.Unlock()
	_ = s.conn.Close()
}

// next returns the next frame on any connection that matches ok.
func (s *jobServer) next(t *testing.T, within time.Duration, what string, ok func(f jobSrvFrame) bool) jobSrvFrame {
	t.Helper()
	end := time.After(within)
	for {
		select {
		case f := <-s.frames:
			if ok(f) {
				return f
			}
		case <-end:
			t.Fatalf("no %s within %s", what, within)
		}
	}
}

// nextJob returns the next frame carrying job id.
func (s *jobServer) nextJob(t *testing.T, id string, within time.Duration) map[string]interface{} {
	t.Helper()
	return s.next(t, within, "frame for "+id, func(f jobSrvFrame) bool { return f.m["job_id"] == id }).m
}

// firstOn returns the first frame of connection n, failing if a frame of
// another connection newer than n shows up first.
func (s *jobServer) firstOn(t *testing.T, n int64, within time.Duration) map[string]interface{} {
	t.Helper()
	return s.next(t, within, fmt.Sprintf("first frame on connection %d", n), func(f jobSrvFrame) bool { return f.n >= n }).m
}

func startJobAgent(t *testing.T) (*jobServer, *agentConn, ed25519.PrivateKey) {
	t.Helper()
	pubKey, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub := base64.StdEncoding.EncodeToString(pubKey)
	s := &jobServer{frames: make(chan jobSrvFrame, 1024)}
	s.gate.Store(true)
	var a *agentConn
	srv, _ := fakeControlPlane(t, func(n int64, c *websocket.Conn) {
		if !s.gate.Load() {
			return
		}
		s.mu.Lock()
		s.conn, s.n = c, n
		err := c.WriteJSON(map[string]string{"type": "enrolled", "host_id": a.st.HostID, "control_pubkey": pub})
		s.mu.Unlock()
		if err != nil {
			return
		}
		for {
			for s.stall.Load() {
				time.Sleep(10 * time.Millisecond)
			}
			_, raw, err := c.ReadMessage()
			if err != nil {
				return
			}
			var m map[string]interface{}
			if json.Unmarshal(raw, &m) == nil && m["type"] != "telemetry" {
				s.frames <- jobSrvFrame{n: n, m: m}
			}
		}
	})
	a = testConn(t, srv, "good")
	a.telemetryEvery = time.Hour
	stop := make(chan struct{})
	done := make(chan error, 1)
	go func() { done <- a.run(stop) }()
	t.Cleanup(func() {
		close(stop)
		select {
		case <-done:
		case <-time.After(20 * time.Second):
			t.Error("agent did not stop")
		}
	})
	return s, a, priv
}

// jobResult skips id's status frames and returns its result.
func (s *jobServer) jobResult(t *testing.T, id string, within time.Duration) map[string]interface{} {
	t.Helper()
	return s.next(t, within, "result of "+id, func(f jobSrvFrame) bool {
		return f.m["job_id"] == id && f.m["type"] == "sysscript_job_result"
	}).m
}

func payloadOf(m map[string]interface{}) map[string]interface{} {
	p, _ := m["payload"].(map[string]interface{})
	return p
}

// expectSync waits for connection n's first frame and checks it is the
// sync with these active and unacked ids.
func expectSync(t *testing.T, s *jobServer, n int64, active, unacked []string) {
	t.Helper()
	m := s.firstOn(t, n, 5*time.Second)
	if m["type"] != "sysscript_job_sync" {
		t.Fatalf("first frame on connection %d is %v", n, m)
	}
	p := payloadOf(m)
	gotActive, _ := p["active"].([]interface{})
	gotUnacked, _ := p["unacked"].([]interface{})
	if len(gotActive) != len(active) || len(gotUnacked) != len(unacked) {
		t.Fatalf("sync on %d = %v, want active %v unacked %v", n, p, active, unacked)
	}
	for i, id := range active {
		if gotActive[i] != id {
			t.Fatalf("sync active %v, want %v", gotActive, active)
		}
	}
	for i, id := range unacked {
		e, _ := gotUnacked[i].(map[string]interface{})
		if e["job_id"] != id || e["status"] == "" {
			t.Fatalf("sync unacked %v, want %v", gotUnacked, unacked)
		}
	}
}

func doneIDs(m *jobManager) []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	ids := make([]string, 0, len(m.done))
	for _, d := range m.done {
		ids = append(ids, d.id)
	}
	return ids
}

func TestJobAcceptedRunningSucceededAck(t *testing.T) {
	m := useTestJobManager(t, jobWorkersDefault, jobPendingMax)
	s, a, priv := startJobAgent(t)
	expectSync(t, s, 1, nil, nil)
	id := newJobID(t)
	now := time.Now().Unix()
	s.write(t, jobStart(t, priv, a.st.HostID, id, "sys.alerts.push('warning', 'disk')\nprint('hi')\n", nil, now+60, 30))
	acc := s.nextJob(t, id, 2*time.Second)
	p := payloadOf(acc)
	dl, _ := p["deadline_unix"].(float64)
	if acc["type"] != "sysscript_job_status" || p["status"] != "accepted" || p["queued"] != true || int64(dl) < now+29 || int64(dl) > now+31 {
		t.Fatalf("accepted=%v", acc)
	}
	run := s.nextJob(t, id, 2*time.Second)
	if run["type"] != "sysscript_job_status" || payloadOf(run)["status"] != "running" {
		t.Fatalf("running=%v", run)
	}
	alert := s.nextJob(t, id, 5*time.Second)
	if _, legacy := alert["request_id"]; alert["type"] != "sysscript_alert" || legacy || payloadOf(alert)["message"] != "disk" {
		t.Fatalf("alert=%v", alert)
	}
	res := s.nextJob(t, id, 5*time.Second)
	p = payloadOf(res)
	if res["type"] != "sysscript_job_result" || p["status"] != "succeeded" || p["output"] != "hi\n" || p["error"] != "" || p["output_truncated"] != false {
		t.Fatalf("result=%v", res)
	}
	if _, ok := p["duration_ms"].(float64); !ok {
		t.Fatalf("no duration_ms: %v", p)
	}
	if ids := doneIDs(m); len(ids) != 1 || ids[0] != id {
		t.Fatalf("kept results %v before ack", ids)
	}
	s.write(t, map[string]string{"type": "sysscript_job_ack", "job_id": "sjb_AAAAAAAAAAAAAAAAAAAAAA"})
	s.write(t, map[string]string{"type": "sysscript_job_ack", "job_id": id})
	waitFor(t, "ack frees the result", 2*time.Second, func() bool { return len(doneIDs(m)) == 0 })
	m.mu.Lock()
	b := m.doneB
	m.mu.Unlock()
	if b != 0 {
		t.Fatalf("done bytes %d after ack", b)
	}
}

func TestJobDeadlineAndSignedTimeout(t *testing.T) {
	useTestJobManager(t, jobWorkersDefault, jobPendingMax)
	s, a, priv := startJobAgent(t)
	expectSync(t, s, 1, nil, nil)
	for _, c := range []struct {
		name     string
		deadline int64 // from now
		timeout  int
	}{
		{"deadline", 2, 60},
		{"signed timeout shorter than the deadline", 60, 1},
	} {
		id := newJobID(t)
		now := time.Now()
		s.write(t, jobStart(t, priv, a.st.HostID, id, busyLoop, nil, now.Unix()+c.deadline, c.timeout))
		acc := s.nextJob(t, id, 2*time.Second)
		dl, _ := payloadOf(acc)["deadline_unix"].(float64)
		if want := now.Unix() + min(c.deadline, int64(c.timeout)); int64(dl) > want+1 || int64(dl) < want-1 {
			t.Fatalf("%s: accepted deadline %v, want %d", c.name, dl, want)
		}
		res := s.jobResult(t, id, 4*time.Second)
		if st := payloadOf(res)["status"]; st != "timed_out" {
			t.Fatalf("%s: status %v (%v)", c.name, st, res)
		}
		if d := time.Since(now); d > 3*time.Second {
			t.Fatalf("%s: timed out after %s", c.name, d)
		}
	}
}

func TestJobCeilingClampsDeadline(t *testing.T) {
	prev := jobCfg
	jobCfg.Max = time.Second
	t.Cleanup(func() { jobCfg = prev })
	useTestJobManager(t, jobWorkersDefault, jobPendingMax)
	s, a, priv := startJobAgent(t)
	expectSync(t, s, 1, nil, nil)
	id := newJobID(t)
	now := time.Now()
	s.write(t, jobStart(t, priv, a.st.HostID, id, busyLoop, nil, now.Unix()+600, 600))
	acc := s.nextJob(t, id, 2*time.Second)
	if dl, _ := payloadOf(acc)["deadline_unix"].(float64); int64(dl) > now.Unix()+2 {
		t.Fatalf("accepted deadline %v not clamped to the 1 s ceiling", dl)
	}
	s.nextJob(t, id, 2*time.Second) // running
	res := s.nextJob(t, id, 3*time.Second)
	if payloadOf(res)["status"] != "timed_out" || time.Since(now) > 2500*time.Millisecond {
		t.Fatalf("result %v after %s", res, time.Since(now))
	}
}

func TestJobRejections(t *testing.T) {
	m := useTestJobManager(t, jobWorkersDefault, jobPendingMax)
	s, a, priv := startJobAgent(t)
	expectSync(t, s, 1, nil, nil)
	host := a.st.HostID
	dl := time.Now().Unix() + 60
	rejected := func(name string, frame map[string]interface{}, id, want string) {
		t.Helper()
		s.write(t, frame)
		var res map[string]interface{}
		if id == "" {
			res = s.next(t, 2*time.Second, name, func(f jobSrvFrame) bool { return f.m["type"] == "sysscript_job_result" }).m
			if _, echoed := res["job_id"]; echoed {
				t.Fatalf("%s: echoed a bad job id: %v", name, res)
			}
		} else {
			res = s.nextJob(t, id, 2*time.Second)
		}
		p := payloadOf(res)
		if res["type"] != "sysscript_job_result" || p["status"] != "rejected" || p["error"] != want {
			t.Fatalf("%s: %v, want rejected/%s", name, res, want)
		}
	}

	// Duplicate id: while the result is unacked the kept result is sent
	// again; after the ack the id is refused.
	id := newJobID(t)
	s.write(t, jobStart(t, priv, host, id, "print(1)\n", nil, dl, 30))
	s.jobResult(t, id, 5*time.Second)
	s.write(t, jobStart(t, priv, host, id, "print(1)\n", nil, dl, 30))
	if res := s.nextJob(t, id, 2*time.Second); res["type"] != "sysscript_job_result" || payloadOf(res)["status"] != "succeeded" {
		t.Fatalf("duplicate unacked: %v", res)
	}
	s.write(t, map[string]string{"type": "sysscript_job_ack", "job_id": id})
	waitFor(t, "ack", 2*time.Second, func() bool { return len(doneIDs(m)) == 0 })
	rejected("duplicate acked", jobStart(t, priv, host, id, "print(1)\n", nil, dl, 30), id, "duplicate_job")

	// A lease for host B.
	other := newJobID(t)
	rejected("host B", jobStart(t, priv, "22222222-2222-4222-8222-222222222222", other, "print(1)\n", nil, dl, 30), other, "bad_host")

	// A list item the canonical form refuses.
	bad := newJobID(t)
	frame := jobStart(t, priv, host, bad, "print(1)\n", nil, dl, 30)
	frame["entitlements"] = map[string]interface{}{"allow_fs_read": []string{"/etc\n/root"}}
	rejected("bad entitlements", frame, bad, "bad_entitlements")

	// Entitlements changed in transit: one flag flipped.
	swapped := newJobID(t)
	frame = jobStart(t, priv, host, swapped, "print(1)\n", map[string]interface{}{"allow_exec": false}, dl, 30)
	frame["entitlements"] = map[string]interface{}{"allow_exec": true}
	rejected("entitlements swapped", frame, swapped, "payload_mismatch")

	// Malformed id, past deadline, out-of-range timeout, replayed frame.
	frame = jobStart(t, priv, host, newJobID(t), "print(1)\n", nil, dl, 30)
	frame["job_id"] = "sjb_short"
	rejected("bad id", frame, "", "bad_job_id")
	past := newJobID(t)
	rejected("past deadline", jobStart(t, priv, host, past, "print(1)\n", nil, time.Now().Unix()-1, 30), past, "bad_deadline")
	long := newJobID(t)
	frame = jobStart(t, priv, host, long, "print(1)\n", nil, dl, 30)
	frame["timeout_s"] = sysscriptJobTimeoutMax + 1
	rejected("timeout over cap", frame, long, "bad_deadline")
	replay := newJobID(t)
	frame = jobStart(t, priv, host, replay, "print(1)\n", nil, dl, 30)
	s.write(t, frame)
	s.jobResult(t, replay, 5*time.Second)
	s.write(t, frame)
	if res := s.nextJob(t, replay, 2*time.Second); res["type"] != "sysscript_job_result" || payloadOf(res)["status"] != "succeeded" {
		t.Fatalf("replay of an unacked job: %v", res)
	}
	s.write(t, map[string]string{"type": "sysscript_job_ack", "job_id": replay})
	waitFor(t, "ack", 2*time.Second, func() bool { return len(doneIDs(m)) == 0 })
	rejected("replayed frame", frame, replay, "replay")

	// A replayed or duplicate start for a running job gets its status.
	held := newJobID(t)
	frame = jobStart(t, priv, host, held, busyLoop, nil, dl, 2)
	s.write(t, frame)
	s.next(t, 2*time.Second, "running", func(f jobSrvFrame) bool {
		return f.m["job_id"] == held && payloadOf(f.m)["status"] == "running"
	})
	s.write(t, frame)
	s.write(t, jobStart(t, priv, host, held, busyLoop, nil, dl, 2))
	for i := 0; i < 2; i++ {
		if st := s.nextJob(t, held, 2*time.Second); st["type"] != "sysscript_job_status" || payloadOf(st)["status"] != "running" {
			t.Fatalf("repeat %d of a running job: %v", i, st)
		}
	}
	if res := s.jobResult(t, held, 4*time.Second); payloadOf(res)["status"] != "timed_out" {
		t.Fatalf("held job %v", res)
	}
}

// With every worker and queue slot taken a job is refused at once; at
// shutdown queued and running jobs end failed[agent_stopped] and their
// results are written before stopAll returns.
func TestJobBusyAndAgentStopped(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	clearIdentity()
	t.Cleanup(clearIdentity)
	if err := pinControlPublicKey(base64.StdEncoding.EncodeToString(pub), ptyTestHost); err != nil {
		t.Fatal(err)
	}
	m := newJobManager(1, 1)
	out := newFakeOut()
	m.attach(out, nil)
	start := func(id string) {
		raw, err := json.Marshal(jobStart(t, priv, ptyTestHost, id, busyLoop, nil, time.Now().Unix()+60, 60))
		if err != nil {
			t.Fatal(err)
		}
		var cmd CommandMessage
		if err := json.Unmarshal(raw, &cmd); err != nil {
			t.Fatal(err)
		}
		m.startJob(ptyTestHost, &cmd, time.Now())
	}
	result := func(id string) map[string]interface{} {
		out.mu.Lock()
		defer out.mu.Unlock()
		for _, f := range out.jsons {
			if f["type"] == "sysscript_job_result" && f["job_id"] == id {
				return payloadOf(f)
			}
		}
		return nil
	}
	ids := []string{newJobID(t), newJobID(t), newJobID(t)}
	start(ids[0])
	waitFor(t, "first job running", 2*time.Second, func() bool { return len(m.pending) == 0 })
	start(ids[1])
	sent := time.Now()
	start(ids[2])
	m.flush(time.Second)
	if p := result(ids[2]); p == nil || p["status"] != "rejected" || p["error"] != "agent_busy" || time.Since(sent) > 750*time.Millisecond {
		t.Fatalf("third job %v after %s", p, time.Since(sent))
	}
	if !m.stopAll(5 * time.Second) {
		t.Fatal("workers did not stop")
	}
	for _, id := range ids[:2] {
		if p := result(id); p == nil || p["status"] != "failed" || p["error"] != "agent_stopped" {
			t.Fatalf("%s at shutdown: %v", id, p)
		}
	}
}

// Frames emitted while attach runs never overtake the sync or the re-sent
// results, each emitter's frames stay in order, and a result that finishes
// during attach is sent exactly once. Run with -race.
func TestJobAttachOrderingRace(t *testing.T) {
	m := newJobManager(1, 1)
	defer m.stopAll(5 * time.Second)
	frame := func(id string) []byte {
		b, err := jobResultFrame(id, "succeeded", "", "x", false, time.Millisecond)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	var before []string
	for i := 0; i < 3; i++ {
		id := fmt.Sprintf("sjb_before%013d", i)
		before = append(before, id)
		m.finishJob(id, "succeeded", frame(id))
	}
	// 4*100 alerts + 43 results + the sync stay under jobQueueMax.
	const emitters, perEmitter, finishers, perFinisher = 4, 100, 2, 20
	startGate := make(chan struct{})
	var wg sync.WaitGroup
	for e := 0; e < emitters; e++ {
		wg.Add(1)
		go func(e int) {
			defer wg.Done()
			<-startGate
			for k := 0; k < perEmitter; k++ {
				_ = m.sendFrame(ResponseMessage{Type: "sysscript_alert", JobID: fmt.Sprintf("emitter-%d", e), Payload: map[string]int{"seq": k}})
			}
		}(e)
	}
	for f := 0; f < finishers; f++ {
		wg.Add(1)
		go func(f int) {
			defer wg.Done()
			<-startGate
			for k := 0; k < perFinisher; k++ {
				id := fmt.Sprintf("sjb_during%d-%011d", f, k)
				m.finishJob(id, "succeeded", frame(id))
			}
		}(f)
	}
	out := newFakeOut()
	close(startGate)
	m.attach(out, nil)
	wg.Wait()
	if !m.flush(5 * time.Second) {
		t.Fatal("queue did not drain")
	}
	out.mu.Lock()
	frames := append([]map[string]interface{}(nil), out.jsons...)
	out.mu.Unlock()
	if len(frames) == 0 || frames[0]["type"] != "sysscript_job_sync" {
		t.Fatalf("first frame %v", frames)
	}
	unacked, _ := payloadOf(frames[0])["unacked"].([]interface{})
	if len(unacked) < len(before) {
		t.Fatalf("sync unacked %v", unacked)
	}
	for i, u := range unacked {
		e, _ := u.(map[string]interface{})
		if i < len(before) && e["job_id"] != before[i] {
			t.Fatalf("unacked order %v", unacked)
		}
		if f := frames[1+i]; f["type"] != "sysscript_job_result" || f["job_id"] != e["job_id"] {
			t.Fatalf("frame %d after sync is %v, want the result of %v", 1+i, f, e["job_id"])
		}
	}
	seq := map[string]float64{}
	results := map[string]int{}
	for _, f := range frames[1:] {
		switch f["type"] {
		case "sysscript_job_sync":
			t.Fatal("second sync")
		case "sysscript_alert":
			src, _ := f["job_id"].(string)
			k, _ := payloadOf(f)["seq"].(float64)
			if last, ok := seq[src]; ok && k <= last {
				t.Fatalf("%s: seq %v after %v", src, k, last)
			}
			seq[src] = k
		case "sysscript_job_result":
			id, _ := f["job_id"].(string)
			results[id]++
		}
	}
	if len(results) != len(before)+finishers*perFinisher {
		t.Fatalf("%d distinct results, want %d", len(results), len(before)+finishers*perFinisher)
	}
	for id, n := range results {
		if n != 1 {
			t.Fatalf("result %s sent %d times", id, n)
		}
	}
}

func TestJobDoneCapDropsOldest(t *testing.T) {
	m := newJobManager(1, 1)
	defer m.stopAll(5 * time.Second)
	for i := 0; i <= jobDoneMax; i++ {
		m.finishJob(fmt.Sprintf("sjb_cap%015d", i), "succeeded", []byte(`{}`))
	}
	ids := doneIDs(m)
	if len(ids) != jobDoneMax || ids[0] != fmt.Sprintf("sjb_cap%015d", 1) {
		t.Fatalf("kept %d, oldest %s", len(ids), ids[0])
	}
	big := make([]byte, 1<<20)
	n := jobDoneBytesMax/len(big) + 1
	m2 := newJobManager(1, 1)
	defer m2.stopAll(5 * time.Second)
	for i := 0; i < n; i++ {
		m2.finishJob(fmt.Sprintf("sjb_big%015d", i), "succeeded", big)
	}
	ids = doneIDs(m2)
	m2.mu.Lock()
	b := m2.doneB
	m2.mu.Unlock()
	if len(ids) != n-1 || ids[0] != fmt.Sprintf("sjb_big%015d", 1) || b > jobDoneBytesMax {
		t.Fatalf("kept %d (%d bytes), oldest %s", len(ids), b, ids[0])
	}
}

// gatedOut blocks every write until gate is closed: a stalled connection.
type gatedOut struct {
	*fakeOut
	gate chan struct{}
}

func (g *gatedOut) WriteText(b []byte) error {
	<-g.gate
	return g.fakeOut.WriteText(b)
}

func (m *jobManager) queued() (frames, bytes, overflow int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.ctl) + len(m.bulk), m.queueB, m.overflow
}

// With the writer stalled, a flood of bad job frames fills the queue to its
// cap and then closes the connection once; a legacy frame over the cap is
// dropped. detach clears the frames and the next connection syncs first.
func TestJobQueueOverflowClosesConnection(t *testing.T) {
	m := newJobManager(1, 1)
	out := &gatedOut{fakeOut: newFakeOut(), gate: make(chan struct{})}
	var closed atomic.Int32
	m.attach(out, func() { closed.Add(1) })
	waitFor(t, "writer stalled on the sync", 2*time.Second, func() bool {
		n, _, _ := m.queued()
		return n == 0
	})
	for i := 0; i < jobQueueMax+100; i++ {
		m.startJob(ptyTestHost, &CommandMessage{Type: "sysscript_job", JobID: "bad"}, time.Now())
	}
	n, b, over := m.queued()
	if n != jobQueueMax || b > jobQueueMaxBytes || over != 100 {
		t.Fatalf("queued %d frames (%d bytes), %d dropped", n, b, over)
	}
	waitFor(t, "connection closed", 2*time.Second, func() bool { return closed.Load() == 1 })
	m.sendFrameTo(newFakeOut(), []byte(`{"type":"command_result"}`))
	if _, _, over := m.queued(); over != 101 {
		t.Fatalf("pinned frame over the cap not dropped: %d", over)
	}
	time.Sleep(50 * time.Millisecond)
	if closed.Load() != 1 {
		t.Fatalf("closed %d times", closed.Load())
	}
	m.detach(out)
	if n, b, _ := m.queued(); n != 0 || b != 0 {
		t.Fatalf("after detach %d frames, %d bytes", n, b)
	}
	close(out.gate)
	next := newFakeOut()
	m.attach(next, nil)
	if !m.flush(2 * time.Second) {
		t.Fatal("queue did not drain")
	}
	next.mu.Lock()
	defer next.mu.Unlock()
	if len(next.jsons) != 1 || next.jsons[0]["type"] != "sysscript_job_sync" {
		t.Fatalf("new connection got %v", next.jsons)
	}
	m.stopAll(5 * time.Second)
}

// After a reconnect with 16 MiB of unacked results queued behind a slow
// writer, a newly dispatched job's accepted (control lane) is written before
// the results (bulk lane), and the sync still comes first.
func TestJobControlLaneBeforeBulk(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	clearIdentity()
	t.Cleanup(clearIdentity)
	if err := pinControlPublicKey(base64.StdEncoding.EncodeToString(pub), ptyTestHost); err != nil {
		t.Fatal(err)
	}
	m := newJobManager(1, 1)
	defer m.stopAll(5 * time.Second)
	big := strings.Repeat("a", 1<<20-8<<10)
	for i := 0; i < 16; i++ {
		id := fmt.Sprintf("sjb_bulk%014d", i)
		b, err := jobResultFrame(id, "succeeded", "", big, false, time.Second)
		if err != nil {
			t.Fatal(err)
		}
		m.finishJob(id, "succeeded", b)
	}
	m.mu.Lock()
	kept, keptB := len(m.done), m.doneB
	m.mu.Unlock()
	if kept != 16 || keptB < 15<<20 {
		t.Fatalf("kept %d results, %d bytes", kept, keptB)
	}
	out := &gatedOut{fakeOut: newFakeOut(), gate: make(chan struct{})}
	m.attach(out, nil)
	waitFor(t, "writer stalled on the sync", 2*time.Second, func() bool {
		n, _, _ := m.queued()
		return n == 16
	})
	id := newJobID(t)
	raw, err := json.Marshal(jobStart(t, priv, ptyTestHost, id, "print(1)\n", nil, time.Now().Unix()+60, 30))
	if err != nil {
		t.Fatal(err)
	}
	var cmd CommandMessage
	if err := json.Unmarshal(raw, &cmd); err != nil {
		t.Fatal(err)
	}
	m.startJob(ptyTestHost, &cmd, time.Now())
	close(out.gate)
	waitFor(t, "all frames", 10*time.Second, func() bool {
		out.mu.Lock()
		defer out.mu.Unlock()
		results := 0
		for _, f := range out.jsons {
			if f["type"] == "sysscript_job_result" {
				results++
			}
		}
		return results == 17
	})
	out.mu.Lock()
	defer out.mu.Unlock()
	if out.jsons[0]["type"] != "sysscript_job_sync" {
		t.Fatalf("first frame %v", out.jsons[0]["type"])
	}
	accepted, firstBulk := -1, -1
	for i, f := range out.jsons {
		if f["job_id"] == id && f["type"] == "sysscript_job_status" && payloadOf(f)["status"] == "accepted" && accepted < 0 {
			accepted = i
		}
		if f["type"] == "sysscript_job_result" && firstBulk < 0 {
			firstBulk = i
		}
	}
	if accepted != 1 || firstBulk < accepted {
		t.Fatalf("accepted at %d, first result at %d", accepted, firstBulk)
	}
}

// A job whose deadline passes while it waits for a worker ends without a
// running status.
func TestJobEndedWhileQueuedSkipsRunning(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	clearIdentity()
	t.Cleanup(clearIdentity)
	if err := pinControlPublicKey(base64.StdEncoding.EncodeToString(pub), ptyTestHost); err != nil {
		t.Fatal(err)
	}
	m := newJobManager(1, 1)
	defer m.stopAll(5 * time.Second)
	out := newFakeOut()
	m.attach(out, nil)
	start := func(id string, timeoutS int) {
		raw, err := json.Marshal(jobStart(t, priv, ptyTestHost, id, busyLoop, nil, time.Now().Unix()+60, timeoutS))
		if err != nil {
			t.Fatal(err)
		}
		var cmd CommandMessage
		if err := json.Unmarshal(raw, &cmd); err != nil {
			t.Fatal(err)
		}
		m.startJob(ptyTestHost, &cmd, time.Now())
	}
	first, queued := newJobID(t), newJobID(t)
	start(first, 60)
	waitFor(t, "first job running", 2*time.Second, func() bool { return len(m.pending) == 0 })
	start(queued, 1)
	time.Sleep(1200 * time.Millisecond)
	m.cancelJob(first, "user")
	var frames []map[string]interface{}
	waitFor(t, "queued job result", 5*time.Second, func() bool {
		m.flush(time.Second)
		out.mu.Lock()
		defer out.mu.Unlock()
		frames = frames[:0]
		for _, f := range out.jsons {
			if f["job_id"] == queued {
				frames = append(frames, f)
			}
		}
		return len(frames) > 0 && frames[len(frames)-1]["type"] == "sysscript_job_result"
	})
	if len(frames) != 2 || payloadOf(frames[0])["status"] != "accepted" || payloadOf(frames[1])["status"] != "timed_out" {
		t.Fatalf("queued job frames %v", frames)
	}
}

// When the server stops reading, the agent's frames back up until the
// writer queue overflows; the real close hook closes the connection, and
// the redial's sync lists the unacked result and sends it again.
func TestJobQueueOverflowResyncsOnNewConnection(t *testing.T) {
	m := useTestJobManager(t, jobWorkersDefault, jobPendingMax)
	s, a, priv := startJobAgent(t)
	expectSync(t, s, 1, nil, nil)
	id := newJobID(t)
	s.write(t, jobStart(t, priv, a.st.HostID, id, "print('kept')\n", nil, time.Now().Unix()+60, 30))
	s.jobResult(t, id, 5*time.Second)

	s.stall.Store(true)
	big := strings.Repeat("a", 1<<20-8<<10)
	// Flood until the first overflow, so the next connection is not
	// flooded too.
	for i := 0; i < 64; i++ {
		if _, _, over := m.queued(); over > 0 {
			break
		}
		_ = m.sendFrame(ResponseMessage{Type: "sysscript_alert", JobID: id, Payload: map[string]string{"message": big}})
	}
	waitFor(t, "overflow", 10*time.Second, func() bool {
		_, _, over := m.queued()
		return over > 0
	})
	s.stall.Store(false)
	expectSync(t, s, 2, nil, []string{id})
	f := s.next(t, 5*time.Second, "re-sent result", func(f jobSrvFrame) bool { return f.n >= 2 })
	if f.m["type"] != "sysscript_job_result" || f.m["job_id"] != id || payloadOf(f.m)["output"] != "kept\n" {
		t.Fatalf("after the resync on %d: %v", f.n, f.m)
	}
}
