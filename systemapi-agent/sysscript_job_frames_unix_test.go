//go:build linux || darwin

package main

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// A cancel ends a running job as cancelled and its process group is gone.
func TestJobCancelKillsGroup(t *testing.T) {
	useTestJobManager(t, jobWorkersDefault, jobPendingMax)
	s, a, priv := startJobAgent(t)
	expectSync(t, s, 1, nil, nil)
	pidFile := filepath.Join(t.TempDir(), "pid")
	script := `r = sys.exec.run("sh", "-c", "echo $$ > ` + pidFile + `; sleep 600 & wait")` + "\n" + `print(r["error"])` + "\n"
	id := newJobID(t)
	s.write(t, jobStart(t, priv, a.st.HostID, id, script, map[string]interface{}{"allow_exec": true}, time.Now().Unix()+120, 120))
	if st := payloadOf(s.nextJob(t, id, 2*time.Second))["status"]; st != "accepted" {
		t.Fatalf("status %v", st)
	}
	var pgid int
	waitFor(t, "pid file", 5*time.Second, func() bool {
		b, err := os.ReadFile(pidFile)
		if err != nil {
			return false
		}
		pgid, err = strconv.Atoi(strings.TrimSpace(string(b)))
		return err == nil && pgid > 0
	})
	sent := time.Now()
	s.write(t, map[string]string{"type": "sysscript_job_cancel", "job_id": "sjb_AAAAAAAAAAAAAAAAAAAAAA", "reason": "user"})
	s.write(t, map[string]string{"type": "sysscript_job_cancel", "job_id": id, "reason": "user"})
	res := s.jobResult(t, id, 12*time.Second)
	if p := payloadOf(res); p["status"] != "cancelled" {
		t.Fatalf("result %v", res)
	}
	if d := time.Since(sent); d > 12*time.Second {
		t.Fatalf("cancelled after %s", d)
	}
	waitGroupGone(t, pgid, 2*time.Second)
}

// A job survives a dropped connection. Each new connection starts with a
// sync listing the running job as active and the finished, unacked one as
// unacked, followed by that result again, until the server acks it.
func TestJobSurvivesDropAndResendsUntilAcked(t *testing.T) {
	m := useTestJobManager(t, jobWorkersDefault, jobPendingMax)
	s, a, priv := startJobAgent(t)
	expectSync(t, s, 1, nil, nil)
	ents := map[string]interface{}{"allow_exec": true}
	dl := time.Now().Unix() + 120
	short, long := newJobID(t), newJobID(t)
	s.write(t, jobStart(t, priv, a.st.HostID, short, `sys.exec.run("sleep", "1")`+"\n", ents, dl, 60))
	s.write(t, jobStart(t, priv, a.st.HostID, long, `sys.exec.run("sleep", "8")`+"\n", ents, dl, 60))
	// The two jobs run on different workers, so their running frames come
	// in either order.
	running := map[interface{}]bool{}
	for len(running) < 2 {
		f := s.next(t, 3*time.Second, "both jobs running", func(f jobSrvFrame) bool {
			return (f.m["job_id"] == short || f.m["job_id"] == long) && payloadOf(f.m)["status"] == "running"
		})
		running[f.m["job_id"]] = true
	}

	// Down while the short job finishes.
	s.gate.Store(false)
	s.drop()
	waitFor(t, "short job finished while down", 5*time.Second, func() bool {
		ids := doneIDs(m)
		return len(ids) == 1 && ids[0] == short
	})
	s.mu.Lock()
	n := s.n
	s.mu.Unlock()
	s.gate.Store(true)

	resent := func(n int64) {
		t.Helper()
		f := s.next(t, 2*time.Second, "re-sent result", func(f jobSrvFrame) bool { return f.n == n })
		if f.m["type"] != "sysscript_job_result" || f.m["job_id"] != short || payloadOf(f.m)["status"] != "succeeded" {
			t.Fatalf("frame after the sync on %d: %v", n, f.m)
		}
	}
	// Redial: the sync, then the kept result. No ack.
	expectSync(t, s, n+1, []string{long}, []string{short})
	s.mu.Lock()
	n = s.n
	s.mu.Unlock()
	resent(n)

	// Next connection: still unacked, so listed and sent again.
	s.drop()
	expectSync(t, s, n+1, []string{long}, []string{short})
	s.mu.Lock()
	n = s.n
	s.mu.Unlock()
	resent(n)
	s.write(t, map[string]string{"type": "sysscript_job_ack", "job_id": short})
	waitFor(t, "ack", 2*time.Second, func() bool { return len(doneIDs(m)) == 0 })

	// After the ack it is gone; the long job is still active and reports on
	// the current connection.
	s.drop()
	expectSync(t, s, n+1, []string{long}, nil)
	res := s.jobResult(t, long, 10*time.Second)
	if payloadOf(res)["status"] != "succeeded" {
		t.Fatalf("long job %v", res)
	}
}
