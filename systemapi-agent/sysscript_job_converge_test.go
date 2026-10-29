package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"runtime"
	"strings"
	"testing"
	"time"
)

// convergeJobHarness is a job manager on a fake connection, with the control
// key pinned, --converge on, and converge jobs run against a fake host.
type convergeJobHarness struct {
	t     *testing.T
	m     *jobManager
	out   *fakeOut
	priv  ed25519.PrivateKey
	host  *fakeHost
	built int
}

func newConvergeJobHarness(t *testing.T) *convergeJobHarness {
	t.Helper()
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skip("converge jobs run on Linux and macOS only")
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	clearIdentity()
	t.Cleanup(clearIdentity)
	if err := pinControlPublicKey(base64.StdEncoding.EncodeToString(pub), ptyTestHost); err != nil {
		t.Fatal(err)
	}
	h := &convergeJobHarness{t: t, out: newFakeOut(), priv: priv, host: newFakeHost()}
	prevOn, prevJobs, prevBackend := convergeOn, sysscriptJobsOn, convergeBackend
	convergeOn, sysscriptJobsOn = true, true
	convergeBackend = func() hostBackend { return countingBackend(h.host, &h.built) }
	h.m = newJobManager(1, 2)
	h.m.attach(h.out, nil)
	t.Cleanup(func() {
		h.m.stopAll(5 * time.Second)
		convergeOn, sysscriptJobsOn, convergeBackend = prevOn, prevJobs, prevBackend
	})
	return h
}

// convergeFrame is a kind=converge sysscript_job frame whose converge_job
// lease signs (leaseMode, leasePlan); the frame itself says (mode, plan).
type convergeFrame struct {
	id, bundle, mode, plan, leaseMode, leasePlan, leaseAction string
}

func (h *convergeJobHarness) start(f convergeFrame) {
	h.t.Helper()
	ents := convergeGrants()
	canon, err := canonicalEntitlements(ents)
	if err != nil {
		h.t.Fatal(err)
	}
	if f.leaseMode == "" {
		f.leaseMode, f.leasePlan = f.mode, f.plan
	}
	if f.leaseAction == "" {
		f.leaseAction = "converge_job"
	}
	deadline := time.Now().Unix() + 60
	var payload string
	if f.leaseAction == "converge_job" {
		payload, err = convergeJobLeasePayload(f.id, deadline, 60, sha256Hex(f.bundle), sha256Hex(canon), f.leaseMode, f.leasePlan)
	} else {
		payload, err = sysscriptJobLeasePayload(f.id, deadline, 60, sha256Hex(f.bundle), sha256Hex(canon))
	}
	if err != nil {
		h.t.Fatal(err)
	}
	raw, err := json.Marshal(map[string]interface{}{
		"type": "sysscript_job", "job_id": f.id, "kind": "converge", "bundle_json": f.bundle,
		"mode": f.mode, "expect_plan_sha256": f.plan, "entitlements": ents,
		"deadline_unix": deadline, "timeout_s": 60,
		"lease": signLease(h.t, h.priv, ptyTestHost, f.leaseAction, payload, time.Now().Add(time.Minute).Unix()),
	})
	if err != nil {
		h.t.Fatal(err)
	}
	var cmd CommandMessage
	if err := json.Unmarshal(raw, &cmd); err != nil {
		h.t.Fatal(err)
	}
	h.m.startJob(ptyTestHost, &cmd, time.Now())
}

// result waits for the job's sysscript_job_result payload.
func (h *convergeJobHarness) result(id string) map[string]interface{} {
	h.t.Helper()
	var got map[string]interface{}
	waitFor(h.t, "result of "+id, 5*time.Second, func() bool {
		h.out.mu.Lock()
		defer h.out.mu.Unlock()
		for _, f := range h.out.jsons {
			if f["type"] == "sysscript_job_result" && f["job_id"] == id {
				got = payloadOf(f)
				return true
			}
		}
		return false
	})
	return got
}

func reportOf(t *testing.T, p map[string]interface{}) convergeReport {
	t.Helper()
	raw, err := json.Marshal(p["report"])
	if err != nil {
		t.Fatal(err)
	}
	var rep convergeReport
	if err := json.Unmarshal(raw, &rep); err != nil || rep.V != 1 {
		t.Fatalf("report %s: %v", raw, err)
	}
	return rep
}

// A check job runs convergeRun read-only and puts its report in the result
// frame; an apply job with a stale plan hash fails plan_stale before any
// write, with its report.
func TestConvergeJobCheckAndStaleApply(t *testing.T) {
	h := newConvergeJobHarness(t)
	bundle := nginxBundle(t, 8080)
	id := newJobID(t)
	h.start(convergeFrame{id: id, bundle: bundle, mode: "check", plan: "-"})
	p := h.result(id)
	if p["status"] != "succeeded" || p["error"] != "" {
		t.Fatalf("check result %v", p)
	}
	rep := reportOf(t, p)
	if rep.Mode != "check" || rep.BundleSHA256 != sha256Hex(bundle) || !hashHexRe.MatchString(rep.PlanSHA256) || rep.Summary.Drift == 0 {
		t.Fatalf("check report %+v", rep)
	}
	if h.built != 0 || h.host.writes != 0 {
		t.Fatalf("a check built %d write hosts and wrote %d times", h.built, h.host.writes)
	}

	stale := newJobID(t)
	h.start(convergeFrame{id: stale, bundle: bundle, mode: "apply", plan: strings.Repeat("0", 64)})
	p = h.result(stale)
	if p["status"] != "failed" || !strings.HasPrefix(p["error"].(string), "plan_stale") {
		t.Fatalf("stale apply %v", p)
	}
	if rep := reportOf(t, p); rep.Mode != "apply" {
		t.Fatalf("stale apply report %+v", rep)
	}
	if h.built != 0 || h.host.writes != 0 {
		t.Fatalf("a stale apply built %d write hosts and wrote %d times", h.built, h.host.writes)
	}
}

// A report at its cap beside oversized output: the output is cut, the
// report kept whole, and the encoded frame stays within jobFrameMax.
func TestConvergeResultFrameCap(t *testing.T) {
	pad := strings.Repeat("r", convergeReportMax-32)
	report, err := json.Marshal(map[string]any{"v": 1, "pad": pad})
	if err != nil || len(report) > convergeReportMax {
		t.Fatalf("report %d bytes: %v", len(report), err)
	}
	b, err := jobResultFrame("sjb_AAAAAAAAAAAAAAAAAAAAAA", "succeeded", "", strings.Repeat("<", 2<<20), false, time.Second, report)
	if err != nil || len(b) > jobFrameMax {
		t.Fatalf("frame %d bytes: %v", len(b), err)
	}
	var f struct {
		Payload jobResultPayload `json:"payload"`
	}
	if err := json.Unmarshal(b, &f); err != nil {
		t.Fatal(err)
	}
	if !f.Payload.OutputTruncated || string(f.Payload.Report) != string(report) {
		t.Fatalf("truncated=%v report kept=%v", f.Payload.OutputTruncated, string(f.Payload.Report) == string(report))
	}
	// A script job's frame has no report key.
	b, err = jobResultFrame("sjb_AAAAAAAAAAAAAAAAAAAAAA", "succeeded", "", "x", false, time.Second, nil)
	if err != nil || strings.Contains(string(b), `"report"`) {
		t.Fatalf("script frame %s: %v", b, err)
	}
}

// AC 2: bad_mode on an inconsistent mode and plan pairing; a frame whose
// mode or plan differs from the lease is payload_mismatch; a sysscript_job
// lease cannot start a converge job; other refusals before any run.
func TestConvergeJobRefusals(t *testing.T) {
	h := newConvergeJobHarness(t)
	bundle := nginxBundle(t, 8080)
	plan := strings.Repeat("a", 64)
	cases := []struct {
		name string
		f    convergeFrame
		want string
	}{
		{"check with a plan", convergeFrame{bundle: bundle, mode: "check", plan: plan, leaseMode: "check", leasePlan: "-"}, "bad_mode"},
		{"apply without a plan", convergeFrame{bundle: bundle, mode: "apply", plan: "-", leaseMode: "check", leasePlan: "-"}, "bad_mode"},
		{"no mode", convergeFrame{bundle: bundle, mode: "", plan: "-", leaseMode: "check", leasePlan: "-"}, "bad_mode"},
		{"check lease, apply frame", convergeFrame{bundle: bundle, mode: "apply", plan: plan, leaseMode: "check", leasePlan: "-"}, "payload_mismatch"},
		{"apply lease, check frame", convergeFrame{bundle: bundle, mode: "check", plan: "-", leaseMode: "apply", leasePlan: plan}, "payload_mismatch"},
		{"other plan", convergeFrame{bundle: bundle, mode: "apply", plan: plan, leaseMode: "apply", leasePlan: strings.Repeat("b", 64)}, "payload_mismatch"},
		{"sysscript_job lease", convergeFrame{bundle: bundle, mode: "check", plan: "-", leaseAction: "sysscript_job"}, "bad_action"},
		{"bundle too large", convergeFrame{bundle: strings.Repeat(" ", convergeBundleMax+1), mode: "check", plan: "-"}, "bundle_too_large"},
	}
	for _, c := range cases {
		c.f.id = newJobID(t)
		h.start(c.f)
		if p := h.result(c.f.id); p["status"] != "rejected" || p["error"] != c.want {
			t.Fatalf("%s: %v, want %s", c.name, p, c.want)
		}
	}
	// A changed bundle under the original lease.
	id := newJobID(t)
	ents := convergeGrants()
	canon, _ := canonicalEntitlements(ents)
	deadline := time.Now().Unix() + 60
	payload, err := convergeJobLeasePayload(id, deadline, 60, sha256Hex(bundle), sha256Hex(canon), "check", "-")
	if err != nil {
		t.Fatal(err)
	}
	cmd := CommandMessage{Type: "sysscript_job", JobID: id, Kind: "converge", BundleJSON: nginxBundle(t, 8081), Mode: "check", ExpectPlan: "-",
		Entitlements: ents, DeadlineUnix: deadline, TimeoutS: 60, Lease: signLease(t, h.priv, ptyTestHost, "converge_job", payload, time.Now().Add(time.Minute).Unix())}
	h.m.startJob(ptyTestHost, &cmd, time.Now())
	if p := h.result(id); p["status"] != "rejected" || p["error"] != "payload_mismatch" {
		t.Fatalf("changed bundle: %v", p)
	}
	// A script beside the bundle, and an unknown kind.
	id = newJobID(t)
	h.m.startJob(ptyTestHost, &CommandMessage{Type: "sysscript_job", JobID: id, Kind: "converge", Script: "print(1)", Mode: "check", ExpectPlan: "-"}, time.Now())
	if p := h.result(id); p["error"] != "bad_payload" {
		t.Fatalf("script beside bundle: %v", p)
	}
	id = newJobID(t)
	h.m.startJob(ptyTestHost, &CommandMessage{Type: "sysscript_job", JobID: id, Kind: "shell"}, time.Now())
	if p := h.result(id); p["error"] != "bad_kind" {
		t.Fatalf("unknown kind: %v", p)
	}
	// Without --converge a converge frame is refused before its lease.
	convergeOn = false
	id = newJobID(t)
	h.start(convergeFrame{id: id, bundle: bundle, mode: "check", plan: "-"})
	if p := h.result(id); p["error"] != "converge_unsupported" {
		t.Fatalf("--converge off: %v", p)
	}
	if h.built != 0 || h.host.writes != 0 || h.host.reads != 0 {
		t.Fatalf("a refused frame reached the host: built=%d writes=%d reads=%d", h.built, h.host.writes, h.host.reads)
	}
}
