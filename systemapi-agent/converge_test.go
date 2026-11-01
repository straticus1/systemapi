package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"testing"
	"time"
)

// bundleJSON builds a bundle string.
func bundleJSON(t *testing.T, files map[string]string, vars map[string]any) string {
	t.Helper()
	b, err := json.Marshal(map[string]any{
		"v": 1, "files": files, "vars": vars,
		"host": map[string]any{"host_id": "h1", "hostname": "web-1", "os": "linux", "tags": []string{"web"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// convergeGrants grants /srv/app and nginx.
func convergeGrants() *Entitlements {
	return &Entitlements{
		AllowFSWrite:       []string{"/srv/app"},
		AllowPackages:      []string{"nginx"},
		AllowServiceReload: []string{"nginx"},
		AllowSysctl:        []string{"net.ipv4.ip_forward"},
		AllowLinux:         true,
	}
}

// countingBackend wraps a fake host and counts write hosts built.
func countingBackend(h *fakeHost, built *int) hostBackend {
	return hostBackend{reads: h, newWrites: func() hostWrites { *built++; return h }}
}

func decodeReport(t *testing.T, res convergeResult) convergeReport {
	t.Helper()
	var rep convergeReport
	if err := json.Unmarshal(res.Report, &rep); err != nil {
		t.Fatalf("report: %v\n%s", err, res.Report)
	}
	return rep
}

func runCheck(t *testing.T, bundle string, h *fakeHost, built *int) convergeResult {
	t.Helper()
	return convergeRun(context.Background(), convergeRequest{BundleJSON: bundle, Ents: convergeGrants(), Mode: "check", ExpectPlan: "-"}, countingBackend(h, built))
}

const nginxMain = `
conf = state.file("/srv/app/nginx.conf", template("nginx.conf.tmpl", {"port": state.vars["port"], "host": state.host.hostname}))
state.package("nginx")
state.service("nginx", restart_on=[conf])
`

func nginxBundle(t *testing.T, port int) string {
	return bundleJSON(t, map[string]string{
		"main.star":       nginxMain,
		"nginx.conf.tmpl": "listen {{.port}};\nserver_name {{.host}};\n",
	}, map[string]any{"port": port})
}

// AC: in check mode a bundle never builds a write host or writes, whether
// it is well-formed and drifted or hostile.
func TestConvergeCheckModeNeverWrites(t *testing.T) {
	hostile := map[string]map[string]string{
		"load traversal": {"main.star": `load("../x.star", "y")`},
		"load absolute":  {"main.star": `load("/etc/systemapi/scripts/x.star", "y")`},
		"sys reference":  {"main.star": `sys.fs.write("/srv/app/x", "y")`},
		"load cycle":     {"main.star": `load("a.star", "a")`, "a.star": `load("b.star", "b")` + "\na = 1", "b.star": `load("a.star", "a")` + "\nb = 1"},
		"self load":      {"main.star": `load("main.star", "x")`},
		"infinite loop":  {"main.star": "for i in range(1 << 62):\n    pass"},
		"while":          {"main.star": "while True:\n    pass"},
		"recursion":      {"main.star": "def f():\n    f()\nf()"},
	}
	wantCode := map[string]string{
		"load traversal": "bad_load", "load absolute": "bad_load", "sys reference": "declaration_failed",
		"load cycle": "load_cycle", "self load": "load_cycle", "infinite loop": "too_many_steps",
		"while": "declaration_failed", "recursion": "declaration_failed",
	}
	for name, files := range hostile {
		h := newFakeHost()
		built := 0
		res := runCheck(t, bundleJSON(t, files, nil), h, &built)
		if res.Status != "failed" || res.ErrorCode != wantCode[name] {
			t.Errorf("%s: status %s code %s error %q", name, res.Status, res.ErrorCode, res.Error)
		}
		if built != 0 || h.writes != 0 {
			t.Errorf("%s: %d write hosts, %d writes", name, built, h.writes)
		}
	}
	// A drifted, well-formed bundle: everything drifts, nothing is written.
	h := newFakeHost()
	built := 0
	res := runCheck(t, nginxBundle(t, 8080), h, &built)
	rep := decodeReport(t, res)
	if res.Status != "succeeded" || rep.Summary.Drift != 4 || built != 0 || h.writes != 0 {
		t.Fatalf("drifted check: %s %q %+v built %d writes %d", res.Status, res.Error, rep.Summary, built, h.writes)
	}
}

func TestConvergeApplyThenCheckIsClean(t *testing.T) {
	h := newFakeHost()
	built := 0
	bundle := nginxBundle(t, 8080)
	plan := decodeReport(t, runCheck(t, bundle, h, &built))
	res := convergeRun(context.Background(), convergeRequest{BundleJSON: bundle, Ents: convergeGrants(), Mode: "apply", ExpectPlan: plan.PlanSHA256}, countingBackend(h, &built))
	rep := decodeReport(t, res)
	if res.Status != "succeeded" || built != 1 || rep.Summary.Changed != 4 {
		t.Fatalf("apply: %s %q %+v built %d", res.Status, res.Error, rep.Summary, built)
	}
	if got := h.files["/srv/app/nginx.conf"].content; got != "listen 8080;\nserver_name web-1;\n" {
		t.Fatalf("rendered %q", got)
	}
	// The restart came after the file change, as its own line.
	var keys []string
	for _, p := range rep.Plan {
		keys = append(keys, p.Key+"="+p.Status)
	}
	if strings.Join(keys, " ") != "file:/srv/app/nginx.conf=changed package:nginx=changed service:nginx=changed restart:nginx=changed" {
		t.Fatalf("plan %v", keys)
	}
	again := decodeReport(t, runCheck(t, bundle, h, &built))
	if again.Summary.OK != 3 || again.Summary.Total != 3 {
		t.Fatalf("recheck %+v", again.Summary)
	}
}

func TestConvergeApplyRefusesStalePlan(t *testing.T) {
	h := newFakeHost()
	built := 0
	plan := decodeReport(t, runCheck(t, nginxBundle(t, 8080), h, &built))
	h.packages["nginx"] = "1.0" // the host changed after the plan
	res := convergeRun(context.Background(), convergeRequest{BundleJSON: nginxBundle(t, 8080), Ents: convergeGrants(), Mode: "apply", ExpectPlan: plan.PlanSHA256}, countingBackend(h, &built))
	if res.ErrorCode != "plan_stale" || built != 0 || h.writes != 0 {
		t.Fatalf("stale: %s %s built %d writes %d", res.Status, res.ErrorCode, built, h.writes)
	}
}

func TestConvergeBadMode(t *testing.T) {
	hash := strings.Repeat("a", 64)
	for _, req := range []convergeRequest{
		{Mode: "check", ExpectPlan: hash},
		{Mode: "apply", ExpectPlan: "-"},
		{Mode: "apply", ExpectPlan: "XYZ"},
		{Mode: "plan", ExpectPlan: "-"},
	} {
		h := newFakeHost()
		built := 0
		req.BundleJSON, req.Ents = nginxBundle(t, 1), convergeGrants()
		res := convergeRun(context.Background(), req, countingBackend(h, &built))
		if res.ErrorCode != "bad_mode" || built != 0 || h.reads != 0 {
			t.Errorf("%+v: %s built %d reads %d", req.Mode, res.ErrorCode, built, h.reads)
		}
	}
}

func TestConvergeApplyStopsAtFirstFailure(t *testing.T) {
	h := newFakeHost()
	built := 0
	bundle := bundleJSON(t, map[string]string{"main.star": `
state.file("/srv/app/a", "a")
state.package("nginx", version="9.9")
state.file("/srv/app/b", "b")
`}, nil)
	h.packages["nginx"] = "1.0"
	plan := decodeReport(t, runCheck(t, bundle, h, &built))
	res := convergeRun(context.Background(), convergeRequest{BundleJSON: bundle, Ents: convergeGrants(), Mode: "apply", ExpectPlan: plan.PlanSHA256}, countingBackend(h, &built))
	rep := decodeReport(t, res)
	var st []string
	for _, p := range rep.Plan {
		st = append(st, p.Status)
	}
	if res.Status != "failed" || strings.Join(st, ",") != "changed,failed,skipped" {
		t.Fatalf("%s %v", res.Status, st)
	}
	if _, ok := h.files["/srv/app/b"]; ok {
		t.Fatal("a resource after the failure was applied")
	}
}

func TestParseBundleRejects(t *testing.T) {
	ok := func(files map[string]string) map[string]any {
		return map[string]any{"v": 1, "files": files}
	}
	main := map[string]string{"main.star": "x = 1"}
	cases := map[string]any{
		"version":        map[string]any{"v": 2, "files": main},
		"unknown field":  map[string]any{"v": 1, "files": main, "extra": 1},
		"no main":        ok(map[string]string{"a.star": ""}),
		"bad name":       ok(map[string]string{"main.star": "", "../x.star": ""}),
		"upper name":     ok(map[string]string{"main.star": "", "A.star": ""}),
		"bad extension":  ok(map[string]string{"main.star": "", "x.py": ""}),
		"vars not obj":   map[string]any{"v": 1, "files": main, "vars": []int{1}},
		"vars too large": map[string]any{"v": 1, "files": main, "vars": map[string]string{"a": strings.Repeat("x", convergeVarsMax)}},
		"bad tag":        map[string]any{"v": 1, "files": main, "host": map[string]any{"tags": []string{"Web Server"}}},
		"control char":   map[string]any{"v": 1, "files": main, "host": map[string]any{"hostname": "a\nb"}},
	}
	for name, c := range cases {
		b, err := json.Marshal(c)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := parseBundle(string(b)); err == nil || !strings.HasPrefix(err.Error(), "bad_bundle") {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := parseBundle(`{"v":1,"files":{"main.star":""}} {}`); err == nil {
		t.Error("trailing data accepted")
	}
	big := bundleJSON(t, map[string]string{"main.star": strings.Repeat("#", convergeBundleMax)}, nil)
	if _, err := parseBundle(big); err == nil || !strings.HasPrefix(err.Error(), "bundle_too_large") {
		t.Errorf("large: %v", err)
	}
}

func TestConvergeDeclarationLimits(t *testing.T) {
	many := "def f():\n    for i in range(501):\n        state.sysctl(\"net.ipv4.ip_forward\" if i == 0 else \"net.k%d\" % i, \"1\")\nf()"
	var chain = map[string]string{"main.star": `load("m0.star", "x")`}
	for i := 0; i < convergeMaxModules+1; i++ {
		chain[fmt.Sprintf("m%d.star", i)] = fmt.Sprintf("load(\"m%d.star\", \"x\")\nx = 1", i+1)
	}
	chain[fmt.Sprintf("m%d.star", convergeMaxModules+1)] = "x = 1"
	cases := map[string]struct {
		files map[string]string
		vars  map[string]any
		code  string
	}{
		"resources":    {map[string]string{"main.star": many}, nil, "too_many_resources"},
		"duplicate":    {map[string]string{"main.star": "state.file(\"/srv/app/a\", \"\")\nstate.absent(\"/srv/app/a\")"}, nil, "duplicate_resource"},
		"modules":      {chain, nil, "too_many_modules"},
		"missing load": {map[string]string{"main.star": `load("nope.star", "x")`}, nil, "bad_load"},
		"tmpl as load": {map[string]string{"main.star": `load("a.tmpl", "x")`, "a.tmpl": ""}, nil, "bad_load"},
		"generated_at": {map[string]string{"main.star": `state.file("/srv/app/a", template("x", {"generated_at": "now"}))`}, nil, "bad_template_var"},
		"restart_on":   {map[string]string{"main.star": `state.service("nginx", restart_on=["file:/nope"])`}, nil, "bad_restart_on"},
		"no template":  {map[string]string{"main.star": `template("gone.tmpl", {})`}, nil, "template_not_found"},
	}
	for name, c := range cases {
		h := newFakeHost()
		built := 0
		res := runCheck(t, bundleJSON(t, c.files, c.vars), h, &built)
		if res.ErrorCode != c.code || built != 0 || h.reads != 0 {
			t.Errorf("%s: code %s (%q) built %d reads %d", name, res.ErrorCode, res.Error, built, h.reads)
		}
	}
}

func TestConvergeLoadSharesModules(t *testing.T) {
	h := newFakeHost()
	built := 0
	res := runCheck(t, bundleJSON(t, map[string]string{
		"main.star":   "load(\"lib.star\", \"conf\")\nload(\"other.star\", \"o\")\nstate.file(\"/srv/app/a\", conf)",
		"lib.star":    "conf = \"x=1\\n\"",
		"other.star":  "load(\"lib.star\", \"conf\")\no = conf",
		"nginx.tmpl":  "",
		"readme.txt":  "",
		"vars_x.star": "",
	}, nil), h, &built)
	if res.Status != "succeeded" {
		t.Fatalf("%s %q", res.ErrorCode, res.Error)
	}
}

func TestConvergePlanHashDeterministicAndCoversRestart(t *testing.T) {
	h := newFakeHost()
	built := 0
	a := decodeReport(t, runCheck(t, nginxBundle(t, 8080), h, &built))
	b := decodeReport(t, runCheck(t, nginxBundle(t, 8080), h, &built))
	if a.PlanSHA256 == "" || a.PlanSHA256 != b.PlanSHA256 {
		t.Fatalf("plan hash not stable: %s %s", a.PlanSHA256, b.PlanSHA256)
	}
	last := a.Plan[len(a.Plan)-1]
	if last.Key != "restart:nginx" || last.Status != statusDrift {
		t.Fatalf("plan %+v", a.Plan)
	}
	// Recompute without the restart line: the hash must differ.
	bundle, err := parseBundle(nginxBundle(t, 8080))
	if err != nil {
		t.Fatal(err)
	}
	resources, err := declare(context.Background(), bundle, &maskedPrinter{out: capWriter{max: convergeOutputMax}})
	if err != nil {
		t.Fatal(err)
	}
	ro := newReadOnlyHost(convergeGrants(), h)
	results := make([]resourceResult, len(resources))
	keys := map[string]int{}
	for i, r := range resources {
		results[i] = checkResource(context.Background(), r, ro)
		keys[r.Key()] = i
	}
	plan := buildPlan(resources, results, keys)
	bsha := sha256Hex(nginxBundle(t, 8080))
	if planSHA256(bsha, plan, resources, results) != a.PlanSHA256 {
		t.Fatal("recomputed hash differs")
	}
	if planSHA256(bsha, plan[:len(plan)-1], resources, results) == a.PlanSHA256 {
		t.Fatal("the restart line is not in the plan hash")
	}
	// A different port is a different plan.
	c := decodeReport(t, runCheck(t, nginxBundle(t, 9090), h, &built))
	if c.PlanSHA256 == a.PlanSHA256 {
		t.Fatal("different desired content, same plan hash")
	}
}

func TestConvergePrintMasksVars(t *testing.T) {
	h := newFakeHost()
	built := 0
	res := runCheck(t, bundleJSON(t, map[string]string{"main.star": `
print(state.vars)
print("pw is " + state.vars["db"]["password"])
print("port", state.vars["port"])
print("ok line")
`}, map[string]any{"db": map[string]any{"password": "hunter2-secret"}, "port": 80}), h, &built)
	if res.Status != "succeeded" {
		t.Fatalf("%s %q", res.ErrorCode, res.Error)
	}
	if strings.Contains(res.Output, "hunter2") {
		t.Fatalf("vars leaked: %q", res.Output)
	}
	if res.Output != "[masked]\n[masked]\nport 80\nok line\n" {
		t.Fatalf("output %q", res.Output)
	}
	big := runCheck(t, bundleJSON(t, map[string]string{"main.star": "def f():\n    for i in range(5000):\n        print(\"line %d\" % i)\nf()"}, nil), h, &built)
	if len(big.Output) > convergeOutputMax || !big.OutputTruncated {
		t.Fatalf("output %d bytes, truncated %v", len(big.Output), big.OutputTruncated)
	}
}

func TestConvergeSensitiveReport(t *testing.T) {
	h := newFakeHost()
	h.files["/srv/app/token"] = &fakeFile{content: "old-token", mode: 0o600}
	built := 0
	res := runCheck(t, bundleJSON(t, map[string]string{"main.star": `state.file("/srv/app/token", state.vars["t"], mode="0600", sensitive=True)`},
		map[string]any{"t": "new-token-value"}), h, &built)
	if strings.Contains(string(res.Report), "token-value") || strings.Contains(string(res.Report), sha256Hex("new-token-value")) ||
		strings.Contains(string(res.Report), sha256Hex("old-token")) || strings.Contains(string(res.Report), `"diff":"-`) {
		t.Fatalf("sensitive data in report: %s", res.Report)
	}
}

func TestCapReportTruncatesInOrder(t *testing.T) {
	rep := convergeReport{V: 1, Mode: "check", PlanSHA256: "p"}
	for i := 0; i < 300; i++ {
		rep.Plan = append(rep.Plan, reportPlanLine{Key: fmt.Sprintf("file:/x/%d", i), Status: "drift"})
		rep.Resources = append(rep.Resources, reportResource{Key: fmt.Sprintf("file:/x/%d", i), Status: "drift",
			Before: Facts{"sha256": strings.Repeat("a", 64)}, Diff: strings.Repeat("+line\n", 400)})
	}
	out := capReport(&rep)
	if len(out) > convergeReportMax {
		t.Fatalf("report %d bytes", len(out))
	}
	var got convergeReport
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatal(err)
	}
	if !got.Truncated || got.Resources[0].Diff != "" || got.Resources[0].Before == nil || len(got.Plan) != 300 {
		t.Fatalf("truncation dropped the wrong things: truncated=%v before=%v plan=%d", got.Truncated, got.Resources[0].Before, len(got.Plan))
	}
	small := convergeReport{V: 1, Resources: []reportResource{{Diff: "d"}}}
	if err := json.Unmarshal(capReport(&small), &got); err != nil || got.Truncated || got.Resources[0].Diff != "d" {
		t.Fatalf("small report changed: %+v %v", got, err)
	}
}

// --- template ---

func render(t *testing.T, src string, data map[string]any) (string, error) {
	t.Helper()
	b := templateBudget{rangeLeft: templateRangeBudget}
	return renderTemplate(context.Background(), src, data, &b)
}

func TestTemplateRenderTwiceIdentical(t *testing.T) {
	src := "{{range $k, $v := .m}}{{$k}}={{$v}}\n{{end}}{{join .l \",\"}} {{quote .s}} {{upper .s}} {{indent 2 .s}} {{default \"d\" .missing_ok}}"
	data := map[string]any{"m": map[string]any{"b": 2, "a": 1, "c": 3}, "l": []any{"x", "y"}, "s": "v", "missing_ok": ""}
	a, err := render(t, src, data)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 20; i++ {
		if b, _ := render(t, src, data); b != a {
			t.Fatalf("render %d differs:\n%q\n%q", i, a, b)
		}
	}
	if a != "a=1\nb=2\nc=3\nx,y \"v\" V   v d" {
		t.Fatalf("render %q", a)
	}
}

func TestTemplateRefusals(t *testing.T) {
	cases := map[string]string{
		"define":         `{{define "x"}}a{{end}}{{template "x"}}`,
		"block":          `{{block "x" .}}a{{end}}`,
		"template":       `{{template "t"}}`,
		"range int":      `{{range 1000000000}}{{range 1000000000}}{{end}}{{end}}`,
		"nested range":   `{{range .l}}{{range $.l}}{{range $.l}}{{end}}{{end}}{{end}}`,
		"printf width":   `{{printf "%01000000000d" 1}}`,
		"printf star":    `{{printf "%*d" 100000000 1}}`,
		"missing key":    `{{.nope}}`,
		"indent too big": `{{indent 100000000 "x"}}`,
		"output cap":     `{{range .l}}{{$.big}}{{end}}`,
		"no now":         `{{now}}`,
		"no env":         `{{env "HOME"}}`,
	}
	l := make([]any, 1000)
	data := map[string]any{"l": l, "big": strings.Repeat("x", 1024)}
	for name, src := range cases {
		out, err := render(t, src, data)
		if err == nil {
			t.Errorf("%s: rendered %d bytes", name, len(out))
			continue
		}
		if strings.Contains(name, "range") && !strings.HasPrefix(err.Error(), "template_too_complex") {
			t.Errorf("%s: %v", name, err)
		}
		if name == "output cap" && !strings.HasPrefix(err.Error(), "template_output_too_large") {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestTemplateRunOutputCap(t *testing.T) {
	b := templateBudget{rangeLeft: templateRangeBudget}
	data := map[string]any{"big": strings.Repeat("x", 200*1024)}
	n := 0
	for ; n < 10; n++ {
		if _, err := renderTemplate(context.Background(), "{{.big}}", data, &b); err != nil {
			break
		}
	}
	if n != templateRunMax/(200*1024) || b.out > templateRunMax {
		t.Fatalf("calls before the run cap: %d, out %d", n, b.out)
	}
}

// cancelAfter is a context whose Err turns Canceled after n calls.
type cancelAfter struct {
	context.Context
	calls, n int
}

func (c *cancelAfter) Err() error {
	c.calls++
	if c.calls > c.n {
		return context.Canceled
	}
	return nil
}

func TestTemplateCancelMidRender(t *testing.T) {
	ctx := &cancelAfter{Context: context.Background(), n: 10}
	b := templateBudget{rangeLeft: templateRangeBudget}
	out, err := renderTemplate(ctx, "{{range .l}}x{{end}}", map[string]any{"l": make([]any, 100)}, &b)
	if !errors.Is(err, errScriptCancelled) || out != "" {
		t.Fatalf("out %q err %v", out, err)
	}
	if ctx.calls > 20 {
		t.Fatalf("kept rendering after cancel: %d ctx checks", ctx.calls)
	}
}

func TestConvergeTemplateInDeclarationIsPure(t *testing.T) {
	h := newFakeHost()
	built := 0
	files := map[string]string{
		"main.star": `state.file("/srv/app/a", template("a.tmpl", {"v": state.vars, "tags": state.host.tags}))`,
		"a.tmpl":    "{{range $k, $v := .v}}{{$k}}={{$v}}\n{{end}}{{join .tags \",\"}}\n",
	}
	vars := map[string]any{"z": 1, "a": "b", "m": 2}
	first := decodeReport(t, runCheck(t, bundleJSON(t, files, vars), h, &built))
	for i := 0; i < 5; i++ {
		if again := decodeReport(t, runCheck(t, bundleJSON(t, files, vars), h, &built)); again.PlanSHA256 != first.PlanSHA256 {
			t.Fatal("declaration is not deterministic")
		}
	}
	if first.Resources[0].Desired["sha256"] != sha256Hex("a=b\nm=2\nz=1\nweb\n") {
		t.Fatalf("rendered content: %v", first.Resources[0].Desired)
	}
}

// B1: a value doubled through a variable is refused long before it grows
// large, although it is never written.
func TestTemplateDoublingBombRefused(t *testing.T) {
	for _, src := range []string{
		`{{$x := "ab"}}{{range 24}}{{$x = printf "%s%s" $x $x}}{{end}}{{len $x}}`,
		`{{$x := "ab"}}{{range 40}}{{$x = printf "%s%s" $x $x}}{{end}}{{len $x}}`,
		`{{$x := "ab"}}{{range 40}}{{$x = print $x $x}}{{end}}{{len $x}}`,
		`{{$x := "ab"}}{{range 40}}{{$x = quote (print $x $x)}}{{end}}{{len $x}}`,
		`{{$x := "ab"}}{{range 40}}{{$x = indent 64 (print $x "\n" $x)}}{{end}}{{len $x}}`,
	} {
		b := templateBudget{rangeLeft: templateRangeBudget}
		out, err := renderTemplate(context.Background(), src, map[string]any{}, &b)
		if err == nil {
			t.Errorf("%s: rendered %q", src, out)
			continue
		}
		var ce *codedError
		if !errors.As(err, &ce) || (ce.code != "template_output_too_large" && ce.code != "template_too_complex") {
			t.Errorf("%s: %v", src, err)
		}
		if b.funcBytes > templateFuncBytesMax+templateCallMax {
			t.Errorf("%s: produced %d bytes", src, b.funcBytes)
		}
	}
	// Many small values add up to the run budget.
	b := templateBudget{rangeLeft: templateRangeBudget}
	big := strings.Repeat("y", 200*1024)
	_, err := renderTemplate(context.Background(), `{{range 100}}{{$y := upper $.s}}{{end}}`, map[string]any{"s": big}, &b)
	if err == nil || !strings.HasPrefix(err.Error(), "template_too_complex") {
		t.Fatalf("run budget: %v", err)
	}
}

// B1: a range that writes nothing still stops on cancel, per iteration.
func TestTemplateNonWritingRangeCancels(t *testing.T) {
	ctx := &cancelAfter{Context: context.Background(), n: 50}
	b := templateBudget{rangeLeft: templateRangeBudget}
	_, err := renderTemplate(ctx, `{{range .l}}{{end}}`, map[string]any{"l": make([]any, 900000)}, &b)
	if !errors.Is(err, errScriptCancelled) {
		t.Fatalf("err %v", err)
	}
	if ctx.calls > 60 {
		t.Fatalf("ran on after cancel: %d ctx checks", ctx.calls)
	}
}

// B1: a declaration that grows the heap past the budget is stopped.
func TestConvergeHeapWatchdog(t *testing.T) {
	oldMax, oldSample := convergeHeapMax, convergeHeapSample
	convergeHeapMax, convergeHeapSample = 32<<20, 2*time.Millisecond
	t.Cleanup(func() { convergeHeapMax, convergeHeapSample = oldMax, oldSample })
	h := newFakeHost()
	built := 0
	res := runCheck(t, bundleJSON(t, map[string]string{"main.star": `
l = []
for i in range(400):
    l.append("x" * (1 << 20) + str(i))
`}, nil), h, &built)
	if res.ErrorCode != "too_much_memory" || built != 0 {
		t.Fatalf("%s %s %q", res.Status, res.ErrorCode, res.Error)
	}
}

// B2: error text that quotes a vars value is masked.
func TestConvergeErrorMasksVars(t *testing.T) {
	vars := map[string]any{"pw": "hunter2secret", "path": "/srv/app/hunter3-secret"}
	for name, main := range map[string]string{
		"fail":      `fail(state.vars["pw"])`,
		"dict miss": `x = {}[state.vars["pw"]]`,
		"template":  `template("{{" + state.vars["pw"] + "}}", {})`,
	} {
		h := newFakeHost()
		built := 0
		res := runCheck(t, bundleJSON(t, map[string]string{"main.star": main}, vars), h, &built)
		if res.Status != "failed" || strings.Contains(res.Error, "hunter2") || !strings.HasSuffix(res.Error, "[masked]") {
			t.Errorf("%s: %s %q", name, res.ErrorCode, res.Error)
		}
		if strings.Contains(string(res.Report), "hunter2") {
			t.Errorf("%s: report %s", name, res.Report)
		}
	}
	// A resource error quoting a path built from vars. (The key itself is
	// the resource's identity and stays in the plan.)
	h := newFakeHost()
	built := 0
	ents := convergeGrants()
	ents.AllowFSWrite = nil
	res := convergeRun(context.Background(), convergeRequest{BundleJSON: bundleJSON(t, map[string]string{"main.star": `state.file(state.vars["path"], "x")`}, vars),
		Ents: ents, Mode: "check", ExpectPlan: "-"}, countingBackend(h, &built))
	if !strings.Contains(string(res.Report), `"error":"[masked]"`) {
		t.Fatalf("report %s", res.Report)
	}
}

// Gate 3: a change to a sensitive file's desired content changes the plan
// hash although its facts carry no hash.
func TestConvergePlanHashCoversSensitiveContent(t *testing.T) {
	h := newFakeHost()
	h.files["/srv/app/token"] = &fakeFile{content: "old", mode: 0o600}
	built := 0
	plan := func(v string) string {
		return decodeReport(t, runCheck(t, bundleJSON(t, map[string]string{"main.star": `state.file("/srv/app/token", state.vars["t"], sensitive=True)`},
			map[string]any{"t": v}), h, &built)).PlanSHA256
	}
	if plan("new-1") == plan("new-2") {
		t.Fatal("sensitive content change kept the plan hash")
	}
}

// Gate 6: one path cannot be declared as two kinds.
func TestConvergePathDeclaredTwice(t *testing.T) {
	for _, main := range []string{
		"state.directory(\"/srv/app/x\")\nstate.file(\"/srv/app/x\", \"\")",
		"state.file(\"/srv/app/x\", \"\")\nstate.directory(\"/srv/app/x\")",
		"state.absent(\"/srv/app/x\")\nstate.directory(\"/srv/app/x\")",
	} {
		h := newFakeHost()
		built := 0
		if res := runCheck(t, bundleJSON(t, map[string]string{"main.star": main}, nil), h, &built); res.ErrorCode != "duplicate_resource" {
			t.Errorf("%q: %s", main, res.ErrorCode)
		}
	}
}

// Low 9: restart_on must be a list or tuple.
func TestConvergeRestartOnType(t *testing.T) {
	h := newFakeHost()
	built := 0
	res := runCheck(t, bundleJSON(t, map[string]string{"main.star": "k = state.file(\"/srv/app/a\", \"\")\nstate.service(\"nginx\", restart_on=k)"}, nil), h, &built)
	if res.ErrorCode != "declaration_failed" || !strings.Contains(res.Error, "list or tuple") {
		t.Fatalf("%s %q", res.ErrorCode, res.Error)
	}
	res = runCheck(t, bundleJSON(t, map[string]string{"main.star": "k = state.file(\"/srv/app/a\", \"\")\nstate.service(\"nginx\", restart_on=(k,))"}, nil), h, &built)
	if res.Status != "succeeded" {
		t.Fatalf("tuple: %s %q", res.ErrorCode, res.Error)
	}
}

// Low 10: a large diff is cut with a marker.
func TestConvergeDiffCapped(t *testing.T) {
	h := newFakeHost()
	h.files["/srv/app/big"] = &fakeFile{content: strings.Repeat("a", 100000) + "\n", mode: 0o644}
	built := 0
	rep := decodeReport(t, runCheck(t, bundleJSON(t, map[string]string{"main.star": `state.file("/srv/app/big", "b" * 100000 + "\n")`}, nil), h, &built))
	d := rep.Resources[0].Diff
	if len(d) > stateDiffMax+64 || !strings.HasSuffix(d, "[diff truncated]\n") {
		t.Fatalf("diff %d bytes", len(d))
	}
}

// allocDuring returns the bytes allocated while f runs.
func allocDuring(f func()) uint64 {
	var a, b runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&a)
	f()
	runtime.ReadMemStats(&b)
	return b.TotalAlloc - a.TotalAlloc
}

// Re-review B1: a list or map argument is refused before fmt formats it,
// so 1500 copies of a 900 KB value never get built.
func TestTemplateContainerArgsRefusedCheaply(t *testing.T) {
	big := strings.Repeat("x", 900000)
	data := map[string]any{"l": []any{big}, "m": map[string]any{"k": big}, "s": big}
	cases := map[string]string{
		"printf list": `{{$x := printf "` + strings.Repeat("%v", 1500) + `" ` + strings.Repeat(".l ", 1500) + `}}ok`,
		"print map":   `{{$x := print ` + strings.Repeat(".m ", 60) + `}}ok`,
		"println":     `{{println .l}}`,
		"html":        `{{html .m}}`,
		"js":          `{{js .l}}`,
		"urlquery":    `{{urlquery .l}}`,
		"quote":       `{{quote .l}}`,
		"join nested": `{{join (slice .ll 0) ","}}`,
		"many args":   `{{print ` + strings.Repeat("1 ", 65) + `}}`,
		"big strings": `{{printf "%s%s" .s .s}}`,
	}
	data["ll"] = []any{[]any{big}, []any{big}}
	for name, src := range cases {
		var err error
		n := allocDuring(func() {
			b := templateBudget{rangeLeft: templateRangeBudget}
			_, err = renderTemplate(context.Background(), src, data, &b)
		})
		var ce *codedError
		if err == nil || !errors.As(err, &ce) || (ce.code != "template_bad_arg" && ce.code != "template_output_too_large") {
			t.Errorf("%s: %v", name, err)
		}
		if n > 10<<20 {
			t.Errorf("%s: allocated %d bytes", name, n)
		}
	}
	// Scalars still format.
	b := templateBudget{rangeLeft: templateRangeBudget}
	out, err := renderTemplate(context.Background(), `{{printf "%s-%d-%v-%.1f" "a" 1 true 2.5}} {{print 1 "b" nil}} {{join .j ","}}`,
		map[string]any{"j": []any{"x", int64(2), true}}, &b)
	if err != nil || out != "a-1-true-2.5 1b<nil> x,2,true" {
		t.Fatalf("%q %v", out, err)
	}
}

// Re-review 2: a var straddling the error cap is masked, not cut to a
// leaking prefix.
func TestConvergeErrorMaskedBeforeCap(t *testing.T) {
	vars := map[string]any{"pw": "hunter2-supersecret"}
	for k := 975; k <= 1005; k++ {
		h := newFakeHost()
		built := 0
		main := fmt.Sprintf(`fail("A" * %d + state.vars["pw"])`, k)
		res := runCheck(t, bundleJSON(t, map[string]string{"main.star": main}, vars), h, &built)
		if strings.Contains(res.Error, "hunter") || !strings.HasSuffix(res.Error, "[masked]") {
			t.Fatalf("k=%d: %q", k, res.Error[max(0, len(res.Error)-40):])
		}
	}
	// A resource error longer than the cap, quoting a path from vars.
	long := "/srv/app/" + strings.Repeat("d", 1000) + "/hunter2-supersecret"
	h := newFakeHost()
	built := 0
	ents := convergeGrants()
	ents.AllowFSWrite = nil
	res := convergeRun(context.Background(), convergeRequest{BundleJSON: bundleJSON(t, map[string]string{"main.star": `state.file(state.vars["p"], "x")`},
		map[string]any{"p": long}), Ents: ents, Mode: "check", ExpectPlan: "-"}, countingBackend(h, &built))
	if !strings.Contains(string(res.Report), `"error":"[masked]"`) {
		t.Fatalf("report %s", res.Report)
	}
}
