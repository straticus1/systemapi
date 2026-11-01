package main

// Converge engine (.omc/plans/convergence-drift.md §4, §6, §7.3). A bundle
// is a set of Starlark and template files plus vars and host facts. Its
// declaration step runs main.star with no sys module and only pure
// builtins, and yields an ordered list of resources. The engine then checks
// every resource through a ReadOnlyHost, builds the plan and its hash, and,
// in apply mode only, re-checks the plan hash against the signed one before
// it applies the drifted resources in order, stopping on the first failure.
// A sysscript_job frame of kind "converge" under a converge_job lease
// reaches convergeRun through the job manager (sysscript_jobs.go), only
// with --converge.
//
// Threats: the bundle is untrusted. The declaration has no sys, clock, env,
// disk or network: its predeclared names are state (resource builtins,
// frozen vars and host), json, yaml, ini and template, all pure. Starlark is
// run without while loops or recursion, under a shared step budget
// (convergeMaxSteps), the run's context (deadline and cancel through
// threadSet) and a cap of convergeMaxResources resources. load() resolves
// only names from the bundle's files (.star, name regex), detects cycles
// (load_cycle) and caps distinct modules at convergeMaxModules. template()
// renders text/template from a bundle file or an inline string with a fixed
// side-effect-free FuncMap: no now, env or file function, no define, block
// or template action (so no recursion), a range iteration budget charged
// before each range runs, a context check at every range iteration and
// every write, an output cap per call and per run, formatting functions
// taking at most 64 scalar arguments (a list or map is refused before fmt
// expands it), and every text-producing function refusing a value over
// the per-call cap and charging its length to a per-run byte budget, so a
// value doubled through a variable stays bounded although it is never
// written; a top-level generated_at var is refused so no timestamp can enter
// rendered content. print() output is capped, and a print line, the run's
// error and a resource's error holding a vars value are masked. Check mode
// never builds a WriteHost: newWrites is called only on the apply path,
// after the plan hash matched; the plan hash starts with the bundle hash, so
// a change to a sensitive file's content (whose facts carry no hash) changes
// it. Starlark has no allocation accounting: starlark-go caps one allocation
// at 1 GiB, and heapWatchdog cancels the declaration once the process heap
// has grown by convergeHeapMax (512 MiB) over the lowest heap it has seen
// during the run. It is a backstop, not a bound: the heap is process-wide
// and sampled every 20 ms, a single large allocation lands before the
// cancel, and it cannot interrupt a Go builtin. Masking is best effort: a
// shorter or transformed var, or one inside a resource key, is not masked;
// error text is masked whole before it is capped. Resource keys (paths, names) are the
// plan's identity and are reported as declared, even when built from vars.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"regexp"
	"runtime/metrics"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"text/template"
	"text/template/parse"
	"time"

	"go.starlark.net/starlark"
	"go.starlark.net/starlarkstruct"
	"go.starlark.net/syntax"
)

const (
	convergeBundleMax       = scriptMaxBytes // 64 KiB, as a script
	convergeVarsMax         = 8 * 1024
	convergeMaxFiles        = 64
	convergeMaxSteps        = 5_000_000
	convergeMaxResources    = 500
	convergeMaxModules      = 32
	convergeOutputMax       = 16 * 1024
	convergeReportMax       = 512 * 1024
	convergeContentTotalMax = 8 << 20
	convergeMaskMin         = 8 // a vars value shorter than this is not masked
	templateSrcMax          = 64 * 1024
	templateCallMax         = 256 * 1024
	templateRunMax          = 1 << 20
	templateDataMax         = 20000 // values
	templateDataBytesMax    = 1 << 20
	templateDataDepthMax    = 32
	templateRangeBudget     = 1_000_000 // iterations per run
	templateIndentMax       = 64
	templatePrintfWidthMax  = 256
	templateFuncBytesMax    = 4 << 20 // bytes FuncMap calls may produce per run
	templateArgsMax         = 64
	hostFieldMax            = 253
	hostTagsMax             = 32
)

var (
	bundleFileRE = regexp.MustCompile(`^[a-z0-9_][a-z0-9_.-]{0,62}\.(star|tmpl|txt)$`)
	hostTagRE    = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,62}$`)
)

// convergeFileOptions: top-level loops and reassignment are allowed (a
// declaration is a script), while loops and recursion are not.
var convergeFileOptions = &syntax.FileOptions{TopLevelControl: true, GlobalReassign: true}

// convergeBundle is the parsed bundle_json.
type convergeBundle struct {
	V     int               `json:"v"`
	Files map[string]string `json:"files"`
	Vars  json.RawMessage   `json:"vars"`
	Host  convergeHostInfo  `json:"host"`
}

type convergeHostInfo struct {
	HostID   string   `json:"host_id"`
	Hostname string   `json:"hostname"`
	OS       string   `json:"os"`
	Tags     []string `json:"tags"`
}

func badBundle(format string, a ...any) error {
	return &codedError{code: "bad_bundle", detail: fmt.Sprintf(format, a...)}
}

func hostFieldOK(s string) bool {
	if len(s) > hostFieldMax {
		return false
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

// parseBundle decodes and validates bundle_json strictly.
func parseBundle(s string) (*convergeBundle, error) {
	if len(s) > convergeBundleMax {
		return nil, &codedError{code: "bundle_too_large", detail: fmt.Sprintf("bundle exceeds %d bytes", convergeBundleMax)}
	}
	dec := json.NewDecoder(strings.NewReader(s))
	dec.DisallowUnknownFields()
	var b convergeBundle
	if err := dec.Decode(&b); err != nil {
		return nil, badBundle("%v", err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, badBundle("trailing data")
	}
	if b.V != 1 {
		return nil, badBundle("unsupported version %d", b.V)
	}
	if len(b.Files) == 0 || len(b.Files) > convergeMaxFiles {
		return nil, badBundle("files: 1 to %d entries", convergeMaxFiles)
	}
	for name := range b.Files {
		if !bundleFileRE.MatchString(name) {
			return nil, badBundle("invalid file name %q", name)
		}
	}
	if _, ok := b.Files["main.star"]; !ok {
		return nil, badBundle("main.star is required")
	}
	vars := bytes.TrimSpace(b.Vars)
	if len(vars) == 0 || string(vars) == "null" {
		b.Vars = json.RawMessage("{}")
	} else if vars[0] != '{' {
		return nil, badBundle("vars must be an object")
	}
	if len(b.Vars) > convergeVarsMax {
		return nil, badBundle("vars exceed %d bytes", convergeVarsMax)
	}
	h := b.Host
	if !hostFieldOK(h.HostID) || !hostFieldOK(h.Hostname) || !hostFieldOK(h.OS) || len(h.Tags) > hostTagsMax {
		return nil, badBundle("invalid host")
	}
	for _, t := range h.Tags {
		if !hostTagRE.MatchString(t) {
			return nil, badBundle("invalid host tag")
		}
	}
	return &b, nil
}

// decodeVars decodes the vars object with numbers kept exact.
func decodeVars(raw json.RawMessage) (map[string]any, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v map[string]any
	if err := dec.Decode(&v); err != nil {
		return nil, badBundle("vars: %v", err)
	}
	return v, nil
}

// jsonToStarlark converts decoded JSON (json.Number for numbers) to a
// Starlark value with dict keys in sorted order.
func jsonToStarlark(v any) (starlark.Value, error) {
	switch x := v.(type) {
	case nil:
		return starlark.None, nil
	case bool:
		return starlark.Bool(x), nil
	case string:
		return starlark.String(x), nil
	case json.Number:
		if i, err := x.Int64(); err == nil {
			return starlark.MakeInt64(i), nil
		}
		f, err := x.Float64()
		if err != nil {
			return nil, badBundle("vars: number %s", x)
		}
		return starlark.Float(f), nil
	case []any:
		elems := make([]starlark.Value, len(x))
		for i, e := range x {
			sv, err := jsonToStarlark(e)
			if err != nil {
				return nil, err
			}
			elems[i] = sv
		}
		return starlark.NewList(elems), nil
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		d := starlark.NewDict(len(x))
		for _, k := range keys {
			sv, err := jsonToStarlark(x[k])
			if err != nil {
				return nil, err
			}
			if err := d.SetKey(starlark.String(k), sv); err != nil {
				return nil, err
			}
		}
		return d, nil
	default:
		return nil, badBundle("vars: unsupported value")
	}
}

// maskNeedles collects the strings whose presence masks a print line: the
// JSON form of every vars value and leaf, and every string leaf as is, when
// at least convergeMaskMin bytes long.
func maskNeedles(vars map[string]any) []string {
	seen := map[string]bool{}
	var out []string
	add := func(s string) {
		if len(s) >= convergeMaskMin && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	var walk func(v any)
	walk = func(v any) {
		if b, err := json.Marshal(v); err == nil {
			add(string(b))
		}
		switch x := v.(type) {
		case string:
			add(x)
		case []any:
			for _, e := range x {
				walk(e)
			}
		case map[string]any:
			for _, e := range x {
				walk(e)
			}
		}
	}
	for _, v := range vars {
		walk(v)
	}
	sort.Strings(out)
	return out
}

// maskedPrinter caps print() output and masks lines holding a vars value.
type maskedPrinter struct {
	out     capWriter
	needles []string
}

// masks reports whether s holds a vars value.
func (p *maskedPrinter) masks(s string) bool {
	for _, n := range p.needles {
		if strings.Contains(s, n) {
			return true
		}
	}
	return false
}

func (p *maskedPrinter) print(msg string) {
	for _, line := range strings.Split(msg, "\n") {
		for _, n := range p.needles {
			if strings.Contains(line, n) {
				line = "[masked]"
				break
			}
		}
		_, _ = p.out.Write([]byte(line + "\n"))
	}
}

// declaration is the state of one declaration step.
type declaration struct {
	ctx          context.Context
	files        map[string]string
	predeclared  starlark.StringDict
	resources    []Applier
	keys         map[string]int
	contentTotal int
	tmpl         templateBudget
	threads      *threadSet
	printer      *maskedPrinter
	modules      map[string]starlark.StringDict
	loading      map[string]bool
	stack        []*starlark.Thread
	stepsDone    uint64
	code         string            // first coded failure raised by a builtin
	paths        map[string]string // path -> key, across file:, dir: and absent
}

func (d *declaration) fail(code, format string, a ...any) error {
	if d.code == "" {
		d.code = code
	}
	return &codedError{code: code, detail: fmt.Sprintf(format, a...)}
}

// stepsUsed is the steps of finished module threads plus the running ones.
func (d *declaration) stepsUsed() uint64 {
	n := d.stepsDone
	for _, t := range d.stack {
		n += t.ExecutionSteps()
	}
	return n
}

func (d *declaration) newThread(name string, budget uint64) *starlark.Thread {
	t := &starlark.Thread{
		Name:  name,
		Print: func(_ *starlark.Thread, msg string) { d.printer.print(msg) },
		Load:  d.load,
	}
	t.SetMaxExecutionSteps(budget)
	d.threads.add(t)
	return t
}

// load resolves a module from the bundle only.
func (d *declaration) load(parent *starlark.Thread, module string) (starlark.StringDict, error) {
	if !bundleFileRE.MatchString(module) || !strings.HasSuffix(module, ".star") {
		return nil, d.fail("bad_load", "load(%q): not a bundle module name", module)
	}
	if g, ok := d.modules[module]; ok {
		return g, nil
	}
	if d.loading[module] {
		return nil, d.fail("load_cycle", "load(%q): cycle", module)
	}
	src, ok := d.files[module]
	if !ok {
		return nil, d.fail("bad_load", "load(%q): not in the bundle", module)
	}
	if len(d.modules)+len(d.loading) > convergeMaxModules {
		return nil, d.fail("too_many_modules", "more than %d modules", convergeMaxModules)
	}
	used := d.stepsUsed()
	if used >= convergeMaxSteps {
		return nil, d.fail("too_many_steps", "step budget exhausted")
	}
	mt := d.newThread("load "+module, convergeMaxSteps-used)
	d.loading[module] = true
	d.stack = append(d.stack, mt)
	g, err := starlark.ExecFileOptions(convergeFileOptions, mt, module, src, d.predeclared)
	d.stack = d.stack[:len(d.stack)-1]
	delete(d.loading, module)
	d.stepsDone += mt.ExecutionSteps()
	// The caller may use only what is left of the shared budget.
	left := uint64(1)
	if used := d.stepsUsed(); used < convergeMaxSteps {
		left = convergeMaxSteps - used
	}
	parent.SetMaxExecutionSteps(parent.ExecutionSteps() + left)
	if err != nil {
		return nil, err
	}
	d.modules[module] = g
	return g, nil
}

// add records a resource, refusing duplicates and the caps.
func (d *declaration) add(r Applier) (starlark.Value, error) {
	if len(d.resources) >= convergeMaxResources {
		return nil, d.fail("too_many_resources", "more than %d resources", convergeMaxResources)
	}
	if _, dup := d.keys[r.Key()]; dup {
		return nil, d.fail("duplicate_resource", "%s declared twice", r.Key())
	}
	var path string
	switch x := r.(type) {
	case *fileResource:
		path = x.path
	case *dirResource:
		path = x.path
	case *absentResource:
		path = x.path
	}
	if path != "" {
		if other, dup := d.paths[path]; dup {
			return nil, d.fail("duplicate_resource", "%s and %s name the same path", other, r.Key())
		}
		d.paths[path] = r.Key()
	}
	if f, ok := r.(*fileResource); ok {
		d.contentTotal += len(f.content)
		if d.contentTotal > convergeContentTotalMax {
			return nil, d.fail("bundle_too_large", "file contents exceed %d bytes", convergeContentTotalMax)
		}
	}
	d.keys[r.Key()] = len(d.resources)
	d.resources = append(d.resources, r)
	return starlark.String(r.Key()), nil
}

// resourceBuiltin wraps a parser as a declaration builtin returning the key.
func (d *declaration) resourceBuiltin(name string, parse stateParser) *starlark.Builtin {
	return starlark.NewBuiltin(name, func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
		r, err := parse(name, args, kwargs)
		if err != nil {
			return nil, err
		}
		return d.add(r)
	})
}

// templateBuiltin is template(name_or_src, vars=None).
func (d *declaration) templateBuiltin(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var src string
	var vars starlark.Value = starlark.None
	if err := starlark.UnpackArgs("template", args, kwargs, "name_or_src", &src, "vars?", &vars); err != nil {
		return nil, err
	}
	if bundleFileRE.MatchString(src) && !strings.HasSuffix(src, ".star") {
		body, ok := d.files[src]
		if !ok {
			return nil, d.fail("template_not_found", "template %q is not in the bundle", src)
		}
		src = body
	}
	data := map[string]any{}
	if vars != starlark.None {
		dict, ok := vars.(*starlark.Dict)
		if !ok {
			return nil, fmt.Errorf("template: vars must be a dict")
		}
		if _, found, _ := dict.Get(starlark.String("generated_at")); found {
			return nil, d.fail("bad_template_var", "generated_at is not allowed in template vars")
		}
		budget := templateDataLimits{nodes: templateDataMax, bytes: templateDataBytesMax}
		v, err := templateValue(dict, &budget, 0)
		if err != nil {
			return nil, fmt.Errorf("template: %w", err)
		}
		data = v.(map[string]any)
	}
	out, err := renderTemplate(d.ctx, src, data, &d.tmpl)
	if err != nil {
		var ce *codedError
		if errors.As(err, &ce) && d.code == "" {
			d.code = ce.code
		}
		return nil, err
	}
	return starlark.String(out), nil
}

// declare runs main.star and returns the resources in declaration order.
func declare(ctx context.Context, b *convergeBundle, printer *maskedPrinter) ([]Applier, error) {
	varsGo, err := decodeVars(b.Vars)
	if err != nil {
		return nil, err
	}
	printer.needles = maskNeedles(varsGo)
	varsVal, err := jsonToStarlark(varsGo)
	if err != nil {
		return nil, err
	}
	varsVal.Freeze()
	tags := make([]starlark.Value, len(b.Host.Tags))
	for i, t := range b.Host.Tags {
		tags[i] = starlark.String(t)
	}
	host := starlarkstruct.FromStringDict(starlark.String("host"), starlark.StringDict{
		"host_id":  starlark.String(b.Host.HostID),
		"hostname": starlark.String(b.Host.Hostname),
		"os":       starlark.String(b.Host.OS),
		"tags":     starlark.Tuple(tags),
	})
	host.Freeze()

	d := &declaration{
		ctx:     ctx,
		files:   b.Files,
		keys:    map[string]int{},
		paths:   map[string]string{},
		tmpl:    templateBudget{rangeLeft: templateRangeBudget},
		threads: &threadSet{},
		printer: printer,
		modules: map[string]starlark.StringDict{},
		loading: map[string]bool{"main.star": true},
	}
	stateDict := starlark.StringDict{"vars": varsVal, "host": host}
	for _, k := range stateKinds {
		parse := k.parse
		if k.kind == "service" {
			parse = func(fn string, a starlark.Tuple, kw []starlark.Tuple) (Applier, error) {
				return parseServiceResource(fn, a, kw, true)
			}
		}
		stateDict[k.kind] = d.resourceBuiltin(k.kind, parse)
	}
	d.predeclared = starlark.StringDict{
		"state": starlarkstruct.FromStringDict(starlark.String("state"), stateDict),
		"json": starlarkstruct.FromStringDict(starlark.String("json"), starlark.StringDict{
			"parse":         starlark.NewBuiltin("parse", jsonParse),
			"encode":        starlark.NewBuiltin("encode", jsonEncode),
			"encode_pretty": starlark.NewBuiltin("encode_pretty", jsonEncodePretty),
		}),
		"yaml": starlarkstruct.FromStringDict(starlark.String("yaml"), starlark.StringDict{
			"parse":  starlark.NewBuiltin("parse", yamlParse),
			"encode": starlark.NewBuiltin("encode", yamlEncode),
		}),
		"ini": starlarkstruct.FromStringDict(starlark.String("ini"), starlark.StringDict{
			"parse":  starlark.NewBuiltin("parse", iniParse),
			"encode": starlark.NewBuiltin("encode", iniEncode),
			"get":    starlark.NewBuiltin("get", iniGet),
		}),
		"template": starlark.NewBuiltin("template", d.templateBuiltin),
	}
	d.predeclared.Freeze()

	if ctx.Err() != nil {
		return nil, scriptCtxErr(ctx)
	}
	stop := context.AfterFunc(ctx, func() { d.threads.cancelAll(jobCtxReason(ctx)) })
	defer stop()
	overHeap := heapWatchdog(d.threads)
	main := d.newThread("main.star", convergeMaxSteps)
	d.stack = append(d.stack, main)
	_, err = starlark.ExecFileOptions(convergeFileOptions, main, "main.star", b.Files["main.star"], d.predeclared)
	exceeded := overHeap()
	if err != nil {
		if ctx.Err() != nil {
			return nil, scriptCtxErr(ctx)
		}
		if exceeded {
			return nil, &codedError{code: "too_much_memory", detail: fmt.Sprintf("the declaration grew the heap by more than %d MiB", convergeHeapMax>>20)}
		}
		code := d.code
		if code == "" {
			code = "declaration_failed"
			if strings.Contains(err.Error(), "too many steps") {
				code = "too_many_steps"
			}
		}
		// Not capped here: convergeRun masks the whole text, then caps it,
		// so a var cut at the cap cannot leak a prefix.
		return nil, &codedError{code: code, detail: err.Error()}
	}
	for _, r := range d.resources {
		s, ok := r.(*serviceResource)
		if !ok {
			continue
		}
		for _, k := range s.restartOn {
			if _, ok := d.keys[k]; !ok || k == s.Key() {
				return nil, &codedError{code: "bad_restart_on", detail: fmt.Sprintf("%s: restart_on %q is not another declared resource", s.Key(), k)}
			}
		}
	}
	return d.resources, nil
}

// convergeHeapMax and convergeHeapSample drive heapWatchdog. Vars so tests
// can lower them.
var (
	convergeHeapMax    uint64 = 512 << 20
	convergeHeapSample        = 20 * time.Millisecond
)

// heapBytes is the bytes in heap objects (live plus not yet swept).
func heapBytes() uint64 {
	s := []metrics.Sample{{Name: "/memory/classes/heap/objects:bytes"}}
	metrics.Read(s)
	if s[0].Value.Kind() != metrics.KindUint64 {
		return 0
	}
	return s[0].Value.Uint64()
}

// heapWatchdog samples the heap while a declaration runs and cancels its
// threads once the heap has grown by more than convergeHeapMax since the
// start. The returned func stops the watchdog and reports whether it fired.
// The heap is process-wide, so another job allocating at the same time
// counts too; that errs toward stopping the declaration.
func heapWatchdog(threads *threadSet) func() bool {
	base := heapBytes()
	var fired atomic.Bool
	done := make(chan struct{})
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		t := time.NewTicker(convergeHeapSample)
		defer t.Stop()
		for {
			select {
			case <-done:
				return
			case <-t.C:
				h := heapBytes()
				if h < base {
					base = h // garbage collected since: a lower baseline
				}
				if h-base > convergeHeapMax {
					fired.Store(true)
					threads.cancelAll("memory budget exceeded")
					return
				}
			}
		}
	}()
	return func() bool {
		close(done)
		<-finished
		return fired.Load()
	}
}

// --- template ---

// templateBudget is shared by every template() call of one run.
type templateBudget struct {
	out       int // bytes written
	rangeLeft int // range iterations left
	funcBytes int // bytes produced by FuncMap calls, intermediate values included
}

type templateDataLimits struct{ nodes, bytes int }

// templateValue converts Starlark vars to Go data for text/template, within
// value, byte and depth limits.
func templateValue(v starlark.Value, lim *templateDataLimits, depth int) (any, error) {
	lim.nodes--
	if lim.nodes < 0 || depth > templateDataDepthMax {
		return nil, fmt.Errorf("vars too large")
	}
	switch x := v.(type) {
	case starlark.NoneType:
		return nil, nil
	case starlark.Bool:
		return bool(x), nil
	case starlark.Int:
		i, ok := x.Int64()
		if !ok {
			return nil, fmt.Errorf("integer out of range")
		}
		return i, nil
	case starlark.Float:
		return float64(x), nil
	case starlark.String:
		lim.bytes -= len(x)
		if lim.bytes < 0 {
			return nil, fmt.Errorf("vars too large")
		}
		return string(x), nil
	case starlark.Indexable: // list, tuple
		out := make([]any, 0, x.Len())
		for i := 0; i < x.Len(); i++ {
			e, err := templateValue(x.Index(i), lim, depth+1)
			if err != nil {
				return nil, err
			}
			out = append(out, e)
		}
		return out, nil
	case *starlark.Dict:
		out := make(map[string]any, x.Len())
		for _, kv := range x.Items() {
			k, ok := kv[0].(starlark.String)
			if !ok {
				return nil, fmt.Errorf("vars keys must be strings")
			}
			e, err := templateValue(kv[1], lim, depth+1)
			if err != nil {
				return nil, err
			}
			out[string(k)] = e
		}
		return out, nil
	case *starlarkstruct.Struct:
		out := map[string]any{}
		for _, name := range x.AttrNames() {
			av, err := x.Attr(name)
			if err != nil {
				return nil, err
			}
			e, err := templateValue(av, lim, depth+1)
			if err != nil {
				return nil, err
			}
			out[name] = e
		}
		return out, nil
	default:
		return nil, fmt.Errorf("unsupported vars value %s", v.Type())
	}
}

// templateWriter caps output and stops when ctx ends.
type templateWriter struct {
	ctx context.Context
	buf bytes.Buffer
	max int
}

func (w *templateWriter) Write(p []byte) (int, error) {
	if w.ctx.Err() != nil {
		return 0, scriptCtxErr(w.ctx)
	}
	if w.buf.Len()+len(p) > w.max {
		return 0, &codedError{code: "template_output_too_large", detail: fmt.Sprintf("template output exceeds %d bytes", w.max)}
	}
	return w.buf.Write(p)
}

// templatePrintf is printf with width and precision capped and no '*'.
func templatePrintf(format string, args ...any) (string, error) {
	for i := 0; i < len(format); i++ {
		if format[i] != '%' {
			continue
		}
		i++
		for i < len(format) && strings.IndexByte("+-# 0", format[i]) >= 0 {
			i++
		}
		for _, part := range []bool{true, false} {
			if !part {
				if i >= len(format) || format[i] != '.' {
					break
				}
				i++
			}
			start := i
			for i < len(format) && format[i] >= '0' && format[i] <= '9' {
				i++
			}
			if i-start > 3 {
				return "", fmt.Errorf("printf width too large")
			}
			if n, err := strconv.Atoi(format[start:i]); err == nil && n > templatePrintfWidthMax {
				return "", fmt.Errorf("printf width too large")
			}
		}
		if i < len(format) && (format[i] == '*' || format[i] == '[') {
			return "", fmt.Errorf("printf argument widths are not allowed")
		}
	}
	return fmt.Sprintf(format, args...), nil
}

// templateScalar reports whether fmt formats v in bounded space: nil, a
// string (sized separately), a boolean or a number.
func templateScalar(v any) bool {
	if v == nil {
		return true
	}
	switch reflect.ValueOf(v).Kind() {
	case reflect.String, reflect.Bool,
		reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr,
		reflect.Float32, reflect.Float64:
		return true
	}
	return false
}

// templateFuncs is the fixed FuncMap. Every function that returns text
// refuses a result over templateCallMax and charges its length to the run's
// funcBytes budget, so a value grown through variables ($x = printf "%s%s"
// $x $x) is bounded even though it is never written. It overrides the
// text-producing builtins (printf, print, println, html, js, urlquery) and
// call; the rest (len, index, slice, eq, and, ...) return parts of their
// inputs.
func templateFuncs(ctx context.Context, budget *templateBudget) template.FuncMap {
	charge := func(s string) (string, error) {
		if ctx.Err() != nil {
			return "", scriptCtxErr(ctx)
		}
		if len(s) > templateCallMax {
			return "", &codedError{code: "template_output_too_large", detail: fmt.Sprintf("a template value exceeds %d bytes", templateCallMax)}
		}
		budget.funcBytes += len(s)
		if budget.funcBytes > templateFuncBytesMax {
			return "", &codedError{code: "template_too_complex", detail: fmt.Sprintf("template functions produced more than %d bytes", templateFuncBytesMax)}
		}
		return s, nil
	}
	// argsFit refuses arguments that fmt could expand without bound before
	// charge sees the result: more than templateArgsMax arguments, any that
	// is not a scalar (a list or map of data could be formatted many times
	// over), or strings over the cap in total.
	argsFit := func(args []any) error {
		if len(args) > templateArgsMax {
			return &codedError{code: "template_bad_arg", detail: fmt.Sprintf("more than %d arguments", templateArgsMax)}
		}
		n := 0
		for _, a := range args {
			if !templateScalar(a) {
				return &codedError{code: "template_bad_arg", detail: "only strings, numbers, booleans and nil can be formatted"}
			}
			if s, ok := a.(string); ok {
				n += len(s)
			}
		}
		if n > templateCallMax {
			return &codedError{code: "template_output_too_large", detail: fmt.Sprintf("a template value exceeds %d bytes", templateCallMax)}
		}
		return nil
	}
	return template.FuncMap{
		"default": func(def, val any) (any, error) {
			out := val
			if val == nil || val == "" || val == 0 || val == int64(0) {
				out = def
			}
			if s, ok := out.(string); ok {
				if _, err := charge(s); err != nil {
					return nil, err
				}
			}
			return out, nil
		},
		"join": func(list any, sep string) (string, error) {
			rv := reflect.ValueOf(list)
			if rv.Kind() != reflect.Slice {
				return "", fmt.Errorf("join: not a list")
			}
			parts := make([]string, rv.Len())
			n := 0
			for i := range parts {
				e := rv.Index(i).Interface()
				if !templateScalar(e) {
					return "", &codedError{code: "template_bad_arg", detail: "join takes a list of strings, numbers or booleans"}
				}
				if s, ok := e.(string); ok {
					n += len(s)
				} else {
					n += 32 // a formatted number or boolean
				}
				n += len(sep)
				if n > templateCallMax {
					return "", &codedError{code: "template_output_too_large", detail: fmt.Sprintf("a template value exceeds %d bytes", templateCallMax)}
				}
				parts[i] = fmt.Sprint(e)
			}
			return charge(strings.Join(parts, sep))
		},
		"indent": func(n int, s string) (string, error) {
			if n < 0 || n > templateIndentMax {
				return "", fmt.Errorf("indent: 0 to %d", templateIndentMax)
			}
			if len(s)+n*(strings.Count(s, "\n")+1) > templateCallMax {
				return charge(strings.Repeat(" ", templateCallMax+1))
			}
			pad := strings.Repeat(" ", n)
			return charge(pad + strings.ReplaceAll(s, "\n", "\n"+pad))
		},
		"quote": func(v any) (string, error) {
			if err := argsFit([]any{v}); err != nil {
				return "", err
			}
			return charge(strconv.Quote(fmt.Sprint(v)))
		},
		"lower": func(s string) (string, error) { return charge(strings.ToLower(s)) },
		"upper": func(s string) (string, error) { return charge(strings.ToUpper(s)) },
		"printf": func(format string, args ...any) (string, error) {
			if err := argsFit(append([]any{format}, args...)); err != nil {
				return "", err
			}
			out, err := templatePrintf(format, args...)
			if err != nil {
				return "", err
			}
			return charge(out)
		},
		"print": func(args ...any) (string, error) {
			if err := argsFit(args); err != nil {
				return "", err
			}
			return charge(fmt.Sprint(args...))
		},
		"println": func(args ...any) (string, error) {
			if err := argsFit(args); err != nil {
				return "", err
			}
			return charge(fmt.Sprintln(args...))
		},
		"html": func(args ...any) (string, error) {
			if err := argsFit(args); err != nil {
				return "", err
			}
			return charge(template.HTMLEscaper(args...))
		},
		"js": func(args ...any) (string, error) {
			if err := argsFit(args); err != nil {
				return "", err
			}
			return charge(template.JSEscaper(args...))
		},
		"urlquery": func(args ...any) (string, error) {
			if err := argsFit(args); err != nil {
				return "", err
			}
			return charge(template.URLQueryEscaper(args...))
		},
		"call": func(any, ...any) (any, error) { return nil, fmt.Errorf("call is not allowed") },
		// rangeGuardFunc is appended to every range pipeline by guardRanges:
		// it charges the iterations before the range runs.
		rangeGuardFunc: func(v any) (any, error) {
			if ctx.Err() != nil {
				return nil, scriptCtxErr(ctx)
			}
			n := 1
			rv := reflect.ValueOf(v)
			switch rv.Kind() {
			case reflect.Slice, reflect.Array, reflect.Map:
				n = rv.Len()
			case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
				if rv.Int() > int64(templateRangeBudget) {
					n = templateRangeBudget + 1
				} else if rv.Int() > 0 {
					n = int(rv.Int())
				}
			}
			budget.rangeLeft -= n
			if budget.rangeLeft < 0 {
				return nil, &codedError{code: "template_too_complex", detail: fmt.Sprintf("more than %d range iterations", templateRangeBudget)}
			}
			return v, nil
		},
		// rangeTickFunc opens every range body (guardRanges): it checks the
		// context once per iteration, so a range that writes nothing still
		// stops on cancel. It prints nothing.
		rangeTickFunc: func() (string, error) {
			if ctx.Err() != nil {
				return "", scriptCtxErr(ctx)
			}
			return "", nil
		},
	}
}

const (
	rangeGuardFunc = "_range_guard"
	rangeTickFunc  = "_range_tick"
)

// guardRanges refuses template actions (recursion) and appends the range
// guard to every range pipeline.
func guardRanges(tree *parse.Tree, n parse.Node) error {
	switch x := n.(type) {
	case nil:
		return nil
	case *parse.ListNode:
		if x == nil {
			return nil
		}
		for _, c := range x.Nodes {
			if err := guardRanges(tree, c); err != nil {
				return err
			}
		}
	case *parse.TemplateNode:
		return fmt.Errorf("template: the template action is not allowed")
	case *parse.IfNode:
		return guardBranch(tree, &x.BranchNode)
	case *parse.WithNode:
		return guardBranch(tree, &x.BranchNode)
	case *parse.RangeNode:
		ident := parse.NewIdentifier(rangeGuardFunc).SetTree(tree).SetPos(x.Pos)
		x.Pipe.Cmds = append(x.Pipe.Cmds, &parse.CommandNode{NodeType: parse.NodeCommand, Pos: x.Pos, Args: []parse.Node{ident}})
		if err := guardBranch(tree, &x.BranchNode); err != nil {
			return err
		}
		if x.List == nil {
			x.List = &parse.ListNode{NodeType: parse.NodeList, Pos: x.Pos}
		}
		tick := parse.NewIdentifier(rangeTickFunc).SetTree(tree).SetPos(x.Pos)
		action := &parse.ActionNode{NodeType: parse.NodeAction, Pos: x.Pos, Line: x.Line, Pipe: &parse.PipeNode{
			NodeType: parse.NodePipe, Pos: x.Pos, Line: x.Line,
			Cmds: []*parse.CommandNode{{NodeType: parse.NodeCommand, Pos: x.Pos, Args: []parse.Node{tick}}},
		}}
		x.List.Nodes = append([]parse.Node{action}, x.List.Nodes...)
		return nil
	}
	return nil
}

func guardBranch(tree *parse.Tree, b *parse.BranchNode) error {
	if err := guardRanges(tree, b.List); err != nil {
		return err
	}
	if b.ElseList != nil {
		return guardRanges(tree, b.ElseList)
	}
	return nil
}

// renderTemplate renders src with data. It is pure: the output depends only
// on src and data.
func renderTemplate(ctx context.Context, src string, data map[string]any, budget *templateBudget) (string, error) {
	if ctx.Err() != nil {
		return "", scriptCtxErr(ctx)
	}
	if len(src) > templateSrcMax {
		return "", fmt.Errorf("template: source exceeds %d bytes", templateSrcMax)
	}
	t, err := template.New("t").Funcs(templateFuncs(ctx, budget)).Option("missingkey=error").Parse(src)
	if err != nil {
		return "", fmt.Errorf("template: %w", err)
	}
	if len(t.Templates()) > 1 {
		return "", fmt.Errorf("template: define and block are not allowed")
	}
	if t.Tree == nil {
		return "", nil
	}
	if err := guardRanges(t.Tree, t.Tree.Root); err != nil {
		return "", err
	}
	room := templateRunMax - budget.out
	if room > templateCallMax {
		room = templateCallMax
	}
	w := &templateWriter{ctx: ctx, max: room}
	if err := t.Execute(w, data); err != nil {
		if ctx.Err() != nil {
			return "", scriptCtxErr(ctx)
		}
		var ce *codedError
		if errors.As(err, &ce) {
			return "", ce
		}
		return "", fmt.Errorf("template: %w", err)
	}
	if ctx.Err() != nil {
		return "", scriptCtxErr(ctx)
	}
	budget.out += w.buf.Len()
	return w.buf.String(), nil
}

// --- plan, apply, report ---

// planItem is one plan line: a resource, or the restart of a service.
type planItem struct {
	res     int    // index into resources, or -1 for a restart
	service int    // the service's index for a restart
	status  string // for a restart line
	errText string
	errFull string
}

// buildPlan orders the resources and their restart lines. A service's
// restart line follows the last of the service and its restart_on keys,
// and appears only when one of those keys drifted.
func buildPlan(resources []Applier, results []resourceResult, keys map[string]int) []planItem {
	after := map[int][]int{}
	for i, r := range resources {
		s, ok := r.(*serviceResource)
		if !ok || len(s.restartOn) == 0 {
			continue
		}
		pos, drift := i, false
		for _, k := range s.restartOn {
			j := keys[k]
			if j > pos {
				pos = j
			}
			if results[j].Status == statusDrift {
				drift = true
			}
		}
		if drift {
			after[pos] = append(after[pos], i)
		}
	}
	var plan []planItem
	for i := range resources {
		plan = append(plan, planItem{res: i})
		for _, s := range after[i] {
			plan = append(plan, planItem{res: -1, service: s, status: statusDrift})
		}
	}
	return plan
}

func (p planItem) key(resources []Applier) string {
	if p.res >= 0 {
		return resources[p.res].Key()
	}
	return "restart:" + resources[p.service].(*serviceResource).name
}

// planSHA256 is sha256 over "bundle\t<bundle_sha256>\n" followed by
// "<key>\t<status>\t<before_digest>\t<desired_digest>\n" for every plan line
// in order (restart lines carry "-" digests). The bundle line binds the plan
// to the exact desired content, including a sensitive file's, whose facts
// carry no hash.
func planSHA256(bundleSHA string, plan []planItem, resources []Applier, results []resourceResult) string {
	var b strings.Builder
	fmt.Fprintf(&b, "bundle\t%s\n", bundleSHA)
	for _, p := range plan {
		status, before, desired := p.status, "-", "-"
		if p.res >= 0 {
			r := results[p.res]
			status, before, desired = r.Status, factsDigest(r.Before), factsDigest(r.Desired)
		}
		fmt.Fprintf(&b, "%s\t%s\t%s\t%s\n", p.key(resources), status, before, desired)
	}
	return sha256Hex(b.String())
}

// convergeRequest is one run: the bundle, the signed entitlements, the mode
// and, for apply, the plan hash the apply was approved against.
type convergeRequest struct {
	BundleJSON string
	Ents       *Entitlements
	Mode       string // "check" or "apply"
	ExpectPlan string // "-" for check
}

// convergeResult is the job outcome: status, a coded error, the capped
// print output and the capped report JSON.
type convergeResult struct {
	Status          string // "succeeded" or "failed"
	ErrorCode       string
	Error           string
	Output          string
	OutputTruncated bool
	Report          []byte
}

type convergeSummary struct {
	Total   int `json:"total"`
	OK      int `json:"ok"`
	Drift   int `json:"drift"`
	Changed int `json:"changed"`
	Failed  int `json:"failed"`
	Denied  int `json:"denied"`
	Skipped int `json:"skipped"`
}

type reportPlanLine struct {
	Key    string `json:"key"`
	Status string `json:"status"`
}

type reportResource struct {
	Key       string  `json:"key"`
	Kind      string  `json:"kind"`
	Status    string  `json:"status"`
	Sensitive bool    `json:"sensitive"`
	Before    Facts   `json:"before"`
	Desired   Facts   `json:"desired"`
	Diff      string  `json:"diff"`
	Error     string  `json:"error"`
	BackupID  *string `json:"backup_id"`
	errFull   string  // uncapped error, for masking; not reported
}

type convergeReport struct {
	V            int              `json:"v"`
	Mode         string           `json:"mode"`
	BundleSHA256 string           `json:"bundle_sha256"`
	PlanSHA256   string           `json:"plan_sha256"`
	Truncated    bool             `json:"truncated"`
	Summary      convergeSummary  `json:"summary"`
	Plan         []reportPlanLine `json:"plan"`
	Resources    []reportResource `json:"resources"`
}

var expectPlanRE = regexp.MustCompile(`^[0-9a-f]{64}$`)

// convergeRun runs one converge job. The check path never calls
// b.newWrites; the apply path calls it once, after the plan hash matched.
func convergeRun(ctx context.Context, req convergeRequest, b hostBackend) convergeResult {
	printer := &maskedPrinter{out: capWriter{max: convergeOutputMax}}
	rep := convergeReport{V: 1, Mode: capText(req.Mode, 16), BundleSHA256: sha256Hex(req.BundleJSON), Plan: []reportPlanLine{}, Resources: []reportResource{}}
	finish := func(err error) convergeResult {
		res := convergeResult{Status: "succeeded", Output: printer.out.buf.String(), OutputTruncated: printer.out.truncated}
		s := rep.Summary
		if err != nil {
			res.Status = "failed"
			res.ErrorCode = "error"
			var ce *codedError
			switch {
			case errors.As(err, &ce):
				res.ErrorCode = ce.code
			case errors.Is(err, errScriptTimedOut):
				res.ErrorCode = "timed_out"
			case errors.Is(err, errScriptCancelled):
				res.ErrorCode = "cancelled"
			}
		} else if s.Failed+s.Denied > 0 {
			res.Status = "failed"
		}
		// Error text can quote a vars value (fail(state.vars["pw"]), a
		// missing dict key, a path built from vars): mask it as print is,
		// on the whole text before it is capped.
		if err != nil {
			if full := err.Error(); printer.masks(full) {
				res.Error = res.ErrorCode + ": [masked]"
			} else {
				res.Error = capText(full, stateErrorMax)
			}
		}
		for i := range rep.Resources {
			if printer.masks(rep.Resources[i].errFull) || printer.masks(rep.Resources[i].Error) {
				rep.Resources[i].Error = "[masked]"
			}
		}
		res.Report = capReport(&rep)
		return res
	}

	apply := req.Mode == "apply"
	if !(req.Mode == "check" && req.ExpectPlan == "-") && !(apply && expectPlanRE.MatchString(req.ExpectPlan)) {
		return finish(&codedError{code: "bad_mode", detail: "mode=apply needs a plan hash and mode=check needs \"-\""})
	}
	bundle, err := parseBundle(req.BundleJSON)
	if err != nil {
		return finish(err)
	}
	resources, err := declare(ctx, bundle, printer)
	if err != nil {
		return finish(err)
	}
	keys := make(map[string]int, len(resources))
	for i, r := range resources {
		keys[r.Key()] = i
	}

	ro := newReadOnlyHost(req.Ents, b.reads)
	results := make([]resourceResult, len(resources))
	for i, r := range resources {
		results[i] = checkResource(ctx, r, ro)
	}
	plan := buildPlan(resources, results, keys)
	rep.PlanSHA256 = planSHA256(rep.BundleSHA256, plan, resources, results)

	var runErr error
	if apply {
		runErr = applyPlan(ctx, req, b, ro, resources, results, plan, rep.PlanSHA256)
	} else if ctx.Err() != nil {
		runErr = scriptCtxErr(ctx)
	}
	fillReport(&rep, plan, resources, results)
	return finish(runErr)
}

// applyPlan re-checks the plan hash, then applies drifted lines in order and
// stops at the first that does not end changed; the lines after it that
// were to change are skipped.
func applyPlan(ctx context.Context, req convergeRequest, b hostBackend, ro ReadOnlyHost, resources []Applier, results []resourceResult, plan []planItem, planSHA string) error {
	if planSHA != req.ExpectPlan {
		return &codedError{code: "plan_stale", detail: "the host no longer matches the approved plan"}
	}
	for _, r := range results {
		if r.Status != statusOK && r.Status != statusDrift {
			return &codedError{code: "plan_not_applicable", detail: "the plan has failed, denied or skipped resources"}
		}
	}
	rw := newWriteHost(req.Ents, b.newWrites())
	changed := map[string]bool{}
	stopped := false
	for i := range plan {
		p := &plan[i]
		if p.res >= 0 {
			r := &results[p.res]
			if r.Status != statusDrift {
				continue
			}
			if stopped {
				r.Status = statusSkipped
				continue
			}
			*r = applyChecked(ctx, resources[p.res], ro, rw, *r)
			if r.Status == statusChanged {
				changed[r.Key] = true
			} else {
				stopped = true
			}
			continue
		}
		if stopped || ctx.Err() != nil {
			p.status, stopped = statusSkipped, true
			continue
		}
		svc := resources[p.service].(*serviceResource)
		due := false
		for _, k := range svc.restartOn {
			due = due || changed[k]
		}
		if !due {
			p.status = statusOK
			continue
		}
		if err := rw.Service(ctx, "restart", svc.name); err != nil {
			p.status, p.errText, p.errFull, stopped = statusFailed, stateErrText(err), err.Error(), true
			if errors.Is(err, errStateDenied) {
				p.status = statusDenied
			}
			continue
		}
		p.status = statusChanged
	}
	if ctx.Err() != nil {
		return scriptCtxErr(ctx)
	}
	return nil
}

// fillReport writes the plan lines, resources and summary.
func fillReport(rep *convergeReport, plan []planItem, resources []Applier, results []resourceResult) {
	for _, p := range plan {
		line := reportPlanLine{Key: p.key(resources), Status: p.status}
		rr := reportResource{Key: line.Key, Kind: "restart", Status: p.status, Error: p.errText, errFull: p.errFull}
		if p.res >= 0 {
			r := results[p.res]
			line.Status = r.Status
			rr = reportResource{Key: r.Key, Kind: r.Kind, Status: r.Status, Sensitive: r.Sensitive,
				Before: r.Before, Desired: r.Desired, Error: r.Error, errFull: r.errFull}
			if !r.Sensitive {
				rr.Diff = r.Diff
			}
			if r.BackupID != "" {
				id := r.BackupID
				rr.BackupID = &id
			}
		}
		rep.Plan = append(rep.Plan, line)
		rep.Resources = append(rep.Resources, rr)
		rep.Summary.Total++
		switch line.Status {
		case statusOK:
			rep.Summary.OK++
		case statusDrift:
			rep.Summary.Drift++
		case statusChanged:
			rep.Summary.Changed++
		case statusFailed:
			rep.Summary.Failed++
		case statusDenied:
			rep.Summary.Denied++
		case statusSkipped:
			rep.Summary.Skipped++
		}
	}
}

// capReport encodes the report within convergeReportMax. Over the cap it
// drops, in order, the diffs, then before/desired, then the resources, then
// the plan lines, and sets truncated. The summary and hashes always stay.
func capReport(rep *convergeReport) []byte {
	steps := []func(){
		func() {
			for i := range rep.Resources {
				rep.Resources[i].Diff = ""
			}
		},
		func() {
			for i := range rep.Resources {
				rep.Resources[i].Before, rep.Resources[i].Desired = nil, nil
			}
		},
		func() { rep.Resources = []reportResource{} },
		func() { rep.Plan = []reportPlanLine{} },
	}
	for i := 0; ; i++ {
		out, err := json.Marshal(rep)
		if err == nil && len(out) <= convergeReportMax {
			return out
		}
		if i == len(steps) {
			// Unreachable with the caps above: what is left is the fixed
			// header and summary.
			out, err := json.Marshal(struct {
				V            int             `json:"v"`
				Mode         string          `json:"mode"`
				BundleSHA256 string          `json:"bundle_sha256"`
				PlanSHA256   string          `json:"plan_sha256"`
				Truncated    bool            `json:"truncated"`
				Summary      convergeSummary `json:"summary"`
			}{rep.V, rep.Mode, rep.BundleSHA256, rep.PlanSHA256, true, rep.Summary})
			if err != nil {
				return []byte(`{"v":1,"truncated":true}`)
			}
			return out
		}
		rep.Truncated = true
		steps[i]()
	}
}
