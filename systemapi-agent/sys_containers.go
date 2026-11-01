package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"go.starlark.net/starlark"
	"go.starlark.net/starlarkstruct"
	"gopkg.in/yaml.v3"
)

// containersList implements sys.containers.list().
// Returns a Starlark list of container structs. On Docker unavailability, logs and returns empty list (D-02).
func (engine *SysscriptEngine) containersList(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	containers, err := engine.dockerClient.ListContainers()
	if err != nil {
		log.Printf("[sys.containers.list] Docker unavailable: %v", err)
		return starlark.NewList(nil), nil // D-02: return empty list, not error
	}

	items := make([]starlark.Value, 0, len(containers))
	for _, c := range containers {
		name := ""
		if len(c.Names) > 0 {
			name = strings.TrimPrefix(c.Names[0], "/")
		}
		s := starlarkstruct.FromStringDict(starlark.String("container"), starlark.StringDict{
			"id":    starlark.String(c.Id),
			"name":  starlark.String(name),
			"image": starlark.String(c.Image),
			"state": starlark.String(c.State),
		})
		items = append(items, s)
	}
	return starlark.NewList(items), nil
}

// containersStats implements sys.containers.stats(id).
// Returns a stats struct or None on error.
func (engine *SysscriptEngine) containersStats(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var id string
	if err := starlark.UnpackArgs("stats", args, kwargs, "id", &id); err != nil {
		return starlark.None, err
	}

	stats, err := engine.dockerClient.GetContainerStats(id)
	if err != nil {
		log.Printf("[sys.containers.stats] error for %q: %v", id, err)
		return starlark.None, nil
	}

	s := starlarkstruct.FromStringDict(starlark.String("stats"), starlark.StringDict{
		"id":              starlark.String(stats.Id),
		"name":            starlark.String(stats.Name),
		"image":           starlark.String(stats.Image),
		"state":           starlark.String(stats.State),
		"cpu_pct":         starlark.Float(stats.CpuPct),
		"mem_used_bytes":  starlark.MakeUint64(stats.MemUsedBytes),
		"mem_limit_bytes": starlark.MakeUint64(stats.MemLimitBytes),
		"mem_pct":         starlark.Float(stats.MemPct),
		"rx_bytes":        starlark.MakeUint64(stats.RxBytes),
		"tx_bytes":        starlark.MakeUint64(stats.TxBytes),
	})
	return s, nil
}

// containersStop implements sys.containers.stop(id).
func (engine *SysscriptEngine) containersStop(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var id string
	if err := starlark.UnpackArgs("stop", args, kwargs, "id", &id); err != nil {
		return starlark.None, err
	}
	return containerActionResult(engine.dockerClient.StopContainer(id))
}

// containersStart implements sys.containers.start(id).
func (engine *SysscriptEngine) containersStart(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var id string
	if err := starlark.UnpackArgs("start", args, kwargs, "id", &id); err != nil {
		return starlark.None, err
	}
	return containerActionResult(engine.dockerClient.StartContainer(id))
}

// containersRestart implements sys.containers.restart(id).
func (engine *SysscriptEngine) containersRestart(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var id string
	if err := starlark.UnpackArgs("restart", args, kwargs, "id", &id); err != nil {
		return starlark.None, err
	}
	return containerActionResult(engine.dockerClient.RestartContainer(id))
}

// containerActionResult builds a {success, error} dict following the sys_config.go pattern.
func containerActionResult(err error) (starlark.Value, error) {
	result := starlark.NewDict(2)
	if err != nil {
		result.SetKey(starlark.String("success"), starlark.False)
		result.SetKey(starlark.String("error"), starlark.String(fmt.Sprintf("%v", err)))
	} else {
		result.SetKey(starlark.String("success"), starlark.True)
		result.SetKey(starlark.String("error"), starlark.String(""))
	}
	return result, nil
}

func (engine *SysscriptEngine) containersInspect(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var id string
	if err := starlark.UnpackArgs("inspect", args, kwargs, "id", &id); err != nil {
		return starlark.None, err
	}
	if !isValidContainerID(id) {
		return starlark.None, fmt.Errorf("invalid container id")
	}
	if engine.dockerClient == nil {
		return starlark.None, fmt.Errorf("docker client not initialized")
	}
	info, err := engine.dockerClient.Inspect(id)
	if err != nil {
		return starlark.None, err
	}
	return starlarkDict(info)
}

func (engine *SysscriptEngine) containersLogs(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var id string
	if err := starlark.UnpackArgs("logs", args, kwargs, "id", &id); err != nil {
		return starlark.None, err
	}
	if !isValidContainerID(id) {
		return starlark.None, fmt.Errorf("invalid container id")
	}
	if engine.dockerClient == nil {
		return starlark.None, fmt.Errorf("docker client not initialized")
	}
	text, err := engine.dockerClient.Logs(id)
	if err != nil {
		return starlark.None, err
	}
	return starlark.String(text), nil
}

func (engine *SysscriptEngine) containersRun(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var image string
	var cmd *starlark.List
	if err := starlark.UnpackArgs("run", args, kwargs, "image", &image, "cmd?", &cmd); err != nil {
		return starlark.None, err
	}
	if !imageAllowed(image) || !imageGranted(engine.Entitlements.AllowImages, image) {
		return starlark.None, fmt.Errorf("image not allowed")
	}
	argv, err := listStrings(cmd)
	if err != nil {
		return starlark.None, err
	}
	if len(argv) > 0 {
		if err := validateArgv(argv); err != nil {
			return starlark.None, err
		}
	}
	if engine.dockerClient == nil {
		return starlark.None, fmt.Errorf("docker client not initialized")
	}
	id, err := engine.dockerClient.Run(image, argv)
	if err != nil {
		return starlark.None, err
	}
	return starlark.String(id), nil
}

func (engine *SysscriptEngine) containersExec(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var id string
	var cmd *starlark.List
	if err := starlark.UnpackArgs("exec", args, kwargs, "id", &id, "cmd", &cmd); err != nil {
		return starlark.None, err
	}
	if !isValidContainerID(id) {
		return starlark.None, fmt.Errorf("invalid container id")
	}
	if cmd == nil {
		return starlark.None, fmt.Errorf("command required")
	}
	argv, err := listStrings(cmd)
	if err != nil {
		return starlark.None, err
	}
	if len(argv) == 0 {
		return starlark.None, fmt.Errorf("command required")
	}
	if err := validateArgv(argv); err != nil {
		return starlark.None, err
	}
	if engine.dockerClient == nil {
		return starlark.None, fmt.Errorf("docker client not initialized")
	}
	text, err := engine.dockerClient.Exec(id, argv)
	if err != nil {
		return starlark.None, err
	}
	return starlark.String(text), nil
}

// imageGranted is the allow_images rule for run, pull and remove_image: an
// exact grant, where "name" and "name:latest" are the same image (Docker
// adds ":latest" to an untagged ref). A digest ref needs its exact digest
// grant; "*" is not allow-all.
func imageGranted(list []string, ref string) bool {
	if exactGrant(list, ref) {
		return true
	}
	if strings.Contains(ref, "@") {
		return false
	}
	repo, tag := splitImageRef(ref)
	if tag != "latest" {
		return false
	}
	if ref == repo {
		return exactGrant(list, repo+":latest")
	}
	return exactGrant(list, repo)
}

// imageRefGranted gates pull and remove_image the way run is gated: a valid
// ref, imageAllowed for a tag ref, and an exact grant.
func imageRefGranted(list []string, ref string) error {
	if !isValidImageRef(ref) {
		return fmt.Errorf("invalid image reference")
	}
	if !strings.Contains(ref, "@") && !imageAllowed(ref) {
		return fmt.Errorf("image not allowed")
	}
	if !imageGranted(list, ref) {
		return fmt.Errorf("image not allowed")
	}
	return nil
}

func (engine *SysscriptEngine) requireDocker() error {
	if engine.dockerClient == nil {
		return fmt.Errorf("docker client not initialized")
	}
	return nil
}

func (engine *SysscriptEngine) containersImages(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	if err := starlark.UnpackArgs("images", args, kwargs); err != nil {
		return starlark.None, err
	}
	if err := engine.requireDocker(); err != nil {
		return starlark.None, err
	}
	images, err := engine.dockerClient.ListImages()
	if err != nil {
		return starlark.None, err
	}
	items := make([]starlark.Value, 0, len(images))
	for _, img := range images {
		tags := make([]starlark.Value, 0, len(img.RepoTags))
		for _, tag := range img.RepoTags {
			tags = append(tags, starlark.String(tag))
		}
		d := starlark.NewDict(4)
		d.SetKey(starlark.String("id"), starlark.String(img.Id))
		d.SetKey(starlark.String("tags"), starlark.NewList(tags))
		d.SetKey(starlark.String("size"), starlark.MakeInt64(img.Size))
		d.SetKey(starlark.String("created"), starlark.MakeInt64(img.Created))
		items = append(items, d)
	}
	return starlark.NewList(items), nil
}

func (engine *SysscriptEngine) containersPull(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var ref string
	if err := starlark.UnpackArgs("pull", args, kwargs, "ref", &ref); err != nil {
		return starlark.None, err
	}
	if err := imageRefGranted(engine.Entitlements.AllowImages, ref); err != nil {
		return starlark.None, err
	}
	if err := engine.requireDocker(); err != nil {
		return starlark.None, err
	}
	status, err := engine.dockerClient.PullImage(engine.ctx, ref)
	if err != nil {
		return starlark.None, err
	}
	return starlarkDict(map[string]string{"ref": ref, "status": status})
}

func (engine *SysscriptEngine) containersRemoveImage(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var ref string
	force := false
	if err := starlark.UnpackArgs("remove_image", args, kwargs, "ref", &ref, "force?", &force); err != nil {
		return starlark.None, err
	}
	if err := imageRefGranted(engine.Entitlements.AllowImages, ref); err != nil {
		return starlark.None, err
	}
	if err := engine.requireDocker(); err != nil {
		return starlark.None, err
	}
	if err := engine.dockerClient.RemoveImage(ref, force); err != nil {
		return starlark.None, err
	}
	return starlark.None, nil
}

func volumeDict(v DockerVolume) (starlark.Value, error) {
	return starlarkDict(map[string]string{"name": v.Name, "driver": v.Driver, "mountpoint": v.Mountpoint, "scope": v.Scope})
}

func (engine *SysscriptEngine) containersVolumes(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	if err := starlark.UnpackArgs("volumes", args, kwargs); err != nil {
		return starlark.None, err
	}
	if err := engine.requireDocker(); err != nil {
		return starlark.None, err
	}
	vols, err := engine.dockerClient.ListVolumes()
	if err != nil {
		return starlark.None, err
	}
	items := make([]starlark.Value, 0, len(vols))
	for _, v := range vols {
		d, err := volumeDict(v)
		if err != nil {
			return starlark.None, err
		}
		items = append(items, d)
	}
	return starlark.NewList(items), nil
}

func (engine *SysscriptEngine) containersCreateVolume(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var name string
	if err := starlark.UnpackArgs("create_volume", args, kwargs, "name", &name); err != nil {
		return starlark.None, err
	}
	if !isValidDockerName(name) {
		return starlark.None, fmt.Errorf("invalid volume name")
	}
	if err := engine.requireDocker(); err != nil {
		return starlark.None, err
	}
	vol, err := engine.dockerClient.CreateVolume(name)
	if err != nil {
		return starlark.None, err
	}
	return volumeDict(*vol)
}

func (engine *SysscriptEngine) containersRemoveVolume(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var name string
	if err := starlark.UnpackArgs("remove_volume", args, kwargs, "name", &name); err != nil {
		return starlark.None, err
	}
	if !isValidDockerName(name) {
		return starlark.None, fmt.Errorf("invalid volume name")
	}
	if err := engine.requireDocker(); err != nil {
		return starlark.None, err
	}
	if err := engine.dockerClient.RemoveVolume(name); err != nil {
		return starlark.None, err
	}
	return starlark.None, nil
}

func (engine *SysscriptEngine) containersNetworks(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	if err := starlark.UnpackArgs("networks", args, kwargs); err != nil {
		return starlark.None, err
	}
	if err := engine.requireDocker(); err != nil {
		return starlark.None, err
	}
	nets, err := engine.dockerClient.ListNetworks()
	if err != nil {
		return starlark.None, err
	}
	rows := make([]map[string]string, 0, len(nets))
	for _, n := range nets {
		rows = append(rows, map[string]string{"id": n.Id, "name": n.Name, "driver": n.Driver, "scope": n.Scope})
	}
	return starlarkDictList(rows)
}

func (engine *SysscriptEngine) containersCreateNetwork(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var name string
	driver := "bridge"
	if err := starlark.UnpackArgs("create_network", args, kwargs, "name", &name, "driver?", &driver); err != nil {
		return starlark.None, err
	}
	if !isValidDockerName(name) {
		return starlark.None, fmt.Errorf("invalid network name")
	}
	if _, ok := networkDrivers[driver]; !ok {
		return starlark.None, fmt.Errorf("network driver not allowed")
	}
	if err := engine.requireDocker(); err != nil {
		return starlark.None, err
	}
	id, err := engine.dockerClient.CreateNetwork(name, driver)
	if err != nil {
		return starlark.None, err
	}
	return starlarkDict(map[string]string{"id": id, "name": name, "driver": driver})
}

func (engine *SysscriptEngine) containersRemoveNetwork(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var idOrName string
	if err := starlark.UnpackArgs("remove_network", args, kwargs, "id_or_name", &idOrName); err != nil {
		return starlark.None, err
	}
	if !isValidDockerName(idOrName) {
		return starlark.None, fmt.Errorf("invalid network name")
	}
	if err := engine.requireDocker(); err != nil {
		return starlark.None, err
	}
	if err := engine.dockerClient.RemoveNetwork(idOrName); err != nil {
		return starlark.None, err
	}
	return starlark.None, nil
}

// Threats: compose runs a fixed argv with no shell and a fixed environment
// (no inherited DOCKER_HOST or COMPOSE_FILE). The project dir must be
// absolute, clean, a real directory (symlinks resolved and re-checked), hold
// a regular compose file, and pass the sys.fs read policy. It must not
// overlap any fs or config write grant, compared on resolved paths in both
// directions: a script that can write the compose file could start
// privileged containers, so writable dirs fail closed. Before every action,
// `docker compose config` is run and its output must pass an allowlist of
// top-level, service, volume, network, secret and config keys (see the list
// above checkComposeService), with bind mounts, build contexts and secret
// files inside the project dir; the raw compose files are also refused when
// they use include, extends with a file, or env_file. Any parse failure
// refuses. Every action (up, pull, down, ps) then runs that exact checked
// document from stdin (-f -), so files changed after the check are not read;
// binds into the project dir must be read-only so a container cannot
// rewrite them. Does NOT inspect a .env file in the project
// dir (it is not script-writable) or what the images themselves do. The
// whole call stops at the script's deadline or cancel, which kills the
// compose process group (jobCommand). Output is truncated at outputCap.

const (
	composePathMax = 4096
	composePATH    = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
)

var composeActions = map[string][]string{
	"up":   {"up", "-d"},
	"down": {"down"},
	"ps":   {"ps"},
	"pull": {"pull"},
}

var composeFiles = []string{"compose.yaml", "compose.yml", "docker-compose.yaml", "docker-compose.yml"}

// composeOverrideFiles are merged automatically by docker compose.
var composeOverrideFiles = []string{"compose.override.yaml", "compose.override.yml", "docker-compose.override.yaml", "docker-compose.override.yml"}

// composeEnv is the child's whole environment. HOME is kept only so the
// docker CLI finds its per-user plugins and the daemon credentials it
// already has.
func composeEnv() []string {
	env := []string{"PATH=" + composePATH, "LC_ALL=C"}
	if home, err := os.UserHomeDir(); err == nil && filepath.IsAbs(home) {
		env = append(env, "HOME="+home)
	}
	return env
}

// composeExec runs argv[0] with argv[1:] in dir with composeEnv, feeding
// stdin when it is not empty. With stdoutOnly the result is stdout alone
// (stderr is dropped), for output that is parsed (capped at hostFileCap).
// Tests replace it.
var composeExec = func(ctx context.Context, dir string, argv []string, stdin string, stdoutOnly bool) (int, string, error) {
	cmd := jobCommand(ctx, argv[0], argv[1:]...)
	cmd.Dir = dir
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	cmd.Env = composeEnv()
	out := &capWriter{max: outputCap}
	if stdoutOnly {
		// Parsed output gets a larger cap; a truncated document fails to parse.
		out.max = hostFileCap
	}
	cmd.Stdout = out
	if stdoutOnly {
		cmd.Stderr = &capWriter{max: 0}
	} else {
		cmd.Stderr = out
	}
	err := cmd.Run()
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return exitErr.ExitCode(), out.buf.String(), nil
	}
	if err != nil {
		return -1, out.buf.String(), err
	}
	return 0, out.buf.String(), nil
}

// capWriter keeps the first max bytes and drops the rest so the child
// never blocks or dies on a closed pipe.
type capWriter struct {
	buf       bytes.Buffer
	max       int
	truncated bool // bytes past max were dropped
}

func (w *capWriter) Write(p []byte) (int, error) {
	room := w.max - w.buf.Len()
	if room < 0 {
		room = 0
	}
	if len(p) > room {
		w.truncated = true
		w.buf.Write(p[:room])
	} else {
		w.buf.Write(p)
	}
	return len(p), nil
}

// writeGrantOverlaps reports whether a write grant covers path or lies
// inside it. Both sides are compared cleaned and with symlinks resolved.
func writeGrantOverlaps(allow []string, path string) bool {
	for _, prefix := range allow {
		if prefix == "*" {
			return true
		}
		if prefix == "" || !filepath.IsAbs(prefix) {
			continue
		}
		forms := []string{filepath.Clean(prefix)}
		if real, err := resolveExisting(filepath.Clean(prefix)); err == nil {
			forms = append(forms, real)
		} else {
			return true // an unresolvable grant fails closed
		}
		for _, p := range forms {
			if pathWithin(p, path) || pathWithin(path, p) {
				return true
			}
		}
	}
	return false
}

func (engine *SysscriptEngine) composeDirPolicy(dir string) (string, error) {
	if dir == "" || len(dir) > composePathMax || strings.ContainsAny(dir, "\x00\n\r") {
		return "", fmt.Errorf("invalid project dir")
	}
	if !filepath.IsAbs(dir) || filepath.Clean(dir) != dir || dir == string(os.PathSeparator) {
		return "", fmt.Errorf("project dir must be absolute and clean")
	}
	perms := engine.Entitlements
	check := func(p string) error {
		if !fsPrefixAllowed(perms.AllowFSRead, p) {
			return fmt.Errorf("security exception: read to %s not granted", p)
		}
		if writeGrantOverlaps(perms.AllowFSWrite, p) || writeGrantOverlaps(perms.AllowConfigWrite, p) {
			return fmt.Errorf("security exception: project dir is writable by scripts")
		}
		return nil
	}
	if err := check(dir); err != nil {
		return "", err
	}
	resolved, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return "", fmt.Errorf("project dir not found")
	}
	resolved = filepath.Clean(resolved)
	if err := check(resolved); err != nil {
		return "", fmt.Errorf("project dir symlink escape")
	}
	info, err := os.Stat(resolved)
	if err != nil || !info.IsDir() {
		return "", fmt.Errorf("project dir is not a directory")
	}
	for _, name := range composeFiles {
		if fi, err := os.Lstat(filepath.Join(resolved, name)); err == nil && fi.Mode().IsRegular() {
			return resolved, nil
		}
	}
	return "", fmt.Errorf("no compose file in project dir")
}

// composeRawCheck refuses include, extends with a file, and env_file in the
// compose files docker compose would load from dir. `compose config` has
// already merged those away, so they are checked in the source.
func composeRawCheck(dir string) error {
	for _, name := range append(append([]string(nil), composeFiles...), composeOverrideFiles...) {
		p := filepath.Join(dir, name)
		fi, err := os.Lstat(p)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil || !fi.Mode().IsRegular() {
			return fmt.Errorf("security exception: compose file %s is not a regular file", name)
		}
		text, err := readFileCapped(p, hostFileCap)
		if err != nil {
			return fmt.Errorf("compose file %s: %w", name, err)
		}
		var doc map[string]any
		if err := yaml.Unmarshal([]byte(text), &doc); err != nil {
			return fmt.Errorf("security exception: compose file %s does not parse", name)
		}
		if _, ok := doc["include"]; ok {
			return fmt.Errorf("security exception: compose file %s uses include", name)
		}
		services, ok := doc["services"]
		if !ok || services == nil {
			continue
		}
		svcMap, ok := services.(map[string]any)
		if !ok {
			return fmt.Errorf("security exception: compose file %s does not parse", name)
		}
		for svcName, v := range svcMap {
			svc, ok := v.(map[string]any)
			if !ok {
				if v == nil {
					continue
				}
				return fmt.Errorf("security exception: compose file %s does not parse", name)
			}
			if _, ok := svc["env_file"]; ok {
				return fmt.Errorf("security exception: compose service %q uses env_file", svcName)
			}
			if ext, ok := svc["extends"].(map[string]any); ok {
				if _, ok := ext["file"]; ok {
					return fmt.Errorf("security exception: compose service %q extends a file", svcName)
				}
			}
		}
	}
	return nil
}

// composeHostPathOK reports whether a host path named by the project stays
// inside dir (a resolved real directory), symlinks resolved.
func composeHostPathOK(dir, p string) bool {
	if !filepath.IsAbs(p) {
		return false
	}
	cleaned := filepath.Clean(p)
	if !pathWithin(dir, cleaned) {
		return false
	}
	real, err := resolveExisting(cleaned)
	return err == nil && pathWithin(dir, real)
}

// The compose preflight is an allowlist: a key not listed here refuses the
// project, so a field compose adds later fails closed. Listed keys either
// cannot reach the host or carry a checked value.
//
// image (and build tags) need an allow_images grant, as for
// sys.containers.run. Top-level volumes and networks keep compose's own
// <project>_<key> name, so they cannot adopt another project's volume or a
// daemon network such as host.
//
// Service keys taken as is: command, entrypoint, environment, ports,
// expose, restart, healthcheck, labels, annotations, depends_on, working_dir,
// user, tmpfs, container_name, hostname, domainname, init, stop_signal,
// stop_grace_period, read_only, tty, stdin_open, platform, pull_policy,
// scale, profiles, attach, secrets and configs (references to the checked
// top-level definitions), the resource limits (mem_limit, mem_reservation,
// memswap_limit, mem_swappiness, cpus, cpu_shares, cpu_quota, cpu_period,
// cpuset, pids_limit, shm_size, ulimits), and dns, dns_search, dns_opt,
// extra_hosts.
//
// Service keys with a checked value: volumes (read-only bind inside the
// project dir, named volume, or tmpfs; no propagation), build (context and Dockerfile
// inside the project dir; network default or none; no privileged,
// entitlements, extra contexts, caches, secrets or ssh), networks (project
// networks; no driver_opts), network_mode (bridge or none only, so no host,
// container: or service: join), deploy (replicas, restart and update policy,
// labels, placement, and cpus/memory/pids resources; no device
// reservations), logging (json-file, local, journald or none, with size and
// tag options).
//
// Refused by omission, among others: privileged, cap_add, cap_drop,
// devices, device_cgroup_rules, security_opt, pid, ipc, uts, userns_mode,
// cgroup, cgroup_parent, runtime, gpus, volumes_from, links, external_links,
// sysctls, isolation, env_file, extends, provider, post_start, pre_stop,
// oom_kill_disable, oom_score_adj, storage_opt, credential_spec.

func keySet(keys ...string) map[string]bool {
	m := make(map[string]bool, len(keys))
	for _, k := range keys {
		m[k] = true
	}
	return m
}

var (
	composeTopKeys     = keySet("name", "services", "networks", "volumes", "secrets", "configs")
	composeServiceFree = keySet("command", "entrypoint", "environment", "ports", "expose",
		"restart", "healthcheck", "labels", "annotations", "depends_on", "working_dir", "user",
		"tmpfs", "container_name", "hostname", "domainname", "init", "stop_signal",
		"stop_grace_period", "read_only", "tty", "stdin_open", "platform", "pull_policy", "scale",
		"profiles", "attach", "secrets", "configs", "mem_limit", "mem_reservation",
		"memswap_limit", "mem_swappiness", "cpus", "cpu_shares", "cpu_quota", "cpu_period",
		"cpuset", "pids_limit", "shm_size", "ulimits", "dns", "dns_search", "dns_opt",
		"extra_hosts")
	composeMountKeys     = keySet("type", "source", "target", "read_only", "bind", "volume", "tmpfs", "consistency")
	composeBindKeys      = keySet("create_host_path", "selinux")
	composeVolOptKeys    = keySet("nocopy", "subpath")
	composeTmpfsKeys     = keySet("size", "mode")
	composeBuildKeys     = keySet("context", "dockerfile", "dockerfile_inline", "args", "target", "labels", "no_cache", "pull", "shm_size", "tags", "network")
	composeSvcNetKeys    = keySet("aliases", "ipv4_address", "ipv6_address", "link_local_ips", "priority", "gw_priority", "mac_address")
	composeDeployKeys    = keySet("replicas", "restart_policy", "update_config", "rollback_config", "labels", "placement", "mode", "endpoint_mode", "resources")
	composeResourceKeys  = keySet("limits", "reservations")
	composeLimitKeys     = keySet("cpus", "memory", "pids")
	composeLoggingKeys   = keySet("driver", "options")
	composeLogDrivers    = keySet("json-file", "local", "journald", "none")
	composeLogOptKeys    = keySet("max-size", "max-file", "compress", "tag", "labels", "env", "mode", "max-buffer-size")
	composeVolumeKeys    = keySet("name", "driver", "labels")
	composeNetworkKeys   = keySet("name", "driver", "labels", "internal", "attachable", "enable_ipv6", "enable_ipv4", "ipam")
	composeIPAMKeys      = keySet("driver", "config")
	composeSecretKeys    = keySet("name", "file", "environment", "content", "labels")
	composeNetworkModes  = keySet("bridge", "none")
	composeBuildNetworks = keySet("default", "none")
)

// extraKey returns the first key of m (sorted) that allowed does not hold.
// Top-level "x-" extension keys are allowed by the caller.
func extraKey(m map[string]any, allowed map[string]bool) (string, bool) {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if !allowed[k] {
			return k, true
		}
	}
	return "", false
}

// asMap returns v as a map; nil is an empty map. ok is false for any other
// type.
func asMap(v any) (map[string]any, bool) {
	if v == nil {
		return map[string]any{}, true
	}
	m, ok := v.(map[string]any)
	return m, ok
}

// checkKeys requires v to be a map holding only allowed keys.
func checkKeys(v any, allowed map[string]bool, what string) (map[string]any, error) {
	m, ok := asMap(v)
	if !ok {
		return nil, fmt.Errorf("unparsed %s", what)
	}
	if k, bad := extraKey(m, allowed); bad {
		return nil, fmt.Errorf("%s key %q", what, k)
	}
	return m, nil
}

func checkComposeService(dir, name string, svc map[string]any, allowImages []string) error {
	deny := func(what string) error {
		return fmt.Errorf("security exception: compose service %q uses %s", name, what)
	}
	keys := make([]string, 0, len(svc))
	for k := range svc {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		v := svc[k]
		if k == "image" {
			ref, _ := v.(string)
			if err := imageRefGranted(allowImages, ref); err != nil {
				return deny(fmt.Sprintf("image %q (%v)", ref, err))
			}
			continue
		}
		if composeServiceFree[k] {
			continue
		}
		var err error
		switch k {
		case "volumes":
			err = checkComposeMounts(dir, v)
		case "build":
			err = checkComposeBuild(dir, v, allowImages)
		case "networks":
			err = checkComposeSvcNetworks(v)
		case "network_mode":
			if s, _ := v.(string); !composeNetworkModes[s] {
				err = fmt.Errorf("network_mode %q", s)
			}
		case "deploy":
			err = checkComposeDeploy(v)
		case "logging":
			err = checkComposeLogging(v)
		default:
			err = fmt.Errorf("%s", k)
		}
		if err != nil {
			return deny(err.Error())
		}
	}
	return nil
}

func checkComposeMounts(dir string, v any) error {
	if v == nil {
		return nil
	}
	list, ok := v.([]any)
	if !ok {
		return fmt.Errorf("unparsed volumes")
	}
	for _, item := range list {
		m, err := checkKeys(item, composeMountKeys, "volume")
		if err != nil {
			if _, isMap := item.(map[string]any); !isMap {
				return fmt.Errorf("unparsed volumes")
			}
			return err
		}
		typ, _ := m["type"].(string)
		switch typ {
		case "volume":
			if _, err := checkKeys(m["volume"], composeVolOptKeys, "volume option"); err != nil {
				return err
			}
		case "tmpfs":
			if _, err := checkKeys(m["tmpfs"], composeTmpfsKeys, "tmpfs option"); err != nil {
				return err
			}
		case "bind":
			src, _ := m["source"].(string)
			if !composeHostPathOK(dir, src) {
				return fmt.Errorf("a bind mount outside the project dir")
			}
			// A writable bind would let a container rewrite the compose
			// files the next action runs.
			if ro, _ := m["read_only"].(bool); !ro {
				return fmt.Errorf("a writable bind mount (needs read_only)")
			}
			if _, err := checkKeys(m["bind"], composeBindKeys, "bind option"); err != nil {
				return err
			}
		default:
			return fmt.Errorf("volume type %q", typ)
		}
	}
	return nil
}

func checkComposeBuild(dir string, v any, allowImages []string) error {
	b, err := checkKeys(v, composeBuildKeys, "build")
	if err != nil {
		return err
	}
	ctxDir, _ := b["context"].(string)
	if !composeHostPathOK(dir, ctxDir) {
		return fmt.Errorf("a build context outside the project dir")
	}
	if df, _ := b["dockerfile"].(string); filepath.IsAbs(df) && !composeHostPathOK(dir, df) {
		return fmt.Errorf("a Dockerfile outside the project dir")
	}
	if n, ok := b["network"]; ok {
		if s, _ := n.(string); !composeBuildNetworks[s] {
			return fmt.Errorf("build network %q", s)
		}
	}
	if t, ok := b["tags"]; ok && t != nil {
		tags, ok := t.([]any)
		if !ok {
			return fmt.Errorf("unparsed build tags")
		}
		for _, tv := range tags {
			ref, _ := tv.(string)
			if err := imageRefGranted(allowImages, ref); err != nil {
				return fmt.Errorf("build tag %q (%v)", ref, err)
			}
		}
	}
	return nil
}

func checkComposeSvcNetworks(v any) error {
	switch x := v.(type) {
	case nil:
		return nil
	case []any:
		for _, n := range x {
			if _, ok := n.(string); !ok {
				return fmt.Errorf("unparsed networks")
			}
		}
		return nil
	case map[string]any:
		for _, nv := range x {
			if _, err := checkKeys(nv, composeSvcNetKeys, "network"); err != nil {
				return err
			}
		}
		return nil
	default:
		return fmt.Errorf("unparsed networks")
	}
}

func checkComposeDeploy(v any) error {
	d, err := checkKeys(v, composeDeployKeys, "deploy")
	if err != nil {
		return err
	}
	r, err := checkKeys(d["resources"], composeResourceKeys, "deploy.resources")
	if err != nil {
		return err
	}
	for _, k := range []string{"limits", "reservations"} {
		if _, err := checkKeys(r[k], composeLimitKeys, "deploy.resources."+k); err != nil {
			return err
		}
	}
	return nil
}

func checkComposeLogging(v any) error {
	l, err := checkKeys(v, composeLoggingKeys, "logging")
	if err != nil {
		return err
	}
	if d, ok := l["driver"]; ok {
		if s, _ := d.(string); !composeLogDrivers[s] {
			return fmt.Errorf("logging driver %q", s)
		}
	}
	_, err = checkKeys(l["options"], composeLogOptKeys, "logging option")
	return err
}

// composeOwnName reports whether a volume or network definition keeps the
// name compose gives it (<project>_<key>), so it cannot adopt another
// project's volume or a daemon network such as host.
func composeOwnName(project, key string, def map[string]any) bool {
	n, ok := def["name"]
	if !ok {
		return true
	}
	s, _ := n.(string)
	return project != "" && s == project+"_"+key
}

// checkComposeConfig applies the preflight allowlist to the JSON output of
// `docker compose config --format json` for the project in dir. Every
// service image and build tag needs an allow_images grant (imageGranted).
func checkComposeConfig(dir string, raw []byte, allowImages []string) error {
	var cfg map[string]any
	if err := json.Unmarshal(raw, &cfg); err != nil || cfg == nil {
		return fmt.Errorf("security exception: compose config does not parse")
	}
	refuse := func(format string, a ...any) error {
		return fmt.Errorf("security exception: compose "+format, a...)
	}
	for k := range cfg {
		if !composeTopKeys[k] && !strings.HasPrefix(k, "x-") {
			return refuse("project uses %s", k)
		}
	}
	project, _ := cfg["name"].(string)
	services, ok := asMap(cfg["services"])
	if !ok {
		return refuse("config does not parse")
	}
	for name, sv := range services {
		svc, ok := sv.(map[string]any)
		if !ok {
			return refuse("config does not parse")
		}
		if err := checkComposeService(dir, name, svc, allowImages); err != nil {
			return err
		}
	}
	vols, ok := asMap(cfg["volumes"])
	if !ok {
		return refuse("config does not parse")
	}
	for name, vv := range vols {
		vol, err := checkKeys(vv, composeVolumeKeys, "volume")
		if err != nil {
			return refuse("volume %q uses %s", name, err)
		}
		if !composeOwnName(project, name, vol) {
			return refuse("volume %q names another volume", name)
		}
		if d, ok := vol["driver"]; ok {
			if s, _ := d.(string); s != "" && s != "local" {
				return refuse("volume %q uses driver %q", name, s)
			}
		}
	}
	nets, ok := asMap(cfg["networks"])
	if !ok {
		return refuse("config does not parse")
	}
	for name, nv := range nets {
		n, err := checkKeys(nv, composeNetworkKeys, "network")
		if err != nil {
			return refuse("network %q uses %s", name, err)
		}
		if !composeOwnName(project, name, n) {
			return refuse("network %q names another network", name)
		}
		if d, ok := n["driver"]; ok {
			if s, _ := d.(string); s != "" && s != "bridge" {
				return refuse("network %q uses driver %q", name, s)
			}
		}
		ipam, err := checkKeys(n["ipam"], composeIPAMKeys, "ipam")
		if err != nil {
			return refuse("network %q uses %s", name, err)
		}
		if d, ok := ipam["driver"]; ok {
			if s, _ := d.(string); s != "" && s != "default" {
				return refuse("network %q uses ipam driver %q", name, s)
			}
		}
	}
	for _, kind := range []string{"secrets", "configs"} {
		items, ok := asMap(cfg[kind])
		if !ok {
			return refuse("config does not parse")
		}
		for name, iv := range items {
			item, err := checkKeys(iv, composeSecretKeys, kind)
			if err != nil {
				return refuse("%s %q uses %s", kind, name, err)
			}
			if f, ok := item["file"]; ok {
				s, _ := f.(string)
				if !composeHostPathOK(dir, s) {
					return refuse("%s %q reads a host file outside the project dir", kind, name)
				}
			}
		}
	}
	return nil
}

func (engine *SysscriptEngine) containersCompose(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var action, dir string
	if err := starlark.UnpackArgs("compose", args, kwargs, "action", &action, "project_dir", &dir); err != nil {
		return starlark.None, err
	}
	tail, ok := composeActions[action]
	if !ok {
		return starlark.None, fmt.Errorf("compose action not allowed")
	}
	resolved, err := engine.composeDirPolicy(dir)
	if err != nil {
		return starlark.None, err
	}
	ctx := engine.ctx
	var stdin string
	timedOut := func() error {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("docker compose: %s", jobCtxReason(ctx))
		}
		return nil
	}
	// Every action is checked first: down and ps also act on the project
	// (down starts a provider service's plugin binary), so none of them may
	// read the files unchecked.
	{
		if err := composeRawCheck(resolved); err != nil {
			return starlark.None, err
		}
		cfgArgv := []string{"docker", "compose", "--project-directory", resolved, "config", "--format", "json"}
		code, out, err := composeExec(ctx, resolved, cfgArgv, "", true)
		if terr := timedOut(); terr != nil {
			return starlark.None, terr
		}
		if err != nil {
			return starlark.None, fmt.Errorf("docker compose config: %w", err)
		}
		if code != 0 {
			return starlark.None, fmt.Errorf("docker compose config failed (exit %d)", code)
		}
		if err := checkComposeConfig(resolved, []byte(out), engine.Entitlements.AllowImages); err != nil {
			return starlark.None, err
		}
		stdin = out
	}
	// Run the exact document that was checked, from stdin, so the action
	// never re-reads files that may have changed since.
	argv := append([]string{"docker", "compose", "-f", "-", "--project-directory", resolved}, tail...)
	code, output, err := composeExec(ctx, resolved, argv, stdin, false)
	if terr := timedOut(); terr != nil {
		return starlark.None, terr
	}
	if err != nil {
		return starlark.None, fmt.Errorf("docker compose: %w", err)
	}
	d := starlark.NewDict(2)
	d.SetKey(starlark.String("exit_code"), starlark.MakeInt(code))
	d.SetKey(starlark.String("output"), starlark.String(capText(output, outputCap)))
	return d, nil
}
