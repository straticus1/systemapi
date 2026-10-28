package main

import (
	"fmt"
	"time"

	"go.starlark.net/starlark"
	"gopkg.in/yaml.v3"
)

// --- sys.config.write(path, content) ---

func (engine *SysscriptEngine) configWrite(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var path, content string
	if err := starlark.UnpackArgs("write", args, kwargs, "path", &path, "content", &content); err != nil {
		return starlark.None, err
	}

	resolved, err := fsGrantPath(engine.Entitlements.AllowConfigWrite, path, "config write", true)
	if err != nil {
		result := starlark.NewDict(2)
		result.SetKey(starlark.String("success"), starlark.False)
		result.SetKey(starlark.String("error"), starlark.String(fmt.Sprintf("security exception: config write to %s not granted", path)))
		return result, nil
	}

	err = currentPlatform().Config.AtomicWrite(resolved, content)
	result := starlark.NewDict(2)
	if err != nil {
		result.SetKey(starlark.String("success"), starlark.False)
		result.SetKey(starlark.String("error"), starlark.String(err.Error()))
	} else {
		result.SetKey(starlark.String("success"), starlark.True)
		result.SetKey(starlark.String("error"), starlark.String(""))
	}
	return result, nil
}

// --- sys.config.template(name, vars) ---

func (engine *SysscriptEngine) configTemplate(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var name string
	var varsVal starlark.Value
	if err := starlark.UnpackArgs("template", args, kwargs, "name", &name, "vars", &varsVal); err != nil {
		return starlark.None, err
	}

	// Convert Starlark dict to Go map
	goVars := make(map[string]interface{})
	if d, ok := varsVal.(*starlark.Dict); ok {
		for _, kv := range d.Items() {
			key, ok := kv[0].(starlark.String)
			if !ok {
				continue
			}
			goVars[string(key)] = starlarkToGo(kv[1])
		}
	}

	// Add generated_at if not already present
	if _, exists := goVars["generated_at"]; !exists {
		goVars["generated_at"] = time.Now().UTC().Format(time.RFC3339)
	}

	rendered, err := engine.cm.RenderTemplate(name, goVars)
	if err != nil {
		return starlark.None, err
	}
	return starlark.String(rendered), nil
}

// --- sys.config.validate(path, service) ---

func (engine *SysscriptEngine) configValidate(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var path, service string
	if err := starlark.UnpackArgs("validate", args, kwargs, "path", &path, "service", &service); err != nil {
		return starlark.None, err
	}

	// The checkers run as root and echo the file back in their errors, so the
	// path needs the same grant as sys.config.write (AllowConfigWrite), and
	// only the resolved absolute path reaches argv.
	resolved, err := fsGrantPath(engine.Entitlements.AllowConfigWrite, path, "config validate", true)
	if err != nil {
		result := starlark.NewDict(3)
		result.SetKey(starlark.String("success"), starlark.False)
		result.SetKey(starlark.String("output"), starlark.String(""))
		result.SetKey(starlark.String("error"), starlark.String(err.Error()))
		return result, nil
	}

	out, err := currentPlatform().Config.Validate(engine.ctx, service, resolved)
	result := starlark.NewDict(3)
	if err != nil {
		result.SetKey(starlark.String("success"), starlark.False)
		result.SetKey(starlark.String("output"), starlark.String(out))
		result.SetKey(starlark.String("error"), starlark.String(err.Error()))
	} else {
		result.SetKey(starlark.String("success"), starlark.True)
		result.SetKey(starlark.String("output"), starlark.String(out))
		result.SetKey(starlark.String("error"), starlark.String(""))
	}
	return result, nil
}

// --- sys.config.reload(service) ---

func (engine *SysscriptEngine) configReload(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var service string
	if err := starlark.UnpackArgs("reload", args, kwargs, "service", &service); err != nil {
		return starlark.None, err
	}

	allowed := false
	for _, s := range engine.Entitlements.AllowServiceReload {
		if s == "*" || s == service {
			allowed = true
			break
		}
	}
	if !allowed {
		result := starlark.NewDict(3)
		result.SetKey(starlark.String("success"), starlark.False)
		result.SetKey(starlark.String("output"), starlark.String(""))
		result.SetKey(starlark.String("error"), starlark.String(fmt.Sprintf("security exception: reload of %s not granted", service)))
		return result, nil
	}

	out, err := currentPlatform().Config.Reload(engine.ctx, service)
	result := starlark.NewDict(3)
	if err != nil {
		result.SetKey(starlark.String("success"), starlark.False)
		result.SetKey(starlark.String("output"), starlark.String(out))
		result.SetKey(starlark.String("error"), starlark.String(err.Error()))
	} else {
		result.SetKey(starlark.String("success"), starlark.True)
		result.SetKey(starlark.String("output"), starlark.String(out))
		result.SetKey(starlark.String("error"), starlark.String(""))
	}
	return result, nil
}

// --- sys.config.backup(path) ---

func (engine *SysscriptEngine) configBackup(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var path string
	if err := starlark.UnpackArgs("backup", args, kwargs, "path", &path); err != nil {
		return starlark.None, err
	}

	resolved, err := fsGrantPath(engine.Entitlements.AllowFSRead, path, "read", true)
	if err != nil {
		result := starlark.NewDict(3)
		result.SetKey(starlark.String("success"), starlark.False)
		result.SetKey(starlark.String("backup_path"), starlark.String(""))
		result.SetKey(starlark.String("error"), starlark.String(fmt.Sprintf("security exception: read of %s not granted", path)))
		return result, nil
	}

	backupPath, err := engine.cm.BackupConfig(resolved)
	result := starlark.NewDict(3)
	if err != nil {
		result.SetKey(starlark.String("success"), starlark.False)
		result.SetKey(starlark.String("backup_path"), starlark.String(""))
		result.SetKey(starlark.String("error"), starlark.String(err.Error()))
	} else {
		result.SetKey(starlark.String("success"), starlark.True)
		result.SetKey(starlark.String("backup_path"), starlark.String(backupPath))
		result.SetKey(starlark.String("error"), starlark.String(""))
	}
	return result, nil
}

// --- sys.config.restore(path) ---

func (engine *SysscriptEngine) configRestore(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var path string
	if err := starlark.UnpackArgs("restore", args, kwargs, "path", &path); err != nil {
		return starlark.None, err
	}

	// Check AllowFSWrite or AllowConfigWrite
	resolved, err := fsGrantPath(engine.Entitlements.AllowFSWrite, path, "write", true)
	if err != nil {
		resolved, err = fsGrantPath(engine.Entitlements.AllowConfigWrite, path, "write", true)
	}
	if err != nil {
		result := starlark.NewDict(2)
		result.SetKey(starlark.String("success"), starlark.False)
		result.SetKey(starlark.String("error"), starlark.String(fmt.Sprintf("security exception: write to %s not granted", path)))
		return result, nil
	}

	err = engine.cm.RestoreConfig(resolved)
	result := starlark.NewDict(2)
	if err != nil {
		result.SetKey(starlark.String("success"), starlark.False)
		result.SetKey(starlark.String("error"), starlark.String(err.Error()))
	} else {
		result.SetKey(starlark.String("success"), starlark.True)
		result.SetKey(starlark.String("error"), starlark.String(""))
	}
	return result, nil
}

// --- sys.yaml.parse(content) ---

func (engine *SysscriptEngine) yamlParse(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var content string
	if err := starlark.UnpackArgs("parse", args, kwargs, "content", &content); err != nil {
		return starlark.None, err
	}

	var raw interface{}
	if err := yaml.Unmarshal([]byte(content), &raw); err != nil {
		return starlark.None, fmt.Errorf("yaml parse error: %w", err)
	}
	return goToStarlark(raw), nil
}

// --- sys.yaml.encode(value) ---

func (engine *SysscriptEngine) yamlEncode(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var val starlark.Value
	if err := starlark.UnpackArgs("encode", args, kwargs, "value", &val); err != nil {
		return starlark.None, err
	}

	goVal := starlarkToGo(val)
	out, err := yaml.Marshal(goVal)
	if err != nil {
		return starlark.None, fmt.Errorf("yaml encode error: %w", err)
	}
	return starlark.String(string(out)), nil
}

// --- Conversion helpers ---

// starlarkToGo converts a Starlark value to a native Go value.
func starlarkToGo(v starlark.Value) interface{} {
	switch val := v.(type) {
	case starlark.NoneType:
		return nil
	case starlark.Bool:
		return bool(val)
	case starlark.Int:
		i, _ := val.Int64()
		return i
	case starlark.Float:
		return float64(val)
	case starlark.String:
		return string(val)
	case *starlark.List:
		result := make([]interface{}, val.Len())
		for i := 0; i < val.Len(); i++ {
			result[i] = starlarkToGo(val.Index(i))
		}
		return result
	case *starlark.Dict:
		result := make(map[string]interface{})
		for _, kv := range val.Items() {
			key, ok := kv[0].(starlark.String)
			if !ok {
				// Non-string keys: convert via String()
				result[kv[0].String()] = starlarkToGo(kv[1])
				continue
			}
			result[string(key)] = starlarkToGo(kv[1])
		}
		return result
	default:
		return v.String()
	}
}

// goToStarlark converts a native Go value (as produced by yaml.v3 Unmarshal) to a Starlark value.
func goToStarlark(v interface{}) starlark.Value {
	if v == nil {
		return starlark.None
	}
	switch val := v.(type) {
	case bool:
		return starlark.Bool(val)
	case int:
		return starlark.MakeInt(val)
	case int64:
		return starlark.MakeInt64(val)
	case float64:
		return starlark.Float(val)
	case string:
		return starlark.String(val)
	case []interface{}:
		elems := make([]starlark.Value, len(val))
		for i, item := range val {
			elems[i] = goToStarlark(item)
		}
		return starlark.NewList(elems)
	case map[string]interface{}:
		d := starlark.NewDict(len(val))
		for k, item := range val {
			d.SetKey(starlark.String(k), goToStarlark(item))
		}
		return d
	case map[interface{}]interface{}:
		// yaml.v3 can produce this for non-string-keyed maps
		d := starlark.NewDict(len(val))
		for k, item := range val {
			keyStr := fmt.Sprintf("%v", k)
			d.SetKey(starlark.String(keyStr), goToStarlark(item))
		}
		return d
	default:
		return starlark.String(fmt.Sprintf("%v", val))
	}
}
