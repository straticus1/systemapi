package main

// Pure Starlark helpers: sys.json, sys.yaml and sys.ini. They read nothing
// but their arguments and touch no host state, so the converge declaration
// (converge.go) predeclares them as json, yaml and ini. Moved here from
// sys_extras.go and sys_config.go unchanged except that they are plain
// functions rather than engine methods.

import (
	"encoding/json"
	"fmt"
	"strings"

	"go.starlark.net/starlark"
	"gopkg.in/yaml.v3"
)

// =============================================================================
// sys.json
// =============================================================================

// sys.json.parse(content) - JSON string -> Starlark dict/list tree
func jsonParse(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var content string
	if err := starlark.UnpackArgs("parse", args, kwargs, "content", &content); err != nil {
		return starlark.None, err
	}
	var raw interface{}
	if err := json.Unmarshal([]byte(content), &raw); err != nil {
		return starlark.None, fmt.Errorf("json.parse: %w", err)
	}
	return goToStarlark(raw)
}

// sys.json.encode(value) - Starlark dict/list -> JSON string
func jsonEncode(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	if err := starlark.UnpackArgs("encode", args, kwargs, "value", &value); err != nil {
		return starlark.None, err
	}
	out, err := json.Marshal(starlarkToGo(value))
	if err != nil {
		return starlark.None, fmt.Errorf("json.encode: %w", err)
	}
	return starlark.String(string(out)), nil
}

// sys.json.encode_pretty(value) - indented JSON
func jsonEncodePretty(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	if err := starlark.UnpackArgs("encode_pretty", args, kwargs, "value", &value); err != nil {
		return starlark.None, err
	}
	out, err := json.MarshalIndent(starlarkToGo(value), "", "  ")
	if err != nil {
		return starlark.None, fmt.Errorf("json.encode_pretty: %w", err)
	}
	return starlark.String(string(out)), nil
}

// =============================================================================
// sys.ini  (key=value + [sections], covers postfix main.cf, most /etc configs)
// =============================================================================

// sys.ini.parse(content) - returns dict of dicts: {"": {global keys}, "section": {keys}}
// Lines starting with # or ; are comments. Keys without a section go into "".
func iniParse(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var content string
	if err := starlark.UnpackArgs("parse", args, kwargs, "content", &content); err != nil {
		return starlark.None, err
	}

	result := starlark.NewDict(4)
	currentSection := ""
	sectionDict := starlark.NewDict(8)
	result.SetKey(starlark.String(""), sectionDict)

	for _, rawLine := range strings.Split(content, "\n") {
		line := strings.TrimSpace(rawLine)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			currentSection = line[1 : len(line)-1]
			if _, found, _ := result.Get(starlark.String(currentSection)); !found {
				sectionDict = starlark.NewDict(8)
				result.SetKey(starlark.String(currentSection), sectionDict)
			} else {
				existing, _, _ := result.Get(starlark.String(currentSection))
				sectionDict = existing.(*starlark.Dict)
			}
			_ = currentSection
			continue
		}
		// key = value  or  key: value
		sep := strings.IndexAny(line, "=:")
		if sep < 0 {
			continue
		}
		k := strings.TrimSpace(line[:sep])
		v := strings.TrimSpace(line[sep+1:])
		// strip inline comments
		if idx := strings.Index(v, " #"); idx >= 0 {
			v = strings.TrimSpace(v[:idx])
		}
		sectionDict.SetKey(starlark.String(k), starlark.String(v))
	}

	return result, nil
}

// sys.ini.encode(data) - dict of dicts -> INI string
func iniEncode(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var value starlark.Value
	if err := starlark.UnpackArgs("encode", args, kwargs, "value", &value); err != nil {
		return starlark.None, err
	}
	d, ok := value.(*starlark.Dict)
	if !ok {
		return starlark.None, fmt.Errorf("ini.encode: expected dict, got %s", value.Type())
	}

	var sb strings.Builder
	// global section first
	if global, found, _ := d.Get(starlark.String("")); found {
		if gd, ok := global.(*starlark.Dict); ok {
			for _, kv := range gd.Items() {
				sb.WriteString(fmt.Sprintf("%s = %s\n", kv[0], kv[1]))
			}
		}
	}
	for _, kv := range d.Items() {
		section := kv[0].(starlark.String).GoString()
		if section == "" {
			continue
		}
		sb.WriteString(fmt.Sprintf("\n[%s]\n", section))
		if sd, ok := kv[1].(*starlark.Dict); ok {
			for _, skv := range sd.Items() {
				sb.WriteString(fmt.Sprintf("%s = %s\n", skv[0], skv[1]))
			}
		}
	}
	return starlark.String(sb.String()), nil
}

// sys.ini.get(data, key, section="") - convenience getter with default
func iniGet(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var data starlark.Value
	var key, section, def string
	if err := starlark.UnpackArgs("get", args, kwargs, "data", &data, "key", &key, "section?", &section, "default?", &def); err != nil {
		return starlark.None, err
	}
	d, ok := data.(*starlark.Dict)
	if !ok {
		return starlark.String(def), nil
	}
	sectionVal, found, _ := d.Get(starlark.String(section))
	if !found {
		return starlark.String(def), nil
	}
	sd, ok := sectionVal.(*starlark.Dict)
	if !ok {
		return starlark.String(def), nil
	}
	val, found, _ := sd.Get(starlark.String(key))
	if !found {
		return starlark.String(def), nil
	}
	return val, nil
}

// --- sys.yaml.parse(content) ---

func yamlParse(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var content string
	if err := starlark.UnpackArgs("parse", args, kwargs, "content", &content); err != nil {
		return starlark.None, err
	}

	var raw interface{}
	if err := yaml.Unmarshal([]byte(content), &raw); err != nil {
		return starlark.None, fmt.Errorf("yaml parse error: %w", err)
	}
	return goToStarlark(raw)
}

// --- sys.yaml.encode(value) ---

func yamlEncode(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
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
