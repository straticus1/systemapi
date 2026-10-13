package main

import (
	"fmt"
	"strings"
)

// parseOSRelease keeps keys that match [A-Z0-9_]+ and strips one pair of quotes.
func parseOSRelease(data string) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(data, "\n") {
		line = strings.TrimSpace(strings.TrimRight(line, "\r"))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, val, ok := strings.Cut(line, "=")
		if !ok || !osReleaseKeyRE.MatchString(key) {
			continue
		}
		val = strings.TrimSpace(val)
		if len(val) >= 2 {
			if (val[0] == '"' && val[len(val)-1] == '"') || (val[0] == '\'' && val[len(val)-1] == '\'') {
				val = val[1 : len(val)-1]
			}
		}
		if strings.ContainsRune(val, 0) {
			continue
		}
		out[key] = val
	}
	return out
}

// parsePasswd returns name, uid, gid, home, and shell. The password field is dropped.
func parsePasswd(data string) ([]map[string]string, error) {
	var out []map[string]string
	for _, line := range strings.Split(data, "\n") {
		line = strings.TrimRight(line, "\r")
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Split(line, ":")
		if len(parts) < 7 {
			continue
		}
		if parts[0] == "" || strings.ContainsAny(parts[0], "\x00\n\r") {
			continue
		}
		out = append(out, map[string]string{
			"name":  parts[0],
			"uid":   parts[2],
			"gid":   parts[3],
			"home":  parts[5],
			"shell": parts[6],
		})
		if len(out) > rowCap {
			return nil, fmt.Errorf("too many rows")
		}
	}
	return out, nil
}

// parseGroup returns name, gid, and members. The password field is dropped.
func parseGroup(data string) ([]map[string]string, error) {
	var out []map[string]string
	for _, line := range strings.Split(data, "\n") {
		line = strings.TrimRight(line, "\r")
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Split(line, ":")
		if len(parts) < 3 {
			continue
		}
		members := ""
		if len(parts) >= 4 {
			members = parts[3]
		}
		if parts[0] == "" || strings.ContainsAny(parts[0], "\x00\n\r") {
			continue
		}
		out = append(out, map[string]string{
			"name":    parts[0],
			"gid":     parts[2],
			"members": members,
		})
		if len(out) > rowCap {
			return nil, fmt.Errorf("too many rows")
		}
	}
	return out, nil
}

func parseMounts(data string) ([]map[string]string, error) {
	var out []map[string]string
	for _, line := range strings.Split(data, "\n") {
		line = strings.TrimRight(line, "\r")
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		out = append(out, map[string]string{
			"source":  unescapeProc(fields[0]),
			"target":  unescapeProc(fields[1]),
			"fstype":  unescapeProc(fields[2]),
			"options": unescapeProc(fields[3]),
		})
		if len(out) > rowCap {
			return nil, fmt.Errorf("too many rows")
		}
	}
	return out, nil
}

// unescapeProc decodes procfs octal escapes such as \040 for space.
func unescapeProc(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) && isOctal(s[i+1]) && isOctal(s[i+2]) && isOctal(s[i+3]) {
			v := (s[i+1]-'0')*64 + (s[i+2]-'0')*8 + (s[i+3]-'0')
			b.WriteByte(v)
			i += 3
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func isOctal(c byte) bool {
	return c >= '0' && c <= '7'
}
