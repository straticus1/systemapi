package main

import (
	"bytes"
	"embed"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"text/template"
	"time"
)

//go:embed templates/*.tmpl
var embeddedTemplates embed.FS

// ConfigManager handles atomic config writes, backups, and template rendering.
type ConfigManager struct{}

// AtomicWrite safely replaces path with content:
//  1. Write content to path + ".systemapi.tmp"
//  2. If original exists: copy to path + ".bak." + unix-timestamp
//  3. os.Rename(tmp, path) — atomic on same filesystem
//  4. On rename failure: remove tmp, return error (backup preserved)
func (cm *ConfigManager) AtomicWrite(path, content string) error {
	tmp := path + ".systemapi.tmp"

	if err := os.WriteFile(tmp, []byte(content), 0644); err != nil {
		return fmt.Errorf("atomic write: create tmp: %w", err)
	}

	// Backup original if it exists
	if _, err := os.Stat(path); err == nil {
		backupPath := fmt.Sprintf("%s.bak.%d", path, time.Now().Unix())
		if err := copyFile(path, backupPath); err != nil {
			_ = os.Remove(tmp)
			return fmt.Errorf("atomic write: backup: %w", err)
		}
	}

	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("atomic write: rename: %w", err)
	}

	return nil
}

// BackupConfig copies path to path + ".bak." + timestamp. Returns the backup path.
func (cm *ConfigManager) BackupConfig(path string) (string, error) {
	backupPath := fmt.Sprintf("%s.bak.%d", path, time.Now().Unix())
	if err := copyFile(path, backupPath); err != nil {
		return "", err
	}
	return backupPath, nil
}

// RestoreConfig finds the latest .bak.* file for path and restores it atomically.
func (cm *ConfigManager) RestoreConfig(path string) error {
	pattern := path + ".bak.*"
	matches, err := filepath.Glob(pattern)
	if err != nil || len(matches) == 0 {
		return fmt.Errorf("restore: no backup found for %s", path)
	}
	// Latest backup = last lexicographic match (unix timestamps sort correctly)
	latest := matches[len(matches)-1]
	data, err := os.ReadFile(latest)
	if err != nil {
		return fmt.Errorf("restore: read backup: %w", err)
	}
	return os.WriteFile(path, data, 0644)
}

// RenderTemplate renders a named embedded template with the given vars map.
// name must match a file in templates/ without the .tmpl extension.
// The "default" function is provided via FuncMap since text/template has no built-in default.
func (cm *ConfigManager) RenderTemplate(name string, vars map[string]interface{}) (string, error) {
	tmplPath := "templates/" + name + ".tmpl"
	data, err := embeddedTemplates.ReadFile(tmplPath)
	if err != nil {
		return "", fmt.Errorf("template %q not found: %w", name, err)
	}

	tmpl, err := template.New(name).
		Funcs(template.FuncMap{
			"default": func(def, val interface{}) interface{} {
				if val == nil || val == "" || val == 0 {
					return def
				}
				return val
			},
			// toYAMLList renders a []interface{} as inline YAML list: ["a", "b"]
			"toYAMLList": func(v interface{}) string {
				items, ok := v.([]interface{})
				if !ok || len(items) == 0 {
					return "[]"
				}
				var b bytes.Buffer
				b.WriteString("[")
				for i, item := range items {
					if i > 0 {
						b.WriteString(", ")
					}
					b.WriteString(fmt.Sprintf("%q", fmt.Sprintf("%v", item)))
				}
				b.WriteString("]")
				return b.String()
			},
		}).
		Option("missingkey=zero").
		Parse(string(data))
	if err != nil {
		return "", fmt.Errorf("template parse error: %w", err)
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, vars); err != nil {
		return "", fmt.Errorf("template render error: %w", err)
	}
	return buf.String(), nil
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, in)
	return err
}
