// Package editorsettings owns reversible JSONC proxy settings for VS Code-family
// editors. Adapters supply their store, identity, and additional managed keys.
package editorsettings

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/cquark7/withhold/internal/integration"
	"github.com/cquark7/withhold/internal/localstate"
)

// VS Code reads these application-scoped settings from the default User file
// for every local profile, regardless of how the editor was started.
var networkSettings = []string{
	"http.proxy", "http.proxySupport", "http.proxyStrictSSL", "http.noProxy",
	"http.systemCertificates", "http.fetchAdditionalSupport", "http.webSocketAdditionalSupport",
}

var managed = append(append([]string{}, networkSettings...), "settingsSync.ignoredSettings")

type Application struct {
	Options                             integration.ApplicationOptions
	SettingsDir, Binary, Label, Missing string
	Additional                          map[string]any
	WindowsExecutables                  map[string]string
}

func (a Application) Name() string       { return a.Label }
func (a Application) MissingCLI() string { return a.Missing }

func (a Application) Resolve() (integration.Target, error) {
	if !filepath.IsLocal(a.SettingsDir) {
		return integration.Target{}, errors.New("editor settings directory must be relative to the platform settings root")
	}
	home := a.Options.Home
	if home == "" {
		return integration.Target{}, errors.New("cannot resolve home directory")
	}
	root := a.Options.ConfigRoot
	if root == "" {
		root = filepath.Join(home, ".config")
	}
	switch a.Options.Platform {
	case "darwin":
		root = filepath.Join(home, "Library", "Application Support")
	case "windows":
		root = a.Options.AppData
		if root == "" {
			root = filepath.Join(home, "AppData", "Roaming")
		}
	}
	return integration.Target{Resource: filepath.Join(root, a.SettingsDir, "User", "settings.json"), Binary: a.Binary}, nil
}

func (Application) Read(target integration.Target) (integration.State, error) {
	state := integration.State{BackupPath: backupPath(target.Resource)}
	_, err := os.Stat(state.BackupPath)
	state.BackupPresent = err == nil
	data, err := readSettings(target.Resource)
	if err != nil {
		return state, err
	}
	if raw, ok := data["http.proxy"]; ok {
		_ = json.Unmarshal(raw, &state.Proxy)
	}
	return state, nil
}

func (a Application) Apply(target integration.Target, options integration.SetupOptions) error {
	return applySettings(target.Resource, options.Port, a.Additional)
}
func (a Application) Restore(target integration.Target) error {
	return restoreSettings(target.Resource, a.Additional)
}
func backupPath(path string) string { return path + ".withhold-backup" }

// Comments become whitespace so they cannot join tokens. Strings remain intact.
func ParseSettings(data []byte) (map[string]json.RawMessage, error) {
	out := bytes.Clone(data)
	quoted, escape := false, false
	for i := 0; i < len(out); i++ {
		c := out[i]
		if quoted {
			if escape {
				escape = false
			} else if c == '\\' {
				escape = true
			} else if c == '"' {
				quoted = false
			}
			continue
		}
		if c == '"' {
			quoted = true
			continue
		}
		if c == '/' && i+1 < len(out) {
			if out[i+1] == '/' {
				out[i] = ' '
				i++
				for i < len(out) && out[i] != '\n' {
					out[i] = ' '
					i++
				}
				continue
			}
			if out[i+1] == '*' {
				start := i
				out[i] = ' '
				i++
				out[i] = ' '
				found := false
				for i+1 < len(out) {
					i++
					if out[i] == '*' && i+1 < len(out) && out[i+1] == '/' {
						out[i] = ' '
						i++
						out[i] = ' '
						found = true
						break
					}
					if out[i] != '\n' && out[i] != '\r' {
						out[i] = ' '
					}
				}
				if !found {
					return nil, fmt.Errorf("unterminated settings comment at %d", start)
				}
			}
		}
	}
	quoted, escape = false, false
	for i, c := range out {
		if quoted {
			if escape {
				escape = false
			} else if c == '\\' {
				escape = true
			} else if c == '"' {
				quoted = false
			}
			continue
		}
		if c == '"' {
			quoted = true
		}
		if c == ',' {
			j := i + 1
			for j < len(out) && strings.ContainsRune(" \t\r\n", rune(out[j])) {
				j++
			}
			if j < len(out) && (out[j] == '}' || out[j] == ']') {
				out[i] = ' '
			}
		}
	}
	var result map[string]json.RawMessage
	if json.Unmarshal(out, &result) != nil || result == nil {
		return nil, errors.New("settings must be a valid JSONC object")
	}
	return result, nil
}
func readSettings(path string) (map[string]json.RawMessage, error) {
	if err := localstate.Regular(path); err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return map[string]json.RawMessage{}, nil
	}
	if err != nil {
		return nil, err
	}
	return ParseSettings(data)
}
func saveSettings(path string, data map[string]json.RawMessage) error {
	out, err := json.MarshalIndent(data, "", "    ")
	if err != nil {
		return err
	}
	return localstate.Write(path, append(out, '\n'), false)
}
func set(data map[string]json.RawMessage, key string, value any) { data[key], _ = json.Marshal(value) }
func addStrings(raw json.RawMessage, extra ...string) []any {
	var list []any
	_ = json.Unmarshal(raw, &list)
	for _, s := range extra {
		found := false
		for _, v := range list {
			if v == s {
				found = true
				break
			}
		}
		if !found {
			list = append(list, s)
		}
	}
	return list
}
func ApplySettings(path string, port int) error {
	return applySettings(path, port, nil)
}

func applySettings(path string, port int, additional map[string]any) error {
	if port < 1 || port > 65535 {
		return errors.New("invalid proxy port")
	}
	current, err := readSettings(path)
	if err != nil {
		return err
	}
	backup := backupPath(path)
	if _, err = os.Lstat(backup); os.IsNotExist(err) {
		data, e := os.ReadFile(path)
		if os.IsNotExist(e) {
			data = []byte("{}\n")
		} else if e != nil {
			return e
		}
		if err = localstate.Write(backup, data, true); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	if _, err = readSettings(backup); err != nil {
		return fmt.Errorf("cannot use settings backup: %w", err)
	}
	set(current, "http.proxy", "http://127.0.0.1:"+strconv.Itoa(port))
	set(current, "http.proxySupport", "override")
	set(current, "http.proxyStrictSSL", true)
	// Existing wildcards or provider exclusions must not bypass the guard. The
	// original list is restored by off along with the other managed settings.
	set(current, "http.noProxy", []string{"localhost", "127.0.0.1", "::1"})
	set(current, "http.systemCertificates", true)
	set(current, "http.fetchAdditionalSupport", true)
	set(current, "http.webSocketAdditionalSupport", true)
	keys := append([]string{}, networkSettings...)
	var extra []string
	for key, value := range additional {
		set(current, key, value)
		extra = append(extra, key)
	}
	slices.Sort(extra)
	keys = append(keys, extra...)
	set(current, "settingsSync.ignoredSettings", addStrings(current["settingsSync.ignoredSettings"], keys...))
	return saveSettings(path, current)
}

// A successfully restored backup is consumed so the next session captures fresh values.
func RestoreSettings(path string) error {
	return restoreSettings(path, nil)
}

func restoreSettings(path string, additional map[string]any) error {
	backup := backupPath(path)
	if _, err := os.Lstat(backup); os.IsNotExist(err) {
		return nil
	} else if err != nil {
		return err
	}
	previous, err := readSettings(backup)
	if err != nil {
		return err
	}
	current, err := readSettings(path)
	if err != nil {
		return err
	}
	if _, e := os.Stat(path); os.IsNotExist(e) {
		current = previous
	} else {
		for _, key := range managed {
			if value, ok := previous[key]; ok {
				current[key] = value
			} else {
				delete(current, key)
			}
		}
		for key := range additional {
			if value, ok := previous[key]; ok {
				current[key] = value
			} else {
				delete(current, key)
			}
		}
	}
	if len(current) == 0 {
		if err = os.Remove(path); err != nil && !os.IsNotExist(err) {
			return err
		}
	} else if err = saveSettings(path, current); err != nil {
		return err
	}
	return os.Remove(backup)
}
