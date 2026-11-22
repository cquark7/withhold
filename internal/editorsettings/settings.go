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

	"github.com/cquark7/withhold/internal/integration"
	"github.com/cquark7/withhold/internal/localstate"
)

// VS Code reads these application-scoped settings from the default User file
// for every local profile, regardless of how the editor was started.
var networkSettings = []string{
	"http.proxy", "http.proxySupport", "http.proxyStrictSSL", "http.noProxy",
	"http.systemCertificates", "http.fetchAdditionalSupport", "http.webSocketAdditionalSupport",
}

const syncExclusions = "settingsSync.ignoredSettings"

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

// Comments become whitespace so existing byte offsets remain valid.
func maskComments(data []byte) ([]byte, error) {
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
	return out, nil
}

func stripTrailingCommas(out []byte) {
	quoted, escape := false, false
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
			before, after := bytes.TrimRight(out[:i], " \t\r\n"), bytes.TrimLeft(out[i+1:], " \t\r\n")
			if len(before) > 0 && before[len(before)-1] != '{' && before[len(before)-1] != '[' &&
				len(after) > 0 && (after[0] == '}' || after[0] == ']') {
				out[i] = ' '
			}
		}
	}
}

func ParseSettings(data []byte) (map[string]json.RawMessage, error) {
	out, err := maskComments(data)
	if err != nil {
		return nil, err
	}
	stripTrailingCommas(out)
	var result map[string]json.RawMessage
	if json.Unmarshal(out, &result) != nil || result == nil {
		return nil, errors.New("settings must be a valid JSONC object")
	}
	return result, nil
}

func readSettingsFile(path string) ([]byte, error) {
	if err := localstate.Regular(path); err != nil {
		return nil, err
	}
	return os.ReadFile(path)
}

func readSettings(path string) (map[string]json.RawMessage, error) {
	data, err := readSettingsFile(path)
	if os.IsNotExist(err) {
		return map[string]json.RawMessage{}, nil
	}
	if err != nil {
		return nil, err
	}
	return ParseSettings(data)
}

func ApplySettings(path string, port int) error {
	return applySettings(path, port, nil)
}

func applySettings(path string, port int, additional map[string]any) error {
	if port < 1 || port > 65535 {
		return errors.New("invalid proxy port")
	}
	data, err := readSettingsFile(path)
	if os.IsNotExist(err) {
		data = []byte("{}\n")
	} else if err != nil {
		return err
	}
	current, err := parseContainer(data, '{')
	if err != nil {
		return err
	}
	backup := backupPath(path)
	if _, err = os.Lstat(backup); os.IsNotExist(err) {
		if err = localstate.Write(backup, data, true); err != nil {
			return err
		}
	} else if err != nil {
		return err
	} else if _, err = readSettings(backup); err != nil {
		return fmt.Errorf("cannot use settings backup: %w", err)
	}
	settings := map[string]any{
		"http.proxy":        "http://127.0.0.1:" + strconv.Itoa(port),
		"http.proxySupport": "override", "http.proxyStrictSSL": true,
		// Override existing wildcards and provider exclusions while guarding traffic.
		"http.noProxy":            []string{"localhost", "127.0.0.1", "::1"},
		"http.systemCertificates": true, "http.fetchAdditionalSupport": true,
		"http.webSocketAdditionalSupport": true,
	}
	for key, value := range additional {
		settings[key] = value
	}
	changes := make(map[string][]byte, len(settings)+1)
	for key, value := range settings {
		encoded, err := json.Marshal(value)
		if err != nil {
			return err
		}
		changes[key] = encoded
	}
	list := syncList(current.value(syncExclusions))
	present := list.strings()
	var added [][]byte
	for _, key := range managedKeys(additional) {
		if !present[key] {
			added = append(added, strconv.AppendQuote(nil, key))
		}
	}
	changes[syncExclusions] = list.edit(nil, added, "        ")
	return writeSettings(path, current.update(changes))
}

func writeSettings(path string, data []byte) error {
	if _, err := ParseSettings(data); err != nil {
		return err
	}
	return localstate.Write(path, data, false)
}

func managedKeys(additional map[string]any) []string {
	keys := slices.Clone(networkSettings)
	for key := range additional {
		keys = append(keys, key)
	}
	slices.Sort(keys[len(networkSettings):])
	return keys
}

// A successfully restored backup is consumed so the next session captures fresh values.
func RestoreSettings(path string) error {
	return restoreSettings(path, nil)
}

func restoreSettings(path string, additional map[string]any) error {
	backup := backupPath(path)
	original, err := readSettingsFile(backup)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	previous, err := parseContainer(original, '{')
	if err != nil {
		return err
	}
	data, err := readSettingsFile(path)
	output := original
	if err == nil {
		current, err := parseContainer(data, '{')
		if err != nil {
			return err
		}
		keys := managedKeys(additional)
		changes := make(map[string][]byte, len(keys)+1)
		for _, key := range keys {
			changes[key] = previous.value(key)
		}
		oldSync := previous.value(syncExclusions)
		if list, err := parseContainer(current.value(syncExclusions), '['); err == nil {
			prior := syncList(oldSync)
			present := prior.strings()
			remove := make(map[int][]byte)
			for i, entry := range list.entries {
				value := list.string(entry)
				if slices.Contains(keys, value) && !present[value] {
					remove[i] = nil
				}
			}
			if len(remove) > 0 {
				if len(remove) == len(list.entries) && len(prior.entries) == 0 && bytes.Equal(list.data, list.masked) {
					changes[syncExclusions] = oldSync
				} else {
					changes[syncExclusions] = list.edit(remove, nil, "")
				}
			}
		}
		output = current.update(changes)
	} else if !os.IsNotExist(err) {
		return err
	}
	if len(bytes.TrimSpace(bytes.Trim(bytes.TrimSpace(output), "{}"))) == 0 {
		if err = os.Remove(path); err != nil && !os.IsNotExist(err) {
			return err
		}
	} else if err = writeSettings(path, output); err != nil {
		return err
	}
	return os.Remove(backup)
}
