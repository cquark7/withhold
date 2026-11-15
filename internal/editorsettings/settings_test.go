package editorsettings

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/cquark7/withhold/internal/integration"
)

func exists(path string) bool { _, err := os.Stat(path); return err == nil }

func TestMergeRestoreAndFreshBackup(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.json")
	before := []byte(`{// keep URL syntax inside strings
 "http.proxy":"http://old", "http.noProxy":["company"], "untouched":"https://example/a//b", "number":12345678901234567890,
}`)
	if err := os.WriteFile(path, before, 0600); err != nil {
		t.Fatal(err)
	}
	if err := ApplySettings(path, 12345); err != nil {
		t.Fatal(err)
	}
	data, _ := readSettings(path)
	data["mid-session"] = json.RawMessage(`true`)
	if err := saveSettings(path, data); err != nil {
		t.Fatal(err)
	}
	if err := RestoreSettings(path); err != nil {
		t.Fatal(err)
	}
	data, _ = readSettings(path)
	if string(data["http.proxy"]) != `"http://old"` || string(data["mid-session"]) != "true" || string(data["number"]) != "12345678901234567890" {
		t.Fatalf("restore lost values: %v", data)
	}
	if exists(backupPath(path)) {
		t.Fatal("successful restore must consume backup")
	}
	data["http.proxy"] = json.RawMessage(`"http://new"`)
	_ = saveSettings(path, data)
	if err := ApplySettings(path, 12346); err != nil {
		t.Fatal(err)
	}
	if err := RestoreSettings(path); err != nil {
		t.Fatal(err)
	}
	data, _ = readSettings(path)
	if string(data["http.proxy"]) != `"http://new"` {
		t.Fatal("new session reused stale backup")
	}
}

func TestApplicationNetworkSettingsEnableOrdinaryLaunchesAndRestore(t *testing.T) {
	for _, exclusions := range []string{`["*"]`, `["*.githubcopilot.com","company"]`} {
		t.Run(exclusions, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "User", "settings.json")
			before, err := ParseSettings([]byte(`{
				"http.proxy": "http://old", "http.proxySupport": "off",
				"http.proxyStrictSSL": false, "http.noProxy": ` + exclusions + `,
				"http.systemCertificates": false, "http.fetchAdditionalSupport": false,
				"http.webSocketAdditionalSupport": false,
				"settingsSync.ignoredSettings": ["custom"], "keep": true
			}`))
			if err != nil {
				t.Fatal(err)
			}
			if err := saveSettings(path, before); err != nil {
				t.Fatal(err)
			}
			before, err = readSettings(path)
			if err != nil {
				t.Fatal(err)
			}
			for range 2 {
				if err := ApplySettings(path, 12345); err != nil {
					t.Fatal(err)
				}
			}
			current, err := readSettings(path)
			if err != nil {
				t.Fatal(err)
			}
			for key, want := range map[string]string{
				"http.proxy": `"http://127.0.0.1:12345"`, "http.proxySupport": `"override"`,
				"http.proxyStrictSSL": "true", "http.noProxy": `["localhost","127.0.0.1","::1"]`,
				"http.systemCertificates": "true", "http.fetchAdditionalSupport": "true",
				"http.webSocketAdditionalSupport": "true",
			} {
				var compact bytes.Buffer
				if err := json.Compact(&compact, current[key]); err != nil {
					t.Fatal(err)
				}
				if compact.String() != want {
					t.Errorf("%s = %s, want %s", key, current[key], want)
				}
			}
			var ignored []string
			if err := json.Unmarshal(current["settingsSync.ignoredSettings"], &ignored); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(ignored, append([]string{"custom"}, networkSettings...)) {
				t.Fatalf("network settings are not excluded from sync: %v", ignored)
			}
			current["mid-session"] = json.RawMessage(`true`)
			if err := saveSettings(path, current); err != nil {
				t.Fatal(err)
			}
			if err := RestoreSettings(path); err != nil {
				t.Fatal(err)
			}
			current, err = readSettings(path)
			if err != nil {
				t.Fatal(err)
			}
			before["mid-session"] = json.RawMessage(`true`)
			if !reflect.DeepEqual(current, before) {
				t.Fatalf("settings were not restored: %v", current)
			}
		})
	}
}

func TestApplyUsesSharedApplicationSettingsWithoutEditingProfilesOrProjects(t *testing.T) {
	home := t.TempDir()
	a := Application{Options: integration.ApplicationOptions{Home: home, Platform: "linux"}, SettingsDir: "Code"}
	target, err := a.Resolve()
	if err != nil {
		t.Fatal(err)
	}
	// Local profiles inherit APPLICATION-scoped HTTP keys from User/settings.json;
	// profile and workspace files must not be patched or enumerated by withhold.
	paths := []string{
		filepath.Join(filepath.Dir(target.Resource), "profiles", "existing", "settings.json"),
		filepath.Join(home, "project", ".vscode", "settings.json"),
	}
	const content = `{"http.proxy":"http://other", "keep":true}`
	for _, path := range paths {
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := a.Apply(target, integration.SetupOptions{Port: 12345}); err != nil {
		t.Fatal(err)
	}
	for _, path := range paths {
		got, err := os.ReadFile(path)
		if err != nil || string(got) != content || exists(backupPath(path)) {
			t.Fatalf("modified a profile or workspace: %s: %s, %v", path, got, err)
		}
	}
	if err := a.Restore(target); err != nil {
		t.Fatal(err)
	}
}
func TestMalformedSettingsNeverOverwriteBackupOrCurrent(t *testing.T) {
	for _, bad := range []string{`{"a":1/* unterminated`, `[]`, `{"a": 1 2}`, `null`} {
		path := filepath.Join(t.TempDir(), "settings.json")
		_ = os.WriteFile(path, []byte(bad), 0600)
		if ApplySettings(path, 12345) == nil {
			t.Fatal("malformed settings accepted")
		}
		got, _ := os.ReadFile(path)
		if string(got) != bad || exists(backupPath(path)) {
			t.Fatal("malformed settings modified")
		}
	}
	path := filepath.Join(t.TempDir(), "settings.json")
	_ = os.WriteFile(path, []byte(`{"safe":true}`), 0600)
	_ = os.WriteFile(backupPath(path), []byte(`[]`), 0600)
	if RestoreSettings(path) == nil {
		t.Fatal("invalid backup accepted")
	}
	got, _ := os.ReadFile(path)
	if string(got) != `{"safe":true}` {
		t.Fatal("current settings changed")
	}
}
func TestMissingSettingsAndNoBackupAreSafe(t *testing.T) {
	path := filepath.Join(t.TempDir(), "settings.json")
	if err := RestoreSettings(path); err != nil {
		t.Fatal(err)
	}
	if err := ApplySettings(path, 12345); err != nil {
		t.Fatal(err)
	}
	if err := RestoreSettings(path); err != nil {
		t.Fatal(err)
	}
	data, err := readSettings(path)
	if err != nil || len(data) != 0 {
		t.Fatal("managed keys left behind")
	}
	if exists(path) {
		t.Fatal("empty original settings file should be removed")
	}
}
