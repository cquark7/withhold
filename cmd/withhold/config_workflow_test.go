package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/cquark7/withhold/internal/config"
	"github.com/cquark7/withhold/internal/integrations"
)

func TestStarterInheritsDefaultsAndNeverOverwrites(t *testing.T) {
	cleanConfigEnvironment(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	if err := createConfig(path, nil); err != nil {
		t.Fatal(err)
	}
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	c, err := config.Load(path, true, config.Defaults(runtime.GOOS))
	if err != nil || !reflect.DeepEqual(c, config.Defaults(runtime.GOOS)) {
		t.Fatalf("starter pinned built-in settings: %+v %v", c, err)
	}
	if !strings.Contains(string(original), "# agents = []") {
		t.Fatal("starter silently selected an agent")
	}
	if err := createConfig(path, nil); !os.IsExist(err) {
		t.Fatalf("second init did not refuse overwrite: %v", err)
	}
	if after, _ := os.ReadFile(path); !bytes.Equal(original, after) {
		t.Fatal("existing config changed")
	}
	if runtime.GOOS != "windows" {
		if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0600 {
			t.Fatal("starter is not private")
		}
	}
}

func TestEffectiveTOMLRoundTripsNormalizedSettings(t *testing.T) {
	c := config.Defaults(runtime.GOOS)
	c.Agents = []string{"vscode-copilot"}
	c.Applications["vscode-copilot"] = json.RawMessage(`{"binary":"code","settings_dir":"Code","traffic":{"extra_chat_paths":["/v2/chat"]}}`)
	err := integrations.Normalize(&c, nil)
	if err != nil {
		t.Fatal(err)
	}
	c.Proxy.Port = 8091
	c.Proxy.SuspicionPattern = "copilot"
	c.Protection.PII = []string{"email"}
	c.Audit = filepath.Join(t.TempDir(), "audit\".jsonl")
	data, err := config.TOML(c)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "snapshot.toml")
	if err = os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	got, err := config.Load(path, true, config.Defaults(runtime.GOOS))
	if err != nil {
		t.Fatalf("TOML snapshot cannot be reloaded: %v\n%s", err, data)
	}
	err = integrations.Normalize(&got, nil)
	if err != nil || !reflect.DeepEqual(got, c) {
		t.Fatalf("TOML snapshot changed settings: %+v %v\n%s", got, err, data)
	}
}

func TestInstallConfigPreservesExplicitAndExistingFiles(t *testing.T) {
	dir := t.TempDir()
	o := defaultOptions(dir)
	o.dir = dir
	o.configPath = filepath.Join(dir, "selected.toml")
	var output bytes.Buffer
	installConfig(&output, o)
	if _, err := os.Stat(filepath.Join(dir, "config.toml")); !os.IsNotExist(err) {
		t.Fatal("install created an unused default configuration")
	}
	if _, err := os.Stat(o.configPath); !os.IsNotExist(err) {
		t.Fatal("install created an explicitly selected file")
	}
	o.configPath = ""
	path := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(path, []byte("user content"), 0600); err != nil {
		t.Fatal(err)
	}
	installConfig(&output, o)
	if content, _ := os.ReadFile(path); string(content) != "user content" {
		t.Fatal("install changed existing configuration")
	}
}
