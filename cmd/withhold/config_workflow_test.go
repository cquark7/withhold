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
	if err := createConfig(path, integrations.Default, false); err != nil {
		t.Fatal(err)
	}
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	c, err := config.Load(path, true, config.Defaults(integrations.Default, runtime.GOOS))
	if err != nil || !reflect.DeepEqual(c, config.Defaults(integrations.Default, runtime.GOOS)) {
		t.Fatalf("starter pinned built-in settings: %+v %v", c, err)
	}
	if !strings.Contains(string(original), "# [application.traffic]") || !strings.Contains(string(original), "# extra_chat_paths = []") {
		t.Fatal("starter does not expose adapter customization")
	}
	if err := createConfig(path, integrations.Default, false); !os.IsExist(err) {
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
	c := config.Defaults(integrations.Default, runtime.GOOS)
	c.Application = json.RawMessage(`{"binary":"code","settings_dir":"Code","traffic":{"extra_chat_paths":["/v2/chat"]}}`)
	var err error
	c.Application, err = integrations.Configure(c.Integration, c.Application, nil)
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
	got, err := config.Load(path, true, config.Defaults(integrations.Default, runtime.GOOS))
	if err != nil {
		t.Fatalf("TOML snapshot cannot be reloaded: %v\n%s", err, data)
	}
	got.Application, err = integrations.Configure(got.Integration, got.Application, nil)
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
