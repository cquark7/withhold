package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/cquark7/withhold/internal/integrations"
)

func cleanConfigEnvironment(t *testing.T) {
	t.Helper()
	for _, key := range []string{"WITHHOLD_INTEGRATION", "WITHHOLD_MAX_BYTES", "WITHHOLD_AUDIT", "WITHHOLD_HINT", "WITHHOLD_EDITOR_BIN", "WITHHOLD_EDITOR_SETTINGS_DIR", "WITHHOLD_PII", "WITHHOLD_ENFORCE", "WITHHOLD_ON_STARTUP_TIMEOUT", "WITHHOLD_EXTRA_HOSTS", "WITHHOLD_EXTRA_HOST_REGEX", "WITHHOLD_TEST_ALLOW_HOSTS", "WITHHOLD_PLACEHOLDER_KEY"} {
		t.Setenv(key, "")
	}
}

func TestPersistentConfigurationPrecedenceAndAdditiveScope(t *testing.T) {
	cleanConfigEnvironment(t)
	dir := t.TempDir()
	text := `schema = 1
integration = "vscode-copilot"
[protection]
chat = "block"
pii = ["email"]
[proxy]
port = 8090
max_bytes = "8m"
extra_hosts = ["file.example"]
[application]
settings_dir = "Code - Insiders"
`
	if err := os.WriteFile(filepath.Join(dir, "config.toml"), []byte(text), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("WITHHOLD_MAX_BYTES", "16m")
	t.Setenv("WITHHOLD_PII", "aadhaar")
	t.Setenv("WITHHOLD_EXTRA_HOSTS", "env.example")
	o := defaultOptions(dir)
	o.dir = dir
	f := o.flags("on")
	if _, _, err := parseOptions(f, "on", []string{"--max-bytes", "24m", "--chat-mode", "redact", "--pii", "off", "--extra-hosts", "flag.example"}); err != nil {
		t.Fatal(err)
	}
	c, err := o.resolve(f)
	if err != nil || c.Validate() != nil {
		t.Fatal(err)
	}
	var application map[string]string
	if json.Unmarshal(c.Application, &application) != nil {
		t.Fatal("application settings lost")
	}
	if c.Proxy.MaxBytes != "24m" || c.Protection.Chat != "redact" || len(c.Protection.PII) != 0 || c.Proxy.Port != 8090 || application["settings_dir"] != "Code - Insiders" {
		t.Fatal("scalar precedence failed")
	}
	if !reflect.DeepEqual(c.Proxy.ExtraHosts, []string{"file.example", "env.example", "flag.example"}) {
		t.Fatal("scope overlays did not merge")
	}
	if _, err := integrations.Traffic(c.Integration, c.Scope(), c.Application); err != nil {
		t.Fatal(err)
	}
}

func TestConfigurationFingerprintUsesEffectiveSettingsNotFileIdentity(t *testing.T) {
	cleanConfigEnvironment(t)
	o := defaultOptions(t.TempDir())
	f := o.flags("on")
	c, err := o.resolve(f)
	if err != nil {
		t.Fatal(err)
	}
	first := configurationID(c)
	c.Protection.PII = []string{"email"}
	if first == configurationID(c) {
		t.Fatal("changed PII selection reused configuration identity")
	}
	c.Protection.PII = []string{}
	t.Setenv("WITHHOLD_PLACEHOLDER_KEY", "isolated-key-change")
	if first == configurationID(c) {
		t.Fatal("changed key configuration reused identity")
	}
}

func TestDefaultConfigurationReadsOnlyTOML(t *testing.T) {
	cleanConfigEnvironment(t)
	dir := t.TempDir()
	o := defaultOptions(dir)
	o.dir = dir
	f := o.flags("on")
	if err := os.WriteFile(filepath.Join(dir, "config.json"), []byte(`{"schema":1,"protection":{"chat":"block"}}`), 0600); err != nil {
		t.Fatal(err)
	}
	c, err := o.resolve(f)
	if err != nil || c.Protection.Chat != "redact" {
		t.Fatal("JSON default was discovered")
	}
	if err := os.WriteFile(filepath.Join(dir, "config.toml"), []byte("schema = 1\n[proxy]\nport = 8091\n"), 0600); err != nil {
		t.Fatal(err)
	}
	c, err = o.resolve(f)
	if err != nil || c.Proxy.Port != 8091 {
		t.Fatal("unrelated JSON file prevented TOML configuration")
	}
}
