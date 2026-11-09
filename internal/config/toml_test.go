package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestTOMLPreservesTypedAdapterSettingsAndComments(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	text := `schema = 1
integration = "fixture"
[protection]
chat = "redact" # Comments can explain protection decisions.
pii = ["email", "phone"]
[proxy]
port = 8090
extra_host_regex = ['api\.example\.test']
[application]
endpoint = "fixture"
enabled = true
models = ["one", "two"]
`
	if err := os.WriteFile(path, []byte(text), 0600); err != nil {
		t.Fatal(err)
	}
	c, err := Load(path, true, Defaults("fixture", "linux"))
	if err != nil || c.Validate() != nil {
		t.Fatalf("invalid configuration: %v", err)
	}
	var application struct {
		Endpoint string   `json:"endpoint"`
		Enabled  bool     `json:"enabled"`
		Models   []string `json:"models"`
	}
	if json.Unmarshal(c.Application, &application) != nil || application.Endpoint != "fixture" || !application.Enabled || !reflect.DeepEqual(application.Models, []string{"one", "two"}) {
		t.Fatal("typed adapter-owned settings lost")
	}
	if c.Protection.Chat != "redact" || c.Proxy.Port != 8090 || !reflect.DeepEqual(c.Proxy.ExtraHostRegex, []string{`api\.example\.test`}) {
		t.Fatal("shared configuration lost")
	}
	if data, err := os.ReadFile(path); err != nil || string(data) != text {
		t.Fatal("configuration read modified the file")
	}
}

func TestTOMLRejectsAmbiguousUnknownAndUnsupportedValuesWithoutEchoingThem(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	for _, text := range []string{
		`schema = 1
schema = 1`,
		`schema = 1
unknown = "PRIVATE"`,
		`schema = 1
[proxy]
Port = 8090`,
		`schema = 1
[proxy]
port = "PRIVATE"`,
		`schema = 1.0`,
		`schema = 1
[proxy]
port = 8090.0`,
		`schema = 1
[application]
private = 2026-11-09`,
		`schema = 1
[application]
private = nan`,
		`schema = 1
[application]
private = inf`,
		`schema = 1
[proxy]
port = 8090
[proxy]
port = 8091`,
		`schema = 1
[application]
secret = "PRIVATE"
secret = "PRIVATE"`,
		`schema = 1
[Application]
binary = "PRIVATE"`,
		`schema = 1
[application]
value = ` + strings.Repeat("[", 40) + `0` + strings.Repeat("]", 40),
	} {
		if err := os.WriteFile(path, []byte(text), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(path, true, Defaults("fixture", "linux")); err == nil || strings.Contains(err.Error(), "PRIVATE") {
			t.Fatalf("invalid config accepted or private value exposed: %v", err)
		}
	}
}

func TestFilesAlwaysUseTOMLRegardlessOfFilename(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"config.toml", "config.json", "settings"} {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(`{"schema":1,"application":{"private":"PRIVATE"}}`), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(path, true, Defaults("fixture", "linux")); err == nil || strings.Contains(err.Error(), "PRIVATE") {
			t.Fatalf("%s: JSON accepted or private value exposed: %v", name, err)
		}
		if err := os.WriteFile(path, []byte("schema = 1\n"), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(path, true, Defaults("fixture", "linux")); err != nil {
			t.Fatalf("%s: TOML parsing depended on filename: %v", name, err)
		}
	}
}
