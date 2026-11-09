package copilot

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/cquark7/withhold/internal/integration"
)

func TestApplicationConfigIsStrictTypedAndValueFree(t *testing.T) {
	for _, text := range []string{
		`[]`, `null`, `{"unknown":"PRIVATE"}`, `{"binary":123}`,
		`{"binary":null}`, `{"Binary":"PRIVATE"}`,
		`{"binary":"one","binary":"PRIVATE"}`,
		`{"profile":"PRIVATE"}`, `{"settings_dir":"../PRIVATE"}`,
		`{"traffic":{"extra_chat_paths":["PRIVATE["]}}`,
		`{"traffic":{"chat_paths":[""]}}`,
		`{"traffic":{"inline_paths":[null]}}`,
		`{"traffic":{"hosts":["https://PRIVATE"]}}`,
		`{"traffic":{"hosts":["*.PRIVATE"]}}`,
		`{"traffic":{"hosts":["PRIVATE..example"]}}`,
		`{"traffic":{"extra_hosts":["api.github.com"]}}`,
		`{"traffic":{"host_suffixes":[".github.com"]}}`,
		`{"traffic":{"unknown":"PRIVATE"}}`,
	} {
		if _, err := Configure(json.RawMessage(text), nil); err == nil || strings.Contains(err.Error(), "PRIVATE") {
			t.Fatalf("invalid application config accepted or value exposed: %v", err)
		}
	}
}

func TestApplicationDefaultsEnvironmentAndFrozenSettings(t *testing.T) {
	input := json.RawMessage(`{"binary":"file-code","settings_dir":"Code - Insiders"}`)
	data, err := Configure(input, func(key string) string {
		if key == "WITHHOLD_EDITOR_BIN" {
			return "env-code"
		}
		return ""
	})
	if err != nil {
		t.Fatal(err)
	}
	got, err := settings(data, nil)
	if err != nil || got.Binary != "env-code" || got.SettingsDir != "Code - Insiders" {
		t.Fatalf("defaults/environment/file precedence failed: %+v %v", got, err)
	}
	t.Setenv("WITHHOLD_EDITOR_SETTINGS_DIR", "../invalid-current-environment")
	t.Setenv("WITHHOLD_EDITOR_BIN", "wrong-code")
	frozen, err := Configure(data, nil)
	if err != nil || string(frozen) != string(data) {
		t.Fatal("frozen config rediscovered ambient overrides")
	}
	app := Application{Options: integration.ApplicationOptions{Home: t.TempDir(), Platform: "linux", Settings: frozen}}
	target, err := app.Resolve()
	if err != nil || target.Binary != "env-code" || !strings.Contains(target.Resource, "Code - Insiders") {
		t.Fatal("application did not consume frozen settings")
	}
}
