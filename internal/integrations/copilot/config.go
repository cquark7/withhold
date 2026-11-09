package copilot

import (
	"encoding/json"
	"errors"
	"path/filepath"

	"github.com/cquark7/withhold/internal/config"
)

const Example = `[application]
# These overrides select a local VS Code installation, not another supported editor.
binary = "code"
settings_dir = "Code"
`

// Settings belongs to the VS Code harness, not the scanner or proxy.
type Settings struct {
	Binary      string `json:"binary"`
	SettingsDir string `json:"settings_dir"`
}

// Configure resolves only this integration's settings and environment overrides.
// The normalized result is frozen with the session before any child starts.
func Configure(data json.RawMessage, get func(string) string) (json.RawMessage, error) {
	s, err := settings(data, get)
	if err != nil {
		return nil, err
	}
	return json.Marshal(s)
}

func settings(data json.RawMessage, get func(string) string) (Settings, error) {
	s := Settings{Binary: "code", SettingsDir: "Code"}
	if len(data) != 0 {
		if err := config.DecodeObject(data, &s); err != nil {
			return s, err
		}
	}
	if get != nil {
		for key, target := range map[string]*string{"WITHHOLD_EDITOR_BIN": &s.Binary, "WITHHOLD_EDITOR_SETTINGS_DIR": &s.SettingsDir} {
			if value := get(key); value != "" {
				*target = value
			}
		}
	}
	if s.Binary == "" {
		s.Binary = "code"
	}
	if s.SettingsDir == "" {
		s.SettingsDir = "Code"
	}
	if !filepath.IsLocal(s.SettingsDir) {
		return s, errors.New("editor settings directory must be relative to the platform settings root")
	}
	return s, nil
}
