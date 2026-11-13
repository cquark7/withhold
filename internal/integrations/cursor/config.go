package cursor

import (
	"encoding/json"
	"errors"
	"path/filepath"

	"github.com/cquark7/withhold/internal/config"
)

const Example = `[application]
binary = "cursor"
settings_dir = "Cursor"
`

type Settings struct {
	Binary      string `json:"binary"`
	SettingsDir string `json:"settings_dir"`
}

func Configure(data json.RawMessage, get func(string) string) (json.RawMessage, error) {
	s, err := settings(data, get)
	if err != nil {
		return nil, err
	}
	return json.Marshal(s)
}

func settings(data json.RawMessage, get func(string) string) (Settings, error) {
	s := Settings{Binary: "cursor", SettingsDir: "Cursor"}
	if len(data) != 0 {
		if err := config.DecodeObject(data, &s); err != nil {
			return s, err
		}
	}
	if get != nil {
		if value := get("WITHHOLD_EDITOR_BIN"); value != "" {
			s.Binary = value
		}
		if value := get("WITHHOLD_EDITOR_SETTINGS_DIR"); value != "" {
			s.SettingsDir = value
		}
	}
	if s.Binary == "" {
		s.Binary = "cursor"
	}
	if s.SettingsDir == "" {
		s.SettingsDir = "Cursor"
	}
	if !filepath.IsLocal(s.SettingsDir) {
		return s, errors.New("editor settings directory must be relative to the platform settings root")
	}
	return s, nil
}
