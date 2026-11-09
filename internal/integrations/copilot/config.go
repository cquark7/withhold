package copilot

import (
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/cquark7/withhold/internal/config"
)

var Example = fmt.Sprintf(`[application]
# These overrides select a local VS Code installation, not another supported editor.
binary = "code"
settings_dir = "Code"

# Path patterns use full-path Go RE2 matching, without a query string.
# Add paths instead of replacing defaults to keep future built-in updates.
[application.traffic]
hosts = %s
host_suffixes = %s
chat_paths = %s
inline_paths = %s
extra_hosts = []
extra_chat_paths = []
extra_inline_paths = []
`, tomlStrings(defaultTraffic().Hosts), tomlStrings(defaultTraffic().HostSuffixes), tomlStrings(defaultTraffic().ChatPaths), tomlStrings(defaultTraffic().InlinePaths))

func tomlStrings(values []string) string {
	quoted := make([]string, len(values))
	for i, value := range values {
		quoted[i] = fmt.Sprintf("%q", value)
	}
	return "[" + strings.Join(quoted, ", ") + "]"
}

// TrafficSettings is owned by this adapter and frozen with its session.
// The extra lists add to the selected built-in lists without replacing them.
type TrafficSettings struct {
	Hosts            []string `json:"hosts"`
	HostSuffixes     []string `json:"host_suffixes"`
	ChatPaths        []string `json:"chat_paths"`
	InlinePaths      []string `json:"inline_paths"`
	ExtraHosts       []string `json:"extra_hosts"`
	ExtraChatPaths   []string `json:"extra_chat_paths"`
	ExtraInlinePaths []string `json:"extra_inline_paths"`
}

func defaultTraffic() TrafficSettings {
	return TrafficSettings{
		Hosts:            []string{"api.githubcopilot.com", "api.enterprise.githubcopilot.com", "proxy.enterprise.githubcopilot.com", "telemetry.enterprise.githubcopilot.com", "origin-tracker.githubusercontent.com", EmbeddingsHost},
		HostSuffixes:     []string{".individual.githubcopilot.com", ".business.githubcopilot.com"},
		ChatPaths:        []string{`(?s:.*)/chat/completions`, `(?s:.*)/responses`, `(?s:.*)/v1/messages(?s:.*)`},
		InlinePaths:      []string{`/v1/engines/[^/]+/completions`},
		ExtraHosts:       []string{},
		ExtraChatPaths:   []string{},
		ExtraInlinePaths: []string{},
	}
}

// Settings belongs to the VS Code harness, not the scanner or proxy.
type Settings struct {
	Binary      string          `json:"binary"`
	SettingsDir string          `json:"settings_dir"`
	Traffic     TrafficSettings `json:"traffic"`
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
	s := Settings{Binary: "code", SettingsDir: "Code", Traffic: defaultTraffic()}
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
	if err := validateTraffic(s.Traffic); err != nil {
		return s, err
	}
	return s, nil
}

func validateTraffic(t TrafficSettings) error {
	for _, host := range append(append([]string{}, t.Hosts...), t.ExtraHosts...) {
		if !validHost(host) || strings.EqualFold(host, TokenHost) {
			return errors.New("application.traffic hosts must be bare hostnames and cannot include the token-passthrough host")
		}
	}
	for _, suffix := range t.HostSuffixes {
		if !strings.HasPrefix(suffix, ".") || !validHost(suffix[1:]) || strings.HasSuffix(TokenHost, strings.ToLower(suffix)) {
			return errors.New("application.traffic host_suffixes must be dotted host suffixes and cannot include the token-passthrough host")
		}
	}
	for _, paths := range [][]string{t.ChatPaths, t.InlinePaths, t.ExtraChatPaths, t.ExtraInlinePaths} {
		for _, pattern := range paths {
			if pattern == "" {
				return errors.New("application.traffic path patterns cannot be empty")
			}
			if _, err := regexp.Compile("^(?:" + pattern + ")$"); err != nil {
				return errors.New("invalid application.traffic path pattern (patterns use Go RE2 syntax)")
			}
		}
	}
	return nil
}

func validHost(host string) bool {
	if host == "" || len(host) > 253 {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}
