// Package config resolves one immutable, nonsecret native configuration.
// Configuration is user-scoped; working-directory files are never discovered.
package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/pelletier/go-toml/v2"

	"github.com/cquark7/withhold/internal/detector"
	"github.com/cquark7/withhold/internal/localstate"
	"github.com/cquark7/withhold/internal/pii"
	"github.com/cquark7/withhold/internal/policy"
)

type Protection struct {
	Chat    string   `json:"chat"`
	Inline  string   `json:"inline"`
	Observe bool     `json:"observe"`
	PII     []string `json:"pii"`
}

type Proxy struct {
	Port             int      `json:"port"`
	MaxBytes         string   `json:"max_bytes"`
	ScanTimeout      string   `json:"scan_timeout"`
	ExtraHosts       []string `json:"extra_hosts"`
	ExtraHostRegex   []string `json:"extra_host_regex"`
	SuspicionPattern string   `json:"suspicion_pattern,omitempty"`
	UpstreamCA       string   `json:"upstream_ca,omitempty"`
}

// Scan settings affect offline inspection only, never proxy protection.
type Scan struct {
	Confidence string `json:"confidence"`
}

// Config contains no credentials or placeholder key. It can be recorded with a
// private session so children never reread a changing configuration file.
type Config struct {
	Schema      int        `json:"schema"`
	Integration string     `json:"integration"`
	Protection  Protection `json:"protection"`
	Proxy       Proxy      `json:"proxy"`
	Scan        Scan       `json:"scan"`
	// Application is decoded and validated by the selected integration. Shared
	// configuration never accumulates fields for individual harnesses.
	Application    json.RawMessage `json:"application"`
	Trust          string          `json:"trust"`
	StartupTimeout string          `json:"startup_timeout"`
	Audit          string          `json:"audit,omitempty"`
	Hint           string          `json:"hint,omitempty"`
	// AllowHosts is exclusively the isolated process-test scope override.
	AllowHosts []string `json:"-"`
}

func Defaults(integration, platform string) Config {
	trust := "system"
	if platform == "windows" {
		trust = "manual"
	}
	return Config{Schema: 1, Integration: integration, Protection: Protection{Chat: "redact", Inline: "block", PII: []string{}}, Proxy: Proxy{Port: 8080, MaxBytes: "32m", ScanTimeout: "10s", ExtraHosts: []string{}, ExtraHostRegex: []string{}}, Application: json.RawMessage(`{}`), Trust: trust, StartupTimeout: "60s"}
}

// Load reads TOML and rejects ambiguous, unknown, or oversized settings.
// Missing implicit configuration is normal; missing explicit files are errors.
func Load(path string, explicit bool, defaults Config) (Config, error) {
	if err := localstate.Regular(path); err != nil {
		return defaults, fmt.Errorf("config: %w", err)
	}
	f, err := os.Open(path)
	if os.IsNotExist(err) && !explicit {
		return defaults, nil
	}
	if err != nil {
		return defaults, fmt.Errorf("cannot read config: %w", err)
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, (1<<20)+1))
	if err != nil || len(data) > 1<<20 {
		return defaults, errors.New("config exceeds read limit")
	}
	data, err = tomlJSON(data)
	if err != nil {
		return defaults, err
	}
	var version struct {
		Schema int `json:"schema"`
	}
	if json.Unmarshal(data, &version) != nil || version.Schema != 1 {
		return defaults, errors.New("config requires schema 1")
	}
	if err = DecodeObject(data, &defaults); err != nil {
		return defaults, err
	}
	return defaults, nil
}

// Convert TOML to the strict internal JSON representation used by typed shared
// and adapter settings. JSON is not accepted as a configuration-file format.
// Parser errors never echo potentially private configuration values.
func tomlJSON(data []byte) ([]byte, error) {
	var values map[string]any
	if toml.Unmarshal(data, &values) != nil {
		return nil, errors.New("invalid TOML configuration")
	}
	value, err := tomlValue(values, 0)
	if err != nil {
		return nil, err
	}
	result, err := json.Marshal(value)
	if err != nil {
		return nil, errors.New("config contains unsupported TOML values")
	}
	return result, nil
}

func tomlValue(value any, depth int) (any, error) {
	if depth > 32 {
		return nil, errors.New("config nesting exceeds limit")
	}
	switch v := value.(type) {
	case map[string]any:
		for key, item := range v {
			normalized, err := tomlValue(item, depth+1)
			if err != nil {
				return nil, err
			}
			v[key] = normalized
		}
	case []any:
		for i, item := range v {
			normalized, err := tomlValue(item, depth+1)
			if err != nil {
				return nil, err
			}
			v[i] = normalized
		}
	case float64:
		// Preserve the distinction between TOML integers and floats when JSON
		// decoding enforces the type of schema/port and future adapter fields.
		text := strconv.FormatFloat(v, 'g', -1, 64)
		if !strings.ContainsAny(text, ".eE") {
			text += ".0"
		}
		return json.Number(text), nil
	case string, bool, int64, uint64:
	default:
		return nil, errors.New("config contains unsupported TOML values; use strings for durations and paths")
	}
	return value, nil
}

// DecodeObject applies the same strict, value-free validation to the shared
// envelope and integration-owned settings. Callers supply typed defaults.
func DecodeObject(data []byte, target any) error {
	data = bytes.TrimSpace(data)
	if len(data) == 0 || data[0] != '{' || len(data) > 1<<20 {
		return errors.New("config settings must be an object of at most 1 MiB")
	}
	if err := unambiguous(json.NewDecoder(bytes.NewReader(data))); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return errors.New("config contains unknown fields or invalid field types")
	}
	return nil
}

// Reject duplicate keys and null rather than allowing a typo to retain a
// less-protective default. Diagnostics deliberately omit configuration values.
func unambiguous(d *json.Decoder) error {
	var value func(int) error
	value = func(depth int) error {
		if depth > 32 {
			return errors.New("config nesting exceeds limit")
		}
		token, err := d.Token()
		if err != nil || token == nil {
			return errors.New("invalid configuration object")
		}
		if delim, ok := token.(json.Delim); ok {
			seen := map[string]bool{}
			for d.More() {
				if delim == '{' {
					key, err := d.Token()
					name, ok := key.(string)
					if err != nil || !ok || name != strings.ToLower(name) || seen[name] {
						return errors.New("duplicate or invalid config key")
					}
					seen[name] = true
				}
				if err := value(depth + 1); err != nil {
					return err
				}
			}
			if _, err := d.Token(); err != nil {
				return errors.New("invalid configuration object")
			}
		}
		return nil
	}
	if err := value(0); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return errors.New("config must contain one object")
	}
	return nil
}

func (c *Config) Environment(get func(string) string) {
	set := func(key string, target *string) {
		if v := get(key); v != "" {
			*target = v
		}
	}
	set("WITHHOLD_INTEGRATION", &c.Integration)
	set("WITHHOLD_MAX_BYTES", &c.Proxy.MaxBytes)
	set("WITHHOLD_AUDIT", &c.Audit)
	set("WITHHOLD_HINT", &c.Hint)
	if v := get("WITHHOLD_PII"); v != "" {
		c.Protection.PII = strings.Split(v, ",")
		if strings.TrimSpace(v) == "" {
			c.Protection.PII = []string{}
		}
	}
	if v := get("WITHHOLD_ENFORCE"); v != "" {
		c.Protection.Observe = strings.EqualFold(v, "observe")
	}
	if v := get("WITHHOLD_ON_STARTUP_TIMEOUT"); v != "" {
		c.StartupTimeout = v + "s"
	}
	if v := get("WITHHOLD_EXTRA_HOSTS"); v != "" {
		c.Proxy.ExtraHosts = append(c.Proxy.ExtraHosts, v)
	}
	if v := get("WITHHOLD_EXTRA_HOST_REGEX"); v != "" {
		c.Proxy.ExtraHostRegex = append(c.Proxy.ExtraHostRegex, strings.Split(v, "\n")...)
	}
	if v := get("WITHHOLD_TEST_ALLOW_HOSTS"); v != "" {
		c.AllowHosts = strings.Split(v, ",")
	}
}

func (c *Config) Validate() error {
	if c.Schema != 1 || c.Integration == "" {
		return errors.New("config requires schema 1 and an integration")
	}
	confidence, err := detector.ParseConfidence(c.Scan.Confidence)
	if err != nil {
		return err
	}
	c.Scan.Confidence = confidence
	if !policy.ValidMode(c.Protection.Chat) || !policy.ValidMode(c.Protection.Inline) {
		return errors.New("chat and inline must be redact or block")
	}
	if c.Proxy.Port < 1 || c.Proxy.Port > 65535 {
		return errors.New("port must be 1-65535")
	}
	if _, err := Size(c.Proxy.MaxBytes); err != nil {
		return err
	}
	if d, err := time.ParseDuration(c.Proxy.ScanTimeout); err != nil || d <= 0 {
		return errors.New("scan-timeout must be a positive duration (for example 10s)")
	}
	if c.Trust != "system" && c.Trust != "manual" {
		return errors.New("trust must be system or manual")
	}
	if d, err := time.ParseDuration(c.StartupTimeout); err != nil || d < time.Second || d > 600*time.Second {
		return errors.New("startup_timeout / WITHHOLD_ON_STARTUP_TIMEOUT must be 1-600 seconds")
	}
	for _, category := range c.Protection.PII {
		if strings.TrimSpace(category) == "" || strings.Contains(category, ",") {
			return errors.New("PII must be an array of category names, all, or off")
		}
	}
	selected, err := pii.Selection(strings.Join(c.Protection.PII, ","))
	if err != nil {
		return err
	}
	c.Protection.PII = append([]string{}, selected...)
	return nil
}

func (c Config) Scope() policy.ScopeOptions {
	return policy.ScopeOptions{ExtraHosts: c.Proxy.ExtraHosts, ExtraHostRegex: c.Proxy.ExtraHostRegex, AllowHosts: c.AllowHosts, SuspicionPattern: c.Proxy.SuspicionPattern, ChatMode: c.Protection.Chat, InlineMode: c.Protection.Inline}
}

func (c Config) WorkerEnvironment(base []string) []string {
	result := make([]string, 0, len(base)+1)
	for _, entry := range base {
		key, _, _ := strings.Cut(entry, "=")
		if !strings.EqualFold(key, "WITHHOLD_PII") {
			result = append(result, entry)
		}
	}
	return append(result, "WITHHOLD_PII="+strings.Join(c.Protection.PII, ","))
}

func Size(s string) (int64, error) {
	mult := int64(1)
	if len(s) > 0 {
		switch strings.ToLower(s[len(s)-1:]) {
		case "k":
			mult = 1024
			s = s[:len(s)-1]
		case "m":
			mult = 1024 * 1024
			s = s[:len(s)-1]
		case "g":
			mult = 1024 * 1024 * 1024
			s = s[:len(s)-1]
		}
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n <= 0 || n > 128*1024*1024/mult {
		return 0, errors.New("max-bytes must be positive and at most 128 MiB")
	}
	return n * mult, nil
}
