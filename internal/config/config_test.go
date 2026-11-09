package config

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestConfigLoadDefaultsStrictnessAndNoImplicitWrites(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	defaults := Defaults("fixture", "linux")
	if got, err := Load(path, false, defaults); err != nil || !reflect.DeepEqual(got, defaults) {
		t.Fatal("missing optional file changed defaults")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("configuration read wrote a file")
	}
	if _, err := Load(path, true, defaults); err == nil {
		t.Fatal("missing explicit file accepted")
	}
	for _, text := range []string{
		``, `schema = 2`, `schema = "PRIVATE"`, `schema = 1
unknown = "PRIVATE"`, `schema = 1
schema = 1`, `schema = 1
[protection]
pii = "PRIVATE"`, `schema = 1
[protection]
chat = "redact"
chat = "block"`, `schema = 1
[proxy]
port = "PRIVATE"`,
	} {
		if err := os.WriteFile(path, []byte(text), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(path, true, defaults); err == nil || strings.Contains(err.Error(), "PRIVATE") {
			t.Fatal("ambiguous config accepted or private value exposed")
		}
	}
	_ = os.WriteFile(path, []byte("schema = 1\n[protection]\npii = [\"email\"]\nchat = \"redact\"\n"), 0600)
	c, err := Load(path, true, defaults)
	if err != nil || c.Validate() != nil || c.Protection.Chat != "redact" || !reflect.DeepEqual(c.Protection.PII, []string{"email"}) || c.Protection.Inline != "block" {
		t.Fatal("partial configuration did not preserve safe defaults")
	}
}

func TestConfigurationValidationNeverSilentlyDropsPII(t *testing.T) {
	for _, selection := range [][]string{{"emails"}, {"off", "email"}, {"email", ""}, {""}, {"email,phone"}} {
		c := Defaults("fixture", "linux")
		c.Protection.PII = selection
		if c.Validate() == nil {
			t.Fatal("invalid PII selection accepted")
		}
	}
	c := Defaults("fixture", "windows")
	c.Protection.PII = []string{"all"}
	if c.Validate() != nil || len(c.Protection.PII) != 6 || c.Trust != "manual" {
		t.Fatal("all selection or platform default lost")
	}
}

func TestWorkerEnvironmentIsExplicitAndDoesNotMutateParent(t *testing.T) {
	c := Defaults("fixture", "linux")
	c.Protection.PII = []string{"email"}
	base := []string{"PATH=keep", "WITHHOLD_PII=all", "withhold_pii=off"}
	got := c.WorkerEnvironment(base)
	if !reflect.DeepEqual(got, []string{"PATH=keep", "WITHHOLD_PII=email"}) || base[1] != "WITHHOLD_PII=all" {
		t.Fatal("worker selection leaked from or mutated parent environment")
	}
}

func TestRejectsNonregularAndExcessiveConfiguration(t *testing.T) {
	dir := t.TempDir()
	defaults := Defaults("fixture", "linux")
	if _, err := Load(dir, true, defaults); err == nil {
		t.Fatal("directory accepted as configuration")
	}
	path := filepath.Join(dir, "config.toml")
	for _, text := range []string{strings.Repeat(" ", 1<<20+1), "schema = 1\n[application]\nvalue = " + strings.Repeat("[", 40) + `0` + strings.Repeat("]", 40)} {
		if err := os.WriteFile(path, []byte(text), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(path, true, defaults); err == nil {
			t.Fatal("excessive configuration accepted")
		}
	}
	link := filepath.Join(dir, "link.toml")
	if os.Symlink(path, link) == nil {
		if _, err := Load(link, true, defaults); err == nil {
			t.Fatal("configuration symlink followed")
		}
	}
}

func TestInternalObjectsRejectAmbiguousJSONWithoutExposingValues(t *testing.T) {
	for _, text := range []string{
		`[]`, `null`, `{"schema":null}`, `{"Schema":1}`,
		`{"schema":1,"schema":1}`, `{"schema":"PRIVATE"}`,
		`{"schema":1,"unknown":"PRIVATE"}`, `{"schema":1} {"schema":1}`,
	} {
		c := Defaults("fixture", "linux")
		if err := DecodeObject([]byte(text), &c); err == nil || strings.Contains(err.Error(), "PRIVATE") {
			t.Fatalf("invalid internal object accepted or values exposed: %v", err)
		}
	}
}

func TestOnlyCanonicalProtectionModesAreAccepted(t *testing.T) {
	for _, mode := range []string{"redact", "block", "warn", "", "observe"} {
		for _, field := range []string{"chat", "inline"} {
			c := Defaults("fixture", "linux")
			if field == "chat" {
				c.Protection.Chat = mode
			} else {
				c.Protection.Inline = mode
			}
			if (c.Validate() == nil) != (mode == "redact" || mode == "block") {
				t.Fatalf("%s mode %q: incorrect validation", field, mode)
			}
		}
	}
}

func TestEnvironmentDoesNotReadAlternatePrefixAliases(t *testing.T) {
	c := Defaults("fixture", "linux")
	want := Defaults("fixture", "linux")
	c.Environment(func(key string) string {
		return map[string]string{
			"GUARD_INTEGRATION": "other", "GUARD_PII": "email",
			"GUARD_MAX_BYTES": "1m", "GUARD_ENFORCE": "observe",
			"GUARD_EXTRA_HOSTS": "example.test", "GUARD_ON_STARTUP_TIMEOUT": "1",
			"GUARD_AUDIT": "audit", "GUARD_HINT": "hint",
			"GUARD_EXTRA_HOST_REGEX": "example", "GUARD_ALLOW_HOSTS": "example.test",
		}[key]
	})
	if !reflect.DeepEqual(c, want) {
		t.Fatal("alternate-prefix environment changed configuration")
	}
}
