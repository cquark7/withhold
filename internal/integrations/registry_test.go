package integrations

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/cquark7/withhold/internal/config"
	"github.com/cquark7/withhold/internal/integration"
	"github.com/cquark7/withhold/internal/policy"
	"github.com/cquark7/withhold/internal/testintegration"
)

func TestOnlyReviewedBuiltInIsSelectable(t *testing.T) {
	for _, id := range []string{"fixture", "cursor", "codex", "opencode", "unknown"} {
		if _, err := Traffic(id, policy.ScopeOptions{}, nil); err == nil {
			t.Fatal("unregistered traffic integration accepted")
		}
		if _, err := Application(id, integration.ApplicationOptions{}); err == nil {
			t.Fatal("unregistered application integration accepted")
		}
	}
}

func TestCatalogHasUniqueCompleteRegistrationsAndExistingGuides(t *testing.T) {
	_, source, _, _ := runtime.Caller(0)
	root := filepath.Join(filepath.Dir(source), "..", "..")
	seen := map[string]bool{}
	for _, entry := range List() {
		if entry.ID == "" || seen[entry.ID] || entry.Name == "" || entry.Documentation == "" {
			t.Fatal("incomplete or duplicate integration metadata")
		}
		seen[entry.ID] = true
		if _, err := os.Stat(filepath.Join(root, entry.Documentation)); err != nil {
			t.Fatal("catalog guide is missing:", err)
		}
		d, err := lookup(entry.ID)
		if err != nil || d.example == "" || d.configure == nil || d.traffic == nil || d.application == nil {
			t.Fatal("integration lacks a required contract")
		}
	}
	if !seen[Default] {
		t.Fatal("default integration is not registered")
	}
	entries := List()
	entries[0].ID = "mutated-copy"
	if List()[0].ID == "mutated-copy" {
		t.Fatal("catalog callers can mutate registrations")
	}
}

func TestOneRegistrationSupportsIndependentTypedOptionsAndNoLauncher(t *testing.T) {
	// Test-only registration proves extension without modifying shared schemas.
	// It is restored before any other test and never linked into the product.
	before := builtins
	t.Cleanup(func() { builtins = before })
	type settings struct {
		Workspace string `json:"workspace"`
		Enabled   bool   `json:"enabled"`
	}
	builtins = append(append([]definition{}, before...), definition{
		Description: Description{ID: "fixture", Name: "Fixture Client", Documentation: "test-only"},
		example:     "[application]\nworkspace = \"example\"\nenabled = true\n",
		configure: func(data json.RawMessage, get func(string) string) (json.RawMessage, error) {
			s := settings{Workspace: "default"}
			if len(data) > 0 {
				if err := config.DecodeObject(data, &s); err != nil {
					return nil, err
				}
			}
			if get != nil && get("FIXTURE_WORKSPACE") != "" {
				s.Workspace = get("FIXTURE_WORKSPACE")
			}
			return json.Marshal(s)
		},
		traffic: func(o policy.ScopeOptions, data json.RawMessage) (policy.Profile, error) {
			var s settings
			if err := config.DecodeObject(data, &s); err != nil {
				return nil, err
			}
			return testintegration.Profile{Host: s.Workspace + ".test", Mode: o.ChatMode}, nil
		},
		application: func(o integration.ApplicationOptions) (integration.Application, error) {
			var s settings
			if err := config.DecodeObject(o.Settings, &s); err != nil {
				return nil, err
			}
			return &testintegration.Application{Path: filepath.Join(o.Home, s.Workspace+".ini")}, nil
		},
	})
	if example, err := Example("fixture"); err != nil || example != "[application]\nworkspace = \"example\"\nenabled = true\n" {
		t.Fatal("starter configuration did not use the registered adapter's example")
	}
	data, err := Configure("fixture", json.RawMessage(`{"workspace":"file","enabled":true}`), func(string) string { return "env" })
	if err != nil || string(data) != `{"workspace":"env","enabled":true}` {
		t.Fatalf("adapter config did not resolve: %s %v", data, err)
	}
	app, err := Application("fixture", integration.ApplicationOptions{Home: t.TempDir(), Settings: data})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := app.(integration.Launcher); ok {
		t.Fatal("launcher-free adapter gained a mandatory launcher")
	}
	target, err := app.Resolve()
	if err != nil || filepath.Base(target.Resource) != "env.ini" {
		t.Fatal("application did not consume normalized adapter settings")
	}
	profile, err := Traffic("fixture", policy.ScopeOptions{ChatMode: "block"}, data)
	if err != nil {
		t.Fatal(err)
	}
	if route := profile.Classify("env.test", "/submit"); route.Unknown || !route.Scoped || route.Mode != "block" {
		t.Fatal("traffic did not consume normalized adapter settings and shared scope")
	}
	if _, err := Configure("fixture", json.RawMessage(`{"binary":"copilot-only"}`), nil); err == nil {
		t.Fatal("adapter accepted another harness's options")
	}
}
