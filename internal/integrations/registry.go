// Package integrations is the composition boundary for reviewed built-ins.
// Test integrations are injected into core contracts, never registered here.
package integrations

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/cquark7/withhold/internal/integration"
	"github.com/cquark7/withhold/internal/integrations/copilot"
	"github.com/cquark7/withhold/internal/policy"
)

const Default = "vscode-copilot"

// Description is the read-only public catalog. IDs select a supported harness
// and traffic contract together; a provider name alone is not an integration.
type Description struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	Documentation string `json:"documentation"`
}

type definition struct {
	Description
	example     string
	configure   func(json.RawMessage, func(string) string) (json.RawMessage, error)
	traffic     func(policy.ScopeOptions, json.RawMessage) (policy.Profile, error)
	application func(integration.ApplicationOptions) (integration.Application, error)
}

// One explicit registration per reviewed integration drives selection, help,
// completion, and discovery. No init-time registration or dynamic code loading.
var builtins = []definition{{
	Description: Description{ID: Default, Name: "VS Code + GitHub Copilot", Documentation: "docs/integrations/vscode-copilot.md"},
	example:     copilot.Example,
	configure:   copilot.Configure,
	traffic:     func(o policy.ScopeOptions, _ json.RawMessage) (policy.Profile, error) { return copilot.NewTraffic(o) },
	application: func(o integration.ApplicationOptions) (integration.Application, error) {
		return copilot.Application{Options: o}, nil
	},
}}

func List() []Description {
	result := make([]Description, 0, len(builtins))
	for _, d := range builtins {
		result = append(result, d.Description)
	}
	slices.SortFunc(result, func(a, b Description) int { return strings.Compare(a.ID, b.ID) })
	return result
}

func lookup(id string) (definition, error) {
	for _, d := range builtins {
		if d.ID == id {
			return d, nil
		}
	}
	return definition{}, fmt.Errorf("unknown integration %q; run 'withhold integrations'", id)
}

// Configure validates the selected adapter's schema and resolves its defaults
// and environment. A nil getter validates frozen settings without ambient state.
func Configure(id string, data json.RawMessage, get func(string) string) (json.RawMessage, error) {
	d, err := lookup(id)
	if err != nil {
		return nil, err
	}
	return d.configure(data, get)
}

// Example returns the adapter-owned TOML application section without discovery.
func Example(id string) (string, error) {
	d, err := lookup(id)
	if err != nil {
		return "", err
	}
	return d.example, nil
}

func Traffic(id string, options policy.ScopeOptions, settings json.RawMessage) (policy.Profile, error) {
	d, err := lookup(id)
	if err != nil {
		return nil, err
	}
	settings, err = d.configure(settings, nil)
	if err != nil {
		return nil, err
	}
	return d.traffic(options, settings)
}

func Application(id string, options integration.ApplicationOptions) (integration.Application, error) {
	d, err := lookup(id)
	if err != nil {
		return nil, err
	}
	options.Settings, err = d.configure(options.Settings, nil)
	if err != nil {
		return nil, err
	}
	return d.application(options)
}
