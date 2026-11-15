// Package integrations is the composition boundary for reviewed built-ins.
// Test integrations are injected into core contracts, never registered here.
package integrations

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/cquark7/withhold/internal/config"
	"github.com/cquark7/withhold/internal/doclink"
	"github.com/cquark7/withhold/internal/integration"
	"github.com/cquark7/withhold/internal/integrations/copilot"
	"github.com/cquark7/withhold/internal/integrations/cursor"
	"github.com/cquark7/withhold/internal/policy"
)

// Description is the read-only public catalog. IDs select a supported harness
// and traffic contract together; a provider name alone is not a supported agent.
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
	Description: Description{ID: "vscode-copilot", Name: "VS Code + GitHub Copilot", Documentation: doclink.URL("integrations/vscode-copilot.md")},
	example:     copilot.Example,
	configure:   copilot.Configure,
	traffic: func(o policy.ScopeOptions, settings json.RawMessage) (policy.Profile, error) {
		return copilot.TrafficFromSettings(o, settings)
	},
	application: func(o integration.ApplicationOptions) (integration.Application, error) {
		return copilot.Application{Options: o}, nil
	},
}, {
	Description: Description{ID: "cursor", Name: "Cursor", Documentation: doclink.URL("integrations/cursor.md")},
	example:     cursor.Example,
	configure:   cursor.Configure,
	traffic: func(o policy.ScopeOptions, _ json.RawMessage) (policy.Profile, error) {
		return cursor.NewTraffic(o)
	},
	application: func(o integration.ApplicationOptions) (integration.Application, error) {
		return cursor.Application{Options: o}, nil
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
	hint := ""
	for _, d := range List() {
		if closeID(id, d.ID) {
			hint = fmt.Sprintf("; did you mean %q?", d.ID)
			break
		}
	}
	return definition{}, fmt.Errorf("unknown agent %q%s; run 'withhold agents'", id, hint)
}

// Suggest only a single insertion, deletion, substitution, or transposition.
// IDs still require an exact match; suggestions never select an adapter.
func closeID(a, b string) bool {
	for i := 0; i < min(len(a), len(b)); i++ {
		if a[i] == b[i] {
			continue
		}
		switch len(a) - len(b) {
		case 0:
			return a[i+1:] == b[i+1:] || i+1 < len(a) && a[i] == b[i+1] && a[i+1] == b[i] && a[i+2:] == b[i+2:]
		case 1:
			return a[i+1:] == b[i:]
		case -1:
			return a[i:] == b[i+1:]
		}
		return false
	}
	return len(a)-len(b) == 1 || len(b)-len(a) == 1
}

// Normalize validates all namespaced settings, including saved but inactive
// agents, and supplies defaults only for selected agents.
func Normalize(c *config.Config, get func(string) string) error {
	if err := c.Validate(); err != nil {
		return err
	}
	if c.Applications == nil {
		c.Applications = map[string]json.RawMessage{}
	}
	for id, data := range c.Applications {
		if slices.Contains(c.Agents, id) {
			continue // Selected settings apply their environment before validation.
		}
		settings, err := Configure(id, data, nil)
		if err != nil {
			return err
		}
		c.Applications[id] = settings
	}
	for _, id := range c.Agents {
		settings, err := Configure(id, c.Applications[id], get)
		if err != nil {
			return err
		}
		c.Applications[id] = settings
	}
	return nil
}

func RequireAgents(ids []string) error {
	if len(ids) == 0 {
		return fmt.Errorf("no agents selected; run 'withhold setup AGENT...' to save defaults (use 'withhold agents' to see choices)")
	}
	for _, id := range ids {
		if _, err := lookup(id); err != nil {
			return err
		}
	}
	return nil
}

func TrafficSet(c config.Config) (policy.Profile, error) {
	if err := RequireAgents(c.Agents); err != nil {
		return nil, err
	}
	profiles := make([]policy.Profile, 0, len(c.Agents))
	for _, id := range c.Agents {
		p, err := Traffic(id, c.Scope(), c.Applications[id])
		if err != nil {
			return nil, err
		}
		profiles = append(profiles, p)
	}
	return policy.Compose(profiles...), nil
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
