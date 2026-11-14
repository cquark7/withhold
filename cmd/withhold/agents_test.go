package main

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/cquark7/withhold/internal/integrations"
)

func TestCatalogHelpAndCompletionUseRegisteredIntegrationsWithoutRuntimeConfig(t *testing.T) {
	t.Setenv("WITHHOLD_CONFIG", "/missing/config.toml")
	t.Setenv("WITHHOLD_INTEGRATION", "not-registered")
	t.Setenv("WITHHOLD_MAX_BYTES", "invalid")
	var out bytes.Buffer
	if listAgents(&out, []string{"--json"}) != 0 {
		t.Fatal("discovery depended on runtime configuration")
	}
	var payload struct {
		Schema int                        `json:"schema"`
		Agents []integrations.Description `json:"agents"`
	}
	if json.Unmarshal(out.Bytes(), &payload) != nil || payload.Schema != 2 || !reflect.DeepEqual(payload.Agents, integrations.List()) {
		t.Fatal("catalog did not match registered integrations")
	}
	for _, entry := range integrations.List() {
		if got := candidates([]string{"on", entry.ID}); !reflect.DeepEqual(got, []string{entry.ID}) {
			t.Fatal("completion did not use catalog")
		}
	}
	out.Reset()
	if listAgents(&out, []string{"--help"}) != 0 || !strings.Contains(out.String(), "--json") || strings.Contains(out.String(), "--config ") {
		t.Fatal("catalog help is inconsistent")
	}
	if listAgents(&out, []string{"--config", "ignored.toml"}) != 2 {
		t.Fatal("catalog accepted runtime configuration flags")
	}
}
