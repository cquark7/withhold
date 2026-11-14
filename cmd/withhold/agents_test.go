package main

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/cquark7/withhold/internal/integrations"
)

func TestAgentCatalogHelpAndCompletionUseRegistryWithoutRuntimeConfig(t *testing.T) {
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
	if json.Unmarshal(out.Bytes(), &payload) != nil || payload.Schema != 3 || !reflect.DeepEqual(payload.Agents, integrations.List()) {
		t.Fatal("catalog did not match registered agents")
	}
	for _, entry := range payload.Agents {
		if !strings.HasPrefix(entry.Documentation, "https://") {
			t.Fatalf("agent guide is not a clickable URL: %q", entry.Documentation)
		}
	}
	for _, entry := range integrations.List() {
		if got := candidates([]string{"on", entry.ID}); !reflect.DeepEqual(got, []string{entry.ID}) {
			t.Fatal("completion did not use catalog")
		}
	}
	out.Reset()
	if listAgents(&out, nil) != 0 {
		t.Fatal("human catalog failed")
	}
	for _, entry := range integrations.List() {
		if !strings.Contains(out.String(), entry.ID) || !strings.Contains(out.String(), entry.Name) || !strings.Contains(out.String(), entry.Documentation) {
			t.Errorf("human catalog omitted agent metadata or clickable guide: %s", out.String())
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

func TestSetupWithoutSavedAgentsShowsCurrentChoicesAndNextCommand(t *testing.T) {
	var out bytes.Buffer
	if got := setupAgentsRequired(&out); got != 2 {
		t.Fatalf("missing-agent result = %d, want usage error", got)
	}
	text := out.String()
	entries := integrations.List()
	for _, entry := range entries {
		if !strings.Contains(text, entry.ID) || !strings.Contains(text, entry.Name) {
			t.Errorf("setup choice list omitted %s: %s", entry.ID, text)
		}
	}
	if len(entries) == 0 || !strings.Contains(text, "withhold setup "+entries[0].ID) ||
		!strings.Contains(text, "withhold agents") ||
		!strings.Contains(text, "clickable guide URLs") {
		t.Fatalf("setup error did not show the next action: %s", text)
	}
}

func TestSetupWithoutSelectionShowsChoicesBeforeWritingState(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("WITHHOLD_CONFIG", "")
	t.Setenv("WITHHOLD_DIR", "")
	read, write, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	oldStderr := os.Stderr
	os.Stderr = write
	t.Cleanup(func() {
		os.Stderr = oldStderr
		_ = write.Close()
		_ = read.Close()
	})

	code := run([]string{"setup", "--dir", dir})
	_ = write.Close()
	os.Stderr = oldStderr
	output, err := io.ReadAll(read)
	if err != nil {
		t.Fatal(err)
	}
	entries := integrations.List()
	if code != 2 || !strings.Contains(string(output), "Supported agents:") || len(entries) == 0 || !strings.Contains(string(output), "withhold setup "+entries[0].ID) {
		t.Fatalf("setup did not provide agent choices: code=%d output=%s", code, output)
	}
	dirEntries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(dirEntries) != 0 {
		t.Fatalf("setup changed state before an agent was selected: %v", dirEntries)
	}
}
