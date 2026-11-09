package main

import (
	"bytes"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/cquark7/withhold/internal/config"
	"github.com/cquark7/withhold/internal/integrations"
)

func TestConfigExamplesAreValidForEveryRegisteredAdapterAndPlatform(t *testing.T) {
	for _, entry := range integrations.List() {
		application, err := integrations.Example(entry.ID)
		if err != nil || application == "" {
			t.Fatal("registered adapter is missing its TOML example")
		}
		for _, platform := range []string{"linux", "darwin", "windows"} {
			path := filepath.Join(t.TempDir(), "config.toml")
			if err := os.WriteFile(path, []byte(config.Example(entry.ID, platform, application)), 0600); err != nil {
				t.Fatal(err)
			}
			c, err := config.Load(path, true, config.Defaults(entry.ID, platform))
			if err != nil || c.Validate() != nil {
				t.Fatalf("%s/%s example is invalid: %v", entry.ID, platform, err)
			}
			if _, err := integrations.Configure(entry.ID, c.Application, nil); err != nil {
				t.Fatal(err)
			}
			if c.Trust != config.Defaults(entry.ID, platform).Trust {
				t.Fatal("example changed platform trust defaults")
			}
		}
	}
}

func TestConfigExampleRejectsIgnoredOverridesAndUnknownAdapters(t *testing.T) {
	for _, args := range [][]string{
		{"--example", "--max-bytes", "1m"},
		{"--example", "--config", "missing.toml"},
		{"--example", "--integration", "unknown"},
	} {
		o := defaultOptions("~")
		f := o.flags("config")
		if _, _, err := parseOptions(f, "config", args); err != nil {
			t.Fatal(err)
		}
		var out bytes.Buffer
		if configExample(&out, o, f) != 2 || out.Len() != 0 {
			t.Fatal("example accepted an ignored override or unknown adapter")
		}
	}
	if got := candidates([]string{"config", "--ex"}); !slices.Contains(got, "--example") {
		t.Fatal("TOML example is not discoverable through completion")
	}
}
