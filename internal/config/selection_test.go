package config

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestSaveAgentsPreservesUnrelatedTOMLAndReplacesTheSet(t *testing.T) {
	for _, selection := range []string{"", "agents = [] # selection\n", "\"agents\" = [\n 'cursor', # old selection\n]\n"} {
		t.Run(selection, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.toml")
			tail := "# keep this comment\n[proxy]\nport = 9012 # keep this too\n[applications.cursor]\nsettings_dir = 'CustomCursor'\n"
			if err := os.WriteFile(path, []byte("schema = 1\n"+selection+tail), 0600); err != nil {
				t.Fatal(err)
			}
			for _, ids := range [][]string{{"vscode-copilot", "cursor", "cursor"}, {"cursor"}} {
				if err := SaveAgents(path, ids); err != nil {
					t.Fatal(err)
				}
				data, _ := os.ReadFile(path)
				if !bytes.Contains(data, []byte(tail)) {
					t.Fatalf("unrelated content changed: %s", data)
				}
				c, err := Load(path, true, Defaults("linux"))
				if err != nil || c.Validate() != nil || c.Proxy.Port != 9012 {
					t.Fatalf("saved selection is not reloadable: %v", err)
				}
			}
			c, _ := Load(path, true, Defaults("linux"))
			if !reflect.DeepEqual(c.Agents, []string{"cursor"}) {
				t.Fatal("selection appended instead of replacing")
			}
		})
	}
}

func TestSelectionRejectsInvalidFilesWithoutOverwritingThem(t *testing.T) {
	for _, text := range []string{"broken TOML =", "agents = []\n", "schema = 1\nintegration = 'cursor'\n", "schema = 1\n[application]\nbinary = 'cursor'\n"} {
		path := filepath.Join(t.TempDir(), "config.toml")
		if err := os.WriteFile(path, []byte(text), 0600); err != nil {
			t.Fatal(err)
		}
		if SaveAgents(path, []string{"cursor"}) == nil {
			t.Fatal("invalid or singular config accepted")
		}
		if data, _ := os.ReadFile(path); string(data) != text {
			t.Fatal("invalid config was overwritten")
		}
	}
}
