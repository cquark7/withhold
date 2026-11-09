package main

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/cquark7/withhold/internal/integrations"
)

// Discovery, like help and completion, is independent of runtime configuration.
func listIntegrations(w io.Writer, args []string) int {
	if len(args) == 1 && (args[0] == "--help" || args[0] == "-h") {
		return help(w, "integrations")
	}
	if len(args) > 1 || len(args) == 1 && args[0] != "--json" {
		return commandUsageError("integrations", "integrations accepts only --json")
	}
	entries := integrations.List()
	if len(args) == 1 {
		if json.NewEncoder(w).Encode(struct {
			Schema       int                        `json:"schema"`
			Integrations []integrations.Description `json:"integrations"`
		}{1, entries}) != nil {
			return 1
		}
		return 0
	}
	for _, entry := range entries {
		if _, err := fmt.Fprintf(w, "%s\t%s\n  %s\n", entry.ID, entry.Name, entry.Documentation); err != nil {
			return 1
		}
	}
	return 0
}
