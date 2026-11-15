package main

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/cquark7/withhold/internal/integrations"
)

// Discovery, like help and completion, is independent of runtime configuration.
func listAgents(w io.Writer, args []string) int {
	if len(args) == 1 && (args[0] == "--help" || args[0] == "-h") {
		return help(w, "agents")
	}
	if len(args) > 1 || len(args) == 1 && args[0] != "--json" {
		return commandUsageError("agents", "agents accepts only --json")
	}
	entries := integrations.List()
	if len(args) == 1 {
		if json.NewEncoder(w).Encode(struct {
			Schema int                        `json:"schema"`
			Agents []integrations.Description `json:"agents"`
		}{3, entries}) != nil {
			return 1
		}
		return 0
	}
	if _, err := fmt.Fprintln(w, "Supported agents:"); err != nil {
		return 1
	}
	if err := writeAgentChoices(w, entries, true); err != nil {
		return 1
	}
	return 0
}

func writeAgentChoices(w io.Writer, entries []integrations.Description, guides bool) error {
	width := 0
	for _, entry := range entries {
		width = max(width, len(entry.ID))
	}
	for _, entry := range entries {
		if _, err := fmt.Fprintf(w, "  %-*s  %s\n", width, entry.ID, entry.Name); err != nil {
			return err
		}
		if guides {
			if _, err := fmt.Fprintf(w, "    Guide: %s\n", entry.Documentation); err != nil {
				return err
			}
		}
	}
	return nil
}

func setupAgentsRequired(w io.Writer) int {
	entries := integrations.List()
	fmt.Fprintln(w, "withhold: no agents selected; no saved default agent set exists.")
	fmt.Fprintln(w, "Supported agents:")
	if err := writeAgentChoices(w, entries, false); err != nil {
		return 1
	}
	if len(entries) > 0 {
		fmt.Fprintf(w, "Choose one or more, for example: withhold setup %s\n", entries[0].ID)
	}
	fmt.Fprintln(w, "Run 'withhold agents' for clickable guide URLs.")
	fmt.Fprintln(w, "Run 'withhold setup --help' for setup and trust options.")
	return 2
}
