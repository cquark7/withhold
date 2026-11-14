package config

import (
	"fmt"
	"strings"

	"github.com/pelletier/go-toml/v2"
)

// Example is a starter, not a serialization of ambient settings or local paths.
func Example(agents []string, platform, applications string) string {
	c := Defaults(platform)
	if agents == nil {
		agents = []string{}
	}
	selection, _ := toml.Marshal(map[string]any{"agents": agents})
	return fmt.Sprintf(`# withhold starter configuration. Save as config.toml in your state directory.
# Restart a session after changing its settings.
schema = 1
%s
# System trust changes current-user trust during setup; manual requires CA import.
trust = %q
startup_timeout = %q

[protection]
chat = "redact"
inline = "block" # Avoid inserting placeholders into code.
observe = false # true forwards original sensitive content.
pii = [] # Optional: ["email", "phone"]. Secrets are always enabled.

[proxy]
port = %d
max_bytes = %q
scan_timeout = %q
# Extra hosts do not establish support for another agent.
# extra_hosts = ["your-reviewed-provider.example"]

[scan]
confidence = "" # Offline secrets only: low, medium, high; empty keeps all.

`, selection, c.Trust, c.StartupTimeout, c.Proxy.Port, c.Proxy.MaxBytes, c.Proxy.ScanTimeout) + applications
}

// Starter leaves defaults commented out so upgrades can update omitted rules.
func Starter(agents []string, platform, applications string) string {
	lines := strings.Split(Example(agents, platform, applications), "\n")
	var out strings.Builder
	out.WriteString("# withhold configuration. Uncomment settings to override defaults.\n")
	out.WriteString("# Omitted settings follow built-in updates; 'withhold setup AGENT...' saves agents.\n")
	for _, line := range lines[2:] {
		switch {
		case line == "", strings.HasPrefix(line, "#"), strings.HasPrefix(line, "schema = "):
			out.WriteString(line)
		case len(agents) > 0 && strings.HasPrefix(line, "agents = "):
			out.WriteString(line)
		default:
			out.WriteString("# " + line)
		}
		out.WriteByte('\n')
	}
	return out.String()
}
