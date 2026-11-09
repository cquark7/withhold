package config

import (
	"fmt"
	"strings"
)

// Example is a starter, not a serialization of ambient settings or local paths.
// The application section belongs to the selected integration.
func Example(id, platform, application string) string {
	c := Defaults(id, platform)
	return fmt.Sprintf(`# withhold starter configuration. Save as config.toml in your state directory.
# No file is needed for defaults. Restart a session after changing its settings.
schema = 1
integration = %q

# System trust changes current-user trust during setup; manual requires CA import.
trust = %q
startup_timeout = %q

[protection]
chat = "redact"
inline = "block" # Avoid inserting placeholders into code.
observe = false # true forwards original sensitive content; it does not protect it.
pii = [] # Optional: ["email", "phone"]. Secret detection is always enabled.

[proxy]
port = %d
max_bytes = %q
scan_timeout = %q
# Extra hosts do not establish support for another coding agent.
# extra_hosts = ["your-reviewed-provider.example"]

`, c.Integration, c.Trust, c.StartupTimeout, c.Proxy.Port, c.Proxy.MaxBytes, c.Proxy.ScanTimeout) + application
}

// Starter leaves defaults commented out so upgrades can update omitted rules.
func Starter(id, platform, application string, selectIntegration bool) string {
	lines := strings.Split(Example(id, platform, application), "\n")
	var out strings.Builder
	out.WriteString("# withhold configuration. Uncomment a section and its settings to override defaults.\n")
	out.WriteString("# Omitted settings follow built-in updates; view effective values with 'withhold config'.\n")
	out.WriteString("# Restart the session with 'withhold off' and 'withhold on' after changes.\n\n")
	for _, line := range lines[2:] {
		switch {
		case line == "", strings.HasPrefix(line, "#"), strings.HasPrefix(line, "schema = "):
			out.WriteString(line)
		case selectIntegration && strings.HasPrefix(line, "integration = "):
			out.WriteString(line)
		default:
			out.WriteString("# " + line)
		}
		out.WriteByte('\n')
	}
	return out.String()
}
