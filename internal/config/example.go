package config

import "fmt"

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
