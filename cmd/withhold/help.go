package main

import (
	"flag"
	"fmt"
	"io"
	"strings"
)

var commandOrder = []string{"setup", "on", "off", "status", "doctor", "demo", "integrations", "uninstall", "install", "launch", "serve", "init-ca", "config", "completion", "version"}
var commands = map[string]string{
	"setup":        "Create the private CA and configure user-scope certificate trust.",
	"on":           "Configure application routing and start an authenticated background proxy.",
	"off":          "Stop withhold and restore managed settings, preserving other edits.",
	"status":       "Report session, traffic inspection evidence, and recovery state.",
	"doctor":       "Check the bundled scanner, configuration, settings, and trust.",
	"demo":         "Demonstrate redaction and blocking locally, without a provider or setup.",
	"launch":       "Launch the selected application, if its integration supports it.",
	"uninstall":    "Restore settings and remove verified certificate trust.",
	"install":      "Copy this standalone executable into a per-user binary directory.",
	"serve":        "Run the proxy in the foreground, without changing application settings.",
	"init-ca":      "Create CA files only; do not install trust or change settings.",
	"completion":   "Print shell completion for bash, zsh, fish, or powershell.",
	"version":      "Print the native build and bundled detector versions.",
	"config":       "Print effective JSON settings, or a commented TOML starter with --example.",
	"integrations": "List the built-in integrations and their documentation.",
}

var examples = map[string]string{
	"setup":        "withhold setup\n  withhold setup --trust manual",
	"on":           "withhold on\n  withhold on --port 8090 --chat-mode block\n  withhold on --debug",
	"off":          "withhold off",
	"status":       "withhold status\n  withhold status --json",
	"doctor":       "withhold doctor\n  withhold doctor --json\n  withhold doctor --max-bytes 16m --chat-mode block",
	"demo":         "withhold demo\n  withhold demo --json",
	"launch":       "withhold launch -- .\n  withhold launch -- /path/to/project",
	"uninstall":    "withhold uninstall\n  withhold uninstall --keep-files",
	"install":      "withhold install\n  withhold install --bin-dir /path/to/bin",
	"serve":        "withhold serve --port 8090\n  withhold serve --observe\n  withhold serve --debug",
	"init-ca":      "withhold init-ca --dir /path/to/private-state",
	"completion":   "withhold completion bash\n  withhold completion zsh\n  withhold completion fish\n  withhold completion powershell",
	"version":      "withhold version",
	"config":       "withhold config\n  withhold config --example\n  withhold config --config /path/to/config.toml",
	"integrations": "withhold integrations\n  withhold integrations --json",
}

func help(w io.Writer, command string) int {
	if command == "" {
		fmt.Fprintln(w, "withhold — catch secrets before they become AI context\n\nUsage: withhold COMMAND [OPTIONS]")
		for _, group := range []struct {
			title string
			names []string
		}{{"Everyday commands", commandOrder[:5]}, {"Installation and advanced commands", commandOrder[5:]}} {
			fmt.Fprintln(w, "\n"+group.title+":")
			for _, name := range group.names {
				fmt.Fprintf(w, "  %-12s %s\n", name, commands[name])
			}
		}
		fmt.Fprintln(w, "\nGet started:\n  withhold integrations\n  withhold setup\n  withhold doctor\n  withhold on --integration NAME\n\nFollow the selected integration's trust, routing, and restart instructions.\nStop and restore settings: withhold off\n\nUse 'withhold help COMMAND' for options and examples.\nSetup creates an HTTPS inspection CA and configures current-user trust.\nOnly supported request bodies routed through the proxy are inspected.")
		return 0
	}
	description, ok := commands[command]
	if !ok {
		fmt.Fprintf(w, "withhold: unknown command %q; use 'withhold --help'\n", command)
		return 2
	}
	usage := "[OPTIONS]"
	switch command {
	case "version":
		usage = ""
	case "completion":
		usage = "SHELL"
	case "launch":
		usage += " [-- APPLICATION-ARGS...]"
	case "on", "serve":
		usage += " [PORT]"
	}
	fmt.Fprintf(w, "Usage: withhold %s\n\n%s\n", strings.TrimSpace(command+" "+usage), description)
	fmt.Fprintln(w, "\nOptions:\n  -h, --help                 Show help without changing local state")
	o := defaultOptions("~")
	f := o.flags(command)
	f.VisitAll(func(option *flag.Flag) {
		if !allowedFlag(command, option.Name) {
			return
		}
		label := "--" + option.Name
		if !boolFlag(option) {
			label += " " + flagValueName(option.Name)
		}
		description := option.Usage
		if option.DefValue != "" && option.DefValue != "false" {
			description += " (default " + option.DefValue + ")"
		}
		fmt.Fprintf(w, "  %-25s %s\n", label, description)
	})
	fmt.Fprintln(w, "\nExamples:\n  "+examples[command])
	switch command {
	case "demo":
		fmt.Fprintln(w, "\nUses synthetic values, ephemeral IPv4 loopback ports, a temporary CA, and the\nbundled scanner. TLS verification stays enabled. No provider, editor settings,\ntrust stores, or existing configuration are used. Temporary files are removed.\nThis demonstrates the local pipeline, not application routing or live compatibility.")
	case "config":
		fmt.Fprintln(w, "\n--example prints TOML defaults; it does not read config or create files.\nSelect its adapter with --integration or WITHHOLD_INTEGRATION. Other overrides\nare not accepted with --example. Without it, config prints effective JSON settings.")
	case "launch":
		fmt.Fprintln(w, "\nLaunch is optional and integration-specific. Arguments after -- stay literal;\nthe application's exit status is preserved. Follow its integration guide for\nproxy/CA environment and process-restart requirements.")
	case "setup":
		fmt.Fprintln(w, "\nSystem mode changes current-user certificate trust. Linux requires NSS certutil;\nNSS alone may not cover the application's networking runtime. Manual mode prints\nthe CA path. Trust guide:\nhttps://github.com/cquark7/withhold/blob/main/docs/usage.md#certificate-trust")
	case "on", "serve":
		if command == "on" {
			fmt.Fprintln(w, "\nApplication setup and coverage depend on the selected integration.\nRun 'withhold integrations' to find its routing, trust, and restart guide.")
		}
		fmt.Fprintln(w, "\nObserve mode can forward secrets unchanged. Stop with 'withhold off' before\nchanging a background session's options. Foreground serve stops with Ctrl-C.")
		fmt.Fprintln(w, "\nPII is off by default. Use --pii all or comma-separated categories:\naadhaar,credit-card,email,ip-address,phone,us-ssn. See CONTRACTS.md for limits.")
		fmt.Fprintln(w, "\n--debug writes masked findings and send/block outcomes to DIR/debug-findings.log.\nMasks show the first 3 Unicode characters; very short values are fully masked.\nClean traffic and routine connection events are omitted, as are bodies, headers,\nand URL paths. Use 'withhold status' for counters and logging health.\nUse temporarily, then delete the findings file and its .1 backup.")
	case "doctor":
		fmt.Fprintln(w, "\nPolicy, cap, integration, and upstream TLS options are the same as 'withhold on'.\nPass the intended startup options when checking a nondefault configuration.")
	}
	if allowedFlag(command, "config") {
		fmt.Fprintln(w, "\nConfiguration: DIR/config.toml, or --config / WITHHOLD_CONFIG (TOML only).\nPrecedence: flags > environment > file > defaults; extra hosts/patterns merge.\n'withhold config' prints effective settings as JSON. Reference:\nhttps://github.com/cquark7/withhold/blob/main/docs/configuration.md")
	}
	fmt.Fprintln(w, "\nExit codes: 0 success; 1 operation/check failed; 2 invalid usage/configuration.\nDoctor --preflight returns 2 for failed checks. Launch preserves application exit codes.")
	return 0
}

func flagValueName(name string) string {
	switch name {
	case "dir", "bin-dir":
		return "DIR"
	case "port":
		return "PORT"
	case "trust", "chat-mode", "inline-mode":
		return "MODE"
	case "max-bytes":
		return "SIZE"
	case "scan-timeout":
		return "DURATION"
	case "extra-hosts":
		return "HOSTS"
	case "extra-host-regex":
		return "REGEX"
	case "integration":
		return "NAME"
	case "pii":
		return "TYPES"
	default:
		return "FILE"
	}
}

func allowedFlag(command, name string) bool {
	if command == "integrations" || command == "demo" {
		return name == "json"
	}
	if command == "version" || command == "completion" {
		return false
	}
	switch name {
	case "example":
		return command == "config"
	case "dir":
		return true
	case "config":
		return command != "init-ca" && command != "install"
	case "json":
		return command == "status" || command == "doctor"
	case "preflight":
		return command == "doctor"
	case "trust":
		return command == "setup"
	case "integration":
		return command == "setup" || command == "launch" || command == "on" || command == "serve" || command == "doctor" || command == "config"
	case "bin-dir":
		return command == "install"
	case "keep-files":
		return command == "uninstall"
	case "debug":
		return command == "on" || command == "serve"
	case "port":
		return command == "on" || command == "serve" || command == "doctor" || command == "status" || command == "off" || command == "config"
	default:
		return command == "serve" || command == "on" || command == "doctor" || command == "config"
	}
}
