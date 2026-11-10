package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/cquark7/withhold/internal/config"
	"github.com/cquark7/withhold/internal/integrations"
)

type cliOptions struct {
	dir, trust, binDir, chat, inline, max, audit, hint, upstreamCA string
	json, preflight, keep, observe, debug, example, init           bool
	port                                                           int
	timeout                                                        time.Duration
	hosts, patterns                                                stringsFlag
	configPath, integration, pii                                   string
	text                                                           string
	secrets                                                        bool
	exclude                                                        stringsFlag
}

func defaultOptions(home string) cliOptions {
	o := cliOptions{dir: filepath.Join(home, ".config", "withhold"), pii: "off", secrets: true}
	o.use(config.Defaults(integrations.Default, runtime.GOOS))
	return o
}

func (o *cliOptions) flags(command string) *flag.FlagSet {
	f := flag.NewFlagSet(command, flag.ContinueOnError)
	// Errors get a concise command-specific recovery hint, without a full flag dump.
	f.SetOutput(io.Discard)
	f.StringVar(&o.dir, "dir", o.dir, "state and CA directory")
	f.StringVar(&o.configPath, "config", o.configPath, "TOML user configuration (default DIR/config.toml)")
	f.StringVar(&o.integration, "integration", o.integration, "built-in integration; list with 'withhold integrations'")
	f.StringVar(&o.pii, "pii", o.pii, "optional PII: off, all, or comma-separated categories")
	f.StringVar(&o.text, "text", o.text, "scan literal text instead of files or stdin (arguments can enter shell history)")
	f.BoolVar(&o.secrets, "secrets", o.secrets, "detect secrets; use --secrets=false for PII-only scans")
	f.Var(&o.exclude, "exclude", "exclude a file or directory subtree, relative to the working directory (repeatable)")
	f.BoolVar(&o.json, "json", o.json, "emit one versioned JSON object")
	f.BoolVar(&o.example, "example", o.example, "print a commented TOML starter without reading configuration or writing files")
	f.BoolVar(&o.init, "init", o.init, "create a default-inheriting TOML config without overwriting a file")
	f.BoolVar(&o.preflight, "preflight", o.preflight, "print only failures; exit 2 if checks fail")
	f.BoolVar(&o.keep, "keep-files", o.keep, "retain CA files during uninstall")
	f.StringVar(&o.trust, "trust", o.trust, "CA trust mode: system or manual")
	f.StringVar(&o.binDir, "bin-dir", o.binDir, "executable installation directory")
	f.IntVar(&o.port, "port", o.port, "loopback listening port (1-65535)")
	f.StringVar(&o.chat, "chat-mode", o.chat, "chat finding action: redact or block")
	f.StringVar(&o.inline, "inline-mode", o.inline, "inline finding action: redact or block; redaction can alter code")
	f.BoolVar(&o.observe, "observe", o.observe, "audit decisions without enforcement; secrets can pass unchanged")
	f.BoolVar(&o.debug, "debug", o.debug, "write concise, human-readable detections and redaction outcomes to private DIR/debug-findings.log")
	f.StringVar(&o.max, "max-bytes", o.max, "wire and decoded body cap; bytes or k/m/g suffix, at most 128m")
	f.DurationVar(&o.timeout, "scan-timeout", o.timeout, "scan deadline including queue and worker startup")
	f.StringVar(&o.audit, "audit", o.audit, "audit JSONL file (default DIR/audit.jsonl)")
	f.StringVar(&o.hint, "hint", o.hint, "decision hints file (default DIR/hints.log)")
	f.StringVar(&o.upstreamCA, "upstream-ca", o.upstreamCA, "additional PEM roots for verified upstream TLS")
	f.Var(&o.hosts, "extra-hosts", "comma-separated provider hosts (repeatable)")
	f.Var(&o.patterns, "extra-host-regex", "full-host RE2 provider pattern (repeatable)")
	if command == "scan" {
		f.Lookup("max-bytes").Usage = "per-input text cap; bytes or k/m/g suffix, at most 128m"
		f.Lookup("scan-timeout").Usage = "per-input read/startup/scan deadline"
		f.Lookup("dir").Usage = "directory containing the default config.toml (no state is written)"
	}
	return f
}

func boolFlag(f *flag.Flag) bool {
	if f == nil {
		return false
	}
	v, ok := f.Value.(interface{ IsBoolFlag() bool })
	return ok && v.IsBoolFlag()
}

// Help and argument normalization respect values and the application delimiter.
func parseOptions(f *flag.FlagSet, command string, args []string) (applicationArgs []string, showHelp bool, err error) {
	var normalized []string
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			if command == "launch" {
				applicationArgs = append(applicationArgs, args[i+1:]...)
				break
			}
			normalized = append(normalized, args[i:]...)
			break
		}
		if arg == "--help" || arg == "-h" {
			return nil, true, nil
		}
		if _, e := strconv.Atoi(arg); e == nil && (command == "on" || command == "serve") {
			normalized = append(normalized, "--port", arg)
			continue
		}
		normalized = append(normalized, arg)
		if strings.HasPrefix(arg, "-") && !strings.Contains(arg, "=") && !boolFlag(f.Lookup(strings.TrimLeft(arg, "-"))) && i+1 < len(args) {
			i++
			normalized = append(normalized, args[i])
		}
	}
	if err = f.Parse(normalized); err != nil {
		return nil, false, err
	}
	if f.NArg() != 0 {
		return nil, false, fmt.Errorf("unexpected argument %q", f.Arg(0))
	}
	f.Visit(func(option *flag.Flag) {
		if err == nil && !allowedFlag(command, option.Name) {
			err = fmt.Errorf("option --%s is not supported by %s", option.Name, command)
		}
	})
	return applicationArgs, false, err
}

func commandUsageError(command, message string) int {
	fmt.Fprintf(os.Stderr, "withhold: %s\nRun 'withhold %s --help' for usage.\n", message, command)
	return 2
}

func flagSet(f *flag.FlagSet, name string) bool {
	found := false
	f.Visit(func(option *flag.Flag) { found = found || option.Name == name })
	return found
}
