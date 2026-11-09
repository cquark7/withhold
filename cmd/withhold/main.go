// withhold composes the CLI, integrations, proxy, and isolated scanner.
package main

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/cquark7/withhold/internal/certstore"
	"github.com/cquark7/withhold/internal/config"
	"github.com/cquark7/withhold/internal/control"
	"github.com/cquark7/withhold/internal/detector"
	"github.com/cquark7/withhold/internal/integration"
	"github.com/cquark7/withhold/internal/integrations"
	"github.com/cquark7/withhold/internal/policy"
	"github.com/cquark7/withhold/internal/proxy"
	"github.com/cquark7/withhold/internal/scanpool"
	"github.com/cquark7/withhold/internal/session"
	"github.com/cquark7/withhold/internal/worker"
)

var version = "dev"

type stringsFlag []string

func (s *stringsFlag) String() string     { return strings.Join(*s, ",") }
func (s *stringsFlag) Set(v string) error { *s = append(*s, v); return nil }
func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func run(args []string) int {
	if len(args) == 0 || len(args) == 1 && (args[0] == "--help" || args[0] == "-h" || args[0] == "help") {
		return help(os.Stdout, "")
	}
	if args[0] == "help" {
		if len(args) != 2 {
			return commandUsageError("help", "help accepts one command name")
		}
		if _, ok := commands[args[1]]; !ok {
			return help(os.Stderr, args[1])
		}
		return help(os.Stdout, args[1])
	}
	if args[0] == "_complete" {
		for _, candidate := range candidates(args[1:]) {
			fmt.Fprintln(os.Stdout, candidate)
		}
		return 0
	}
	var owner *session.Record
	var ownerPath string
	if len(args) == 3 && args[0] == "_session-serve" && args[1] == "--state" {
		r, e := session.LoadStartupRecord(args[2], os.Stdin)
		_ = os.Stdin.Close()
		if e != nil {
			fmt.Fprintln(os.Stderr, "withhold: invalid private runtime record")
			return 1
		}
		owner = &r
		ownerPath = args[2]
		args = []string{"serve", "--dir", filepath.Dir(ownerPath)}
		if r.Debug {
			args = append(args, "--debug")
		}
	}
	if len(args) == 2 && args[0] == "_scanner" && args[1] == "--body" {
		if worker.Run("--body") != nil {
			return 1
		}
		return 0
	}
	if args[0] == "version" || args[0] == "--version" {
		if len(args) == 2 && (args[1] == "--help" || args[1] == "-h") {
			return help(os.Stdout, "version")
		}
		if len(args) != 1 {
			return commandUsageError("version", "version accepts no arguments or options")
		}
		fmt.Printf("withhold %s (betterleaks %s)\n", version, detector.Version)
		return 0
	}
	if args[0] == "completion" {
		return completion(os.Stdout, args[1:])
	}
	if args[0] == "integrations" {
		return listIntegrations(os.Stdout, args[1:])
	}
	if args[0] == "demo" {
		return demo(os.Stdout, args[1:])
	}
	if _, ok := commands[args[0]]; !ok {
		fmt.Fprintf(os.Stderr, "withhold: unknown command %q\nRun 'withhold --help' for available commands.\n", args[0])
		return 2
	}
	verb := args[0]
	home, homeErr := os.UserHomeDir()
	o := defaultOptions(home)
	o.dir = env("WITHHOLD_DIR", o.dir)
	o.configPath = os.Getenv("WITHHOLD_CONFIG")
	flags := o.flags(verb)
	applicationArgs, showHelp, err := parseOptions(flags, verb, args[1:])
	if showHelp {
		return help(os.Stdout, verb)
	}
	if err != nil {
		return commandUsageError(verb, err.Error())
	}
	if verb == "config" && o.example {
		return configExample(os.Stdout, o, flags)
	}
	if homeErr != nil && !flagSet(flags, "dir") && os.Getenv("WITHHOLD_DIR") == "" {
		return commandUsageError(verb, "cannot resolve home directory; set WITHHOLD_DIR or use --dir")
	}
	if verb == "config" && o.init {
		return configInit(os.Stdout, o, flags)
	}
	if verb == "init-ca" {
		if err = certstore.Init(o.dir); err != nil {
			fmt.Fprintln(os.Stderr, "withhold:", err)
			return 1
		}
		fmt.Fprintln(os.Stdout, "Created local CA; trust stores and application settings were not changed.")
		return 0
	}
	if o.preflight && o.json {
		return commandUsageError(verb, "--preflight cannot be combined with --json")
	}
	if verb == "setup" && o.trust != "manual" && o.trust != "system" {
		return commandUsageError(verb, "--trust must be system or manual")
	}
	o.dir, err = filepath.Abs(o.dir)
	if err != nil {
		return 2
	}
	if o.port < 1 || o.port > 65535 {
		return commandUsageError(verb, "--port must be 1-65535")
	}
	var c config.Config
	var loadErr error
	if owner != nil {
		c = *owner.Configuration
		// The test-only scope override is inherited by the private child, never
		// read from public config or a working-directory file.
		c.AllowHosts = strings.Split(os.Getenv("WITHHOLD_TEST_ALLOW_HOSTS"), ",")
		if c.Integration != owner.Integration || c.Proxy.Port != owner.Port {
			fmt.Fprintln(os.Stderr, "withhold: runtime configuration differs from its private session")
			return 1
		}
	} else {
		c, loadErr = o.resolve(flags)
	}
	configError := ""
	needsConfig := verb == "on" || verb == "serve" || verb == "doctor" || verb == "config" || verb == "setup" || verb == "launch"
	var scope policy.Profile
	if needsConfig {
		if loadErr != nil {
			configError = loadErr.Error()
		}
		if err = c.Validate(); err != nil {
			configError = err.Error()
		}
		get := os.Getenv
		if owner != nil {
			get = nil // Private children consume recorded settings, not new overrides.
		}
		application, appErr := integrations.Configure(c.Integration, c.Application, get)
		if appErr != nil {
			configError = appErr.Error()
		} else {
			c.Application = application
		}
		if strings.TrimSpace(c.Proxy.SuspicionPattern) == "" {
			if pattern, e := integrations.SuspicionDefault(c.Integration); e == nil {
				c.Proxy.SuspicionPattern = pattern
			}
		}
		scope, err = integrations.Traffic(c.Integration, c.Scope(), c.Application)
		if err != nil {
			configError = err.Error()
		}
		if configError != "" && verb != "doctor" {
			return commandUsageError(verb, configError)
		}
	}
	// Recovery never depends on startup policy or configuration validity.
	if !needsConfig && (c.Proxy.Port < 1 || c.Proxy.Port > 65535) {
		c.Proxy.Port = o.port
	}
	o.use(c)
	cap, _ := config.Size(o.max)
	startupTimeout, _ := time.ParseDuration(c.StartupTimeout)
	var roots *x509.CertPool
	if needsConfig && o.upstreamCA != "" {
		roots, err = x509.SystemCertPool()
		if err != nil {
			roots = x509.NewCertPool()
		}
		data, e := os.ReadFile(o.upstreamCA)
		if e != nil || !roots.AppendCertsFromPEM(data) {
			if verb != "doctor" {
				return commandUsageError(verb, "cannot load upstream roots from --upstream-ca; provide a readable PEM certificate file")
			}
			configError = "cannot load upstream roots"
		}
	}
	if verb == "config" {
		application, err := integrations.Application(c.Integration, applicationOptions(home, c))
		if err == nil {
			_, err = application.Resolve()
		}
		if err != nil {
			return commandUsageError(verb, err.Error())
		}
		if !o.json {
			data, err := config.TOML(c)
			if err != nil {
				fmt.Fprintln(os.Stderr, "withhold: cannot render effective TOML configuration")
				return 1
			}
			path := o.configPath
			if path == "" {
				path = filepath.Join(o.dir, "config.toml")
			}
			if absolute, err := filepath.Abs(path); err == nil {
				path = absolute
			}
			displayPath := strings.NewReplacer("\r", `\r`, "\n", `\n`).Replace(path)
			if _, err := fmt.Fprintf(os.Stdout, "# Configuration file: %s\n", displayPath); err != nil {
				return 1
			}
			if _, err := os.Lstat(path); os.IsNotExist(err) {
				if _, err := fmt.Fprintln(os.Stdout, "# No file found; use 'withhold config --init' with the same selection to create one."); err != nil {
					return 1
				}
			}
			if _, err := fmt.Fprintln(os.Stdout, "# Effective settings for a new session. Saving this snapshot pins defaults and may expose private paths."); err != nil {
				return 1
			}
			if _, err := os.Stdout.Write(data); err != nil {
				return 1
			}
			return 0
		}
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		if encoder.Encode(c) != nil {
			return 1
		}
		return 0
	}
	if verb != "serve" {
		portSet := false
		flags.Visit(func(f *flag.Flag) {
			if f.Name == "port" {
				portSet = true
			}
		})
		lookup := func(id string) (integration.Application, error) {
			options := applicationOptions(home, c)
			// Recovery uses the recorded resource; malformed current adapter
			// settings must not prevent constructing its restore implementation.
			if id != c.Integration {
				options.Settings = nil
			}
			if !needsConfig {
				normalized, err := integrations.Configure(id, options.Settings, os.Getenv)
				if err != nil {
					options.Settings = nil
				} else {
					options.Settings = normalized
				}
			} else if verb == "doctor" && configError != "" {
				options.Settings = nil
			}
			return integrations.Application(id, options)
		}
		application, appErr := lookup(c.Integration)
		if appErr != nil && (!needsConfig || verb == "doctor") {
			application, appErr = lookup(integrations.Default)
		}
		if appErr != nil {
			return commandUsageError(verb, appErr.Error())
		}
		rc := session.Run(session.Options{Verb: verb, Dir: o.dir, Port: o.port, PortSet: portSet, JSON: o.json, Preflight: o.preflight, KeepFiles: o.keep, Debug: o.debug, TrustMode: o.trust, BinDir: o.binDir, ApplicationArgs: applicationArgs, StartupTimeout: startupTimeout, ConfigError: configError, Integration: c.Integration, Application: application, LookupApplication: lookup, Configuration: &c, EnvironmentID: configurationID(c)})
		if verb == "install" && rc == 0 {
			installConfig(os.Stdout, o)
		}
		return rc
	}
	ca, err := certstore.Load(o.dir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "withhold:", err)
		return 1
	}
	binary, err := os.Executable()
	if err != nil {
		return 1
	}
	workerEnvironment := c.WorkerEnvironment(os.Environ())
	filteredEnvironment := workerEnvironment[:0]
	for _, entry := range workerEnvironment {
		key, _, _ := strings.Cut(entry, "=")
		if !strings.EqualFold(key, "WITHHOLD_INTERNAL_DEBUG_FINDINGS") {
			filteredEnvironment = append(filteredEnvironment, entry)
		}
	}
	debugSetting := "WITHHOLD_INTERNAL_DEBUG_FINDINGS=0"
	if o.debug {
		debugSetting = "WITHHOLD_INTERNAL_DEBUG_FINDINGS=1"
	}
	workerEnvironment = append(filteredEnvironment, debugSetting)
	pool := scanpool.NewWithEnvironment(binary, workerEnvironment, "_scanner", "--body")
	defer pool.Close()
	var ctl *control.Server
	if owner != nil {
		build, e := session.BuildID(binary)
		if e != nil || build != owner.Build {
			return 1
		}
		ctl = &control.Server{Identity: owner.Identity, PID: os.Getpid(), Build: build}
	}
	debugPath := ""
	if o.debug {
		debugPath = filepath.Join(o.dir, "debug-findings.log")
	}
	p, err := proxy.New(proxy.Config{Control: ctl, CA: ca, Scope: scope, Scanner: pool, Roots: roots, Observe: o.observe, MaxBytes: cap, ScanTimeout: o.timeout, AuditPath: o.audit, HintPath: o.hint, DebugPath: debugPath})
	if err != nil {
		fmt.Fprintln(os.Stderr, "withhold:", err)
		return 2
	}
	defer p.Close()
	if ctl != nil {
		ctl.Stop = p.Close
	}
	// Prove the selected self-worker and its detector canaries work before listening.
	ctx, cancel := context.WithTimeout(context.Background(), o.timeout)
	_, err = pool.Scan(ctx, []byte(`{}`), cap)
	cancel()
	if err != nil {
		fmt.Fprintln(os.Stderr, "withhold: native scanner startup failed")
		return 1
	}
	listener, err := net.Listen("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(o.port)))
	if err != nil {
		fmt.Fprintln(os.Stderr, "withhold: cannot bind loopback listener")
		return 1
	}
	if owner != nil {
		current, e := session.LoadRecord(ownerPath)
		if e != nil || current.Identity != owner.Identity || current.PID != owner.PID {
			_ = listener.Close()
			return 1
		}
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	after := context.AfterFunc(ctx, p.Close)
	defer after()
	fmt.Fprintf(os.Stderr, "withhold: listening on %s\n", listener.Addr())
	if o.debug {
		fmt.Fprintf(os.Stderr, "withhold: debug findings enabled: %s (human-readable, detections only)\n", debugPath)
	}
	if o.observe {
		fmt.Fprintln(os.Stderr, "withhold: OBSERVE mode is active; secrets can be forwarded unchanged.")
	}
	err = p.Serve(listener)
	if err != nil && !errors.Is(err, http.ErrServerClosed) && !errors.Is(err, net.ErrClosed) {
		fmt.Fprintln(os.Stderr, "withhold: proxy stopped")
		return 1
	}
	return 0
}

func main() {
	defer func() {
		if recover() != nil {
			_, _ = io.WriteString(os.Stderr, "withhold: runtime failed\n")
			os.Exit(1)
		}
	}()
	os.Exit(run(os.Args[1:]))
}
