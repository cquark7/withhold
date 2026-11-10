package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/cquark7/withhold/internal/config"
	"github.com/cquark7/withhold/internal/detector"
	"github.com/cquark7/withhold/internal/inspect"
	"github.com/cquark7/withhold/internal/integrations"
	"github.com/cquark7/withhold/internal/pii"
	"github.com/cquark7/withhold/internal/scanpool"
)

// Scan accepts interspersed options and paths without changing launch's literal
// argument handling. Consume option values before recognizing help or paths.
func parseScanOptions(f *flag.FlagSet, args []string) (paths []string, showHelp bool, err error) {
	var options []string
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			paths = append(paths, args[i+1:]...)
			break
		}
		if arg == "--help" || arg == "-h" {
			return nil, true, nil
		}
		if arg == "-" || !strings.HasPrefix(arg, "-") {
			paths = append(paths, arg)
			continue
		}
		name, _, inline := strings.Cut(strings.TrimLeft(arg, "-"), "=")
		option := f.Lookup(name)
		if option == nil || !allowedFlag("scan", name) {
			return nil, false, errors.New("unknown or unsupported scan option")
		}
		options = append(options, arg)
		if !inline && !boolFlag(option) {
			if i+1 == len(args) {
				return nil, false, fmt.Errorf("--%s requires a value", name)
			}
			i++
			options = append(options, args[i])
		}
	}
	if f.Parse(options) != nil {
		return nil, false, errors.New("invalid scan option value")
	}
	return paths, false, nil
}

func scanConfiguration(o cliOptions, f *flag.FlagSet) (config.Config, error) {
	c := config.Defaults(integrations.Default, runtime.GOOS)
	if flagSet(f, "config") && o.configPath == "" {
		return c, errors.New("--config requires a file path")
	}
	path := o.configPath
	if path == "" {
		path = filepath.Join(o.dir, "config.toml")
	}
	c, err := config.Load(path, o.configPath != "", c)
	if err != nil {
		return c, errors.New("cannot load scan configuration; provide a valid schema-1 TOML file")
	}
	// Only detection-related environment overrides affect an offline scan.
	c.Environment(func(key string) string {
		if key == "WITHHOLD_PII" || key == "WITHHOLD_MAX_BYTES" {
			return os.Getenv(key)
		}
		return ""
	})
	if flagSet(f, "pii") {
		c.Protection.PII = strings.Split(o.pii, ",")
	}
	if flagSet(f, "confidence") {
		c.Scan.Confidence = o.confidence
	}
	if flagSet(f, "max-bytes") {
		c.Proxy.MaxBytes = o.max
	}
	if flagSet(f, "scan-timeout") {
		c.Proxy.ScanTimeout = o.timeout.String()
	}
	if err := c.Validate(); err != nil {
		return c, err
	}
	// Strictly validate the file's application schema, without ambient editor
	// overrides, application discovery, or constructing a traffic/session runtime.
	if _, err := integrations.Configure(c.Integration, c.Application, nil); err != nil {
		return c, errors.New("invalid integration/application settings in scan configuration")
	}
	return c, nil
}

func scan(out, diagnostics io.Writer, stdin *os.File, args []string) int {
	usage := func(message string) int {
		fmt.Fprintf(diagnostics, "withhold: %s\nRun 'withhold scan --help' for usage.\n", message)
		return 2
	}
	home, homeErr := os.UserHomeDir()
	o := defaultOptions(home)
	o.dir = env("WITHHOLD_DIR", o.dir)
	o.configPath = os.Getenv("WITHHOLD_CONFIG")
	f := o.flags("scan")
	paths, showHelp, err := parseScanOptions(f, args)
	if showHelp {
		return help(out, "scan")
	}
	if err != nil {
		return usage(err.Error())
	}
	if homeErr != nil && !flagSet(f, "dir") && os.Getenv("WITHHOLD_DIR") == "" && o.configPath == "" {
		return usage("cannot resolve home directory; use --dir or --config")
	}
	if flagSet(f, "text") && len(paths) != 0 {
		return usage("--text cannot be combined with paths or stdin")
	}
	if !flagSet(f, "text") && len(paths) == 0 {
		if inspect.IsTerminal(stdin) {
			return usage("provide a path, --text, or redirected stdin")
		}
		paths = []string{"-"}
	}
	stdinCount := 0
	for _, path := range paths {
		if path == "-" {
			stdinCount++
		}
	}
	if stdinCount > 1 {
		return usage("stdin may be specified only once")
	}
	for _, exclusion := range o.exclude {
		if exclusion == "" {
			return usage("--exclude requires a nonempty path")
		}
	}
	c, err := scanConfiguration(o, f)
	if err != nil {
		return usage(err.Error())
	}
	selection := strings.Join(c.Protection.PII, ",")
	meta, _ := pii.ConfigurationFor(selection)
	if !o.secrets && meta == nil {
		return usage("select at least one detector; use --pii all or enable --secrets")
	}
	cap, _ := config.Size(c.Proxy.MaxBytes)
	timeout, _ := time.ParseDuration(c.Proxy.ScanTimeout)
	settings := inspect.Selection{Secrets: o.secrets, PII: meta, Confidence: c.Scan.Confidence, MaxBytes: cap, ScanTimeout: timeout.String()}
	if o.secrets {
		settings.SecretVersion = detector.Version
	}
	options := inspect.Options{Paths: paths, Stdin: stdin, Exclude: o.exclude, MaxBytes: cap, Timeout: timeout}
	if flagSet(f, "text") {
		options.Text = &o.text
	} else if !o.noDefaultExcludes && (len(paths) != 1 || paths[0] != "-") {
		options.SkipPath, err = detector.DefaultPathFilter()
		if err != nil {
			return usage("cannot initialize bundled path prefilter")
		}
	}
	output, err := inspect.NewOutput(out, diagnostics, o.json, settings)
	if err != nil {
		return usage("cannot write scan report")
	}
	binary, err := os.Executable()
	if err != nil {
		return usage("cannot resolve bundled scanner")
	}
	pool := scanpool.NewInspection(binary, os.Environ(), o.secrets, selection, c.Scan.Confidence)
	defer pool.Close()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	progress := !o.json && inspect.IsTerminal(os.Stderr)
	lastProgress := time.Now()
	inputs := 0
	summary, err := inspect.Run(ctx, options, pool, func(result inspect.Result) error {
		if result.Scanned {
			inputs++
		}
		if progress && time.Since(lastProgress) >= time.Second {
			fmt.Fprintf(diagnostics, "withhold: %d text inputs scanned\n", inputs)
			lastProgress = time.Now()
		}
		return output.Write(result)
	})
	if err != nil || output.Finish(summary) != nil {
		fmt.Fprintln(diagnostics, "withhold: cannot complete scan report")
		return 2
	}
	if !summary.Complete {
		return 2
	}
	if summary.Findings != 0 {
		return 1
	}
	return 0
}
