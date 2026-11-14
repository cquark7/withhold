package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"

	"github.com/cquark7/withhold/internal/config"
	"github.com/cquark7/withhold/internal/localstate"
)

func configInit(w io.Writer, o cliOptions, flags *flag.FlagSet) int {
	var unsupported string
	flags.Visit(func(option *flag.Flag) {
		switch option.Name {
		case "init", "dir", "config":
		default:
			unsupported = option.Name
		}
	})
	if unsupported != "" {
		return commandUsageError("config", "--init accepts only agent names, --dir and --config; omit --"+unsupported)
	}
	if flagSet(flags, "config") && o.configPath == "" {
		return commandUsageError("config", "--config requires a file path")
	}
	if _, err := applicationExamples(flags.Args()); err != nil {
		return commandUsageError("config", err.Error())
	}
	path := o.configPath
	if path == "" {
		path = filepath.Join(o.dir, "config.toml")
	}
	path, err := filepath.Abs(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, "withhold: cannot resolve configuration path")
		return 1
	}
	if err = createConfig(path, flags.Args()); err != nil {
		if errors.Is(err, os.ErrExist) {
			fmt.Fprintf(os.Stderr, "withhold: configuration already exists; not overwritten: %s\n", path)
		} else {
			fmt.Fprintf(os.Stderr, "withhold: cannot create configuration: %v\n", err)
		}
		return 1
	}
	fmt.Fprintf(w, "Created configuration: %s\nEdit this file, then view effective settings with 'withhold config'.\n", path)
	return 0
}

func createConfig(path string, agents []string) error {
	application, err := applicationExamples(agents)
	if err != nil {
		return err
	}
	text := config.Starter(agents, runtime.GOOS, application)
	return localstate.Write(path, []byte(text), true)
}

// Installation creates only the default file, and never changes an existing
// file or an explicitly selected configuration path.
func installConfig(w io.Writer, o cliOptions) {
	if o.configPath != "" {
		fmt.Fprintf(w, "Configuration selected by WITHHOLD_CONFIG: %s\n", o.configPath)
		return
	}
	path := filepath.Join(o.dir, "config.toml")
	if _, err := os.Lstat(path); err == nil {
		fmt.Fprintf(w, "Existing configuration left unchanged: %s\n", path)
		return
	} else if !os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "withhold: installed, but cannot check configuration: %v\n", err)
		return
	}
	if err := createConfig(path, nil); err != nil {
		if errors.Is(err, os.ErrExist) {
			fmt.Fprintf(w, "Existing configuration left unchanged: %s\n", path)
		} else {
			fmt.Fprintf(os.Stderr, "withhold: installed, but could not create configuration: %v\nRun 'withhold config --init' to retry.\n", err)
		}
		return
	}
	fmt.Fprintf(w, "Created configuration: %s\nView effective settings with 'withhold config'.\n", path)
}
