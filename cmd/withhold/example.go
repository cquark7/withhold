package main

import (
	"flag"
	"fmt"
	"io"
	"runtime"

	"github.com/cquark7/withhold/internal/config"
	"github.com/cquark7/withhold/internal/integrations"
)

func configExample(w io.Writer, o cliOptions, f *flag.FlagSet) int {
	var unsupported string
	f.Visit(func(option *flag.Flag) {
		if option.Name != "example" && option.Name != "integration" {
			unsupported = option.Name
		}
	})
	if unsupported != "" {
		return commandUsageError("config", "--example accepts only --integration; omit --"+unsupported)
	}
	id := o.integration
	if !flagSet(f, "integration") {
		id = env("WITHHOLD_INTEGRATION", id)
	}
	application, err := integrations.Example(id)
	if err != nil {
		return commandUsageError("config", err.Error())
	}
	if _, err := fmt.Fprint(w, config.Example(id, runtime.GOOS, application)); err != nil {
		return 1
	}
	return 0
}
