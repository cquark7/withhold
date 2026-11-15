package main

import (
	"flag"
	"fmt"
	"io"
	"runtime"
	"strings"

	"github.com/cquark7/withhold/internal/config"
	"github.com/cquark7/withhold/internal/integrations"
)

func configExample(w io.Writer, o cliOptions, f *flag.FlagSet) int {
	var unsupported string
	f.Visit(func(option *flag.Flag) {
		if option.Name != "example" {
			unsupported = option.Name
		}
	})
	if unsupported != "" {
		return commandUsageError("config", "--example accepts only agent names; omit --"+unsupported)
	}
	application, err := applicationExamples(f.Args())
	if err != nil {
		return commandUsageError("config", err.Error())
	}
	if _, err := fmt.Fprint(w, config.Example(f.Args(), runtime.GOOS, application)); err != nil {
		return 1
	}
	return 0
}

func applicationExamples(ids []string) (string, error) {
	var out strings.Builder
	for _, id := range ids {
		example, err := integrations.Example(id)
		if err != nil {
			return "", err
		}
		out.WriteString(example)
		out.WriteByte('\n')
	}
	return out.String(), nil
}
