package detector

import (
	"context"
	"errors"

	"github.com/betterleaks/betterleaks/config"
	"github.com/betterleaks/betterleaks/detect"
	"github.com/betterleaks/betterleaks/sources"
	"github.com/pelletier/go-toml/v2"
)

// DefaultPathFilter delegates path selection to the bundled Betterleaks
// prefilter. Loading only that setting avoids initializing secret rules for
// PII-only scans; the rule-free detector supplies upstream's expression evaluator.
// Paths use forward slashes. No repository configuration or project ignore
// files are read.
func DefaultPathFilter() (func(string) bool, error) {
	var defaults struct {
		Prefilter string `toml:"prefilter"`
	}
	if err := toml.Unmarshal([]byte(config.DefaultConfig), &defaults); err != nil || defaults.Prefilter == "" {
		return nil, errors.New("cannot load bundled path prefilter")
	}
	cfg := &config.Config{Prefilter: defaults.Prefilter}
	if err := cfg.CompileFilters(nil); err != nil {
		return nil, errors.New("cannot compile bundled path prefilter")
	}
	skip := detect.NewDetectorContext(context.Background(), cfg, detect.ValidationOptions{}).SkipFunc()
	if skip == nil {
		return nil, errors.New("bundled path prefilter is unavailable")
	}
	return func(path string) bool {
		return skip(map[string]string{sources.AttrPath: path})
	}, nil
}
