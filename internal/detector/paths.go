package detector

import (
	"errors"

	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/sources"
	"github.com/betterleaks/betterleaks/v2/sources/prefilter"
)

// DefaultPathFilter uses the bundled Betterleaks prefilter without building a
// scanner or reading repository configuration. Paths use forward slashes.
func DefaultPathFilter() (func(string) bool, error) {
	cfg, err := config.Default()
	if err != nil || cfg.PrefilterExpr == "" {
		return nil, errors.New("cannot load bundled path prefilter")
	}
	skip, err := prefilter.Compile(cfg.PrefilterExpr, prefilter.Options{})
	if err != nil || skip == nil {
		return nil, errors.New("cannot compile bundled path prefilter")
	}
	return func(path string) bool {
		return skip(map[string]string{sources.AttrPath: path})
	}, nil
}
