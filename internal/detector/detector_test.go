package detector

import (
	"testing"

	"github.com/betterleaks/betterleaks/v2/scan"
)

func TestPatchedStockRulesPrecompile(t *testing.T) {
	cfg, err := detectorConfig()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := scan.New(cfg, append(engineOptions(""), scan.WithPrecompile())...); err != nil {
		t.Fatal(err)
	}
}
