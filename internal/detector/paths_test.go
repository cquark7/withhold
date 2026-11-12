package detector

import "testing"

func TestDefaultPathFilterUsesBundledDependencyAndGeneratedPathExclusions(t *testing.T) {
	skip, err := DefaultPathFilter()
	if err != nil {
		t.Fatal(err)
	}
	for path, excluded := range map[string]bool{
		"project/node_modules":                     true,
		"project/packages/app/node_modules/pkg.js": true,
		"project/vendor/github.com/module":         true,
		"project/package-lock.json":                true,
		"project/venv/lib":                         true,
		"project/assets/font.woff2":                true,
		"project/.env":                             false,
		"project/.gitignore":                       false,
		"project/src/node_modules_helper.js":       false,
		"project/vendor/custom/config.env":         false,
	} {
		if got := skip(path); got != excluded {
			t.Errorf("skip(%q)=%t, want %t", path, got, excluded)
		}
	}
}
