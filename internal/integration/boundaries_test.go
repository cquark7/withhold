package integration_test

import (
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

func TestCoreDoesNotImportBuiltInOrTestIntegrations(t *testing.T) {
	_, source, _, _ := runtime.Caller(0)
	root := filepath.Dir(filepath.Dir(source))
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			if entry.Name() == "testintegration" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			return nil
		}
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
		if err != nil {
			return err
		}
		relative, _ := filepath.Rel(root, path)
		dir := strings.Split(filepath.ToSlash(relative), "/")[0]
		for _, spec := range file.Imports {
			dependency, _ := strconv.Unquote(spec.Path.Value)
			if dir != "integrations" && strings.Contains(dependency, "/internal/integrations") || strings.Contains(dependency, "/internal/testintegration") {
				t.Errorf("%s imports implementation %s", path, dependency)
			}
			if (dir == "scanner" || dir == "detector" || dir == "pii") && (dependency == "os" || dependency == "path/filepath" || dependency == "net/http") {
				t.Errorf("%s discovers runtime/application state through %s", path, dependency)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
