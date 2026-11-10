package inspect

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/cquark7/withhold/internal/detector"
)

type scannerFunc func(context.Context, []byte) ([]detector.TextFinding, error)

func (f scannerFunc) Inspect(ctx context.Context, data []byte) ([]detector.TextFinding, error) {
	return f(ctx, data)
}

func TestTraversalIncludesIgnoredTextAndDeduplicatesOverlappingTargets(t *testing.T) {
	root := t.TempDir()
	t.Chdir(root)
	for name, data := range map[string]string{
		".env": "sensitive fixture", ".gitignore": ".env\n", "clean.txt": "ordinary text",
		"binary.dat": "\x00\x01", ".git/config": "metadata", "excluded/file": "excluded",
	} {
		if err := os.MkdirAll(filepath.Dir(name), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(name, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	fake := scannerFunc(func(context.Context, []byte) ([]detector.TextFinding, error) { return nil, nil })
	var paths []string
	summary, err := Run(context.Background(), Options{Paths: []string{".env", ".", "."}, Exclude: []string{"excluded"}, MaxBytes: 1024, Timeout: time.Second}, fake, func(r Result) error {
		if r.Scanned {
			paths = append(paths, *r.Path)
		}
		return nil
	})
	if err != nil || !summary.Complete || summary.FilesScanned != 3 || !reflect.DeepEqual(paths, []string{".env", ".gitignore", "clean.txt"}) || !reflect.DeepEqual(summary.Skipped, map[string]int{"binary": 1, "git-metadata": 1, "excluded": 1}) {
		t.Fatalf("paths=%v summary=%+v error=%v", paths, summary, err)
	}
	// A recursive root must not hide errors for explicitly requested children.
	summary, err = Run(context.Background(), Options{Paths: []string{".", "binary.dat", "missing"}, Exclude: []string{"excluded"}, MaxBytes: 1024, Timeout: time.Second}, fake, func(Result) error { return nil })
	if err != nil || summary.Complete || summary.Errors != 2 || summary.FilesScanned != 3 {
		t.Fatalf("explicit child errors lost: %+v, %v", summary, err)
	}
}

func TestPathPrefilterPrunesBeforeReadingAndCanBeDisabled(t *testing.T) {
	root := t.TempDir()
	t.Chdir(root)
	for name, data := range map[string]string{
		".env": "application text", "node_modules/pkg/index.js": "dependency text", "package-lock.json": "generated text",
	} {
		if err := os.MkdirAll(filepath.Dir(name), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(name, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	filter, err := detector.DefaultPathFilter()
	if err != nil {
		t.Fatal(err)
	}
	fake := scannerFunc(func(context.Context, []byte) ([]detector.TextFinding, error) { return nil, nil })
	options := Options{Paths: []string{".", "node_modules/pkg/index.js"}, MaxBytes: 1024, Timeout: time.Second}
	options.SkipPath = func(path string) bool {
		if strings.Contains(filepath.ToSlash(path), "/node_modules/") {
			t.Fatal("discovery entered a prefiltered directory")
		}
		if filepath.Base(path) == "package-lock.json" {
			// A prefiltered file must not be statted/opened by the reader.
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
		}
		return filter(path)
	}
	summary, err := Run(context.Background(), options, fake, func(Result) error { return nil })
	if err != nil || !summary.Complete || summary.FilesScanned != 1 || !reflect.DeepEqual(summary.Skipped, map[string]int{"default-excluded": 2}) {
		t.Fatalf("prefilter summary=%+v error=%v", summary, err)
	}
	options.SkipPath = nil
	summary, err = Run(context.Background(), options, fake, func(Result) error { return nil })
	if err != nil || !summary.Complete || summary.FilesScanned != 2 || len(summary.Skipped) != 0 {
		t.Fatalf("unfiltered summary=%+v error=%v", summary, err)
	}
}

func TestFailedInputsNeverProduceACompleteReportOrExposeRawErrors(t *testing.T) {
	for _, test := range []struct {
		name, text, code string
		fail             bool
	}{
		{"binary", "\x00\x01", "unsupported-input", false},
		{"oversized", strings.Repeat("x", 17), "over-cap", false},
		{"scanner failure", "text", "scanner-error", true},
		{"deadline", "text", "timeout", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			fake := scannerFunc(func(ctx context.Context, _ []byte) ([]detector.TextFinding, error) {
				if test.fail {
					return nil, errors.New("private raw detector diagnostic")
				}
				<-ctx.Done()
				return nil, ctx.Err()
			})
			var out, diagnostics bytes.Buffer
			output, _ := NewOutput(&out, &diagnostics, true, Selection{})
			summary, err := Run(context.Background(), Options{Text: &test.text, MaxBytes: 16, Timeout: 10 * time.Millisecond}, fake, output.Write)
			if err != nil || summary.Complete || summary.Errors != 1 || summary.InputsScanned != 0 || output.Finish(summary) != nil {
				t.Fatalf("summary=%+v error=%v", summary, err)
			}
			var report struct {
				Schema int
				Errors []ScanError
			}
			if json.Unmarshal(out.Bytes(), &report) != nil || report.Schema != 1 || len(report.Errors) != 1 || report.Errors[0].Code != test.code || strings.Contains(out.String()+diagnostics.String(), "private raw") {
				t.Fatalf("invalid or unsafe report: %s", &out)
			}
		})
	}
}

type failedWriter struct{}

func (failedWriter) Write([]byte) (int, error) { return 0, errors.New("write failed") }

func TestOutputEscapesPathsAndPropagatesWriteFailures(t *testing.T) {
	if got := displayPath("file\x9b31m.txt"); strings.Contains(got, "\x9b") || !strings.Contains(got, `\x9b`) {
		t.Fatalf("invalid UTF-8 path was not escaped: %q", got)
	}
	path := "file\n\x1b[31m.txt"
	r := Result{Input: Input{Source: "file", Path: &path}, Findings: []detector.TextFinding{{RuleID: "aws-access-token", Kind: "secret", StartLine: 2, StartColumn: 3}}}
	var out bytes.Buffer
	o, _ := NewOutput(&out, &out, false, Selection{})
	if o.Write(r) != nil || strings.Contains(out.String(), "\x1b") || !strings.Contains(out.String(), `file\n\x1b[31m.txt`) {
		t.Fatalf("unsafe path output: %q", out.String())
	}
	o, _ = NewOutput(failedWriter{}, &out, true, Selection{})
	if o.Write(r) == nil {
		t.Fatal("output failure was ignored")
	}
}
