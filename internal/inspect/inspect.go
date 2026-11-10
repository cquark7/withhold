// Package inspect scans bounded local text inputs without rewriting or state.
package inspect

import (
	"bytes"
	"context"
	"errors"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/cquark7/withhold/internal/detector"
)

type Scanner interface {
	Inspect(context.Context, []byte) ([]detector.TextFinding, error)
}

type Options struct {
	Paths    []string
	Text     *string
	Stdin    io.Reader
	Exclude  []string
	SkipPath func(string) bool
	MaxBytes int64
	Timeout  time.Duration
}

type Input struct {
	Source string  `json:"source"`
	Path   *string `json:"path"`
}

func (i Input) Label() string {
	if i.Path != nil {
		return *i.Path
	}
	return "<" + i.Source + ">"
}

type Result struct {
	Input
	Findings []detector.TextFinding
	Bytes    int64
	Scanned  bool
	Skipped  string
	Error    string
}

type Summary struct {
	Complete           bool           `json:"complete"`
	InputsScanned      int            `json:"inputs_scanned"`
	FilesScanned       int            `json:"files_scanned"`
	BytesScanned       int64          `json:"bytes_scanned"`
	Findings           int            `json:"findings"`
	InputsWithFindings int            `json:"inputs_with_findings"`
	Skipped            map[string]int `json:"skipped"`
	Errors             int            `json:"errors"`
}

type target struct {
	abs  string
	info fs.FileInfo
	err  error
}

func contains(parent, child string) bool {
	rel, err := filepath.Rel(parent, child)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// A recursive root cannot own an explicitly selected path beneath a pruned
// metadata directory or a symlinked directory that discovery will not enter.
func discoveredBy(parent, child string) bool {
	if !contains(parent, child) {
		return false
	}
	relative, _ := filepath.Rel(parent, child)
	parts := strings.Split(relative, string(filepath.Separator))
	path := parent
	for index, part := range parts {
		if part == ".git" {
			return false
		}
		path = filepath.Join(path, part)
		if index < len(parts)-1 {
			info, err := os.Lstat(path)
			if err != nil || !info.IsDir() {
				return false
			}
		}
	}
	return true
}

// Run admits at most three inputs at once, reducing parallelism for larger caps
// so retained input is bounded by 128 MiB (plus one overflow byte per input).
// Discovery and result reordering have the same bounded lookahead. Workers own
// their input through reading and scanning; unrelated files are never joined.
func Run(ctx context.Context, o Options, scanner Scanner, yield func(Result) error) (Summary, error) {
	summary := Summary{Complete: true, Skipped: make(map[string]int)}
	if o.MaxBytes <= 0 || o.MaxBytes > 128*1024*1024 || o.Timeout <= 0 {
		return summary, errors.New("invalid inspection limits")
	}
	ctx, cancel := context.WithCancel(ctx)
	var running sync.WaitGroup
	defer func() { cancel(); running.Wait() }()
	workers := max(1, min(3, int((128*1024*1024)/(o.MaxBytes+1))))
	var pending []<-chan Result
	consume := func(r Result) error {
		if r.Skipped != "" {
			summary.Skipped[r.Skipped]++
		}
		if r.Error != "" {
			summary.Errors++
			summary.Complete = false
		}
		if r.Scanned {
			summary.InputsScanned++
			if r.Source == "file" {
				summary.FilesScanned++
			}
			summary.BytesScanned += r.Bytes
		}
		summary.Findings += len(r.Findings)
		if len(r.Findings) != 0 {
			summary.InputsWithFindings++
		}
		return yield(r)
	}
	drainOne := func() error {
		r := <-pending[0]
		pending = pending[1:]
		return consume(r)
	}
	drain := func() error {
		for len(pending) > 0 {
			if err := drainOne(); err != nil {
				return err
			}
		}
		return nil
	}
	submit := func(task func(context.Context) Result) error {
		if len(pending) == workers {
			if err := drainOne(); err != nil {
				return err
			}
		}
		ch := make(chan Result, 1)
		pending = append(pending, ch)
		running.Go(func() {
			job, stop := context.WithTimeout(ctx, o.Timeout)
			defer stop()
			ch <- task(job)
		})
		return nil
	}
	if o.Text != nil {
		err := submit(func(job context.Context) Result {
			return scanReader(job, Input{Source: "text"}, strings.NewReader(*o.Text), true, o.MaxBytes, scanner)
		})
		if err != nil {
			return summary, err
		}
	} else {
		cwd, err := os.Getwd()
		if err != nil {
			return summary, errors.New("cannot resolve working directory")
		}
		var exclusions []string
		for _, name := range o.Exclude {
			absolute, err := filepath.Abs(name)
			if err != nil {
				return summary, errors.New("cannot resolve exclusion")
			}
			exclusions = append(exclusions, absolute)
		}
		excluded := func(name string) bool {
			for _, exclusion := range exclusions {
				if contains(exclusion, name) {
					return true
				}
			}
			return false
		}
		prefiltered := func(name string) bool {
			return o.SkipPath != nil && o.SkipPath(filepath.ToSlash(name))
		}
		inputFor := func(absolute string) Input {
			name := absolute
			if contains(cwd, absolute) {
				name, _ = filepath.Rel(cwd, absolute)
			}
			return Input{Source: "file", Path: &name}
		}
		var targets []target
		requested := make(map[string]bool)
		for _, name := range o.Paths {
			if name == "-" {
				targets = append(targets, target{abs: "-"})
				continue
			}
			absolute, err := filepath.Abs(name)
			if err != nil {
				return summary, errors.New("cannot resolve input path")
			}
			info, err := os.Lstat(absolute)
			targets = append(targets, target{abs: absolute, info: info, err: err})
			requested[absolute] = true
		}
		for index, t := range targets {
			if ctx.Err() != nil {
				break
			}
			if t.abs == "-" {
				if err := submit(func(job context.Context) Result {
					return scanReader(job, Input{Source: "stdin"}, o.Stdin, true, o.MaxBytes, scanner)
				}); err != nil {
					return summary, err
				}
				continue
			}
			duplicate := false
			for other, parent := range targets {
				if other != index && (parent.abs == t.abs && other < index || parent.abs != t.abs && parent.info != nil && t.info != nil && parent.info.IsDir() && discoveredBy(parent.abs, t.abs)) {
					duplicate = true
					break
				}
			}
			if duplicate {
				continue
			}
			input := inputFor(t.abs)
			if excluded(t.abs) || t.err != nil || !t.info.IsDir() && !t.info.Mode().IsRegular() {
				r := Result{Input: input, Error: "read-error"}
				if excluded(t.abs) {
					r.Error, r.Skipped = "", "excluded"
				} else if t.err == nil {
					r.Error = "unsupported-input"
				}
				if err := submit(func(context.Context) Result { return r }); err != nil {
					return summary, err
				}
				continue
			}
			if prefiltered(t.abs) {
				if err := submit(func(context.Context) Result { return Result{Input: input, Skipped: "default-excluded"} }); err != nil {
					return summary, err
				}
				continue
			}
			rootPath, fileName := t.abs, "."
			if !t.info.IsDir() {
				rootPath, fileName = filepath.Dir(t.abs), filepath.Base(t.abs)
			}
			root, err := os.OpenRoot(rootPath)
			if err == nil && t.info.IsDir() {
				actual, statErr := root.Stat(".")
				if statErr != nil || !os.SameFile(t.info, actual) {
					err = errors.New("input directory changed")
				}
			}
			if err != nil {
				if root != nil {
					_ = root.Close()
				}
				if err := submit(func(context.Context) Result { return Result{Input: input, Error: "read-error"} }); err != nil {
					return summary, err
				}
				continue
			}
			visit := func(name string, info fs.FileInfo, explicit bool) error {
				input := inputFor(filepath.Join(rootPath, filepath.FromSlash(name)))
				return submit(func(job context.Context) Result {
					f, err := openRegular(root, name, info)
					if err != nil {
						return Result{Input: input, Error: "read-error"}
					}
					defer f.Close()
					return scanReader(job, input, f, explicit, o.MaxBytes, scanner)
				})
			}
			if !t.info.IsDir() {
				err = visit(fileName, t.info, true)
			} else {
				err = fs.WalkDir(root.FS(), ".", func(name string, entry fs.DirEntry, walkErr error) error {
					if ctx.Err() != nil {
						return ctx.Err()
					}
					absolute := filepath.Join(rootPath, filepath.FromSlash(name))
					input := inputFor(absolute)
					if walkErr != nil {
						return submit(func(context.Context) Result { return Result{Input: input, Error: "walk-error"} })
					}
					if excluded(absolute) || entry.IsDir() && entry.Name() == ".git" || prefiltered(absolute) {
						reason := "excluded"
						if !excluded(absolute) {
							reason = "default-excluded"
							if entry.IsDir() && entry.Name() == ".git" {
								reason = "git-metadata"
							}
						}
						if err := submit(func(context.Context) Result { return Result{Input: input, Skipped: reason} }); err != nil {
							return err
						}
						if entry.IsDir() {
							return fs.SkipDir
						}
						return nil
					}
					if entry.IsDir() {
						return nil
					}
					if !entry.Type().IsRegular() {
						reason := "non-regular"
						if entry.Type()&os.ModeSymlink != 0 {
							reason = "symlink"
						}
						r := Result{Input: input, Skipped: reason}
						if requested[absolute] {
							r.Error = "unsupported-input"
						}
						return submit(func(context.Context) Result { return r })
					}
					info, err := entry.Info()
					if err != nil {
						return submit(func(context.Context) Result { return Result{Input: input, Error: "read-error"} })
					}
					return visit(name, info, requested[absolute])
				})
			}
			// Submitted tasks retain the root handle until all reads complete.
			drainErr := drain()
			_ = root.Close()
			if drainErr != nil {
				return summary, drainErr
			}
			if err != nil && ctx.Err() == nil {
				return summary, err
			}
		}
	}
	if err := drain(); err != nil {
		return summary, err
	}
	if ctx.Err() != nil {
		if err := consume(Result{Input: Input{Source: "scan"}, Error: "cancelled"}); err != nil {
			return summary, err
		}
	}
	return summary, nil
}

func openRegular(root *os.Root, name string, expected fs.FileInfo) (*os.File, error) {
	f, err := openRead(root, name)
	if err != nil {
		return nil, err
	}
	actual, err := f.Stat()
	current, pathErr := root.Lstat(name)
	if err != nil || pathErr != nil || !actual.Mode().IsRegular() || !current.Mode().IsRegular() || !os.SameFile(expected, actual) || !os.SameFile(current, actual) {
		_ = f.Close()
		return nil, errors.New("input changed or is not a regular file")
	}
	return f, nil
}

func scanReader(ctx context.Context, input Input, reader io.Reader, explicit bool, cap int64, scanner Scanner) Result {
	r := Result{Input: input}
	if reader == nil {
		r.Error = "read-error"
		return r
	}
	if closer, ok := reader.(io.Closer); ok {
		stop := context.AfterFunc(ctx, func() { _ = closer.Close() })
		defer stop()
	}
	prefix, err := io.ReadAll(io.LimitReader(reader, min(512, cap+1)))
	if err != nil {
		r.Error = "read-error"
	} else if mime := http.DetectContentType(prefix); !strings.HasPrefix(mime, "text/") {
		r.Skipped = "binary"
	} else {
		var data []byte
		data, err = io.ReadAll(io.LimitReader(io.MultiReader(bytes.NewReader(prefix), reader), cap+1))
		switch {
		case err != nil:
			r.Error = "read-error"
		case int64(len(data)) > cap:
			r.Error = "over-cap"
		case !utf8.Valid(data):
			r.Skipped = "binary"
		default:
			r.Findings, err = scanner.Inspect(ctx, data)
			if err != nil {
				r.Error = "scanner-error"
				if errors.Is(err, detector.ErrFindingLimit) {
					r.Error = "finding-limit"
				}
			} else {
				r.Scanned, r.Bytes = true, int64(len(data))
			}
		}
	}
	if explicit && r.Skipped != "" {
		r.Error = "unsupported-input"
	}
	if ctx.Err() != nil {
		r.Scanned, r.Findings, r.Bytes = false, nil, 0
		r.Error = "cancelled"
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			r.Error = "timeout"
		}
	}
	return r
}
