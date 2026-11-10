package inspect

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/cquark7/withhold/internal/detector"
	"github.com/cquark7/withhold/internal/pii"
)

type Selection struct {
	Secrets       bool          `json:"secrets"`
	SecretVersion string        `json:"secret_version,omitempty"`
	PII           *pii.Metadata `json:"pii,omitempty"`
	MaxBytes      int64         `json:"max_bytes"`
	ScanTimeout   string        `json:"scan_timeout"`
}

type ScanError struct {
	Input
	Code string `json:"code"`
}

// Output streams occurrences rather than retaining a repository-wide report.
// Only the first 128 error details are retained; the summary counts every error.
type Output struct {
	w           *bufio.Writer
	diagnostics io.Writer
	json        bool
	selection   Selection
	errors      []ScanError
	rows        int
}

func NewOutput(w, diagnostics io.Writer, machine bool, selection Selection) (*Output, error) {
	o := &Output{w: bufio.NewWriter(w), diagnostics: diagnostics, json: machine, selection: selection, errors: []ScanError{}}
	if machine {
		data, err := json.Marshal(selection)
		if err != nil {
			return nil, err
		}
		if _, err := fmt.Fprintf(o.w, `{"schema":1,"detectors":%s,"findings":[`, data); err != nil {
			return nil, err
		}
	}
	return o, nil
}

func displayPath(path string) string {
	if !utf8.ValidString(path) {
		return strconv.QuoteToGraphic(path)
	}
	for _, r := range path {
		if !strconv.IsPrint(r) {
			return strconv.QuoteToGraphic(path)
		}
	}
	return path
}

func (o *Output) Write(r Result) error {
	for _, f := range r.Findings {
		if o.json {
			data, err := json.Marshal(struct {
				Input
				detector.TextFinding
			}{r.Input, f})
			if err != nil {
				return err
			}
			if o.rows != 0 {
				if _, err := o.w.WriteString(","); err != nil {
					return err
				}
			}
			if _, err := o.w.Write(data); err != nil {
				return err
			}
		} else {
			note := ""
			if f.Encoded {
				note = " (encoded source)"
			}
			if _, err := fmt.Fprintf(o.w, "%s:%d:%d  %s  %s%s\n", displayPath(r.Label()), f.StartLine, f.StartColumn, f.Kind, f.RuleID, note); err != nil {
				return err
			}
		}
		o.rows++
	}
	if r.Error != "" {
		if len(o.errors) < 128 {
			o.errors = append(o.errors, ScanError{Input: r.Input, Code: r.Error})
		}
		if !o.json {
			if _, err := fmt.Fprintf(o.diagnostics, "withhold: %s: %s\n", displayPath(r.Label()), r.Error); err != nil {
				return err
			}
		}
	}
	return o.w.Flush()
}

func (o *Output) Finish(summary Summary) error {
	if o.json {
		data, err := json.Marshal(struct {
			Summary       Summary     `json:"summary"`
			Errors        []ScanError `json:"errors"`
			ErrorsOmitted int         `json:"errors_omitted"`
		}{summary, o.errors, max(0, summary.Errors-len(o.errors))})
		if err != nil {
			return err
		}
		if _, err := fmt.Fprintf(o.w, "],%s\n", data[1:]); err != nil {
			return err
		}
	} else {
		if o.rows != 0 {
			if _, err := o.w.WriteString("\n"); err != nil {
				return err
			}
		}
		message := "No findings"
		if summary.Findings != 0 {
			message = fmt.Sprintf("%d findings in %d inputs", summary.Findings, summary.InputsWithFindings)
		}
		if summary.InputsScanned == 0 && summary.Findings == 0 {
			message = "No eligible text inputs"
		}
		if !summary.Complete {
			message = fmt.Sprintf("Scan incomplete; %d findings; %d errors", summary.Findings, summary.Errors)
		}
		var skipped []string
		for reason, count := range summary.Skipped {
			skipped = append(skipped, fmt.Sprintf("%s: %d", reason, count))
		}
		sort.Strings(skipped)
		if len(skipped) != 0 {
			message += "; skipped (" + strings.Join(skipped, ", ") + ")"
		}
		pii := "off"
		if o.selection.PII != nil {
			pii = strings.Join(o.selection.PII.Categories, ",")
		}
		if _, err := fmt.Fprintf(o.w, "%s; %d inputs scanned (%d files). Secrets: %t; PII: %s.\n", message, summary.InputsScanned, summary.FilesScanned, o.selection.Secrets, pii); err != nil {
			return err
		}
	}
	return o.w.Flush()
}
