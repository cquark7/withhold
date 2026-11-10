package scanpool

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"

	"github.com/cquark7/withhold/internal/detector"
	"github.com/cquark7/withhold/internal/worker"
)

// NewInspection reuses isolated workers without enabling body rewriting or
// inheriting private debug/engine overrides from the invoking environment.
func NewInspection(binary string, environment []string, secrets bool, selection string) *Pool {
	filtered := make([]string, 0, len(environment)+2)
	for _, entry := range environment {
		key, _, _ := strings.Cut(entry, "=")
		if !strings.EqualFold(key, "WITHHOLD_PII") && !strings.EqualFold(key, "WITHHOLD_INTERNAL_SCAN_SECRETS") && !strings.EqualFold(key, "WITHHOLD_INTERNAL_DEBUG_FINDINGS") {
			filtered = append(filtered, entry)
		}
	}
	setting := "0"
	if secrets {
		setting = "1"
	}
	filtered = append(filtered, "WITHHOLD_PII="+selection, "WITHHOLD_INTERNAL_SCAN_SECRETS="+setting)
	p := NewWithEnvironment(binary, filtered, "_scanner", "--text")
	p.inspection, p.secrets = true, secrets
	if !secrets && p.pii == nil && p.configErr == nil {
		p.configErr = errors.New("no detectors selected")
	}
	return p
}

func decodeText(data []byte, target any) error {
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(target); err != nil {
		return errScan
	}
	if d.Decode(new(any)) != io.EOF {
		return errScan
	}
	return nil
}

func (p *Pool) Inspect(ctx context.Context, text []byte) ([]detector.TextFinding, error) {
	if !p.inspection {
		return nil, errScan
	}
	var reply worker.TextResponse
	err := p.exchange(ctx, text, nil, func(data []byte) error {
		if decodeText(data, &reply) != nil || reply.Schema != 1 || len(reply.Findings) > detector.MaxTextFindings {
			return errScan
		}
		if reply.Error != "" {
			if len(reply.Findings) != 0 || reply.Error != "finding-limit" && reply.Error != "detector-error" {
				return errScan
			}
			return nil
		}
		if reply.Findings == nil {
			return errScan
		}
		for _, f := range reply.Findings {
			if !p.validTextFinding(f, len(text)) {
				return errScan
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if reply.Error == "finding-limit" {
		return nil, detector.ErrFindingLimit
	}
	if reply.Error != "" {
		return nil, errScan
	}
	return reply.Findings, nil
}

func (p *Pool) validTextFinding(f detector.TextFinding, size int) bool {
	if f.Start < 0 || f.End <= f.Start || f.End > size || f.StartLine < 1 || f.EndLine < f.StartLine || f.EndLine > size+1 || f.StartColumn < 1 || f.EndColumn < 1 || f.StartColumn > size+1 || f.EndColumn > size+1 {
		return false
	}
	if f.StartLine == f.EndLine && f.EndColumn <= f.StartColumn {
		return false
	}
	if len(f.RuleID) == 0 || len(f.RuleID) > 128 {
		return false
	}
	for _, c := range f.RuleID {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.') {
			return false
		}
	}
	if f.Kind == "secret" {
		return p.secrets && !strings.HasPrefix(f.RuleID, "pii-")
	}
	if f.Kind == "pii" && p.pii != nil && !f.Encoded {
		for _, category := range p.pii.Categories {
			if f.RuleID == "pii-"+category {
				return true
			}
		}
	}
	return false
}
