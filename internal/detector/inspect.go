package detector

import (
	"context"
	"errors"
	"slices"
	"sort"
	"strings"

	"github.com/betterleaks/betterleaks/v2/report"
)

const MaxTextFindings = 10_000

var ErrFindingLimit = errors.New("text finding limit exceeded")

// TextFinding is value-free. Ranges refer to the original UTF-8 input, not a
// captured secret: decoded findings can cover their encoded source container.
// Bytes are zero-based and half-open; lines/byte columns are one-based, with
// the end position exclusive.
type TextFinding struct {
	RuleID      string `json:"rule_id"`
	Kind        string `json:"kind"`
	Start       int    `json:"start"`
	End         int    `json:"end"`
	StartLine   int    `json:"start_line"`
	StartColumn int    `json:"start_column"`
	EndLine     int    `json:"end_line"`
	EndColumn   int    `json:"end_column"`
	Encoded     bool   `json:"encoded"`
}

const sourceBlock = 4096

type sourceCheckpoint struct{ line, lineStart int }

// Sparse byte checkpoints bound location-index memory even for newline-heavy
// files. Each lookup examines at most one block, independent of line length.
type sourceIndex struct {
	text        string
	checkpoints []sourceCheckpoint
}

func indexSource(text string) *sourceIndex {
	index := &sourceIndex{text: text}
	line, lineStart := 1, 0
	for start := 0; start <= len(text); start += sourceBlock {
		index.checkpoints = append(index.checkpoints, sourceCheckpoint{line, lineStart})
		block := text[start:min(len(text), start+sourceBlock)]
		line += strings.Count(block, "\n")
		if last := strings.LastIndexByte(block, '\n'); last >= 0 {
			lineStart = start + last + 1
		}
	}
	return index
}

func (s *sourceIndex) position(offset int) (int, int) {
	blockStart := offset / sourceBlock * sourceBlock
	checkpoint := s.checkpoints[offset/sourceBlock]
	block := s.text[blockStart:offset]
	lineStart := checkpoint.lineStart
	if last := strings.LastIndexByte(block, '\n'); last >= 0 {
		lineStart = blockStart + last + 1
	}
	return checkpoint.line + strings.Count(block, "\n"), offset - lineStart + 1
}

func (s *sourceIndex) offset(line, column int) (int, error) {
	block := sort.Search(len(s.checkpoints), func(i int) bool { return s.checkpoints[i].line > line }) - 1
	if block < 0 || column < 1 {
		return 0, errors.New("invalid detector location")
	}
	checkpoint := s.checkpoints[block]
	start, cursor := checkpoint.lineStart, block*sourceBlock
	for checkpoint.line < line {
		next := strings.IndexByte(s.text[cursor:], '\n')
		if next < 0 {
			return 0, errors.New("invalid detector location")
		}
		cursor += next + 1
		start = cursor
		checkpoint.line++
	}
	offset := start + column - 1
	if offset < start || offset > len(s.text) {
		return 0, errors.New("invalid detector location")
	}
	if actualLine, actualColumn := s.position(offset); actualLine != line || actualColumn != column {
		return 0, errors.New("invalid detector location")
	}
	return offset, nil
}

// Betterleaks reports inclusive byte columns, with column zero at a line boundary.
func offsets(index **sourceIndex, text string, loc report.Location, full string, encoded bool) (start, end int, err error) {
	if *index == nil {
		*index = indexSource(text)
	}
	start, err = (*index).offset(loc.StartLine, loc.StartColumn)
	if err != nil {
		return 0, 0, err
	}
	if !encoded && full != "" {
		// RC9 trims leading newlines from Match.Full without advancing Start.
		for start < len(text) && text[start] == '\n' {
			start++
		}
		if !strings.HasPrefix(text[start:], full) {
			return 0, 0, errors.New("invalid detector match")
		}
		return start, start + len(full), nil
	}
	end, err = (*index).offset(loc.EndLine, loc.EndColumn+1)
	if err != nil || end <= start {
		return 0, 0, errors.New("invalid detector location")
	}
	return start, end, nil
}

// Inspect never rewrites input, resolves placeholder keys, or exposes values.
func (d *Detector) Inspect(ctx context.Context, text string) ([]TextFinding, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var index *sourceIndex
	locations := func() *sourceIndex {
		if index == nil {
			index = indexSource(text)
		}
		return index
	}
	findings := make([]TextFinding, 0)
	seen := make(map[TextFinding]bool)
	appendSpan := func(rule, kind string, start, end int, encoded bool) error {
		if start < 0 || end <= start || end > len(text) {
			return errors.New("invalid detector location")
		}
		sl, sc := locations().position(start)
		el, ec := locations().position(end)
		f := TextFinding{RuleID: rule, Kind: kind, Start: start, End: end, StartLine: sl, StartColumn: sc, EndLine: el, EndColumn: ec, Encoded: encoded}
		if !seen[f] {
			if len(findings) == MaxTextFindings {
				return ErrFindingLimit
			}
			seen[f] = true
			findings = append(findings, f)
		}
		return nil
	}
	if d.engine != nil {
		err := d.scanText(ctx, d.engine, text, func(f report.Finding) error {
			if f.ComponentSetsTruncated {
				return ErrFindingLimit
			}
			return visitFinding(f, func(rule string, match report.Match, loc report.Location, encoded bool) error {
				start, end, err := offsets(&index, text, loc, match.Full, encoded)
				if err != nil {
					return err
				}
				return appendSpan(rule, "secret", start, end, encoded)
			})
		})
		if err != nil {
			return nil, err
		}
	}
	for _, f := range d.pii.Scan(text) {
		if err := appendSpan(f.RuleID, "pii", f.Start, f.End, false); err != nil {
			return nil, err
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	slices.SortFunc(findings, func(a, b TextFinding) int {
		if a.Start != b.Start {
			return a.Start - b.Start
		}
		if a.End != b.End {
			return a.End - b.End
		}
		return strings.Compare(a.RuleID, b.RuleID)
	})
	return findings, nil
}
