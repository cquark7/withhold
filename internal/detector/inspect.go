package detector

import (
	"context"
	"errors"
	"slices"
	"sort"
	"strings"

	"github.com/betterleaks/betterleaks/report"
	"github.com/betterleaks/betterleaks/sources"
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

// textSource preserves whole-input multiline context and source coordinates.
// It deliberately has no filepath: file-specific rules, archive extraction,
// and repository configuration are not part of literal-text inspection.
type textSource string

func (s textSource) Fragments(ctx context.Context, yield sources.FragmentsFunc) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return yield(sources.Fragment{Raw: string(s), StartLine: 1}, nil)
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
	appendSecret := func(rule string, sl, sc, el, ec int, encoded bool) error {
		if sl < 1 || el < sl || sc < 1 || ec < 0 {
			return errors.New("invalid detector location")
		}
		start, err := locations().offset(sl, sc)
		if err != nil {
			return err
		}
		end, err := locations().offset(el, ec+1)
		if err != nil {
			return err
		}
		return appendSpan(rule, "secret", start, end, encoded)
	}
	appendSecrets := func(f report.Finding) error {
		if len(f.ComponentSets) >= maxComponentSets {
			return ErrFindingLimit
		}
		encoded := slices.ContainsFunc(f.Tags, func(tag string) bool { return strings.HasPrefix(tag, "decoded:") })
		if err := appendSecret(f.RuleID, f.StartLine, f.StartColumn, f.EndLine, f.EndColumn, encoded); err != nil {
			return err
		}
		components := make(map[*report.ComponentFinding]bool)
		for _, set := range f.ComponentSets {
			for _, component := range set.Components {
				if component == nil {
					return errors.New("invalid detector component")
				}
				if components[component] {
					continue
				}
				components[component] = true
				if err := appendSecret(component.RuleID, component.StartLine, component.StartColumn, component.EndLine, component.EndColumn, encoded); err != nil {
					return err
				}
			}
		}
		return nil
	}
	if d.engine != nil {
		job, cancel := context.WithCancel(ctx)
		defer cancel()
		var scanErr error
		for result := range d.engine.Run(job, textSource(text)) {
			// Drain cancellation before another input can reuse the engine.
			if scanErr != nil {
				continue
			}
			if result.Err != nil {
				scanErr = errors.New("detector failed")
			} else {
				scanErr = appendSecrets(result.Finding)
			}
			if scanErr != nil {
				cancel()
			}
		}
		if scanErr != nil {
			return nil, scanErr
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
