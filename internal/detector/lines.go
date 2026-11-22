package detector

import (
	"context"
	"errors"
	"strings"

	blregexp "github.com/betterleaks/betterleaks/v2/regexp"
	"github.com/betterleaks/betterleaks/v2/scan"
)

var ErrLineWorkLimit = errors.New("detector line work exceeds limit")

// shortcut: RC9 charges long lines repeatedly per match, so conservatively
// limit candidate work until the SDK indexes its line-boundary lookups.
const (
	longLineBytes    = 64 << 10
	maxLineScanBytes = 4 << 30
)

type lineBudget struct {
	blregexp.Stdlib
	width, remaining int64
	cancel           context.CancelFunc
	exceeded         bool
}

func (b *lineBudget) Compile(pattern string) (blregexp.CompiledRegexp, error) {
	re, err := b.Stdlib.Compile(pattern)
	if err != nil {
		return nil, err
	}
	return lineRegexp{CompiledRegexp: re, budget: b}, nil
}

type lineRegexp struct {
	blregexp.CompiledRegexp
	budget *lineBudget
}

func (r lineRegexp) FindAllStringIndex(text string, n int) [][]int {
	return r.budget.find(r.CompiledRegexp.FindAllStringIndex, text, n)
}

func (r lineRegexp) FindAllStringSubmatchIndex(text string, n int) [][]int {
	return r.budget.find(r.CompiledRegexp.FindAllStringSubmatchIndex, text, n)
}

func (b *lineBudget) find(find func(string, int) [][]int, text string, n int) [][]int {
	if b.exceeded {
		return nil
	}
	if b.width <= longLineBytes {
		return find(text, n)
	}
	remaining := int(b.remaining / b.width)
	if n < 0 || n > remaining {
		n = remaining + 1
	}
	matches := find(text, n)
	if len(matches) > remaining {
		b.exceeded = true
		b.cancel()
		return nil
	}
	b.remaining -= int64(len(matches)) * b.width
	return matches
}

func widestLine(text string) int64 {
	var width int
	for {
		i := strings.IndexByte(text, '\n')
		if i < 0 {
			return int64(max(width, len(text)))
		}
		width = max(width, i)
		text = text[i+1:]
	}
}

func (d *Detector) scanText(ctx context.Context, engine *scan.Scanner, text string, handle scan.Handler) error {
	d.lines.width = widestLine(text)
	d.lines.remaining = maxLineScanBytes
	d.lines.exceeded = false
	if d.lines.width > longLineBytes {
		var cancel context.CancelFunc
		ctx, cancel = context.WithCancel(ctx)
		d.lines.cancel = cancel
		defer cancel()
	}
	_, err := engine.Scan(ctx, textSource(text), handle)
	d.lines.cancel = nil
	if d.lines.exceeded {
		return ErrLineWorkLimit
	}
	return err
}
