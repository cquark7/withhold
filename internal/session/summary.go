package session

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/cquark7/withhold/internal/control"
	"github.com/cquark7/withhold/internal/localstate"
)

const summaryName = "last-session.json"

// LastSession contains no request data, destinations, error text, or identity.
// A snapshot is taken before shutdown, so it can omit late events.
type LastSession struct {
	Schema     int      `json:"schema"`
	Available  bool     `json:"available"`
	CapturedAt string   `json:"captured_at,omitempty"`
	Agents     []string `json:"agents,omitempty"`
	Observe    bool     `json:"observe,omitempty"`
	Traffic    *Traffic `json:"traffic,omitempty"`
}

func loadSummary(dir string) (*LastSession, error) {
	data, err := localstate.ReadPrivate(filepath.Join(dir, summaryName))
	if err != nil {
		return nil, err
	}
	var summary LastSession
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&summary) != nil || summary.Schema != 1 {
		return nil, errors.New("invalid last-session summary")
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return nil, errors.New("invalid last-session summary")
	}
	if summary.Available {
		if summary.Traffic == nil || len(summary.Agents) == 0 {
			return nil, errors.New("invalid last-session summary")
		}
		if _, err := time.Parse(time.RFC3339Nano, summary.CapturedAt); err != nil {
			return nil, errors.New("invalid last-session summary")
		}
		for _, agent := range summary.Agents {
			if agent == "" || !utf8.ValidString(agent) {
				return nil, errors.New("invalid last-session summary")
			}
			for _, r := range agent {
				if !unicode.IsPrint(r) {
					return nil, errors.New("invalid last-session summary")
				}
			}
		}
		t := summary.Traffic
		b, u := t.BlockReasons, t.UpstreamReasons
		if !reasonCountsMatch(t.Blocked, b.Findings, b.Unsupported, b.Intake, b.Suspicious, b.Inspection, b.Other) ||
			!reasonCountsMatch(t.UpstreamErrors, u.Canceled, u.Timeout, u.TLS, u.DNS, u.Other) {
			return nil, errors.New("invalid last-session summary")
		}
	} else if summary.Traffic != nil || len(summary.Agents) != 0 || summary.CapturedAt != "" || summary.Observe {
		return nil, errors.New("invalid last-session summary")
	}
	return &summary, nil
}

func reasonCountsMatch(total uint64, counts ...uint64) bool {
	for _, count := range counts {
		if count > total {
			return false
		}
		total -= count
	}
	return total == 0
}

func saveSummary(dir string, summary LastSession) error {
	// Never replace an unrelated or unsafe file at the reserved state path.
	if _, err := loadSummary(dir); err != nil && !os.IsNotExist(err) {
		return err
	}
	data, err := json.Marshal(summary)
	if err != nil {
		return err
	}
	return localstate.Write(filepath.Join(dir, summaryName), data, false)
}

func pendingSummary(dir string) error {
	return saveSummary(dir, LastSession{Schema: 1})
}

func prepareSummary(dir string) (*LastSession, error) {
	previous, err := loadSummary(dir)
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	if err := pendingSummary(dir); err != nil {
		return nil, err
	}
	return previous, nil
}

func restoreSummary(dir string, previous *LastSession) error {
	current, err := loadSummary(dir)
	if err != nil {
		return err
	}
	if current.Available {
		return errors.New("last-session summary changed during startup")
	}
	if previous != nil {
		return saveSummary(dir, *previous)
	}
	return os.Remove(filepath.Join(dir, summaryName))
}

func capturedSummary(r Record, live *control.DebugStatus, capturedAt time.Time) LastSession {
	return LastSession{Schema: 1, Available: true, CapturedAt: capturedAt.UTC().Format(time.RFC3339Nano),
		Agents: append([]string(nil), r.Configuration.Agents...), Observe: r.Configuration.Protection.Observe,
		Traffic: trafficReport(live)}
}
