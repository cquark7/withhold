package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cquark7/withhold/internal/control"
	"github.com/cquark7/withhold/internal/policy"
	"github.com/cquark7/withhold/internal/scanner"
)

type debugLog struct {
	mu            sync.Mutex
	path, session string
	next          uint64
	status        control.DebugStatus
}

type debugFinding struct {
	scanner.DebugFinding
	PlaceholderInOutboundBody bool `json:"placeholder_in_outbound_body"`
}

// Records contain no body, header, raw URL path, query, or error text.
type debugRecord struct {
	Schema            int            `json:"schema"`
	TS                string         `json:"ts"`
	RequestID         string         `json:"request_id"`
	ConnectionID      string         `json:"connection_id,omitempty"`
	Event             string         `json:"event"`
	Transport         string         `json:"transport"`
	Method            string         `json:"method"`
	Endpoint          string         `json:"endpoint"`
	API               string         `json:"api"`
	Surface           string         `json:"surface"`
	Scoped            bool           `json:"scoped"`
	Supported         bool           `json:"supported"`
	Observe           bool           `json:"observe"`
	ScanStatus        string         `json:"scan_status"`
	ScanAttempted     bool           `json:"scan_attempted"`
	PolicyAction      string         `json:"policy_action"`
	Reason            string         `json:"reason,omitempty"`
	OutboundBody      string         `json:"outbound_body"`
	RedactionVerified bool           `json:"redaction_verified"`
	Findings          []debugFinding `json:"findings,omitempty"`
	FindingsOmitted   int            `json:"findings_omitted,omitempty"`
	UpstreamStatus    int            `json:"upstream_status,omitempty"`
}

// One completed finding summary replaces the internal stream of traffic events.
// Keep this small enough to read directly with tail, without filtering.
type debugSummary struct {
	Transport, Endpoint, Surface string
	OutboundBody, UpstreamWrite  string
	UpstreamStatus               int
	Observe                      bool
	Reason                       string
	Findings                     []debugFinding
	FindingsOmitted              int
}

type debugTrace struct {
	mu            sync.Mutex
	log           *debugLog
	record        debugRecord
	writeResult   string
	roundTripDone bool
	summarized    bool
}
type debugContextKey struct{}
type debugConnectionKey struct{}

func debugEndpoint(r *http.Request) string {
	host := r.URL.Host
	scheme := r.URL.Scheme
	if host == "" && scheme == "" {
		host, scheme = r.Host, "https"
	}
	if r.Method == http.MethodConnect {
		host, scheme = r.Host, "https"
	}
	if scheme != "http" && scheme != "https" {
		scheme = "http"
	}
	port := "80"
	if scheme == "https" {
		port = "443"
	}
	if !strings.Contains(host, ":") {
		host = net.JoinHostPort(host, port)
	}
	if _, err := authority(host); err != nil {
		return scheme + "://[invalid-authority]"
	}
	return scheme + "://" + host
}

func (d *debugLog) begin(r *http.Request, route policy.Route, transport, parent string, observe bool) *http.Request {
	d.mu.Lock()
	d.next++
	id := fmt.Sprintf("%s-%d", d.session, d.next)
	d.mu.Unlock()
	t := &debugTrace{log: d, record: debugRecord{Schema: 2, RequestID: id, ConnectionID: parent,
		Transport: transport, Method: truncate(strings.ToUpper(r.Method), 16), Endpoint: debugEndpoint(r),
		API: route.API, Surface: route.Surface, Scoped: route.Scoped, Supported: route.Scoped && !route.Unknown, Observe: observe,
		ScanStatus: "not-scanned", PolicyAction: "pending", OutboundBody: "none"}}
	r = r.WithContext(context.WithValue(r.Context(), debugContextKey{}, t))
	debugEvent(r, "received", "", 0)
	return r
}

func trace(r *http.Request) *debugTrace {
	t, _ := r.Context().Value(debugContextKey{}).(*debugTrace)
	return t
}

func debugEvent(r *http.Request, event, reason string, status int) {
	if t := trace(r); t != nil {
		t.mu.Lock()
		defer t.mu.Unlock()
		row := t.record
		row.Event, row.Reason, row.UpstreamStatus = event, reason, status
		t.log.count(row)
		switch event {
		case "upstream_written":
			t.writeResult = "written"
		case "write_error":
			t.writeResult = "failed"
		case "body_not_written":
			t.writeResult = "incomplete"
		case "upstream_response":
			t.roundTripDone = true
			t.record.UpstreamStatus = status
		case "upstream_error":
			t.roundTripDone = true
		}
		if event == "upstream_error" || event == "write_error" || event == "body_not_written" || event == "aborted" {
			t.record.Reason = reason
		}
		terminal := event == "blocked" || event == "aborted" || event == "upstream_error"
		if t.record.Transport == "websocket-message" {
			terminal = terminal || event == "upstream_written" || event == "write_error"
		} else {
			terminal = terminal || t.roundTripDone && t.writeResult != ""
		}
		if terminal {
			t.finish()
		}
	}
}

// Called with the trace lock held. Transport callbacks may race with response
// headers; emit only after their results can be combined, never once per stage.
func (t *debugTrace) finish() {
	if t.summarized || len(t.record.Findings) == 0 {
		return
	}
	t.summarized = true
	result := t.writeResult
	if result == "" {
		result = "unconfirmed"
		if t.record.OutboundBody == "blocked" {
			result = "not-attempted"
		}
	}
	r := t.record
	t.log.write(debugSummary{Transport: r.Transport,
		Endpoint: r.Endpoint, Surface: r.Surface, OutboundBody: r.OutboundBody,
		UpstreamWrite: result, UpstreamStatus: r.UpstreamStatus, Observe: r.Observe,
		Reason: r.Reason, Findings: r.Findings,
		FindingsOmitted: r.FindingsOmitted})
}

func debugScan(r *http.Request) {
	if t := trace(r); t != nil {
		t.mu.Lock()
		t.record.ScanAttempted = true
		t.mu.Unlock()
		debugEvent(r, "scan_started", "", 0)
	}
}

func debugWriteAttempt(r *http.Request) {
	if t := trace(r); t != nil {
		t.mu.Lock()
		defer t.mu.Unlock()
		// A retry must not reuse an earlier connection's failed write result.
		t.writeResult = ""
		if t.record.Reason == "upstream-write-failed" || t.record.Reason == "upstream-body-incomplete" {
			t.record.Reason = ""
		}
	}
}

func debugDecision(r *http.Request, status, action, reason string, report scanner.Report, body []byte) {
	if t := trace(r); t != nil {
		t.mu.Lock()
		defer t.mu.Unlock()
		t.record.ScanStatus, t.record.PolicyAction = status, action
		t.record.Reason = reason
		t.record.OutboundBody = "original"
		if action == "block" || action == "drop" {
			t.record.OutboundBody = "blocked"
		}
		if t.record.Observe {
			t.record.OutboundBody = "original"
		} else if action == "redact" {
			t.record.OutboundBody = "redacted"
		}
		if action == "reject" {
			t.record.OutboundBody = "blocked"
		}
		t.record.RedactionVerified = status == "redacted"
		row := t.record
		row.Event, row.Reason = "inspection", reason
		t.log.count(row)
		// Value-free counters remain available without retaining finding details.
		if t.log.path == "" {
			return
		}
		// Bound diagnostic memory independently of request size, especially for
		// long-lived responses. Never retain the report or its rewritten body.
		const maxFindings = 128
		var values any
		switch rows := report["debug_findings"].(type) {
		case []scanner.DebugFinding:
			if len(rows) > maxFindings {
				t.record.FindingsOmitted = len(rows) - maxFindings
				rows = rows[:maxFindings]
			}
			values = rows
		case []any:
			if len(rows) > maxFindings {
				t.record.FindingsOmitted = len(rows) - maxFindings
				rows = rows[:maxFindings]
			}
			values = rows
		}
		data, _ := json.Marshal(values)
		var findings []scanner.DebugFinding
		_ = json.Unmarshal(data, &findings)
		for _, f := range findings {
			if !scanner.ValidDebugMask(f.DetectedMasked) || !validDebugPlaceholder(f.Placeholder) {
				continue
			}
			t.record.Findings = append(t.record.Findings, debugFinding{f,
				t.record.OutboundBody == "redacted" && bytes.Contains(body, []byte(f.Placeholder))})
		}
	}
}

func validDebugPlaceholder(s string) bool {
	if len(s) != len("<WITHHELD_0123456789abcdef>") || !strings.HasPrefix(s, "<WITHHELD_") || !strings.HasSuffix(s, ">") {
		return false
	}
	for _, c := range s[10:26] {
		if !strings.ContainsRune("0123456789abcdef", c) {
			return false
		}
	}
	return true
}

func (d *debugLog) snapshot() control.DebugStatus {
	d.mu.Lock()
	defer d.mu.Unlock()
	s := d.status
	s.Enabled = d.path != ""
	return s
}

func (d *debugLog) count(row debugRecord) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.status.LastEvent = time.Now().UTC().Format("2006-01-02T15:04:05.000000+00:00")
	switch row.Event {
	case "received":
		if row.Transport == "connect" {
			d.status.Connections++
		} else {
			d.status.Received++
		}
	case "scan_started":
		d.status.Scanned++
	case "inspection":
		if row.Supported && row.ScanAttempted && (row.ScanStatus == "clean" || row.ScanStatus == "redacted") {
			d.status.Inspected++
		}
		if row.PolicyAction == "passthrough" {
			d.status.Passthrough++
		}
		if row.ScanStatus == "redacted" {
			d.status.Detected++
		}
		if row.OutboundBody == "redacted" {
			d.status.Redacted++
		}
		if row.OutboundBody == "blocked" {
			d.status.Blocked++
		}
	case "upstream_written":
		d.status.Written++
	case "upstream_response":
		d.status.Responses++
	case "upstream_error", "write_error":
		d.status.UpstreamErrors++
	}
}

func (d *debugLog) write(row debugSummary) {
	d.mu.Lock()
	defer d.mu.Unlock()
	err := appendFile(d.path, []byte(row.text(time.Now().UTC())))
	if err != nil {
		d.status.WriteFailures++
		if d.status.Healthy {
			fmt.Fprintln(os.Stderr, "withhold: WARNING: debug findings write failed; a finding summary was lost. Check log destination, permissions, and disk space; see withhold status.")
		}
		d.status.Healthy = false
		return
	}
	if !d.status.Healthy && d.status.WriteFailures > 0 {
		fmt.Fprintln(os.Stderr, "withhold: debug logging recovered; earlier finding summaries were lost (see withhold status).")
	}
	d.status.Healthy = true
	d.status.EventsWritten++
}

func (r debugSummary) text(now time.Time) string {
	label, sent := "REDACTED", "send unconfirmed"
	switch r.UpstreamWrite {
	case "written":
		sent = "sent"
	case "failed":
		sent = "send failed"
	case "incomplete":
		sent = "send incomplete"
	case "not-attempted":
		sent = "not sent"
	}
	if r.OutboundBody == "blocked" {
		label, sent = "BLOCKED", "not sent"
	} else if r.Observe {
		label, sent = "OBSERVE", "ORIGINAL "+sent+"; NOT redacted"
	}
	if r.Reason == "upstream-roundtrip-failed" {
		sent += "; upstream failed"
	}
	if r.Reason == "proxy-error" {
		sent += "; proxy aborted"
	}
	if r.UpstreamStatus != 0 {
		sent += fmt.Sprintf(" (HTTP %d)", r.UpstreamStatus)
	}
	surface := r.Surface
	if r.Transport == "websocket-message" {
		surface += "/WS"
	}
	// Quote masks so newlines, terminal escapes and other controls cannot forge
	// log entries. Keep ordinary Unicode prefixes readable.
	var out strings.Builder
	for _, f := range r.Findings {
		value := strconv.Quote(f.DetectedMasked)
		if label == "REDACTED" {
			value += " → " + f.Placeholder
		}
		fmt.Fprintf(&out, "%s %-8s %s | %s %s | %s\n", now.Format("2006-01-02 15:04:05Z"), label, value, safeDebugText(surface), safeDebugText(r.Endpoint), sent)
	}
	if r.FindingsOmitted > 0 {
		fmt.Fprintf(&out, "  (+%d additional findings omitted)\n", r.FindingsOmitted)
	}
	return out.String()
}

func safeDebugText(s string) string {
	quoted := strconv.Quote(s)
	return quoted[1 : len(quoted)-1]
}
