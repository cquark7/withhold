package proxy

import (
	"bytes"
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cquark7/withhold/internal/certstore"
	"github.com/cquark7/withhold/internal/control"
	"github.com/cquark7/withhold/internal/localstate"
	"github.com/cquark7/withhold/internal/policy"
	"github.com/cquark7/withhold/internal/scanner"
	"github.com/cquark7/withhold/internal/testintegration"
)

const debugPlaceholder = "<WITHHELD_0123456789abcdef>"

func TestDebugPlaceholderRequiresCurrentMarkerAndLowercaseHexID(t *testing.T) {
	for _, text := range []string{
		debugPlaceholder, "<REDACTED_0123456789abcdef>",
		"<WITHHELD_0123456789abcde>", "<WITHHELD_0123456789abcdeg>",
		"<WITHHELD_0123456789ABCDEF>", "<WITHHELD_0123456789abcdef>extra",
	} {
		if validDebugPlaceholder(text) != (text == debugPlaceholder) {
			t.Fatalf("unexpected marker validation for %q", text)
		}
	}
}

func debugReport() scanner.Report {
	return scanner.Report{"debug_findings": []scanner.DebugFinding{{DetectedMasked: "AKI…", Placeholder: debugPlaceholder, RuleIDs: []string{"synthetic"}}}}
}

func TestCountersDoNotRequireOrRetainFindingLogs(t *testing.T) {
	for _, test := range []struct {
		name, status, action   string
		unknown                bool
		inspected, passthrough uint64
	}{
		{"clean", "clean", "forward", false, 1, 0},
		{"redacted", "redacted", "redact", false, 1, 0},
		{"failed scan", "scanner-error", "block", false, 0, 0},
		{"unsupported route", "clean", "block", true, 0, 0},
		{"policy exception", "scanner-error", "passthrough", false, 0, 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			d := debugLog{}
			r := d.begin(httptest.NewRequest("POST", "https://example.test/chat", nil), policy.Route{Scoped: true, Unknown: test.unknown}, "http", "", false)
			debugScan(r)
			debugDecision(r, test.status, test.action, "", debugReport(), nil)
			s := d.snapshot()
			if s.Enabled || s.Received != 1 || s.Scanned != 1 || s.Inspected != test.inspected || s.Passthrough != test.passthrough || s.EventsWritten != 0 || len(trace(r).record.Findings) != 0 {
				t.Fatalf("incorrect value-free telemetry: %+v", s)
			}
		})
	}
}

func readDebug(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

type findingDebugScanner struct{}

func (findingDebugScanner) Scan(_ context.Context, body []byte, _ int64) (scanner.Report, error) {
	r := debugReport()
	r["status"] = "redacted"
	r["body_base64"] = base64.StdEncoding.EncodeToString(append([]byte(debugPlaceholder), body...))
	return r, nil
}

func TestEarlyUpstreamResponseDoesNotClaimUnsentBody(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		w.(http.Flusher).Flush()
	}))
	defer up.Close()
	u, _ := url.Parse(up.URL)
	dir := t.TempDir()
	path := filepath.Join(dir, "debug-findings.log")
	p, err := New(Config{CA: &certstore.CA{}, Scope: testintegration.Profile{Host: u.Hostname(), Mode: "redact"}, Scanner: findingDebugScanner{}, MaxBytes: 1024 * 1024, ScanTimeout: time.Second, AuditPath: filepath.Join(dir, "audit"), HintPath: filepath.Join(dir, "hint"), DebugPath: path})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	p.transport.ExpectContinueTimeout = time.Second
	r := httptest.NewRequest("POST", up.URL+"/submit", strings.NewReader(strings.Repeat("x", 300*1024)))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Expect", "100-continue")
	w := httptest.NewRecorder()
	p.ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatalf("response: %d", w.Code)
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		text := readDebug(t, path)
		if strings.Contains(text, " | sent") {
			t.Fatal("unsent body claimed as written")
		}
		if strings.Contains(text, "send incomplete (HTTP 403)") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("missing finding outcome: %s", text)
		}
		time.Sleep(time.Millisecond)
	}
}

func TestDebugFindingsAreHumanReadableConciseAndPrivate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "debug-findings.log")
	if err := prepareAudit(path); err != nil {
		t.Fatal(err)
	}
	d := debugLog{path: path, session: "test", status: control.DebugStatus{Healthy: true}}
	r := d.begin(httptest.NewRequest("POST", "https://copilot.example/private-path?credential=private-query", nil), policy.Route{Surface: "chat"}, "http", "", false)
	debugDecision(r, "redacted", "redact", "", scanner.Report{"debug_findings": []scanner.DebugFinding{
		{DetectedMasked: "ééé…", Placeholder: debugPlaceholder},
		{DetectedMasked: "ééééé", Placeholder: debugPlaceholder},
		{DetectedMasked: "***", Placeholder: "private-unvalidated-placeholder"},
	}}, []byte(debugPlaceholder))
	debugEvent(r, "upstream_response", "", 200)
	if text := readDebug(t, path); text != "" {
		t.Fatalf("premature or noisy output: %s", text)
	}
	debugEvent(r, "upstream_written", "", 0)
	debugEvent(r, "response_error", "client-response-write-failed", 0)
	debugEvent(r, "upstream_written", "", 0)
	text := readDebug(t, path)
	if strings.Count(text, "\n") != 1 || !strings.Contains(text, `REDACTED "ééé…" → `+debugPlaceholder+` | chat https://copilot.example:443 | sent (HTTP 200)`) {
		t.Fatalf("unhelpful summary: %s", text)
	}
	for _, private := range []string{"ééééé", "private-path", "private-query", "credential", "private-unvalidated", `"schema"`, `"event"`} {
		if strings.Contains(text, private) {
			t.Fatalf("private data or JSON noise logged: %s", private)
		}
	}
	if err := localstate.CheckPrivate(path); err != nil {
		t.Fatal(err)
	}
}

func TestCleanTrafficOnlyUpdatesStatusCounters(t *testing.T) {
	path := filepath.Join(t.TempDir(), "findings")
	if err := prepareAudit(path); err != nil {
		t.Fatal(err)
	}
	d := debugLog{path: path, status: control.DebugStatus{Healthy: true}}
	for range 100 {
		r := d.begin(httptest.NewRequest("GET", "http://fixture.example/", nil), policy.Route{}, "http", "", false)
		debugScan(r)
		debugDecision(r, "clean", "forward", "", nil, nil)
		debugEvent(r, "upstream_written", "", 0)
		debugEvent(r, "upstream_response", "", 200)
	}
	if text := readDebug(t, path); text != "" {
		t.Fatalf("clean traffic polluted findings: %s", text)
	}
	s := d.snapshot()
	if s.Received != 100 || s.Scanned != 100 || s.Written != 100 || s.Responses != 100 || s.EventsWritten != 0 {
		t.Fatalf("counters lost: %+v", s)
	}
}

func TestRetrySummaryDoesNotReuseEarlierFailedWrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "findings")
	if err := prepareAudit(path); err != nil {
		t.Fatal(err)
	}
	d := debugLog{path: path, status: control.DebugStatus{Healthy: true}}
	r := d.begin(httptest.NewRequest("POST", "http://fixture.example/", nil), policy.Route{Surface: "chat"}, "http", "", false)
	debugDecision(r, "redacted", "redact", "", debugReport(), []byte(debugPlaceholder))
	debugEvent(r, "write_error", "upstream-write-failed", 0)
	debugWriteAttempt(r)
	debugEvent(r, "upstream_error", "upstream-roundtrip-failed", 0)
	// A late callback cannot turn an unconfirmed upload into a second line.
	debugEvent(r, "upstream_written", "", 0)
	text := readDebug(t, path)
	if strings.Count(text, "\n") != 1 || !strings.Contains(text, "send unconfirmed; upstream failed") {
		t.Fatalf("stale retry result: %s", text)
	}
}

func TestDebugWriteFailureAndRecoveryAreVisibleWithoutPrivateErrors(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "findings")
	if err := prepareAudit(path); err != nil {
		t.Fatal(err)
	}
	d := debugLog{path: path, status: control.DebugStatus{Healthy: true}}
	capture, err := os.CreateTemp(dir, "stderr")
	if err != nil {
		t.Fatal(err)
	}
	defer capture.Close()
	old := os.Stderr
	os.Stderr = capture
	defer func() { os.Stderr = old }()
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	row := debugSummary{Findings: []debugFinding{{DebugFinding: scanner.DebugFinding{DetectedMasked: "AKI…", Placeholder: debugPlaceholder}}}}
	for range 2 {
		d.count(debugRecord{Event: "received"})
		d.write(row)
	}
	s := d.snapshot()
	if s.Healthy || s.WriteFailures != 2 || s.Received != 2 || s.EventsWritten != 0 {
		t.Fatalf("failure not visible: %+v", s)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	d.write(row)
	s = d.snapshot()
	if !s.Healthy || s.WriteFailures != 2 || s.EventsWritten != 1 {
		t.Fatalf("recovery not visible: %+v", s)
	}
	output, _ := os.ReadFile(capture.Name())
	if bytes.Count(output, []byte("WARNING")) != 1 || !bytes.Contains(output, []byte("recovered")) || bytes.Contains(output, []byte(dir)) {
		t.Fatalf("unsafe or noisy warning: %s", output)
	}
}

func TestDebugRotationAndConcurrentFindings(t *testing.T) {
	path := filepath.Join(t.TempDir(), "findings")
	if err := prepareAudit(path); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(path, os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(10 * 1024 * 1024); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	d := debugLog{path: path, status: control.DebugStatus{Healthy: true}}
	var wg sync.WaitGroup
	for range 20 {
		wg.Go(func() {
			r := d.begin(httptest.NewRequest("POST", "http://fixture.example/", nil), policy.Route{Surface: "chat"}, "http", "", false)
			debugDecision(r, "redacted", "redact", "", debugReport(), []byte(debugPlaceholder))
			debugEvent(r, "upstream_written", "", 0)
			debugEvent(r, "upstream_response", "", 200)
		})
	}
	wg.Wait()
	if text := readDebug(t, path); strings.Count(text, "\n") != 20 || d.snapshot().EventsWritten != 20 {
		t.Fatalf("concurrent findings lost or repeated: %s", text)
	}
	for _, file := range []string{path, path + ".1"} {
		if err := localstate.CheckPrivate(file); err != nil {
			t.Fatal(err)
		}
	}
}

func TestDebugFindingsBoundedAndControlCharactersEscaped(t *testing.T) {
	path := filepath.Join(t.TempDir(), "findings")
	if err := prepareAudit(path); err != nil {
		t.Fatal(err)
	}
	d := debugLog{path: path, status: control.DebugStatus{Healthy: true}}
	r := d.begin(httptest.NewRequest("POST", "http://fixture.example/", nil), policy.Route{}, "http", "", false)
	findings := make([]scanner.DebugFinding, 129)
	for i := range findings {
		findings[i] = scanner.DebugFinding{DetectedMasked: "\x1b\nx…", Placeholder: debugPlaceholder}
	}
	debugDecision(r, "redacted", "redact", "", scanner.Report{"debug_findings": findings}, []byte("encoded placeholder"))
	debugEvent(r, "upstream_written", "", 0)
	debugEvent(r, "upstream_response", "", 200)
	text := readDebug(t, path)
	if strings.Count(text, "\n") != 129 || !strings.Contains(text, "(+1 additional findings omitted)") || strings.Contains(text, "\x1b") || !strings.Contains(text, `\x1b\nx…`) {
		t.Fatalf("unbounded or unsafe human output: %s", text)
	}
	if trace(r).record.Findings[0].PlaceholderInOutboundBody {
		t.Fatal("encoded placeholder claimed as literal")
	}
}
