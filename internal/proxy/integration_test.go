package proxy_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cquark7/withhold/internal/certstore"
	"github.com/cquark7/withhold/internal/detector"
	"github.com/cquark7/withhold/internal/localstate"
	"github.com/cquark7/withhold/internal/proxy"
	"github.com/cquark7/withhold/internal/scanner"
	"github.com/cquark7/withhold/internal/testintegration"
)

type inspection struct {
	engine *scanner.Scanner
	fail   bool
}

func (s inspection) Scan(_ context.Context, body []byte, cap int64) (scanner.Report, error) {
	if s.fail {
		return nil, errors.New("private diagnostic must never be exposed")
	}
	return s.engine.Scan(body, cap), nil
}

func TestIndependentIntegrationUsesSharedProtectionAndItsOwnProtocol(t *testing.T) {
	// An invalid ambient selection cannot affect explicitly constructed engines.
	t.Setenv("WITHHOLD_PII", "invalid")
	for _, test := range []struct {
		name, pii, mode, path, body, surface, detectedMasked string
		fail, observe, redacted, debug                       bool
		status                                               int
	}{
		{name: "clean", mode: "redact", path: "/submit", body: `{"other_schema":{"text":"ordinary content"}}`, status: 200},
		{name: "debug clean", mode: "redact", path: "/submit", body: `{"input":"ordinary content"}`, debug: true, status: 200},
		{name: "secrets", mode: "redact", path: "/submit", body: `{"other_schema":{"tool_result":"token = AKIA4X7Q2W8K9MNDZZZZ"}}`, redacted: true, status: 200},
		{name: "debug redaction", mode: "redact", path: "/submit", body: `{"input":"token = AKIA4X7Q2W8K9MNDZZZZ"}`, redacted: true, debug: true, detectedMasked: "AKI…", status: 200},
		{name: "debug PII", pii: "email", mode: "redact", path: "/submit", body: `{"contact":"dev@example.com"}`, redacted: true, debug: true, detectedMasked: "dev…", status: 200},
		{name: "PII off", mode: "redact", path: "/submit", body: `{"contact":"dev@example.com"}`, status: 200},
		{name: "PII and secrets", pii: "email", mode: "redact", path: "/submit", body: `{"contact":"dev@example.com","tool":"token = AKIA4X7Q2W8K9MNDZZZZ"}`, redacted: true, status: 200},
		{name: "block uses fixture protocol", mode: "block", path: "/submit", body: `{"stream":true,"input":"token = AKIA4X7Q2W8K9MNDZZZZ"}`, status: 418},
		{name: "failure", mode: "redact", path: "/submit", body: `{"input":"private body"}`, fail: true, debug: true, status: 418},
		{name: "surface labels cannot grant fail open", mode: "redact", surface: "embeddings", path: "/submit", body: `{"input":"private body"}`, fail: true, status: 418},
		{name: "unknown route", mode: "redact", path: "/unknown", body: `{"input":"ordinary content"}`, debug: true, status: 418},
		{name: "unsupported payload", mode: "redact", path: "/submit", body: `not JSON`, debug: true, status: 418},
		{name: "observe preserves bytes", mode: "redact", path: "/submit", body: `{"input":"token = AKIA4X7Q2W8K9MNDZZZZ"}`, observe: true, status: 200},
		{name: "debug observe reports original body", mode: "redact", path: "/submit", body: `{"input":"token = AKIA4X7Q2W8K9MNDZZZZ"}`, observe: true, debug: true, detectedMasked: "AKI…", status: 200},
		{name: "debug blocked request is not marked as sent", mode: "block", path: "/submit", body: `{"input":"token = AKIA4X7Q2W8K9MNDZZZZ"}`, debug: true, detectedMasked: "AKI…", status: 418},
	} {
		t.Run(test.name, func(t *testing.T) {
			d, err := detector.New(test.pii)
			if err != nil {
				t.Fatal(err)
			}
			engine := scanner.NewWithDebug(d, func() []byte { return []byte("isolated-contract-key") }, test.debug)
			received := make(chan []byte, 1)
			up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body, _ := io.ReadAll(r.Body)
				received <- body
				_, _ = w.Write(body)
			}))
			defer up.Close()
			u, _ := url.Parse(up.URL)
			dir := t.TempDir()
			debugPath := ""
			if test.debug {
				debugPath = filepath.Join(dir, "debug-findings.log")
			}
			p, err := proxy.New(proxy.Config{CA: &certstore.CA{}, Scope: testintegration.Profile{Host: u.Hostname(), Mode: test.mode, Surface: test.surface}, Scanner: inspection{engine, test.fail}, Observe: test.observe, MaxBytes: 4096, ScanTimeout: time.Second, AuditPath: filepath.Join(dir, "audit"), HintPath: filepath.Join(dir, "hint"), DebugPath: debugPath})
			if err != nil {
				t.Fatal(err)
			}
			defer p.Close()
			r := httptest.NewRequest("POST", up.URL+test.path, strings.NewReader(test.body))
			r.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			p.ServeHTTP(w, r)
			var forwarded []byte
			select {
			case forwarded = <-received:
			default:
			}
			if w.Code != test.status {
				t.Fatalf("status %d, want %d", w.Code, test.status)
			}
			if test.status == 418 {
				if forwarded != nil || w.Header().Get("X-Fixture-Block") != "yes" || !strings.HasPrefix(w.Body.String(), "fixture denied:") {
					t.Fatal("integration-specific rejection was not enforced")
				}
			} else if test.redacted {
				if !bytes.Contains(forwarded, []byte("<WITHHELD_")) || bytes.Contains(forwarded, []byte("AKIA4X7Q2W8K9MNDZZZZ")) || bytes.Contains(forwarded, []byte("dev@example.com")) {
					t.Fatal("shared engine failed to redact protected content")
				}
			} else if string(forwarded) != test.body {
				t.Fatal("clean or observe bytes changed")
			}
			audit, _ := os.ReadFile(filepath.Join(dir, "audit"))
			hint, _ := os.ReadFile(filepath.Join(dir, "hint"))
			for _, private := range []string{"AKIA4X7Q2W8K9MNDZZZZ", "dev@example.com", "private diagnostic", "private body"} {
				if bytes.Contains(audit, []byte(private)) || bytes.Contains(hint, []byte(private)) {
					t.Fatal("private content entered normal audit or hint logs")
				}
			}
			if test.observe && !bytes.Contains(audit, []byte("would-redact")) {
				t.Fatal("observe decision missing")
			}
			debug, _ := os.ReadFile(filepath.Join(dir, "debug-findings.log"))
			if test.debug {
				if err := localstate.CheckPrivate(filepath.Join(dir, "debug-findings.log")); err != nil {
					t.Fatalf("debug log is not private: %v", err)
				}
				if test.detectedMasked == "" {
					if len(debug) != 0 {
						t.Fatalf("unrelated traffic entered findings: %s", debug)
					}
					return
				}
				if !bytes.Contains(debug, []byte(test.detectedMasked)) || !bytes.Contains(debug, []byte(u.Host)) {
					t.Fatalf("debug log missing detection or endpoint: %s", debug)
				}
				for _, secret := range []string{"AKIA4X7Q2W8K9MNDZZZZ", "dev@example.com"} {
					if bytes.Contains(debug, []byte(secret)) {
						t.Fatal("full detected value entered the debug log")
					}
				}
				if bytes.Count(debug, []byte{'\n'}) != 1 {
					t.Fatalf("finding repeated across stages: %s", debug)
				}
				want := "REDACTED"
				if test.observe {
					want = "OBSERVE"
					if !bytes.Contains(debug, []byte("ORIGINAL sent; NOT redacted")) {
						t.Fatalf("observe output is misleading: %s", debug)
					}
				} else if test.mode == "block" {
					want = "BLOCKED"
					if !bytes.Contains(debug, []byte("not sent")) {
						t.Fatalf("blocked output is misleading: %s", debug)
					}
				} else {
					_, replacement, ok := strings.Cut(string(debug), " → ")
					placeholder, _, _ := strings.Cut(replacement, " | ")
					if !ok || !bytes.Contains(forwarded, []byte(placeholder)) || !bytes.Contains(debug, []byte("sent (HTTP 200)")) {
						t.Fatalf("summary does not match actual forwarding: %s", debug)
					}
				}
				if !bytes.Contains(debug, []byte(want)) {
					t.Fatalf("missing %s outcome: %s", want, debug)
				}
				if bytes.Contains(audit, []byte("AKIA4X7Q2W8K9MNDZZZZ")) {
					t.Fatal("raw secret entered the normal audit log")
				}
			} else if len(debug) != 0 {
				t.Fatalf("raw debug values logged without opt-in: %s", debug)
			}
		})
	}
}
