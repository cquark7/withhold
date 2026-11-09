package proxy

import (
	"bytes"
	"compress/gzip"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/cquark7/withhold/internal/integrations/copilot"
	"github.com/cquark7/withhold/internal/scanner"
)

func TestIntakeCapacityRefusalNeverForwards(t *testing.T) {
	for _, test := range []struct {
		name, host string
		observe    bool
	}{
		{"chat", "api.githubcopilot.com", false},
		{"observe chat", "api.githubcopilot.com", true},
		{"embeddings", copilot.EmbeddingsHost, false},
		{"observe embeddings", copilot.EmbeddingsHost, true},
	} {
		for _, payload := range []struct{ name, text string }{
			{"within cap", "ok"},
			{"over cap", strings.Repeat("synthetic", 16)},
		} {
			t.Run(test.name+"/"+payload.name, func(t *testing.T) {
				scans := 0
				p, upstream := newTestProxy(t, fakeScanner{func(context.Context, []byte, int64) (scanner.Report, error) {
					scans++
					return scanner.Report{"status": "clean"}, nil
				}})
				p.config.Observe, p.config.MaxBytes = test.observe, 32
				var tickets []*ticket
				for range 6 {
					ticket, err := p.budget.acquire()
					if err != nil {
						t.Fatal(err)
					}
					tickets = append(tickets, ticket)
					t.Cleanup(ticket.release)
				}
				response := call(p, "POST", test.host, "/chat/completions", []byte(`{"text":"`+payload.text+`"}`))
				if response.Code != http.StatusRequestEntityTooLarge || upstream.Load() != 0 || scans != 0 {
					t.Fatalf("status=%d upstream=%d scans=%d", response.Code, upstream.Load(), scans)
				}
				audit, err := os.ReadFile(p.config.AuditPath)
				if err != nil || !bytes.Contains(audit, []byte(`"action":"blocked"`)) || bytes.Contains(audit, []byte("would-block")) || bytes.Contains(audit, []byte("embeddings-unscanned")) {
					t.Fatalf("transport refusal was not audited as enforced: %s (%v)", audit, err)
				}
				for _, ticket := range tickets {
					ticket.release()
				}
				response = call(p, "POST", test.host, "/chat/completions", []byte(`{"text":"ok"}`))
				if response.Code != http.StatusOK || upstream.Load() != 1 || scans != 1 {
					t.Fatal("intake did not recover after capacity was released")
				}
			})
		}
	}
}

func TestUnscannedGuardedBodiesStillHaveTransportLimits(t *testing.T) {
	for _, test := range []struct {
		name, method, host, contentType string
		observe                         bool
	}{
		{"observe non-JSON POST", "POST", "api.githubcopilot.com", "text/plain", true},
		{"observe PUT", "PUT", "api.githubcopilot.com", "application/json", true},
		{"embeddings PUT", "PUT", copilot.EmbeddingsHost, "application/json", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			p, upstream := newTestProxy(t, fakeScanner{func(context.Context, []byte, int64) (scanner.Report, error) {
				t.Fatal("unsupported bodies must not invoke the scanner")
				return nil, nil
			}})
			p.config.Observe, p.config.MaxBytes = test.observe, 32
			r := httptest.NewRequest(test.method, "http://"+test.host+"/chat/completions", strings.NewReader(strings.Repeat("synthetic", 16)))
			r.Header.Set("Content-Type", test.contentType)
			response := httptest.NewRecorder()
			p.ServeHTTP(response, r)
			if response.Code != http.StatusRequestEntityTooLarge || upstream.Load() != 0 {
				t.Fatalf("status=%d upstream=%d", response.Code, upstream.Load())
			}
		})
	}
}

func TestDecodedIntakeCapacityRefusalNeverForwards(t *testing.T) {
	var compressed bytes.Buffer
	w := gzip.NewWriter(&compressed)
	if _, err := w.Write([]byte(`{"text":"` + strings.Repeat("synthetic", 16) + `"}`)); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name, host string
		observe    bool
	}{
		{"chat", "api.githubcopilot.com", false},
		{"observe", "api.githubcopilot.com", true},
		{"embeddings", copilot.EmbeddingsHost, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			p, upstream := newTestProxy(t, fakeScanner{func(context.Context, []byte, int64) (scanner.Report, error) {
				t.Fatal("capacity refusal must precede scanning")
				return nil, nil
			}})
			p.config.Observe = test.observe
			reservation, err := p.budget.acquire()
			if err != nil {
				t.Fatal(err)
			}
			defer reservation.release()
			if err := reservation.add(64*1024*1024 - compressed.Len()); err != nil {
				t.Fatal(err)
			}
			r := httptest.NewRequest("POST", "http://"+test.host+"/chat/completions", bytes.NewReader(compressed.Bytes()))
			r.Header.Set("Content-Type", "application/json")
			r.Header.Set("Content-Encoding", "gzip")
			response := httptest.NewRecorder()
			p.ServeHTTP(response, r)
			if response.Code != http.StatusRequestEntityTooLarge || upstream.Load() != 0 {
				t.Fatalf("status=%d upstream=%d", response.Code, upstream.Load())
			}
		})
	}
}
