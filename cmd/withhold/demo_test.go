package main

import (
	"context"
	"errors"
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
	"github.com/cquark7/withhold/internal/scanner"
)

type demoScannerFunc func(context.Context, []byte, int64) (scanner.Report, error)

func (f demoScannerFunc) Scan(ctx context.Context, body []byte, cap int64) (scanner.Report, error) {
	return f(ctx, body, cap)
}

func TestLocalDemoChecksActualUpstreamBytesAndBlockedRequests(t *testing.T) {
	d, err := detector.New("")
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"working", "no redaction", "scanner failure", "no blocking"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			if err := certstore.Init(dir); err != nil {
				t.Fatal(err)
			}
			ca, err := certstore.Load(dir)
			if err != nil {
				t.Fatal(err)
			}
			engine := scanner.New(d, func() []byte { return []byte(demoKey) })
			calls := 0
			fake := demoScannerFunc(func(_ context.Context, body []byte, cap int64) (scanner.Report, error) {
				calls++
				if mode == "scanner failure" {
					return nil, errors.New("private scanner diagnostic")
				}
				if mode == "no redaction" || mode == "no blocking" && calls == 2 {
					return scanner.Report{"status": "clean"}, nil
				}
				return engine.Scan(body, cap), nil
			})
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			checks, err := exerciseDemo(ctx, dir, ca, fake)
			if (err == nil) != (mode == "working") {
				t.Fatalf("demo outcome for %s: %v", mode, err)
			}
			if err == nil && (len(checks) != 2 || !checks[0].OK || !checks[1].OK) {
				t.Fatal("demo did not verify both policies")
			}
			if err != nil && (strings.Contains(err.Error(), demoSecret) || strings.Contains(err.Error(), "private scanner diagnostic")) {
				t.Fatal("demo exposed a value or raw error")
			}
		})
	}
}

func TestDemoScannerFailureRemovesTemporaryState(t *testing.T) {
	dir := t.TempDir()
	for _, key := range []string{"TMPDIR", "TMP", "TEMP"} {
		t.Setenv(key, dir)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := runDemo(ctx, filepath.Join(dir, "missing-scanner")); err == nil {
		t.Fatal("missing bundled scanner did not fail the demo")
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 0 {
		t.Fatal("failed demo retained temporary state")
	}
}

func TestDemoListenerCannotBeUsedForOtherDestinations(t *testing.T) {
	const target = "127.0.0.1:12345"
	for _, test := range []struct {
		method, host      string
		absolute, allowed bool
	}{
		{http.MethodConnect, target, false, true},
		{http.MethodConnect, "api.githubcopilot.com:443", false, false},
		{http.MethodConnect, "127.0.0.1:12346", false, false},
		{http.MethodGet, target, true, false},
		{http.MethodConnect, target, true, false},
	} {
		called := false
		h := demoProxyHandler(target, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			called = true
			w.WriteHeader(http.StatusNoContent)
		}))
		u := &url.URL{Host: test.host}
		if test.absolute {
			u.Scheme = "https"
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, &http.Request{Method: test.method, Host: test.host, URL: u})
		if called != test.allowed || !test.allowed && w.Code != http.StatusForbidden {
			t.Fatal("demo accepted an unintended upstream destination")
		}
	}
}
