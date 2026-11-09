package proxy

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cquark7/withhold/internal/certstore"
	"github.com/cquark7/withhold/internal/integrations/copilot"
	"github.com/cquark7/withhold/internal/policy"
	"github.com/cquark7/withhold/internal/scanner"
	"github.com/gorilla/websocket"
)

type fakeScanner struct {
	run func(context.Context, []byte, int64) (scanner.Report, error)
}

func (f fakeScanner) Scan(ctx context.Context, b []byte, n int64) (scanner.Report, error) {
	return f.run(ctx, b, n)
}

func newTestProxy(t *testing.T, scan fakeScanner) (*Proxy, *atomic.Int32) {
	t.Helper()
	for _, key := range []string{"WITHHOLD_TEST_ALLOW_HOSTS", "WITHHOLD_EXTRA_HOSTS", "WITHHOLD_EXTRA_HOST_REGEX"} {
		t.Setenv(key, "")
	}
	scope, err := copilot.NewTraffic(policy.ScopeOptions{})
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	p, err := New(Config{CA: &certstore.CA{}, Scope: scope, Scanner: scan, MaxBytes: 4096, ScanTimeout: 50 * time.Millisecond, AuditPath: filepath.Join(dir, "audit"), HintPath: filepath.Join(dir, "hint")})
	if err != nil {
		t.Fatal(err)
	}
	var count atomic.Int32
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { count.Add(1); _, _ = io.Copy(w, r.Body) }))
	t.Cleanup(up.Close)
	p.transport.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, up.Listener.Addr().String())
	}
	t.Cleanup(p.Close)
	return p, &count
}

func call(p *Proxy, method, host, path string, body []byte) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, "http://"+host+path, bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	p.ServeHTTP(w, r)
	return w
}

func TestScannerFailuresDoNotDiscloseGuardedBodies(t *testing.T) {
	for _, failure := range []string{"error", "deadline", "panic", "invalid-rewrite"} {
		t.Run(failure, func(t *testing.T) {
			p, count := newTestProxy(t, fakeScanner{func(ctx context.Context, _ []byte, _ int64) (scanner.Report, error) {
				switch failure {
				case "error":
					return nil, errors.New("private scanner detail")
				case "deadline":
					<-ctx.Done()
					return nil, ctx.Err()
				case "panic":
					panic("private scanner detail")
				default:
					return scanner.Report{"status": "redacted", "body_base64": "%%%"}, nil
				}
			}})
			func() {
				defer func() {
					if v := recover(); v != nil && v != http.ErrAbortHandler {
						t.Fatal(v)
					}
				}()
				w := call(p, "POST", "api.githubcopilot.com", "/chat/completions", []byte(`{"text":"private payload"}`))
				if w.Code != 429 {
					t.Fatalf("status %d", w.Code)
				}
			}()
			if count.Load() != 0 {
				t.Fatal("uninspected body reached upstream")
			}
			log, _ := os.ReadFile(p.config.AuditPath)
			if bytes.Contains(log, []byte("private")) {
				t.Fatal("private scanner diagnostic entered audit")
			}
		})
	}
}

func TestEmbeddingsPolicyFailuresPassAndTokenExchangeDoesNotScan(t *testing.T) {
	var scans atomic.Int32
	p, count := newTestProxy(t, fakeScanner{func(context.Context, []byte, int64) (scanner.Report, error) {
		scans.Add(1)
		return nil, errors.New("failed")
	}})
	for _, method := range []string{"POST", "PUT"} {
		w := call(p, method, copilot.EmbeddingsHost, "/anything", []byte("unscannable"))
		if w.Code != 200 || w.Body.String() != "unscannable" {
			t.Fatal("embeddings blocked")
		}
	}
	w := call(p, "POST", copilot.TokenHost, "/copilot_internal/v2/token", []byte("raw token exchange"))
	if w.Code != 200 {
		t.Fatal("token exchange blocked")
	}
	if scans.Load() != 1 || count.Load() != 3 {
		t.Fatalf("scans %d upstream %d", scans.Load(), count.Load())
	}
	data, _ := os.ReadFile(p.config.AuditPath)
	if strings.Count(string(data), "embeddings-unscanned") != 2 {
		t.Fatal("missing embeddings audit")
	}
}

func TestInlineSecretsAndUnscannedResidueBlock(t *testing.T) {
	p, count := newTestProxy(t, fakeScanner{func(context.Context, []byte, int64) (scanner.Report, error) {
		return scanner.Report{"status": "redacted", "body_base64": base64.StdEncoding.EncodeToString([]byte(`{"text":"<WITHHELD_0000000000000000>"}`)), "stats": map[string]any{"sweep_unrewritable": 1.0}}, nil
	}})
	w := call(p, "POST", "proxy.business.githubcopilot.com", "/chat/completions", []byte(`{"text":"secret"}`))
	if w.Code != 429 || !strings.Contains(w.Body.String(), "unscanned-residue") {
		t.Fatal("inline residue not blocked")
	}
	if count.Load() != 0 {
		t.Fatal("inline placeholders reached upstream")
	}
	p.config.Observe = true
	w = call(p, "POST", "proxy.business.githubcopilot.com", "/chat/completions", []byte(`{"text":"secret"}`))
	if w.Code != 200 || !strings.Contains(w.Body.String(), "secret") {
		t.Fatal("observe changed body")
	}
}

func TestUnscopedSuspiciousBodiesBlockAndUnrelatedTrafficPasses(t *testing.T) {
	p, count := newTestProxy(t, fakeScanner{func(context.Context, []byte, int64) (scanner.Report, error) {
		t.Fatal("unscoped scan")
		return nil, nil
	}})
	if w := call(p, "POST", "rotated.copilot.invalid", "/new", []byte("body")); w.Code != 429 {
		t.Fatal("suspicious endpoint bypassed")
	}
	if w := call(p, "GET", "rotated.copilot.invalid", "/models", nil); w.Code != 200 {
		t.Fatal("bodyless request blocked")
	}
	for range 2 {
		if w := call(p, "POST", "unrelated.invalid", "/new", []byte("body")); w.Code != 200 {
			t.Fatal("unrelated traffic blocked")
		}
	}
	if count.Load() != 3 {
		t.Fatal("incorrect upstream count")
	}
	data, _ := os.ReadFile(p.config.AuditPath)
	if strings.Count(string(data), "\"passthrough\"") != 2 {
		t.Fatal("foreign hosts not deduplicated")
	}
}

func TestAuthorityNormalizationRejectsAmbiguousTargets(t *testing.T) {
	for _, s := range []string{"example.com:443", "EXAMPLE.com:0443", "[::1]:443"} {
		if _, err := authority(s); err != nil {
			t.Fatal(s, err)
		}
	}
	for _, s := range []string{"example.com", "example.com:0", "example.com:65536", "user@example.com:443", "example.com/path:443", "example.com%00:443", "[::1%lo0]:443"} {
		if _, err := authority(s); err == nil {
			t.Fatal("ambiguous authority accepted", s)
		}
	}
	if a, err := requestAuthority("EXAMPLE.com"); err != nil || a != "example.com:443" {
		t.Fatal(a, err)
	}
	if a, err := requestAuthority("[::1]"); err != nil || a != "[::1]:443" {
		t.Fatal(a, err)
	}
}

func TestShutdownClosesTLSWithoutWaitingForCloseNotification(t *testing.T) {
	p, _ := newTestProxy(t, fakeScanner{})
	dir := t.TempDir()
	if err := certstore.Init(dir); err != nil {
		t.Fatal(err)
	}
	ca, err := certstore.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := ca.Leaf("localhost")
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca.Certificate)
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	_ = left.SetDeadline(time.Now().Add(3 * time.Second))
	_ = right.SetDeadline(time.Now().Add(3 * time.Second))
	server := tls.Server(left, &tls.Config{Certificates: []tls.Certificate{*leaf}})
	client := tls.Client(right, &tls.Config{RootCAs: roots, ServerName: "localhost"})
	handshake := make(chan error, 1)
	go func() { handshake <- client.Handshake() }()
	if err = server.Handshake(); err != nil {
		t.Fatal(err)
	}
	if err = <-handshake; err != nil {
		t.Fatal(err)
	}
	_ = left.SetDeadline(time.Time{})
	_ = right.SetDeadline(time.Time{})
	if !p.track(server) {
		t.Fatal("connection refused")
	}
	done := make(chan struct{})
	go func() { p.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("shutdown waited for an unread TLS alert")
	}
}

func TestWebSocketPanicReleasesAdmissionAndAbortsObserveSessions(t *testing.T) {
	for _, observe := range []bool{false, true} {
		t.Run(strconv.FormatBool(observe), func(t *testing.T) {
			p, _ := newTestProxy(t, fakeScanner{func(context.Context, []byte, int64) (scanner.Report, error) { panic("private scanner detail") }})
			p.config.Observe = observe
			scope, err := copilot.NewTraffic(policy.ScopeOptions{ExtraHosts: []string{"127.0.0.1"}})
			if err != nil {
				t.Fatal(err)
			}
			p.config.Scope = scope
			var received atomic.Int32
			up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				u := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
				c, e := u.Upgrade(w, r, nil)
				if e != nil {
					return
				}
				defer c.Close()
				if _, _, e = c.ReadMessage(); e == nil {
					received.Add(1)
				}
			}))
			defer up.Close()
			finished := make(chan struct{})
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				defer close(finished)
				r.URL.Scheme = "http"
				r.URL.Host = strings.TrimPrefix(up.URL, "http://")
				p.ServeHTTP(w, r)
			}))
			server.Config.ErrorLog = log.New(io.Discard, "", 0)
			server.Start()
			defer server.Close()
			c, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(server.URL, "http")+"/chat/completions", nil)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
			if err = c.WriteMessage(websocket.TextMessage, []byte(`{"text":"private payload"}`)); err != nil {
				t.Fatal(err)
			}
			if _, _, err = c.ReadMessage(); err == nil {
				t.Fatal("panic session remained open")
			}
			select {
			case <-finished:
			case <-time.After(time.Second):
				t.Fatal("panic handler did not finish")
			}
			p.budget.mu.Lock()
			jobs, n := p.budget.jobs, p.budget.bytes
			p.budget.mu.Unlock()
			if jobs != 0 || n != 0 || received.Load() != 0 {
				t.Fatalf("jobs %d bytes %d upstream %d", jobs, n, received.Load())
			}
			data, _ := os.ReadFile(p.config.AuditPath)
			if !bytes.Contains(data, []byte("killed-on-error")) || bytes.Contains(data, []byte("private")) {
				t.Fatal("unsafe panic audit")
			}
		})
	}
}
