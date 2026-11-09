// Package proxy inspects request bodies before opening an upstream request.
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
	"net/http/httptrace"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cquark7/withhold/internal/certstore"
	"github.com/cquark7/withhold/internal/control"
	"github.com/cquark7/withhold/internal/policy"
	"github.com/cquark7/withhold/internal/scanner"
)

type Scanner interface {
	Scan(context.Context, []byte, int64) (scanner.Report, error)
}
type Config struct {
	Control             *control.Server
	CA                  *certstore.CA
	Scope               policy.Profile
	Scanner             Scanner
	Roots               *x509.CertPool
	Observe             bool
	MaxBytes            int64
	ScanTimeout         time.Duration
	AuditPath, HintPath string
	DebugPath           string
}

type Proxy struct {
	config       Config
	transport    *http.Transport
	websocketTLS *tls.Config
	audit        audit
	debug        debugLog
	budget       budget
	mu           sync.Mutex
	conns        map[net.Conn]bool
	closed       bool
	ctx          context.Context
	cancel       context.CancelFunc
}

func New(c Config) (*Proxy, error) {
	if c.CA == nil || c.Scope == nil || c.Scanner == nil || c.MaxBytes <= 0 || c.MaxBytes > 128*1024*1024 || c.ScanTimeout <= 0 {
		return nil, errors.New("invalid native proxy configuration")
	}
	if c.DebugPath != "" && logPathsCollide(c.DebugPath, c.AuditPath, c.HintPath) {
		return nil, errors.New("debug log path must differ from audit and hint paths")
	}
	logPaths := []string{c.AuditPath, c.HintPath}
	if c.DebugPath != "" {
		logPaths = append(logPaths, c.DebugPath)
	}
	if err := prepareAudit(logPaths...); err != nil {
		return nil, err
	}
	// Resolve aliases through existing parent-directory symlinks after all
	// destinations exist, so sensitive findings cannot share an audit inode.
	if c.DebugPath != "" && logPathsCollide(c.DebugPath, c.AuditPath, c.HintPath) {
		return nil, errors.New("debug log path must differ from audit and hint paths")
	}
	ctx, cancel := context.WithCancel(context.Background())
	p := &Proxy{config: c, ctx: ctx, cancel: cancel, conns: map[net.Conn]bool{}, audit: audit{path: c.AuditPath, hint: c.HintPath, seen: map[string]bool{}}, debug: debugLog{path: c.DebugPath}}
	if c.DebugPath != "" {
		p.debug.session = control.Random()[:12]
	}
	p.debug.status.Healthy = true
	if c.Control != nil {
		c.Control.Debug = p.debug.snapshot
	}
	p.transport = &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: 15 * time.Second, KeepAlive: 30 * time.Second}).DialContext, TLSClientConfig: &tls.Config{RootCAs: c.Roots, MinVersion: tls.VersionTLS12}, ForceAttemptHTTP2: true, DisableCompression: true, MaxIdleConns: 32, MaxIdleConnsPerHost: 8, MaxConnsPerHost: 16, IdleConnTimeout: 60 * time.Second, TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: 30 * time.Second}
	// net/http configures ALPN on its own TLS config. WebSocket upgrades use
	// HTTP/1.1 and must not inherit that mutable HTTP/2 negotiation state.
	p.websocketTLS = &tls.Config{RootCAs: c.Roots, MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}}
	return p, nil
}

func (p *Proxy) Close() {
	p.cancel()
	p.mu.Lock()
	p.closed = true
	conns := make([]net.Conn, 0, len(p.conns))
	for c := range p.conns {
		conns = append(conns, c)
	}
	p.mu.Unlock()
	for _, c := range conns {
		_ = c.Close()
	}
	p.transport.CloseIdleConnections()
}

func networkConn(c net.Conn) net.Conn {
	if tc, ok := c.(*tls.Conn); ok {
		return tc.NetConn()
	}
	return c
}

func (p *Proxy) track(c net.Conn) bool {
	c = networkConn(c)
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		_ = c.Close()
		return false
	}
	p.conns[c] = true
	return true
}
func (p *Proxy) untrack(c net.Conn) {
	c = networkConn(c)
	p.mu.Lock()
	delete(p.conns, c)
	p.mu.Unlock()
}

func (p *Proxy) Serve(l net.Listener) error {
	server := &http.Server{Handler: p, ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 1 << 20, ErrorLog: log.New(io.Discard, "", 0), BaseContext: func(net.Listener) context.Context { return p.ctx }}
	stop := context.AfterFunc(p.ctx, func() { _ = server.Close() })
	defer stop()
	return server.Serve(l)
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if p.config.Control != nil && p.config.Control.Handle(w, r) {
		return
	}
	p.handle(w, r, "")
}

func (p *Proxy) handle(w http.ResponseWriter, r *http.Request, tunnel string) {
	defer func() {
		if recover() != nil {
			route := p.config.Scope.Classify(r.Host, r.URL.RequestURI())
			p.audit.emit(r, route, "block", "killed-on-error", scanner.Report{"rule_ids": []string{"proxy-error"}}, false, false)
			debugEvent(r, "aborted", "proxy-error", 0)
			panic(http.ErrAbortHandler)
		}
	}()
	// Collect value-free traffic evidence even when finding logs are disabled.
	{
		transport := "http"
		if r.Method == http.MethodConnect {
			transport = "connect"
		}
		if isWebSocket(r) {
			transport = "websocket"
		}
		parent, _ := r.Context().Value(debugConnectionKey{}).(string)
		host := r.URL.Host
		if host == "" {
			host = r.Host
		}
		r = p.debug.begin(r, p.config.Scope.Classify(host, r.URL.RequestURI()), transport, parent, p.config.Observe)
	}
	if tunnel != "" {
		a, err := requestAuthority(r.Host)
		urlAuthority := a
		if r.URL.Host != "" {
			urlAuthority, err = requestAuthority(r.URL.Host)
		}
		if err != nil || a != tunnel || urlAuthority != tunnel || r.URL.User != nil || (r.URL.Scheme != "" && r.URL.Scheme != "https") || r.Method == http.MethodConnect {
			debugEvent(r, "rejected", "authority-mismatch", 0)
			http.Error(w, "request authority differs from CONNECT", 421)
			return
		}
		r.URL.Scheme = "https"
		r.URL.Host = tunnel
	} else {
		if r.Method == http.MethodConnect {
			p.connect(w, r)
			return
		}
		if r.URL.Scheme != "http" || r.URL.Host == "" || r.URL.User != nil {
			debugEvent(r, "rejected", "invalid-proxy-url", 0)
			http.Error(w, "absolute HTTP proxy URL required", 400)
			return
		}
	}
	p.request(w, r)
}

func (p *Proxy) block(w http.ResponseWriter, r *http.Request, route policy.Route, reason string, report scanner.Report) bool {
	if report == nil {
		report = scanner.Report{"rule_ids": []string{reason}}
	}
	p.audit.emit(r, route, "block", "blocked", report, p.config.Observe, false)
	if t := trace(r); t != nil {
		t.mu.Lock()
		pending := t.record.PolicyAction == "pending"
		t.mu.Unlock()
		if pending {
			debugDecision(r, "not-scanned", "block", reason, report, nil)
		}
	}
	if p.config.Observe {
		return false
	}
	debugEvent(r, "blocked", reason, 0)
	response := p.config.Scope.Block(reason, report["wants_stream"] == true)
	for key, values := range response.Header {
		w.Header()[key] = values
	}
	w.WriteHeader(response.Status)
	_, _ = w.Write(response.Body)
	return true
}

func (p *Proxy) request(w http.ResponseWriter, r *http.Request) {
	route := p.config.Scope.Classify(r.URL.Host, r.URL.RequestURI())
	if isWebSocket(r) {
		p.websocket(w, r, route)
		return
	}
	if route.Passthrough || !route.Scoped {
		p.audit.foreign(route)
		if !route.Passthrough && route.Looking && (r.Method == "POST" || r.Method == "PUT" || r.Method == "PATCH" || !bodyless(r)) {
			if p.block(w, r, route, "out-of-scope-host", nil) {
				return
			}
		}
		p.forward(w, r)
		return
	}
	scanBody := r.Method == "POST" && (route.AllowNonJSON || strings.Contains(strings.ToLower(r.Header.Get("Content-Type")), "json"))
	if r.Method != "POST" {
		if !bodyless(r) {
			if route.HTTPFailureAction != "" {
				p.audit.emit(r, route, "redact", route.HTTPFailureAction, scanner.Report{"rule_ids": []string{route.NonPostRule}}, false, false)
			} else if p.block(w, r, route, "unscannable-body", nil) {
				return
			}
		}
		if bodyless(r) || route.HTTPFailureAction != "" {
			debugDecision(r, "not-scanned", "passthrough", "method-outside-inspection", nil, nil)
		}
	} else if !scanBody {
		if p.block(w, r, route, "unscannable-body", nil) {
			return
		}
	}
	if !scanBody && bodyless(r) {
		p.forward(w, r)
		return
	}
	t, err := p.budget.acquire()
	if err != nil {
		p.rejectIntake(w, r, route)
		return
	}
	defer t.release()
	// Every guarded body that can be forwarded must pass transport admission,
	// including policy exceptions and unsupported formats in observe mode.
	raw, err := readBounded(r.Body, p.config.MaxBytes, t)
	_ = r.Body.Close()
	if err != nil {
		p.rejectIntake(w, r, route)
		return
	}
	r.Body = io.NopCloser(bytes.NewReader(raw))
	if !scanBody || p.inspect(w, r, route, t, raw) {
		r.Body = &inspectedBody{reader: r.Body, ticket: t}
		defer r.Body.Close()
		p.forward(w, r)
	}
}

func (p *Proxy) rejectIntake(w http.ResponseWriter, r *http.Request, route policy.Route) {
	p.audit.emit(r, route, "block", "blocked", scanner.Report{"rule_ids": []string{"over-cap"}}, false, false)
	debugDecision(r, "over-cap", "reject", "transport-limit", nil, nil)
	debugEvent(r, "blocked", "transport-limit", 0)
	http.Error(w, "request body could not be buffered within transport limits", http.StatusRequestEntityTooLarge)
}

// Finish inspection before streaming the response so extraction and rewrite
// buffers do not live for the duration of an event stream.
func (p *Proxy) inspect(w http.ResponseWriter, r *http.Request, route policy.Route, t *ticket, raw []byte) bool {
	decoded, decodeErr := decodeBody(raw, r.Header, p.config.MaxBytes, t)
	if errors.Is(decodeErr, errCapacity) {
		p.rejectIntake(w, r, route)
		return false
	}
	var report scanner.Report
	if decodeErr != nil {
		status := "unscannable-body"
		if errors.Is(decodeErr, errCap) {
			status = "over-cap-decoded"
		}
		report = scanner.Report{"status": status}
	} else {
		ctx, cancel := context.WithTimeout(r.Context(), p.config.ScanTimeout)
		debugScan(r)
		var err error
		report, err = p.config.Scanner.Scan(ctx, decoded, p.config.MaxBytes)
		cancel()
		if err != nil {
			report = scanner.Report{"status": "scanner-error"}
		}
		if report == nil {
			report = scanner.Report{"status": "scanner-error"}
		}
		// Stream-specific block framing belongs to the selected integration,
		// not to the scanner worker's report.
		report["wants_stream"] = p.config.Scope.WantsStream(decoded)
	}
	status, _ := report["status"].(string)
	decision := policy.Evaluate(route, status, residue(report) > 0, false)
	var rewritten []byte
	if decision.Action == "redact" && !p.config.Observe {
		text, ok := report["body_base64"].(string)
		var e error
		rewritten, e = base64.StdEncoding.Strict().DecodeString(text)
		if !ok || e != nil {
			panic("invalid redaction report")
		}
	}
	debugDecision(r, status, decision.Action, decision.Reason, report, rewritten)
	switch decision.Action {
	case "forward":
		return true
	case "passthrough":
		p.audit.emit(r, route, "redact", route.HTTPFailureAction, scanner.Report{"rule_ids": []string{decision.Reason}}, false, false)
	case "block":
		if status != "redacted" && !route.Unknown {
			report = scanner.Report{"rule_ids": []string{decision.Reason}, "wants_stream": report["wants_stream"] == true}
		}
		if p.block(w, r, route, decision.Reason, report) {
			return false
		}
	case "redact":
		if !p.config.Observe {
			body := rewritten
			r.Body = io.NopCloser(bytes.NewReader(body))
			r.ContentLength = int64(len(body))
			r.TransferEncoding = nil
			r.Trailer = nil
			r.Header.Del("Content-Encoding")
			r.Header.Del("Transfer-Encoding")
			r.Header.Del("Trailer")
			r.Header.Del("Content-MD5")
			r.Header.Del("Digest")
			r.Header.Set("Content-Type", "application/json; charset=utf-8")
			r.Header.Set("Content-Length", strconv.Itoa(len(body)))
		}
		p.audit.emit(r, route, "redact", "forwarded", report, p.config.Observe, true)
	default:
		panic("invalid policy decision")
	}
	return true
}

func residue(r scanner.Report) float64 {
	stats, _ := r["stats"].(map[string]any)
	n, _ := stats["sweep_unrewritable"].(float64)
	return n
}

func stripHop(h http.Header) {
	for _, v := range h.Values("Connection") {
		for _, k := range strings.Split(v, ",") {
			h.Del(strings.TrimSpace(k))
		}
	}
	for _, k := range []string{"Connection", "Proxy-Connection", "Proxy-Authenticate", "Proxy-Authorization", "Keep-Alive", "TE", "Trailer", "Transfer-Encoding", "Upgrade"} {
		h.Del(k)
	}
}

// Reading the body alone is not evidence of a successful write. Combine it
// with WroteRequest so early upstream responses cannot claim an unsent body.
type debugUpload struct {
	io.ReadCloser
	read atomic.Int64
	eof  atomic.Bool
}

func (b *debugUpload) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	b.read.Add(int64(n))
	if err == io.EOF {
		b.eof.Store(true)
	}
	return n, err
}

func (p *Proxy) forward(w http.ResponseWriter, r *http.Request) {
	if t := trace(r); t != nil {
		t.mu.Lock()
		pending := t.record.PolicyAction == "pending"
		t.mu.Unlock()
		if pending {
			debugDecision(r, "not-scanned", "passthrough", "outside-inspection-scope", nil, nil)
		}
	}
	out := r.Clone(r.Context())
	out.RequestURI = ""
	out.Host = out.URL.Host
	stripHop(out.Header)
	if trace(r) != nil {
		var upload *debugUpload
		expected := out.ContentLength
		if out.Body != nil && out.Body != http.NoBody {
			upload = &debugUpload{ReadCloser: out.Body}
			out.Body = upload
		}
		out = out.WithContext(httptrace.WithClientTrace(out.Context(), &httptrace.ClientTrace{
			GotConn: func(httptrace.GotConnInfo) { debugWriteAttempt(r) },
			WroteRequest: func(info httptrace.WroteRequestInfo) {
				if info.Err != nil {
					debugEvent(r, "write_error", "upstream-write-failed", 0)
				} else if upload != nil && ((expected > 0 && upload.read.Load() != expected) || (expected <= 0 && !upload.eof.Load())) {
					debugEvent(r, "body_not_written", "upstream-body-incomplete", 0)
				} else {
					debugEvent(r, "upstream_written", "", 0)
				}
			},
		}))
	}
	debugEvent(r, "forward_attempt", "", 0)
	resp, err := p.transport.RoundTrip(out)
	if err != nil {
		debugEvent(r, "upstream_error", "upstream-roundtrip-failed", 0)
		http.Error(w, "upstream connection failed", 502)
		return
	}
	debugEvent(r, "upstream_response", "", resp.StatusCode)
	defer resp.Body.Close()
	stripHop(resp.Header)
	for k, vs := range resp.Header {
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	for k := range resp.Trailer {
		w.Header().Add("Trailer", k)
	}
	w.WriteHeader(resp.StatusCode)
	// Flush each upstream read, so event streams do not wait for completion.
	buf := make([]byte, 32*1024)
	for {
		n, e := resp.Body.Read(buf)
		if n > 0 {
			if _, err = w.Write(buf[:n]); err != nil {
				debugEvent(r, "response_error", "client-response-write-failed", 0)
				return
			}
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
		}
		if e != nil {
			if e != io.EOF {
				panic(http.ErrAbortHandler)
			}
			break
		}
	}
	for k, vs := range resp.Trailer {
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
}
