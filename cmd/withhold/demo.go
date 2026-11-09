package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"github.com/cquark7/withhold/internal/certstore"
	"github.com/cquark7/withhold/internal/integrations"
	"github.com/cquark7/withhold/internal/policy"
	"github.com/cquark7/withhold/internal/proxy"
	"github.com/cquark7/withhold/internal/scanpool"
)

const demoKey = "withhold-demo-synthetic-key"
const demoSecret = "AKIA4X7Q2W8K9MNDZZZZ"

type demoCheck struct {
	Name   string `json:"name"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail"`
}

func demo(w io.Writer, args []string) int {
	o := defaultOptions("~")
	if _, showHelp, err := parseOptions(o.flags("demo"), "demo", args); showHelp {
		return help(w, "demo")
	} else if err != nil {
		return commandUsageError("demo", err.Error())
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	binary, err := os.Executable()
	var checks []demoCheck
	if err == nil {
		checks, err = runDemo(ctx, binary)
	} else {
		err = errors.New("cannot locate bundled scanner")
	}
	if o.json {
		result := map[string]any{"schema": 1, "verb": "demo", "ok": err == nil, "checks": checks, "scope": "synthetic-loopback-only"}
		if err != nil {
			result["error"] = err.Error()
		}
		if json.NewEncoder(w).Encode(result) != nil {
			return 1
		}
	} else {
		for _, check := range checks {
			fmt.Fprintf(w, "[PASS] %s — %s\n", check.Name, check.Detail)
		}
		if err != nil {
			fmt.Fprintln(w, "[FAIL] demo —", err)
		}
		fmt.Fprintln(w, "Synthetic loopback only; this does not verify application routing or live-provider compatibility.")
	}
	if err != nil {
		return 1
	}
	return 0
}

func runDemo(ctx context.Context, binary string) (checks []demoCheck, err error) {
	dir, err := os.MkdirTemp("", "withhold-demo-")
	if err != nil {
		return nil, errors.New("cannot create temporary demo directory")
	}
	defer func() {
		if os.RemoveAll(dir) != nil {
			err = errors.New("temporary demo cleanup failed")
		}
	}()
	if certstore.Init(dir) != nil {
		return nil, errors.New("temporary demo CA initialization failed")
	}
	ca, err := certstore.Load(dir)
	if err != nil {
		return nil, errors.New("temporary demo CA could not be loaded")
	}
	// Do not inherit user policy, debug settings, keys, or home directories.
	environment := []string{}
	for _, entry := range os.Environ() {
		key, _, _ := strings.Cut(entry, "=")
		key = strings.ToUpper(key)
		if key != "HOME" && key != "USERPROFILE" && !strings.HasPrefix(key, "WITHHOLD_") && !strings.HasPrefix(key, "BETTERLEAKS_") && !strings.HasPrefix(key, "GITLEAKS_") {
			environment = append(environment, entry)
		}
	}
	environment = append(environment, "HOME="+dir, "USERPROFILE="+dir, "WITHHOLD_PII=off", "WITHHOLD_PLACEHOLDER_KEY="+demoKey)
	pool := scanpool.NewWithEnvironment(binary, environment, "_scanner", "--body")
	defer pool.Close()
	if _, err = pool.Scan(ctx, []byte(`{}`), 4096); err != nil {
		return nil, errors.New("bundled scanner self-test failed")
	}
	return exerciseDemo(ctx, dir, ca, pool)
}

func exerciseDemo(ctx context.Context, dir string, ca *certstore.CA, engine proxy.Scanner) ([]demoCheck, error) {
	leaf, err := ca.Leaf("127.0.0.1")
	if err != nil {
		return nil, errors.New("temporary TLS certificate issuance failed")
	}
	upstream, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return nil, errors.New("cannot bind local demo upstream")
	}
	defer upstream.Close()
	var requests atomic.Uint64
	received := make(chan []byte, 2)
	server := &http.Server{ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second, ErrorLog: log.New(io.Discard, "", 0), Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(io.LimitReader(r.Body, 4097))
		requests.Add(1)
		select {
		case received <- body:
		default:
		}
		w.WriteHeader(http.StatusNoContent)
	})}
	go func() {
		_ = server.Serve(tls.NewListener(upstream, &tls.Config{Certificates: []tls.Certificate{*leaf}, MinVersion: tls.VersionTLS12}))
	}()
	defer server.Close()
	roots := x509.NewCertPool()
	roots.AddCert(ca.Certificate)
	// Fixed loopback scope uses the shipped adapter's chat/inline policies.
	scope, err := integrations.Traffic(integrations.Default, policy.ScopeOptions{ExtraHosts: []string{"127.0.0.1"}, ChatMode: "redact", InlineMode: "block"}, nil)
	if err != nil {
		return nil, errors.New("demo traffic profile could not be constructed")
	}
	p, err := proxy.New(proxy.Config{CA: ca, Scope: scope, Scanner: engine, Roots: roots, MaxBytes: 4096, ScanTimeout: 5 * time.Second, AuditPath: filepath.Join(dir, "audit.jsonl"), HintPath: filepath.Join(dir, "hints.log")})
	if err != nil {
		return nil, errors.New("local demo proxy initialization failed")
	}
	defer p.Close()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return nil, errors.New("cannot bind local demo proxy")
	}
	done := make(chan error, 1)
	proxyServer := &http.Server{Handler: demoProxyHandler(upstream.Addr().String(), p), ReadHeaderTimeout: 5 * time.Second, ErrorLog: log.New(io.Discard, "", 0)}
	go func() { done <- proxyServer.Serve(listener) }()
	defer func() { p.Close(); _ = proxyServer.Close(); <-done }()
	transport := &http.Transport{Proxy: http.ProxyURL(&url.URL{Scheme: "http", Host: listener.Addr().String()}), TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}, DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	body := `{"input":"token = ` + demoSecret + `"}`
	post := func(path string) (int, string, error) {
		r, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://"+upstream.Addr().String()+path, strings.NewReader(body))
		if err != nil {
			return 0, "", err
		}
		r.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(r)
		if err != nil {
			return 0, "", err
		}
		defer resp.Body.Close()
		_, err = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return resp.StatusCode, resp.Header.Get("X-Withhold-Block"), err
	}
	status, _, err := post("/chat/completions")
	if err != nil || status != http.StatusNoContent {
		return nil, errors.New("local HTTPS redaction request failed")
	}
	mac := hmac.New(sha256.New, []byte(demoKey))
	_, _ = mac.Write([]byte(demoSecret))
	marker := "<WITHHELD_" + hex.EncodeToString(mac.Sum(nil))[:16] + ">"
	var forwarded map[string]string
	select {
	case data := <-received:
		if bytes.Contains(data, []byte(demoSecret)) || json.Unmarshal(data, &forwarded) != nil || forwarded["input"] != "token = "+marker {
			return nil, errors.New("redaction check failed: local upstream did not receive the expected replacement")
		}
	default:
		return nil, errors.New("redaction check failed: local upstream received no request")
	}
	checks := []demoCheck{{"redact", true, "local HTTPS upstream received " + marker + ", not the synthetic secret"}}
	status, blocked, err := post("/v1/engines/demo/completions")
	if err != nil || status != http.StatusTooManyRequests || blocked != "1" || requests.Load() != 1 {
		return checks, errors.New("block check failed: expected a local rejection without an upstream request")
	}
	checks = append(checks, demoCheck{"block", true, "local rejection confirmed; no second request reached upstream"})
	return checks, nil
}

// The demo listener is not a general proxy: even another local client can only
// CONNECT to the fixed temporary receiver. Inner requests must match that tunnel.
func demoProxyHandler(target string, p http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect || r.URL.IsAbs() || r.Host != target {
			http.Error(w, "demo permits only its local HTTPS receiver", http.StatusForbidden)
			return
		}
		p.ServeHTTP(w, r)
	})
}
