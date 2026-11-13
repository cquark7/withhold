package proxy

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cquark7/withhold/internal/certstore"
	"github.com/cquark7/withhold/internal/connectrpc"
	"github.com/cquark7/withhold/internal/integrations/cursor"
	"github.com/cquark7/withhold/internal/policy"
	"github.com/cquark7/withhold/internal/scanner"
	"github.com/cquark7/withhold/internal/scanpool"
	"github.com/klauspost/compress/zstd"
	"google.golang.org/protobuf/encoding/protowire"
)

// A schema-free test adapter proves that shared transport does not depend on
// Cursor hosts, RPC names, or its protobuf projection.
type testRPCMessage []byte

func (m testRPCMessage) ScanInput() []byte                   { return bytes.Clone(m) }
func (m testRPCMessage) Rewrite(body []byte) ([]byte, error) { return bytes.Clone(body), nil }
func (m testRPCMessage) HasContent() bool                    { return len(m) > 0 }

type testRPCProfile struct {
	codec *policy.RPCCodec
	mode  string
}

func (p testRPCProfile) Classify(host, _ string) policy.Route {
	mode := p.mode
	if mode == "" {
		mode = "redact"
	}
	return policy.Route{Host: host, Surface: "chat", API: "rpc", Scoped: true, Mode: mode, Codec: p.codec}
}
func (p testRPCProfile) WantsStream([]byte) bool { return true }
func (p testRPCProfile) Block(reason string, _ bool) policy.Response {
	return policy.Response{Status: 403, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: []byte(`{"error":"` + reason + `"}`)}
}
func rpcCodec(stream, duplex bool) *policy.RPCCodec {
	return &policy.RPCCodec{Streaming: stream, Duplex: duplex,
		Decode: func(data []byte, limits policy.DecodeLimits) (policy.Message, error) {
			if limits.Reserve != nil {
				if err := limits.Reserve(len(data)); err != nil {
					return nil, err
				}
			}
			if bytes.Contains(data, []byte("unsupported")) {
				return nil, errors.New("unreviewed private detail")
			}
			return testRPCMessage(data), nil
		}}
}
func cleanRPCScanner() fakeScanner {
	return fakeScanner{func(context.Context, []byte, int64) (scanner.Report, error) {
		return scanner.Report{"status": "clean"}, nil
	}}
}
func redactRPCScanner() fakeScanner {
	return fakeScanner{func(_ context.Context, data []byte, _ int64) (scanner.Report, error) {
		if !bytes.Contains(data, []byte("sentinel")) {
			return scanner.Report{"status": "clean"}, nil
		}
		data = bytes.ReplaceAll(data, []byte("sentinel"), []byte("<WITHHELD_0123456789abcdef>"))
		return scanner.Report{"status": "redacted", "body_base64": base64.StdEncoding.EncodeToString(data)}, nil
	}}
}

type rpcFixture struct {
	proxy  *Proxy
	client *http.Client
	url    string
}

func newRPCFixture(t *testing.T, profile policy.Profile, scan Scanner, maxBytes int64, upstream http.HandlerFunc, h2 bool) rpcFixture {
	t.Helper()
	up := httptest.NewUnstartedServer(upstream)
	up.EnableHTTP2 = h2
	up.StartTLS()
	t.Cleanup(up.Close)
	dir := t.TempDir()
	if err := certstore.Init(filepath.Join(dir, "ca")); err != nil {
		t.Fatal(err)
	}
	ca, err := certstore.Load(filepath.Join(dir, "ca"))
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(up.Certificate())
	p, err := New(Config{CA: ca, Roots: roots, Scope: profile, Scanner: scan, MaxBytes: maxBytes,
		ScanTimeout: 200 * time.Millisecond, AuditPath: filepath.Join(dir, "audit"), HintPath: filepath.Join(dir, "hint")})
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { defer close(done); _ = p.Serve(listener) }()
	t.Cleanup(func() { p.Close(); _ = listener.Close(); <-done })
	proxyURL, _ := url.Parse("http://" + listener.Addr().String())
	clientRoots := x509.NewCertPool()
	clientRoots.AddCert(ca.Certificate)
	transport := &http.Transport{Proxy: http.ProxyURL(proxyURL), ForceAttemptHTTP2: true,
		TLSClientConfig: &tls.Config{RootCAs: clientRoots, MinVersion: tls.VersionTLS12}}
	t.Cleanup(transport.CloseIdleConnections)
	return rpcFixture{proxy: p, client: &http.Client{Transport: transport, Timeout: 5 * time.Second}, url: up.URL}
}
func rpcFrame(t *testing.T, data []byte) []byte {
	t.Helper()
	frame, err := connectrpc.Envelope(0, data, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	return frame
}
func (f rpcFixture) request(t *testing.T, body io.Reader, media string) *http.Request {
	t.Helper()
	request, err := http.NewRequest("POST", f.url+"/service/Method", body)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", media)
	return request
}

type rpcResult struct {
	response *http.Response
	err      error
}

func rpcStart(f rpcFixture, request *http.Request) <-chan rpcResult {
	result := make(chan rpcResult, 1)
	go func() { response, err := f.client.Do(request); result <- rpcResult{response, err} }()
	return result
}
func receiveRPC[T any](t *testing.T, ch <-chan T) T {
	t.Helper()
	select {
	case value := <-ch:
		return value
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for fixture")
		var zero T
		return zero
	}
}

func assertRPCAdmissionReleased(t *testing.T, p *Proxy) {
	t.Helper()
	p.budget.mu.Lock()
	defer p.budget.mu.Unlock()
	if p.budget.jobs != 0 || p.budget.bytes != 0 {
		t.Fatalf("upload retained admission: jobs=%d bytes=%d", p.budget.jobs, p.budget.bytes)
	}
}

func TestRPCDuplexInspectsBeforeReleaseAndStreamsBeforeEOF(t *testing.T) {
	started, release := make(chan struct{}, 2), make(chan struct{})
	var scans atomic.Int32
	scan := fakeScanner{func(ctx context.Context, data []byte, max int64) (scanner.Report, error) {
		scans.Add(1)
		started <- struct{}{}
		select {
		case <-release:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		return redactRPCScanner().Scan(ctx, data, max)
	}}
	received := make(chan []byte, 2)
	f := newRPCFixture(t, testRPCProfile{codec: rpcCodec(true, true)}, scan, 4096, func(w http.ResponseWriter, r *http.Request) {
		for range 2 {
			frame, err := connectrpc.ReadFrame(r.Body, 4096, nil)
			if err != nil {
				return
			}
			received <- frame.Data
			_, _ = w.Write([]byte("ack\n"))
			w.(http.Flusher).Flush()
		}
	}, true)
	// Give gating checks ample room without letting a scanner ignore cancellation.
	f.proxy.config.ScanTimeout = 3 * time.Second
	reader, writer := io.Pipe()
	t.Cleanup(func() { _ = writer.Close(); _ = reader.Close() })
	result := rpcStart(f, f.request(t, reader, "application/connect+proto"))
	go func() { _, _ = writer.Write(rpcFrame(t, []byte(`{"text":"clean"}`))) }()
	receiveRPC(t, started)
	select {
	case <-received:
		t.Fatal("first payload reached upstream before scan")
	default:
	}
	release <- struct{}{}
	if got := receiveRPC(t, received); string(got) != `{"text":"clean"}` {
		t.Fatal("clean message changed")
	}
	response := receiveRPC(t, result)
	if response.err != nil {
		t.Fatal(response.err)
	}
	defer response.response.Body.Close()
	ack := make([]byte, 4)
	if _, err := io.ReadFull(response.response.Body, ack); err != nil || string(ack) != "ack\n" {
		t.Fatal("response waited for upload EOF")
	}
	later := rpcFrame(t, []byte(`{"tool_result":"sentinel"}`))
	go func() {
		for i := 0; i < len(later); i += 2 {
			if _, err := writer.Write(later[i:min(i+2, len(later))]); err != nil {
				return
			}
		}
		_ = writer.Close()
	}()
	receiveRPC(t, started)
	select {
	case <-received:
		t.Fatal("later payload escaped before inspection")
	default:
	}
	release <- struct{}{}
	got := receiveRPC(t, received)
	if bytes.Contains(got, []byte("sentinel")) || !bytes.Contains(got, []byte("<WITHHELD_")) {
		t.Fatal("later message not redacted")
	}
	if _, err := io.ReadAll(response.response.Body); err != nil {
		t.Fatal(err)
	}
	if scans.Load() != 2 {
		t.Fatal("incorrect message scan count")
	}
	assertRPCAdmissionReleased(t, f.proxy)
	status := f.proxy.debug.snapshot()
	if status.Inspected != 2 || status.Redacted != 1 || status.Passthrough != 0 {
		t.Fatalf("incorrect coverage: %+v", status)
	}
}

func TestRPCLaterFailuresAbortResponseWithoutReleasingPayload(t *testing.T) {
	for _, failure := range []string{"block", "scanner-error", "deadline", "panic", "invalid-rewrite", "unsupported", "envelope", "wire-cap"} {
		t.Run(failure, func(t *testing.T) {
			var scans atomic.Int32
			scan := fakeScanner{func(ctx context.Context, data []byte, max int64) (scanner.Report, error) {
				if scans.Add(1) == 1 {
					return scanner.Report{"status": "clean"}, nil
				}
				switch failure {
				case "scanner-error":
					return nil, errors.New("private scanner detail")
				case "deadline":
					<-ctx.Done()
					return nil, ctx.Err()
				case "panic":
					panic("private scanner detail")
				case "invalid-rewrite":
					return scanner.Report{"status": "redacted", "body_base64": "%%%"}, nil
				default:
					return redactRPCScanner().Scan(ctx, data, max)
				}
			}}
			mode := "redact"
			if failure == "block" {
				mode = "block"
			}
			received := make(chan []byte, 2)
			upDone := make(chan struct{})
			f := newRPCFixture(t, testRPCProfile{codec: rpcCodec(true, true), mode: mode}, scan, 256, func(w http.ResponseWriter, r *http.Request) {
				defer close(upDone)
				frame, err := connectrpc.ReadFrame(r.Body, 4096, nil)
				if err != nil {
					return
				}
				received <- frame.Data
				_, _ = w.Write([]byte("ack\n"))
				w.(http.Flusher).Flush()
				frame, err = connectrpc.ReadFrame(r.Body, 4096, nil)
				if err == nil {
					received <- frame.Data
				}
				<-r.Context().Done()
			}, true)
			reader, writer := io.Pipe()
			defer reader.Close()
			defer writer.Close()
			result := rpcStart(f, f.request(t, reader, "application/connect+proto"))
			_, _ = writer.Write(rpcFrame(t, []byte(`{"text":"clean"}`)))
			receiveRPC(t, received)
			response := receiveRPC(t, result)
			if response.err != nil {
				t.Fatal(response.err)
			}
			defer response.response.Body.Close()
			ack := make([]byte, 4)
			if _, err := io.ReadFull(response.response.Body, ack); err != nil {
				t.Fatal(err)
			}
			later := rpcFrame(t, []byte(`{"text":"sentinel"}`))
			switch failure {
			case "unsupported":
				later = rpcFrame(t, []byte(`{"text":"unsupported"}`))
			case "envelope":
				later = []byte{0, 0, 0, 0, 10, 'x'}
			case "wire-cap":
				later = rpcFrame(t, bytes.Repeat([]byte("x"), 240))
			}
			go func() { _, _ = writer.Write(later); _ = writer.Close() }()
			if _, err := io.ReadAll(response.response.Body); err == nil {
				t.Fatal("late failure looked like a successful response EOF")
			}
			receiveRPC(t, upDone)
			assertRPCAdmissionReleased(t, f.proxy)
			select {
			case <-received:
				t.Fatal("failed later payload reached upstream")
			default:
			}
			audit, _ := os.ReadFile(f.proxy.config.AuditPath)
			if bytes.Contains(audit, []byte("private")) || bytes.Contains(audit, []byte("sentinel")) {
				t.Fatal("payload entered diagnostics")
			}
		})
	}
}

func TestRPCUnaryCompressionPolicyAndGETCannotBypass(t *testing.T) {
	for _, observe := range []bool{false, true} {
		t.Run(map[bool]string{false: "enforce", true: "observe"}[observe], func(t *testing.T) {
			received := make(chan []byte, 4)
			f := newRPCFixture(t, testRPCProfile{codec: rpcCodec(false, false)}, redactRPCScanner(), 4096, func(w http.ResponseWriter, r *http.Request) {
				data, _ := io.ReadAll(r.Body)
				received <- data
				_, _ = w.Write([]byte("ok"))
			}, true)
			f.proxy.config.Observe = observe
			raw := []byte(`{"text":"sentinel"}`)
			var compressed bytes.Buffer
			z := gzip.NewWriter(&compressed)
			_, _ = z.Write(raw)
			_ = z.Close()
			r := f.request(t, bytes.NewReader(compressed.Bytes()), "application/proto")
			r.Header.Set("Content-Encoding", "gzip")
			r.Header.Set("Digest", "stale")
			r.Header.Set("Content-Digest", "stale")
			response, err := f.client.Do(r)
			if err != nil {
				t.Fatal(err)
			}
			_ = response.Body.Close()
			got := receiveRPC(t, received)
			if observe {
				if !bytes.Equal(got, compressed.Bytes()) {
					t.Fatal("observe changed wire bytes")
				}
			} else if bytes.Contains(got, []byte("sentinel")) || !bytes.Contains(got, []byte("<WITHHELD_")) {
				t.Fatal("unary rewrite failed")
			}
			r = f.request(t, nil, "application/proto")
			r.Method = "GET"
			r.URL.RawQuery = "message=sentinel"
			response, err = f.client.Do(r)
			if err != nil {
				t.Fatal(err)
			}
			_ = response.Body.Close()
			if !observe && response.StatusCode != 403 {
				t.Fatal("bodyless RPC GET bypassed")
			}
		})
	}
}

func TestRPCTransportLimitsRemainEnforcedInObserve(t *testing.T) {
	for _, kind := range []string{"capacity", "decoded-cap", "cumulative-wire", "bad-flags", "truncated"} {
		t.Run(kind, func(t *testing.T) {
			var calls atomic.Int32
			f := newRPCFixture(t, testRPCProfile{codec: rpcCodec(true, true)}, cleanRPCScanner(), 128, func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				_, _ = io.Copy(io.Discard, r.Body)
			}, true)
			f.proxy.config.Observe = true
			body := rpcFrame(t, []byte(`{"text":"clean"}`))
			var tickets []*ticket
			if kind == "capacity" {
				for range 6 {
					ticket, err := f.proxy.budget.acquire()
					if err != nil {
						t.Fatal(err)
					}
					tickets = append(tickets, ticket)
				}
				defer func() {
					for _, ticket := range tickets {
						ticket.release()
					}
				}()
			}
			switch kind {
			case "decoded-cap":
				var compressed bytes.Buffer
				z := gzip.NewWriter(&compressed)
				_, _ = z.Write(bytes.Repeat([]byte("x"), 256))
				_ = z.Close()
				body, _ = connectrpc.Envelope(1, compressed.Bytes(), 128)
			case "cumulative-wire":
				body = append(body, rpcFrame(t, bytes.Repeat([]byte("x"), 110))...)
			case "bad-flags":
				body[0] = 2
			case "truncated":
				body = body[:len(body)-1]
			}
			r := f.request(t, bytes.NewReader(body), "application/connect+proto")
			r.Header.Set("Connect-Content-Encoding", "gzip")
			response, err := f.client.Do(r)
			if err == nil {
				data, readErr := io.ReadAll(response.Body)
				_ = response.Body.Close()
				if response.StatusCode == 200 && readErr == nil && !strings.Contains(string(data), "blocked") {
					t.Fatal("transport failure passed in observe")
				}
			}
			if kind != "cumulative-wire" && calls.Load() != 0 {
				t.Fatal("transport-rejected first message opened upstream")
			}
		})
	}
}

func TestRPCDuplexRejectsUpstreamHTTP1BeforePayload(t *testing.T) {
	var received atomic.Int64
	f := newRPCFixture(t, testRPCProfile{codec: rpcCodec(true, true)}, cleanRPCScanner(), 4096, func(w http.ResponseWriter, r *http.Request) {
		n, _ := io.Copy(io.Discard, r.Body)
		received.Add(n)
	}, false)
	r := f.request(t, bytes.NewReader(rpcFrame(t, []byte(`{"text":"clean"}`))), "application/connect+proto")
	response, err := f.client.Do(r)
	if err == nil {
		_, _ = io.Copy(io.Discard, response.Body)
		_ = response.Body.Close()
		if response.StatusCode != 413 {
			t.Fatal("HTTP/1 fallback accepted")
		}
	}
	if received.Load() != 0 {
		t.Fatal("duplex payload reached HTTP/1 upstream")
	}
}

func TestRPCMessageCompressionPreservesCleanAndReframesRedaction(t *testing.T) {
	for _, encoding := range []string{"gzip", "zstd"} {
		for _, mode := range []string{"clean", "redact", "observe"} {
			t.Run(encoding+"/"+mode, func(t *testing.T) {
				received := make(chan connectrpc.Frame, 1)
				f := newRPCFixture(t, testRPCProfile{codec: rpcCodec(true, true)}, redactRPCScanner(), 4096,
					func(w http.ResponseWriter, r *http.Request) {
						frame, err := connectrpc.ReadFrame(r.Body, 4096, nil)
						if err != nil {
							return
						}
						received <- frame
						_, _ = w.Write([]byte("done"))
					}, true)
				f.proxy.config.Observe = mode == "observe"
				raw := []byte(`{"text":"sentinel"}`)
				if mode == "clean" {
					raw = []byte(`{"text":"clean"}`)
				}
				var compressed bytes.Buffer
				var writer io.WriteCloser
				if encoding == "gzip" {
					writer = gzip.NewWriter(&compressed)
				} else {
					z, err := zstd.NewWriter(&compressed, zstd.WithEncoderConcurrency(1))
					if err != nil {
						t.Fatal(err)
					}
					writer = z
				}
				if _, err := writer.Write(raw); err != nil {
					t.Fatal(err)
				}
				if err := writer.Close(); err != nil {
					t.Fatal(err)
				}
				body, err := connectrpc.Envelope(1, compressed.Bytes(), 4096)
				if err != nil {
					t.Fatal(err)
				}
				request := f.request(t, bytes.NewReader(body), "application/connect+proto")
				request.Header.Set("Connect-Content-Encoding", encoding)
				response, err := f.client.Do(request)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := io.ReadAll(response.Body); err != nil {
					t.Fatal(err)
				}
				_ = response.Body.Close()
				frame := receiveRPC(t, received)
				if mode == "redact" {
					if frame.Flags != 0 || bytes.Contains(frame.Data, []byte("sentinel")) || !bytes.Contains(frame.Data, []byte("<WITHHELD_")) {
						t.Fatal("compressed message redaction failed")
					}
				} else if frame.Flags != 1 || !bytes.Equal(frame.Data, compressed.Bytes()) {
					t.Fatal("clean/observe compressed wire changed")
				}
				assertRPCAdmissionReleased(t, f.proxy)
			})
		}
	}
}

func TestRPCServerStreamingAcceptsHTTP1ClientWithoutWaitingForEOF(t *testing.T) {
	received := make(chan struct{})
	f := newRPCFixture(t, testRPCProfile{codec: rpcCodec(true, false)}, cleanRPCScanner(), 4096,
		func(w http.ResponseWriter, r *http.Request) {
			if _, err := connectrpc.ReadFrame(r.Body, 4096, nil); err != nil {
				return
			}
			_, _ = w.Write([]byte("done"))
			w.(http.Flusher).Flush()
			close(received)
		}, true)
	f.client.Transport.(*http.Transport).ForceAttemptHTTP2 = false
	reader, writer := io.Pipe()
	defer reader.Close()
	defer writer.Close()
	result := rpcStart(f, f.request(t, reader, "application/connect+proto"))
	_, _ = writer.Write(rpcFrame(t, []byte(`{"text":"clean"}`)))
	receiveRPC(t, received)
	response := receiveRPC(t, result)
	if response.err != nil {
		t.Fatal(response.err)
	}
	defer response.response.Body.Close()
	if response.response.ProtoMajor != 1 {
		t.Fatal("fixture did not exercise HTTP/1 client")
	}
	if data, err := io.ReadAll(response.response.Body); err != nil || string(data) != "done" {
		t.Fatalf("HTTP/1 server stream failed: %v", err)
	}
}

func TestRPCEarlyResponseStopsUploadWithoutWaitingForClientEOF(t *testing.T) {
	f := newRPCFixture(t, testRPCProfile{codec: rpcCodec(true, true)}, cleanRPCScanner(), 4096,
		func(w http.ResponseWriter, r *http.Request) {
			if _, err := connectrpc.ReadFrame(r.Body, 4096, nil); err != nil {
				return
			}
			_, _ = w.Write([]byte("finished"))
		}, true)
	reader, writer := io.Pipe()
	defer reader.Close()
	defer writer.Close()
	result := rpcStart(f, f.request(t, reader, "application/connect+proto"))
	_, _ = writer.Write(rpcFrame(t, []byte(`{"text":"clean"}`)))
	response := receiveRPC(t, result)
	if response.err != nil {
		t.Fatal(response.err)
	}
	defer response.response.Body.Close()
	body, err := io.ReadAll(response.response.Body)
	if err != nil || string(body) != "finished" {
		t.Fatalf("early response failed: %v", err)
	}
	assertRPCAdmissionReleased(t, f.proxy)
}

func TestRPCReleasedOutputHasCumulativeCap(t *testing.T) {
	received := make(chan []byte, 2)
	done := make(chan struct{})
	f := newRPCFixture(t, testRPCProfile{codec: rpcCodec(true, true)}, redactRPCScanner(), 60,
		func(w http.ResponseWriter, r *http.Request) {
			defer close(done)
			frame, err := connectrpc.ReadFrame(r.Body, 4096, nil)
			if err != nil {
				return
			}
			received <- frame.Data
			_, _ = w.Write([]byte("ack\n"))
			w.(http.Flusher).Flush()
			frame, err = connectrpc.ReadFrame(r.Body, 4096, nil)
			if err == nil {
				received <- frame.Data
			}
			<-r.Context().Done()
		}, true)
	reader, writer := io.Pipe()
	defer reader.Close()
	defer writer.Close()
	result := rpcStart(f, f.request(t, reader, "application/connect+proto"))
	_, _ = writer.Write(rpcFrame(t, []byte(`{"text":"clean"}`)))
	receiveRPC(t, received)
	response := receiveRPC(t, result)
	if response.err != nil {
		t.Fatal(response.err)
	}
	defer response.response.Body.Close()
	ack := make([]byte, 4)
	if _, err := io.ReadFull(response.response.Body, ack); err != nil {
		t.Fatal(err)
	}
	go func() { _, _ = writer.Write(rpcFrame(t, []byte(`{"text":"sentinel"}`))); _ = writer.Close() }()
	if _, err := io.ReadAll(response.response.Body); err == nil {
		t.Fatal("rewritten cumulative output cap was ignored")
	}
	receiveRPC(t, done)
	select {
	case <-received:
		t.Fatal("over-cap rewritten message reached upstream")
	default:
	}
	assertRPCAdmissionReleased(t, f.proxy)
}

func TestRPCIdleEnvelopeDoesNotHoldIntakeJob(t *testing.T) {
	received := make(chan struct{})
	f := newRPCFixture(t, testRPCProfile{codec: rpcCodec(true, true)}, cleanRPCScanner(), 4096,
		func(w http.ResponseWriter, r *http.Request) {
			if _, err := connectrpc.ReadFrame(r.Body, 4096, nil); err != nil {
				return
			}
			_, _ = w.Write([]byte("ack\n"))
			w.(http.Flusher).Flush()
			close(received)
			_, _ = io.Copy(io.Discard, r.Body)
		}, true)
	reader, writer := io.Pipe()
	defer reader.Close()
	defer writer.Close()
	result := rpcStart(f, f.request(t, reader, "application/connect+proto"))
	_, _ = writer.Write(rpcFrame(t, []byte(`{"text":"clean"}`)))
	receiveRPC(t, received)
	response := receiveRPC(t, result)
	if response.err != nil {
		t.Fatal(response.err)
	}
	defer response.response.Body.Close()
	ack := make([]byte, 4)
	if _, err := io.ReadFull(response.response.Body, ack); err != nil {
		t.Fatal(err)
	}
	// Six finite uploads can still acquire admission while this stream waits for
	// another header. A response is not an intake lease for its whole lifetime.
	var tickets []*ticket
	for range 6 {
		ticket, err := f.proxy.budget.acquire()
		if err != nil {
			t.Fatal("idle duplex stream retained an intake job")
		}
		tickets = append(tickets, ticket)
	}
	for _, ticket := range tickets {
		ticket.release()
	}
	_ = writer.Close()
	if _, err := io.ReadAll(response.response.Body); err != nil {
		t.Fatal(err)
	}
	assertRPCAdmissionReleased(t, f.proxy)
}

func TestCursorDuplexWithScannerWorker(t *testing.T) {
	binary := os.Getenv("WITHHOLD_TEST_SCANNER_WORKER")
	if binary == "" {
		t.Skip("set WITHHOLD_TEST_SCANNER_WORKER to run process scanning")
	}
	home := t.TempDir()
	pool := scanpool.NewWithEnvironment(binary, []string{"HOME=" + home, "WITHHOLD_PLACEHOLDER_KEY=isolated-cursor-test"}, "--body")
	defer pool.Close()
	scope, err := cursor.NewTraffic(policy.ScopeOptions{AllowHosts: []string{"127.0.0.1"}})
	if err != nil {
		t.Fatal(err)
	}
	received := make(chan []byte, 2)
	f := newRPCFixture(t, scope, pool, 1<<20, func(w http.ResponseWriter, r *http.Request) {
		for range 2 {
			frame, err := connectrpc.ReadFrame(r.Body, 1<<20, nil)
			if err != nil {
				return
			}
			received <- frame.Data
			_, _ = w.Write([]byte("ack\n"))
			w.(http.Flusher).Flush()
		}
	}, true)
	f.proxy.config.ScanTimeout = 5 * time.Second
	field := func(n protowire.Number, data []byte) []byte {
		return protowire.AppendBytes(protowire.AppendTag(nil, n, 2), data)
	}
	invoke := func(text string) []byte { return field(2, field(2, field(1, field(2, []byte(text))))) }
	reader, writer := io.Pipe()
	defer reader.Close()
	defer writer.Close()
	request := f.request(t, reader, "application/connect+proto")
	request.URL.Path = "/aiserver.v1.InferenceService/RunInference"
	result := rpcStart(f, request)
	first := invoke("Explain this function.")
	_, _ = writer.Write(rpcFrame(t, first))
	if !bytes.Equal(receiveRPC(t, received), first) {
		t.Fatal("clean protobuf changed")
	}
	response := receiveRPC(t, result)
	if response.err != nil {
		t.Fatal(response.err)
	}
	defer response.response.Body.Close()
	ack := make([]byte, 4)
	if _, err := io.ReadFull(response.response.Body, ack); err != nil {
		t.Fatal(err)
	}
	const sentinel = "sk_live_4eC39HqLyjWDarjtT1zdp7dc"
	second := rpcFrame(t, invoke(`shell output token = "`+sentinel+`"`))
	go func() {
		for i := 0; i < len(second); i += 3 {
			if _, err := writer.Write(second[i:min(i+3, len(second))]); err != nil {
				return
			}
		}
		_ = writer.Close()
	}()
	got := receiveRPC(t, received)
	if bytes.Contains(got, []byte(sentinel)) || !bytes.Contains(got, []byte("<WITHHELD_")) {
		t.Fatal("real scanner did not sanitize actual upstream protobuf")
	}
	// Decode independently of the proxy's projection/rewrite path.
	if _, err := cursor.DecodeRunInference(got, 1<<20); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadAll(response.response.Body); err != nil {
		t.Fatal(err)
	}
}
