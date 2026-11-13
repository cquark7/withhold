package proxy

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"net/http/httptrace"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cquark7/withhold/internal/connectrpc"
	"github.com/cquark7/withhold/internal/policy"
	"github.com/cquark7/withhold/internal/scanner"
)

// Streams retain one inspected envelope at a time. MaxBytes bounds both
// cumulative inbound wire bytes and cumulative released bytes, not merely each
// message. A stream cannot turn a finite upload cap into an unlimited channel.
const (
	rpcMaxMessages = 10000
	rpcMaxLifetime = 30 * time.Minute
	rpcReadTimeout = 5 * time.Minute
)

type rpcFailure struct {
	reason    string
	transport bool
	report    scanner.Report
	reported  atomic.Bool
}

func (e *rpcFailure) Error() string { return e.reason }

func (p *Proxy) rpc(w http.ResponseWriter, r *http.Request, route policy.Route) {
	format, err := connectrpc.Parse(r, route.Codec.Streaming, route.Codec.Duplex)
	if err != nil || route.Codec.Decode == nil {
		if p.block(w, r, route, "unsupported-rpc-transport", nil) {
			return
		}
		// Audit-only unsupported requests are still finite and admitted. There
		// is no raw streaming fallback around envelope/size validation.
		t, err := p.budget.acquire()
		if err != nil {
			p.rejectIntake(w, r, route)
			return
		}
		defer t.release()
		raw, err := readBounded(r.Body, p.config.MaxBytes, t)
		_ = r.Body.Close()
		if err != nil {
			p.rejectIntake(w, r, route)
			return
		}
		r.Body = &inspectedBody{reader: io.NopCloser(bytes.NewReader(raw)), ticket: t}
		defer r.Body.Close()
		p.forward(w, r)
		return
	}
	if !format.Streaming {
		p.rpcUnary(w, r, route)
		return
	}
	// The server's ordinary total upload timeout is appropriate for finite
	// requests, not duplex conversations. Replace it with a per-message read
	// deadline and a separate whole-stream lifetime.
	rc := http.NewResponseController(w)
	if r.ProtoMajor == 1 {
		if err := rc.EnableFullDuplex(); err != nil {
			p.rpcReject(w, r, route, &rpcFailure{reason: "unsupported-rpc-transport", transport: true})
			return
		}
	}
	ctx, cancel := context.WithTimeout(r.Context(), rpcMaxLifetime)
	defer cancel()
	r = r.WithContext(ctx)
	body := &rpcBody{proxy: p, request: r, route: route, format: format,
		source: r.Body, cancel: cancel, controller: rc}
	uploadContext, stopUpload := context.WithCancel(ctx)
	body.request, body.stopUpload = r.WithContext(uploadContext), stopUpload
	// Closing a response/connection or canceling an upload must interrupt an
	// outstanding client read, not leave an intake job alive until EOF.
	stop := context.AfterFunc(ctx, func() {
		_ = rc.SetReadDeadline(time.Now())
		_ = body.source.Close()
	})
	defer stop()
	defer body.Close()
	// Inspect the first message before opening upstream. Later reads are driven
	// by upstream backpressure, not an unbounded producer goroutine or queue.
	if err := body.next(); err != nil {
		if err == io.EOF {
			err = &rpcFailure{reason: "empty-rpc-stream"}
		}
		body.fail(err)
		p.rpcReject(w, r, route, body.failure())
		return
	}
	r.Body = body
	r.ContentLength, r.GetBody, r.TransferEncoding, r.Trailer = -1, nil, nil, nil
	clearBodyIntegrity(r.Header)
	r.Header.Del("Content-Length")
	// A duplex upstream must negotiate HTTP/2 as well. Gate Body.Read on
	// GotConn: no inspected payload may be released to an HTTP/1 fallback.
	body.ready = make(chan struct{})
	var ready sync.Once
	r = r.WithContext(httptrace.WithClientTrace(r.Context(), &httptrace.ClientTrace{
		GotConn: func(info httptrace.GotConnInfo) {
			if route.Codec.Duplex {
				conn, ok := info.Conn.(interface{ ConnectionState() tls.ConnectionState })
				if !ok || conn.ConnectionState().NegotiatedProtocol != "h2" {
					body.fail(&rpcFailure{reason: "duplex-upstream-requires-http2", transport: true})
				}
			}
			ready.Do(func() { close(body.ready) })
		},
	}))
	if trace := trace(r); trace != nil {
		trace.mu.Lock()
		trace.record.PolicyAction = "message-stream"
		trace.mu.Unlock()
	}
	p.forward(w, r)
}

func clearBodyIntegrity(h http.Header) {
	for _, key := range []string{"Content-MD5", "Digest", "Content-Digest", "Repr-Digest", "Trailer", "Transfer-Encoding"} {
		h.Del(key)
	}
}

func (p *Proxy) rpcUnary(w http.ResponseWriter, r *http.Request, route policy.Route) {
	t, err := p.budget.acquire()
	if err != nil {
		p.rejectIntake(w, r, route)
		return
	}
	defer t.release()
	raw, err := readBounded(r.Body, p.config.MaxBytes, t)
	_ = r.Body.Close()
	if err != nil {
		p.rejectIntake(w, r, route)
		return
	}
	decoded, err := decodeBody(raw, r.Header, p.config.MaxBytes, t)
	var output []byte
	if err == nil {
		output, err = p.rpcMessage(r, route, decoded, t)
	}
	if err != nil {
		failure := rpcError(err)
		if failure.transport || !p.config.Observe {
			p.rpcReject(w, r, route, failure)
			return
		}
		p.audit.emit(r, route, "block", "blocked", failureReport(failure), true, false)
	}
	// A nil rewrite means the original wire representation is retained.
	if output != nil && !p.config.Observe {
		raw = output
		r.Header.Del("Content-Encoding")
		clearBodyIntegrity(r.Header)
	}
	r.Body = &inspectedBody{reader: io.NopCloser(bytes.NewReader(raw)), ticket: t}
	r.ContentLength = int64(len(raw))
	r.GetBody, r.TransferEncoding, r.Trailer = nil, nil, nil
	r.Header.Set("Content-Length", strconv.Itoa(len(raw)))
	defer r.Body.Close()
	p.forward(w, r)
}

func rpcError(err error) *rpcFailure {
	var failure *rpcFailure
	if errors.As(err, &failure) {
		return failure
	}
	if errors.Is(err, errCapacity) || errors.Is(err, errCap) || errors.Is(err, connectrpc.ErrLimit) {
		return &rpcFailure{reason: "transport-limit", transport: true}
	}
	return &rpcFailure{reason: "unscannable-rpc-message"}
}

func failureReport(f *rpcFailure) scanner.Report {
	if f.report != nil {
		return f.report
	}
	return scanner.Report{"rule_ids": []string{f.reason}}
}

func (p *Proxy) rpcReject(w http.ResponseWriter, r *http.Request, route policy.Route, failure *rpcFailure) {
	p.rpcAuditFailure(r, route, failure)
	debugDecision(r, "scanner-error", "reject", failure.reason, failure.report, nil)
	debugEvent(r, "blocked", failure.reason, 0)
	// Transport failures are unconditional, including audit-only operation.
	if failure.transport {
		http.Error(w, "RPC upload failed transport admission", http.StatusRequestEntityTooLarge)
		return
	}
	response := p.blockResponse(r, route, failure.reason, route.Codec.Streaming)
	for key, values := range response.Header {
		w.Header()[key] = values
	}
	w.WriteHeader(response.Status)
	_, _ = w.Write(response.Body)
}

func (p *Proxy) rpcAuditFailure(r *http.Request, route policy.Route, failure *rpcFailure) {
	if failure.reported.CompareAndSwap(false, true) {
		p.audit.emit(r, route, "block", "blocked", failureReport(failure), false, false)
	}
}

// rpcMessage shares the scanner and enforcement policy with ordinary JSON and
// WebSockets. The adapter owns only the lossless projection and write-back.
func (p *Proxy) rpcMessage(r *http.Request, route policy.Route, data []byte, t *ticket) ([]byte, error) {
	ctx, cancel := context.WithTimeout(r.Context(), p.config.ScanTimeout)
	defer cancel()
	message, err := route.Codec.Decode(data, policy.DecodeLimits{MaxBytes: p.config.MaxBytes, Reserve: t.add, Context: ctx})
	if err != nil {
		return nil, err
	}
	input := message.ScanInput()
	if !message.HasContent() {
		if trace := trace(r); trace != nil {
			trace.mu.Lock()
			trace.record.Supported = false
			trace.mu.Unlock()
		}
	}
	if int64(len(input)) > p.config.MaxBytes {
		return nil, &rpcFailure{reason: "over-cap-decoded"}
	}
	debugScan(r)
	report, err := p.config.Scanner.Scan(ctx, input, p.config.MaxBytes)
	if err != nil || report == nil || ctx.Err() != nil {
		report = scanner.Report{"status": "scanner-error"}
	}
	status, _ := report["status"].(string)
	decision := policy.Evaluate(route, status, residue(report) > 0, false)
	var rewritten []byte
	if decision.Action == "redact" && !p.config.Observe {
		encoded, ok := report["body_base64"].(string)
		projection, err := base64.StdEncoding.Strict().DecodeString(encoded)
		if !ok || err != nil || int64(len(projection)) > p.config.MaxBytes {
			return nil, &rpcFailure{reason: "invalid-rpc-rewrite"}
		}
		rewritten, err = message.Rewrite(projection)
		if err != nil || rewritten == nil || int64(len(rewritten)) > p.config.MaxBytes {
			return nil, &rpcFailure{reason: "invalid-rpc-rewrite", report: report}
		}
	}
	debugDecision(r, status, decision.Action, decision.Reason, report, rewritten)
	switch decision.Action {
	case "forward":
		return nil, nil
	case "redact":
		p.audit.emit(r, route, "redact", "forwarded", report, p.config.Observe, true)
		return rewritten, nil
	case "block":
		return nil, &rpcFailure{reason: decision.Reason, report: report}
	default:
		// RPC capabilities never inherit JSON inspection-failure passthrough.
		return nil, &rpcFailure{reason: "unscannable-rpc-message"}
	}
}

// rpcBody is read only by net/http's upload goroutine. Close can run
// concurrently and never waits for that goroutine's blocked client read.
type rpcBody struct {
	proxy      *Proxy
	request    *http.Request
	route      policy.Route
	format     connectrpc.Request
	source     io.ReadCloser
	controller *http.ResponseController
	cancel     context.CancelFunc
	ready      chan struct{}
	current    *bytes.Reader
	ticket     *ticket
	in, out    int64
	messages   int
	mu         sync.Mutex
	readMu     sync.Mutex
	stopUpload context.CancelFunc
	closed     bool
	failed     *rpcFailure
}

func (b *rpcBody) failure() *rpcFailure {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.failed
}

func (b *rpcBody) fail(err error) {
	b.mu.Lock()
	if b.failed == nil {
		b.failed = rpcError(err)
	}
	failure := b.failed
	b.mu.Unlock()
	b.proxy.rpcAuditFailure(b.request, b.route, failure)
	b.cancel()
}

func (b *rpcBody) next() error {
	if b.ticket != nil {
		b.ticket.release()
		b.ticket = nil
	}
	if err := b.request.Context().Err(); err != nil {
		return &rpcFailure{reason: "rpc-upload-canceled", transport: true}
	}
	_ = b.controller.SetReadDeadline(time.Now().Add(rpcReadTimeout))
	remaining := b.proxy.config.MaxBytes - b.in
	var t *ticket
	// Allow an EOF read at the exact cumulative cap, but not one more header.
	frame, err := connectrpc.ReadFrame(b.source, remaining, func(size int) error {
		var err error
		t, err = b.proxy.budget.acquire()
		if err != nil {
			return err
		}
		b.ticket = t
		return t.add(size)
	})
	if err != nil {
		if err == io.EOF {
			return io.EOF
		}
		// Invalid/truncated envelopes and failed client reads cannot become an
		// audit-only passthrough; there is no complete admitted message.
		return &rpcFailure{reason: "rpc-envelope-failed", transport: true}
	}
	b.in += int64(len(frame.Data)) + 5
	b.messages++
	if b.messages > rpcMaxMessages {
		return &rpcFailure{reason: "rpc-message-limit", transport: true}
	}
	messageRequest := b.proxy.debug.begin(b.request, b.route, "rpc-message", "", b.proxy.config.Observe)
	decoded := frame.Data
	if frame.Flags == 1 {
		if b.format.Compression == "" || b.format.Compression == "identity" {
			return &rpcFailure{reason: "rpc-compression-missing", transport: true}
		}
		header := http.Header{"Content-Encoding": []string{b.format.Compression}}
		decoded, err = decodeBody(decoded, header, b.proxy.config.MaxBytes, t)
	}
	var rewritten []byte
	if err == nil {
		rewritten, err = b.proxy.rpcMessage(messageRequest, b.route, decoded, t)
	}
	if err != nil {
		failure := rpcError(err)
		if failure.transport || !b.proxy.config.Observe {
			debugEvent(messageRequest, "blocked", failure.reason, 0)
			return failure
		}
		b.proxy.audit.emit(messageRequest, b.route, "block", "blocked", failureReport(failure), true, false)
	}
	if rewritten != nil && !b.proxy.config.Observe {
		// Connect allows uncompressed messages even when a compression coding
		// was negotiated. This avoids retaining a second compression output.
		frame.Flags, frame.Data = 0, rewritten
	}
	outputSize := int64(len(frame.Data)) + 5
	if outputSize > b.proxy.config.MaxBytes-b.out {
		return &rpcFailure{reason: "rpc-output-limit", transport: true}
	}
	if err := t.add(int(outputSize)); err != nil {
		return err
	}
	output, err := connectrpc.Envelope(frame.Flags, frame.Data, b.proxy.config.MaxBytes-b.out)
	if err != nil {
		return &rpcFailure{reason: "rpc-output-limit", transport: true}
	}
	b.out += int64(len(output))
	b.current = bytes.NewReader(output)
	// The upload reader is not proof of a completed network write. Emit any
	// masked summary as unconfirmed without retaining reports for the stream.
	debugEvent(messageRequest, "message_released", "", 0)
	return nil
}

func (b *rpcBody) Read(data []byte) (n int, err error) {
	b.readMu.Lock()
	defer b.readMu.Unlock()
	defer func() {
		if recover() != nil {
			failure := &rpcFailure{reason: "rpc-inspection-failed"}
			b.fail(failure)
			n, err = 0, failure
		}
	}()
	if len(data) == 0 {
		return 0, nil
	}
	if b.ready != nil {
		select {
		case <-b.ready:
		case <-b.request.Context().Done():
			return 0, b.request.Context().Err()
		}
	}
	b.mu.Lock()
	closed := b.closed
	b.mu.Unlock()
	if closed {
		return 0, io.ErrClosedPipe
	}
	if failure := b.failure(); failure != nil {
		return 0, failure
	}
	if b.current == nil || b.current.Len() == 0 {
		b.current = nil
		if err := b.next(); err != nil {
			if err != io.EOF {
				b.mu.Lock()
				closed := b.closed
				b.mu.Unlock()
				if !closed {
					b.fail(err)
				}
			}
			return 0, err
		}
	}
	n, err = b.current.Read(data)
	if b.current.Len() == 0 {
		b.current = nil
		if b.ticket != nil {
			b.ticket.release()
			b.ticket = nil
		}
	}
	return n, err
}

func (b *rpcBody) Close() error {
	b.mu.Lock()
	already := b.closed
	b.closed = true
	b.mu.Unlock()
	if !already {
		// Closing the upload must not cancel a still-streaming response.
		b.stopUpload()
		_ = b.controller.SetReadDeadline(time.Now())
		err := b.source.Close()
		b.readMu.Lock()
		if b.ticket != nil {
			b.ticket.release()
			b.ticket = nil
		}
		b.current = nil
		b.readMu.Unlock()
		return err
	}
	return nil
}
