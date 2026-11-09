package proxy

import (
	"context"
	"encoding/base64"
	"io"
	"net/http"
	"time"
	"unicode/utf8"

	"github.com/cquark7/withhold/internal/policy"
	"github.com/cquark7/withhold/internal/scanner"
	"github.com/gorilla/websocket"
)

func isWebSocket(r *http.Request) bool { return websocket.IsWebSocketUpgrade(r) }

func (p *Proxy) websocket(w http.ResponseWriter, r *http.Request, route policy.Route) {
	if !bodyless(r) {
		debugEvent(r, "rejected", "websocket-upgrade-body", 0)
		http.Error(w, "WebSocket upgrade must be bodyless", 400)
		return
	}
	u := *r.URL
	if u.Scheme == "https" {
		u.Scheme = "wss"
	} else {
		u.Scheme = "ws"
	}
	headers := r.Header.Clone()
	stripHop(headers)
	for _, k := range []string{"Sec-WebSocket-Key", "Sec-WebSocket-Version", "Sec-WebSocket-Extensions", "Sec-WebSocket-Protocol"} {
		headers.Del(k)
	}
	dialer := websocket.Dialer{Proxy: nil, TLSClientConfig: p.websocketTLS, HandshakeTimeout: 10 * time.Second, EnableCompression: true, Subprotocols: websocket.Subprotocols(r)}
	up, resp, err := dialer.DialContext(r.Context(), u.String(), headers)
	if err != nil {
		if resp != nil && resp.Body != nil {
			_ = resp.Body.Close()
		}
		debugEvent(r, "upstream_error", "websocket-handshake-failed", 0)
		http.Error(w, "upstream WebSocket connection failed", 502)
		return
	}
	debugEvent(r, "upstream_response", "", resp.StatusCode)
	defer up.Close()
	responseHeaders := http.Header{}
	for _, k := range []string{"Set-Cookie"} {
		for _, v := range resp.Header.Values(k) {
			responseHeaders.Add(k, v)
		}
	}
	protocols := []string{}
	if up.Subprotocol() != "" {
		protocols = append(protocols, up.Subprotocol())
	}
	upgrade := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }, EnableCompression: true, Subprotocols: protocols}
	client, err := upgrade.Upgrade(w, r, responseHeaders)
	if err != nil {
		debugEvent(r, "rejected", "client-websocket-upgrade-failed", 0)
		return
	}
	debugEvent(r, "websocket_open", "", 0)
	defer client.Close()
	conn := client.UnderlyingConn()
	if !p.track(conn) {
		return
	}
	defer p.untrack(conn)
	if route.Passthrough || !route.Scoped {
		p.audit.foreign(route)
	}
	client.SetReadLimit(p.config.MaxBytes)
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer client.Close()
		defer up.Close()
		// Provider responses remain streamed and uninspected.
		for {
			kind, reader, err := up.NextReader()
			if err != nil {
				debugEvent(r, "websocket_closed", "upstream-read-ended", 0)
				return
			}
			writer, err := client.NextWriter(kind)
			if err != nil {
				return
			}
			_, err = io.Copy(writer, reader)
			closeErr := writer.Close()
			if err != nil || closeErr != nil {
				return
			}
		}
	}()
	defer func() { _ = up.Close(); _ = client.Close(); <-done }()
	parent := ""
	if t := trace(r); t != nil {
		parent = t.record.RequestID
	}
	for {
		kind, reader, err := client.NextReader()
		if err != nil {
			debugEvent(r, "websocket_closed", "client-read-ended", 0)
			return
		}
		message := p.debug.begin(r, route, "websocket-message", parent, p.config.Observe)
		t, err := p.budget.acquire()
		if err != nil {
			debugDecision(message, "not-scanned", "reject", "capacity-limit", nil, nil)
			p.wsDeny(message, route, "scanner-error", nil)
			if p.config.Observe {
				debugEvent(message, "blocked", "capacity-limit", 0)
			}
			return
		}
		closeSession := func() bool {
			defer func() {
				if v := recover(); v != nil {
					debugEvent(message, "aborted", "proxy-error", 0)
					panic(v)
				}
			}()
			defer t.release()
			_ = client.SetReadDeadline(time.Now().Add(30 * time.Second))
			raw, err := readBounded(reader, p.config.MaxBytes, t)
			_ = client.SetReadDeadline(time.Time{})
			if err != nil {
				debugDecision(message, "over-cap", "reject", "transport-limit", nil, nil)
				p.wsDeny(message, route, "over-cap", nil)
				if p.config.Observe {
					debugEvent(message, "blocked", "transport-limit", 0)
				}
				return true
			}
			body, forward, stop := p.inspectMessage(message, route, kind, raw)
			if forward {
				debugEvent(message, "forward_attempt", "", 0)
				_ = up.SetWriteDeadline(time.Now().Add(30 * time.Second))
				err = up.WriteMessage(kind, body)
				if err != nil {
					debugEvent(message, "write_error", "upstream-write-failed", 0)
				} else {
					debugEvent(message, "upstream_written", "", 0)
				}
			}
			return stop || err != nil
		}()
		if closeSession {
			return
		}
	}
}

func (p *Proxy) wsDeny(r *http.Request, route policy.Route, rule string, report scanner.Report) bool {
	if report == nil {
		report = scanner.Report{"rule_ids": []string{rule}}
	}
	p.audit.emit(r, route, "block", "blocked", report, p.config.Observe, false)
	if t := trace(r); t != nil {
		t.mu.Lock()
		pending := t.record.PolicyAction == "pending"
		t.mu.Unlock()
		if pending {
			debugDecision(r, "not-scanned", "block", rule, report, nil)
		}
	}
	if !p.config.Observe {
		debugEvent(r, "blocked", rule, 0)
	}
	return !p.config.Observe
}

// forward=false, stop=false drops a non-JSON message while retaining the session.
func (p *Proxy) inspectMessage(r *http.Request, route policy.Route, kind int, raw []byte) (body []byte, forward, stop bool) {
	if route.Passthrough {
		debugDecision(r, "not-scanned", "passthrough", "token-or-unscoped", nil, nil)
		return raw, true, false
	}
	if !route.Scoped {
		if route.Looking && p.wsDeny(r, route, "out-of-scope-host", nil) {
			return nil, false, true
		}
		if !route.Looking {
			debugDecision(r, "not-scanned", "passthrough", "outside-inspection-scope", nil, nil)
		}
		return raw, true, false
	}
	if route.Unknown {
		stop := p.wsDeny(r, route, "unknown-api-path", nil)
		return raw, !stop, stop
	}
	if kind == websocket.BinaryMessage || !utf8.Valid(raw) {
		if p.wsDeny(r, route, "ws-binary-unscannable", nil) {
			return nil, false, true
		}
		return raw, true, false
	}
	ctx, cancel := context.WithTimeout(r.Context(), p.config.ScanTimeout)
	debugScan(r)
	report, err := p.config.Scanner.Scan(ctx, raw, p.config.MaxBytes)
	cancel()
	if err != nil {
		report = scanner.Report{"status": "scanner-error"}
	}
	status, _ := report["status"].(string)
	if status == "clean" {
		debugDecision(r, status, "forward", "", report, nil)
		return raw, true, false
	}
	if status == "skipped-not-json" && report["reason"] == "body is not JSON" {
		debugDecision(r, status, "drop", "ws-non-json-unscannable", report, nil)
		if p.wsDeny(r, route, "ws-non-json-unscannable", nil) {
			return nil, false, false
		}
		return raw, true, false
	}
	decision := policy.Evaluate(route, status, residue(report) > 0, true)
	if decision.Action == "block" {
		debugDecision(r, status, decision.Action, decision.Reason, report, nil)
		if status != "redacted" {
			report = nil
		}
		if p.wsDeny(r, route, decision.Reason, report) {
			return nil, false, true
		}
		return raw, true, false
	}
	if decision.Action != "redact" {
		panic("invalid WebSocket policy decision")
	}
	p.audit.emit(r, route, "redact", "forwarded", report, p.config.Observe, true)
	if p.config.Observe {
		debugDecision(r, status, decision.Action, decision.Reason, report, nil)
		return raw, true, false
	}
	text, ok := report["body_base64"].(string)
	out, e := base64.StdEncoding.Strict().DecodeString(text)
	if !ok || e != nil {
		panic("invalid redaction report")
	}
	debugDecision(r, status, decision.Action, decision.Reason, report, out)
	return out, true, false
}
