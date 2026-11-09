package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/http2"
)

func authority(s string) (string, error) {
	h, port, err := net.SplitHostPort(s)
	if err != nil || h == "" || strings.ContainsAny(h, "/?#@\\% \t\r\n") {
		return "", errors.New("invalid CONNECT authority")
	}
	for _, c := range h {
		if c < 33 || c > 126 {
			return "", errors.New("invalid CONNECT host")
		}
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return "", errors.New("invalid CONNECT port")
	}
	if strings.Contains(h, ":") && net.ParseIP(h) == nil {
		return "", errors.New("invalid CONNECT host")
	}
	return net.JoinHostPort(strings.ToLower(h), strconv.Itoa(n)), nil
}

func requestAuthority(s string) (string, error) {
	if !strings.Contains(s, ":") || (strings.HasPrefix(s, "[") && strings.HasSuffix(s, "]")) {
		s = net.JoinHostPort(strings.Trim(s, "[]"), "443")
	}
	return authority(s)
}

// Preserve any TLS bytes already buffered by the outer HTTP parser.
type bufferedConn struct {
	net.Conn
	r    *bufio.Reader
	done chan struct{}
	once sync.Once
}

func (c *bufferedConn) Read(b []byte) (int, error) { return c.r.Read(b) }
func (c *bufferedConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() { close(c.done) })
	return err
}

type singleListener struct {
	conn     net.Conn
	done     <-chan struct{}
	accepted bool
}

func (l *singleListener) Accept() (net.Conn, error) {
	if !l.accepted {
		l.accepted = true
		return l.conn, nil
	}
	<-l.done
	return nil, net.ErrClosed
}
func (l *singleListener) Close() error   { return l.conn.Close() }
func (l *singleListener) Addr() net.Addr { return l.conn.LocalAddr() }

func (p *Proxy) connect(w http.ResponseWriter, r *http.Request) {
	target, err := authority(r.Host)
	if err != nil || r.URL.User != nil || r.URL.Host != r.Host {
		debugEvent(r, "rejected", "invalid-connect-authority", 0)
		http.Error(w, "invalid CONNECT authority", 400)
		return
	}
	h, _, _ := net.SplitHostPort(target)
	leaf, err := p.config.CA.Leaf(h)
	if err != nil {
		debugEvent(r, "rejected", "certificate-issuance-failed", 0)
		http.Error(w, "certificate issuance failed", 502)
		return
	}
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		debugEvent(r, "rejected", "connect-hijacking-unavailable", 0)
		http.Error(w, "CONNECT requires HTTP/1.1", 400)
		return
	}
	conn, rw, err := hijacker.Hijack()
	if err != nil {
		debugEvent(r, "rejected", "connect-hijacking-failed", 0)
		return
	}
	raw := &bufferedConn{Conn: conn, r: rw.Reader, done: make(chan struct{})}
	if !p.track(raw) {
		return
	}
	defer p.untrack(raw)
	defer raw.Close()
	if _, err = rw.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		debugEvent(r, "rejected", "connect-response-failed", 0)
		return
	}
	if err = rw.Flush(); err != nil {
		debugEvent(r, "rejected", "connect-response-failed", 0)
		return
	}
	tlsConn := tls.Server(raw, &tls.Config{MinVersion: tls.VersionTLS12, NextProtos: []string{"h2", "http/1.1"}, GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		if hello.ServerName != "" && !strings.EqualFold(hello.ServerName, h) {
			return nil, errors.New("TLS name differs from CONNECT")
		}
		return leaf, nil
	}})
	_ = raw.SetDeadline(time.Now().Add(10 * time.Second))
	if err = tlsConn.HandshakeContext(p.ctx); err != nil {
		debugEvent(r, "tls_error", "client-tls-handshake-failed", 0)
		return
	}
	debugEvent(r, "tls_established", "", 0)
	_ = raw.SetDeadline(time.Time{})
	parent := ""
	if t := trace(r); t != nil {
		parent = t.record.RequestID
	}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = r.WithContext(context.WithValue(r.Context(), debugConnectionKey{}, parent))
		p.handle(w, r, target)
	})
	server := &http.Server{Handler: handler, ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 1 << 20, ErrorLog: log.New(io.Discard, "", 0), BaseContext: func(net.Listener) context.Context { return p.ctx }}
	if tlsConn.ConnectionState().NegotiatedProtocol == "h2" {
		h2 := &http2.Server{MaxConcurrentStreams: 32, IdleTimeout: 60 * time.Second, MaxUploadBufferPerStream: 64 * 1024, MaxUploadBufferPerConnection: 1024 * 1024}
		h2.ServeConn(tlsConn, &http2.ServeConnOpts{Context: p.ctx, BaseConfig: server, Handler: handler})
	} else {
		_ = server.Serve(&singleListener{conn: tlsConn, done: raw.done})
	}
}
