// A loopback-only upstream for native proxy acceptance tests. Never installed.
package main

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"flag"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/andybalholm/brotli"
	"github.com/gorilla/websocket"
	"github.com/klauspost/compress/zstd"
)

func main() {
	if os.Getenv("ELECTRON_RUN_AS_NODE") == "1" && len(os.Args) > 1 && filepath.Base(os.Args[1]) == "cli.js" {
		_ = json.NewEncoder(os.Stdout).Encode(map[string]any{"args": os.Args[1:], "ELECTRON_RUN_AS_NODE": os.Getenv("ELECTRON_RUN_AS_NODE"), "VSCODE_DEV": os.Getenv("VSCODE_DEV"), "HTTP_PROXY": os.Getenv("HTTP_PROXY"), "NODE_EXTRA_CA_CERTS": os.Getenv("NODE_EXTRA_CA_CERTS")})
		return
	}
	if len(os.Args) == 2 && os.Args[1] == "--editor-environment" {
		_ = json.NewEncoder(os.Stdout).Encode(map[string]string{"HTTP_PROXY": os.Getenv("HTTP_PROXY"), "HTTPS_PROXY": os.Getenv("HTTPS_PROXY"), "NO_PROXY": os.Getenv("NO_PROXY"), "no_proxy": os.Getenv("no_proxy"), "NODE_EXTRA_CA_CERTS": os.Getenv("NODE_EXTRA_CA_CERTS")})
		return
	}
	root := flag.String("root", "", "PEM output path")
	flag.Parse()
	var mu sync.Mutex
	var received []map[string]any
	var streamGate chan struct{}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/release" {
			mu.Lock()
			if streamGate != nil {
				close(streamGate)
				streamGate = nil
			}
			mu.Unlock()
			w.WriteHeader(204)
			return
		}
		if r.URL.Path == "/encode/br" {
			z := brotli.NewWriter(w)
			_, _ = io.Copy(z, r.Body)
			_ = z.Close()
			return
		}
		if r.URL.Path == "/encode/zstd" {
			z, _ := zstd.NewWriter(w, zstd.WithEncoderConcurrency(1))
			_, _ = io.Copy(z, r.Body)
			_ = z.Close()
			return
		}
		if r.URL.Path == "/encode/raw-deflate" {
			z, _ := flate.NewWriter(w, flate.DefaultCompression)
			_, _ = io.Copy(z, r.Body)
			_ = z.Close()
			return
		}
		if r.URL.Path == "/stats" {
			mu.Lock()
			defer mu.Unlock()
			_ = json.NewEncoder(w).Encode(received)
			return
		}
		if r.URL.Path == "/reset" {
			mu.Lock()
			received = nil
			mu.Unlock()
			w.WriteHeader(204)
			return
		}
		if websocket.IsWebSocketUpgrade(r) {
			u := websocket.Upgrader{EnableCompression: true, CheckOrigin: func(*http.Request) bool { return true }, Subprotocols: []string{"withhold-test"}}
			c, err := u.Upgrade(w, r, nil)
			if err != nil {
				return
			}
			defer c.Close()
			for {
				kind, body, err := c.ReadMessage()
				if err != nil {
					return
				}
				if r.Header.Get("X-Withhold-Benchmark") == "" {
					mu.Lock()
					received = append(received, map[string]any{"body_base64": base64.StdEncoding.EncodeToString(body), "kind": kind})
					mu.Unlock()
				}
				if c.WriteMessage(kind, body) != nil {
					return
				}
			}
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			return
		}
		if r.Header.Get("X-Withhold-Benchmark") != "" {
			if r.Header.Get("Content-Encoding") == "gzip" {
				z, e := gzip.NewReader(bytes.NewReader(body))
				if e != nil {
					http.Error(w, "invalid benchmark compression", 400)
					return
				}
				body, err = io.ReadAll(z)
				_ = z.Close()
				if err != nil {
					http.Error(w, "invalid benchmark body", 400)
					return
				}
			}
			safe := !bytes.Contains(body, []byte("sk_live_4eC39HqLyjWDarjtT1zdp7dc"))
			if r.Header.Get("X-Withhold-Benchmark") == "redacted" {
				safe = safe && bytes.Contains(body, []byte("<WITHHELD_"))
			}
			if !safe {
				http.Error(w, "inspection failed", 500)
				return
			}
			sum := sha256.Sum256(body)
			_ = json.NewEncoder(w).Encode(map[string]any{"safe": true, "bytes": len(body), "sha256": hex.EncodeToString(sum[:])})
			return
		}
		entry := map[string]any{"body_base64": base64.StdEncoding.EncodeToString(body), "method": r.Method, "path": r.URL.RequestURI(), "headers": r.Header, "proto": r.Proto}
		mu.Lock()
		received = append(received, entry)
		mu.Unlock()
		if r.Header.Get("X-Test-Stream") == "1" {
			gate := make(chan struct{})
			mu.Lock()
			streamGate = gate
			mu.Unlock()
			w.Header().Set("Content-Type", "text/event-stream")
			_, _ = w.Write([]byte("data: first\n\n"))
			w.(http.Flusher).Flush()
			select {
			case <-gate:
			case <-time.After(10 * time.Second):
				return
			case <-r.Context().Done():
				return
			}
			_, _ = w.Write([]byte("data: [DONE]\n\n"))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(entry)
	})
	plain := httptest.NewServer(handler)
	defer plain.Close()
	secure := httptest.NewUnstartedServer(handler)
	secure.EnableHTTP2 = true
	secure.StartTLS()
	defer secure.Close()
	if err := os.WriteFile(*root, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: secure.TLS.Certificates[0].Certificate[0]}), 0600); err != nil {
		panic(err)
	}
	_ = json.NewEncoder(os.Stdout).Encode(map[string]string{"http": plain.URL, "https": secure.URL})
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop
}
