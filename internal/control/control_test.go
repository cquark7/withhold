package control

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

func TestAuthenticatedOwnershipAndShutdown(t *testing.T) {
	stopped := make(chan struct{}, 1)
	identity := Identity{Random(), Random()}
	server := &Server{Identity: identity, PID: 123, Build: "test", Stop: func() { stopped <- struct{}{} }, Debug: func() DebugStatus { return DebugStatus{Enabled: true, Healthy: true, Received: 7} }}
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !server.Handle(w, r) {
			http.NotFound(w, r)
		}
	}))
	defer s.Close()
	_, portText, _ := net.SplitHostPort(strings.TrimPrefix(s.URL, "http://"))
	port, _ := strconv.Atoi(portText)
	if _, err := Probe(port, Identity{identity.Instance, Random()}); err == nil {
		t.Fatal("wrong token proved ownership")
	}
	h, err := Probe(port, identity)
	if err != nil || h.PID != 123 || h.Schema != healthSchema || h.Debug == nil || h.Debug.Received != 7 {
		t.Fatalf("probe: %v", err)
	}
	r, _ := http.NewRequest("POST", s.URL+Prefix+"shutdown", nil)
	r.Header.Set("X-Withhold-Challenge", Random())
	resp, err := http.DefaultClient.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != 404 {
		t.Fatal("unauthenticated shutdown accepted")
	}
	if err := Shutdown(port, identity); err != nil {
		t.Fatal(err)
	}
	<-stopped
}

func TestDebugTelemetryRequiresAuthenticatedProbeAndIsSigned(t *testing.T) {
	identity := Identity{Random(), Random()}
	server := &Server{Identity: identity, PID: 123, Build: "test", Debug: func() DebugStatus { return DebugStatus{Enabled: true, Received: 42} }}
	r := httptest.NewRequest("GET", Prefix+"health", nil)
	r.RemoteAddr = "127.0.0.1:1234"
	r.Header.Set("X-Withhold-Challenge", Random())
	w := httptest.NewRecorder()
	server.Handle(w, r)
	if w.Code != http.StatusNotFound || strings.Contains(w.Body.String(), "received") {
		t.Fatal("health disclosed without authentication")
	}
	h := Health{Schema: healthSchema, Debug: &DebugStatus{Enabled: true, Received: 42}}
	before := sign(identity.Token, h.signed())
	h.Debug.Received++
	if before == sign(identity.Token, h.signed()) {
		t.Fatal("telemetry is not covered by signature")
	}
}

func TestProbeRejectsUnsignedAndTamperedTelemetry(t *testing.T) {
	identity := Identity{Random(), Random()}
	for _, kind := range []string{"current", "no telemetry", "schema 1", "schema 2", "schema 3", "unsigned", "tampered", "downgraded"} {
		t.Run(kind, func(t *testing.T) {
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				h := Health{Schema: healthSchema, Instance: identity.Instance, PID: 123, Build: "test", Challenge: r.Header.Get("X-Withhold-Challenge"), Debug: &DebugStatus{Enabled: true, Received: 42}}
				switch kind {
				case "no telemetry", "unsigned":
					h.Debug = nil
				case "schema 1":
					h.Schema = 1
				case "schema 2":
					h.Schema = 2
				case "schema 3":
					h.Schema = 3
				}
				h.Proof = sign(identity.Token, h.signed())
				switch kind {
				case "unsigned":
					h.Debug = &DebugStatus{Enabled: true, Received: 42}
				case "tampered":
					h.Debug.Received++
				case "downgraded":
					h.Schema = 1
				}
				_ = json.NewEncoder(w).Encode(h)
			}))
			defer s.Close()
			_, text, _ := net.SplitHostPort(strings.TrimPrefix(s.URL, "http://"))
			port, _ := strconv.Atoi(text)
			_, err := Probe(port, identity)
			if (err == nil) != (kind == "current") {
				t.Fatalf("probe %s: %v", kind, err)
			}
		})
	}
}

func TestHealthUsesOneSignedSchemaWithoutFormatNegotiation(t *testing.T) {
	identity := Identity{Random(), Random()}
	s := &Server{Identity: identity, PID: 123, Build: "test", Debug: func() DebugStatus { return DebugStatus{Enabled: true} }}
	for _, format := range []string{"", "text"} {
		r := httptest.NewRequest("GET", Prefix+"health", nil)
		r.RemoteAddr = "127.0.0.1:1234"
		challenge := Random()
		r.Header.Set("X-Withhold-Challenge", challenge)
		r.Header.Set("X-Withhold-Proof", sign(identity.Token, "probe\n"+identity.Instance+"\n"+challenge))
		r.Header.Set("X-Withhold-Findings-Format", format)
		w := httptest.NewRecorder()
		s.Handle(w, r)
		var h Health
		if err := json.Unmarshal(w.Body.Bytes(), &h); err != nil {
			t.Fatal(err)
		}
		if h.Schema != healthSchema || h.Proof != sign(identity.Token, h.signed()) {
			t.Fatalf("format %q: invalid signed response", format)
		}
	}
}
func TestAbsoluteProxyRequestsCannotAccessControl(t *testing.T) {
	s := &Server{}
	r := httptest.NewRequest("GET", "http://example.com"+Prefix+"health", nil)
	if s.Handle(httptest.NewRecorder(), r) {
		t.Fatal("upstream request intercepted as local control")
	}
}

func TestAuthenticatedHealthWithoutDebugStillUsesCompleteCurrentSchema(t *testing.T) {
	identity := Identity{Random(), Random()}
	s := &Server{Identity: identity, PID: 123, Build: "test"}
	r := httptest.NewRequest("GET", Prefix+"health", nil)
	r.RemoteAddr = "127.0.0.1:1234"
	challenge := Random()
	r.Header.Set("X-Withhold-Challenge", challenge)
	r.Header.Set("X-Withhold-Proof", sign(identity.Token, "probe\n"+identity.Instance+"\n"+challenge))
	w := httptest.NewRecorder()
	s.Handle(w, r)
	var h Health
	if json.Unmarshal(w.Body.Bytes(), &h) != nil || h.Schema != healthSchema || h.Debug == nil || h.Debug.Enabled || h.Proof != sign(identity.Token, h.signed()) {
		t.Fatal("missing debug callback changed the signed protocol")
	}
}
