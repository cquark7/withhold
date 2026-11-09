// Package control authenticates session ownership without disclosing its key to listeners.
package control

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

const Prefix = "/_withhold/v1/"
const healthSchema = 4

type Identity struct {
	Instance string `json:"instance"`
	Token    string `json:"token"`
}
type Health struct {
	Schema    int          `json:"schema"`
	Instance  string       `json:"instance"`
	PID       int          `json:"pid"`
	Build     string       `json:"build"`
	Challenge string       `json:"challenge"`
	Proof     string       `json:"proof"`
	Debug     *DebugStatus `json:"debug"`
}

// DebugStatus contains value-free traffic counters and finding-log health.
// Counters are collected without debug logging, only for authenticated probes.
type DebugStatus struct {
	Enabled        bool   `json:"enabled"`
	Healthy        bool   `json:"healthy"`
	Connections    uint64 `json:"connections"`
	Received       uint64 `json:"received"`
	Scanned        uint64 `json:"scanned"`
	Inspected      uint64 `json:"inspected"`
	Passthrough    uint64 `json:"passthrough"`
	Detected       uint64 `json:"detected"`
	Redacted       uint64 `json:"redacted"`
	Blocked        uint64 `json:"blocked"`
	Written        uint64 `json:"written"`
	Responses      uint64 `json:"responses"`
	UpstreamErrors uint64 `json:"upstream_errors"`
	EventsWritten  uint64 `json:"events_written"`
	WriteFailures  uint64 `json:"write_failures"`
	LastEvent      string `json:"last_event,omitempty"`
}

func Random() string {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("cannot generate local identity")
	}
	return hex.EncodeToString(b[:])
}
func Valid(i Identity) bool {
	a, e := hex.DecodeString(i.Token)
	b, f := hex.DecodeString(i.Instance)
	return e == nil && f == nil && len(a) == 32 && len(b) == 32
}
func sign(key, text string) string {
	h := hmac.New(sha256.New, []byte(key))
	_, _ = h.Write([]byte(text))
	return hex.EncodeToString(h.Sum(nil))
}
func (h Health) signed() string {
	data, _ := json.Marshal(h.Debug)
	return "health\n" + h.Instance + "\n" + strconv.Itoa(h.PID) + "\n" + h.Build + "\n" + h.Challenge + "\n" + strconv.Itoa(h.Schema) + "\n" + string(data)
}

type Server struct {
	Identity Identity
	PID      int
	Build    string
	Stop     func()
	Debug    func() DebugStatus
	mu       sync.Mutex
	stopping bool
}

func (s *Server) Handle(w http.ResponseWriter, r *http.Request) bool {
	if r.URL.IsAbs() || !strings.HasPrefix(r.URL.Path, Prefix) {
		return false
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil || net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback() {
		http.NotFound(w, r)
		return true
	}
	w.Header().Set("Cache-Control", "no-store")
	challenge := r.Header.Get("X-Withhold-Challenge")
	if len(challenge) != 64 {
		http.NotFound(w, r)
		return true
	}
	if _, err = hex.DecodeString(challenge); err != nil {
		http.NotFound(w, r)
		return true
	}
	switch {
	case r.Method == "GET" && r.URL.Path == Prefix+"health":
		if !hmac.Equal([]byte(r.Header.Get("X-Withhold-Proof")), []byte(sign(s.Identity.Token, "probe\n"+s.Identity.Instance+"\n"+challenge))) {
			http.NotFound(w, r)
			return true
		}
		h := Health{Schema: healthSchema, Instance: s.Identity.Instance, PID: s.PID, Build: s.Build, Challenge: challenge, Debug: &DebugStatus{}}
		if s.Debug != nil {
			d := s.Debug()
			h.Debug = &d
		}
		h.Proof = sign(s.Identity.Token, h.signed())
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(h)
	case r.Method == "POST" && r.URL.Path == Prefix+"shutdown":
		stamp := r.Header.Get("X-Withhold-Time")
		seconds, e := strconv.ParseInt(stamp, 10, 64)
		proof := sign(s.Identity.Token, "shutdown\n"+s.Identity.Instance+"\n"+challenge+"\n"+stamp)
		if e != nil || time.Since(time.Unix(seconds, 0)).Abs() > 10*time.Second || !hmac.Equal([]byte(proof), []byte(r.Header.Get("X-Withhold-Proof"))) {
			http.NotFound(w, r)
			return true
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		if !s.stopping {
			s.stopping = true
			w.WriteHeader(202)
			_ = http.NewResponseController(w).Flush()
			go s.Stop()
		} else {
			w.WriteHeader(202)
		}
	default:
		http.NotFound(w, r)
	}
	return true
}
func client() *http.Client {
	return &http.Client{Timeout: 750 * time.Millisecond, Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}
func Probe(port int, i Identity) (Health, error) {
	var h Health
	if !Valid(i) {
		return h, errors.New("invalid local identity")
	}
	challenge := Random()
	r, _ := http.NewRequest("GET", "http://127.0.0.1:"+strconv.Itoa(port)+Prefix+"health", nil)
	r.Header.Set("X-Withhold-Challenge", challenge)
	r.Header.Set("X-Withhold-Proof", sign(i.Token, "probe\n"+i.Instance+"\n"+challenge))
	c := client()
	defer c.CloseIdleConnections()
	resp, err := c.Do(r)
	if err != nil {
		return h, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 || json.NewDecoder(io.LimitReader(resp.Body, 16384)).Decode(&h) != nil || h.Schema != healthSchema || h.Debug == nil || h.PID <= 0 || h.Instance != i.Instance || h.Challenge != challenge || !hmac.Equal([]byte(h.Proof), []byte(sign(i.Token, h.signed()))) {
		return Health{}, errors.New("listener did not prove ownership")
	}
	return h, nil
}
func Shutdown(port int, i Identity) error {
	if _, err := Probe(port, i); err != nil {
		return err
	}
	challenge, stamp := Random(), strconv.FormatInt(time.Now().Unix(), 10)
	r, _ := http.NewRequest("POST", "http://127.0.0.1:"+strconv.Itoa(port)+Prefix+"shutdown", nil)
	r.Header.Set("X-Withhold-Challenge", challenge)
	r.Header.Set("X-Withhold-Time", stamp)
	r.Header.Set("X-Withhold-Proof", sign(i.Token, "shutdown\n"+i.Instance+"\n"+challenge+"\n"+stamp))
	c := client()
	defer c.CloseIdleConnections()
	resp, err := c.Do(r)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 202 {
		return errors.New("shutdown refused")
	}
	return nil
}
