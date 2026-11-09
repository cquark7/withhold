// Package copilot implements the built-in VS Code/Copilot integration.
package copilot

import (
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"strings"

	"github.com/cquark7/withhold/internal/jsonmeta"
	"github.com/cquark7/withhold/internal/policy"
)

const TokenHost = "api.github.com"
const EmbeddingsHost = "embeddings.vscode-cdn.net"
const DefaultSuspicion = "copilot"

type Scope struct {
	vendor, extra map[string]bool
	patterns      []*regexp.Regexp
	suffixes      []string
	chatPaths     []*regexp.Regexp
	inlinePaths   []*regexp.Regexp
	suspicion     *regexp.Regexp
	chat, inline  string
}

func NewTraffic(o policy.ScopeOptions) (*Scope, error) {
	return newTraffic(o, defaultTraffic())
}

// TrafficFromSettings uses the same normalized adapter configuration recorded
// with the session, including any user-supplied host and path rules.
func TrafficFromSettings(o policy.ScopeOptions, data json.RawMessage) (*Scope, error) {
	s, err := settings(data, nil)
	if err != nil {
		return nil, err
	}
	return newTraffic(o, s.Traffic)
}

func newTraffic(o policy.ScopeOptions, traffic TrafficSettings) (*Scope, error) {
	if err := validateTraffic(traffic); err != nil {
		return nil, err
	}
	s := &Scope{vendor: map[string]bool{}, extra: map[string]bool{}, chat: o.ChatMode, inline: o.InlineMode}
	if s.chat == "" {
		s.chat = "redact"
	}
	if s.inline == "" {
		s.inline = "block"
	}
	if !policy.ValidMode(s.chat) || !policy.ValidMode(s.inline) {
		return nil, errors.New("invalid surface mode")
	}
	for _, h := range append(append([]string{}, traffic.Hosts...), traffic.ExtraHosts...) {
		s.vendor[strings.ToLower(h)] = true
	}
	for _, suffix := range traffic.HostSuffixes {
		s.suffixes = append(s.suffixes, strings.ToLower(suffix))
	}
	for _, pattern := range append(append([]string{}, traffic.ChatPaths...), traffic.ExtraChatPaths...) {
		s.chatPaths = append(s.chatPaths, regexp.MustCompile("^(?:"+pattern+")$"))
	}
	for _, pattern := range append(append([]string{}, traffic.InlinePaths...), traffic.ExtraInlinePaths...) {
		s.inlinePaths = append(s.inlinePaths, regexp.MustCompile("^(?:"+pattern+")$"))
	}
	// Only the isolated acceptance harness uses the vendor-scope override.
	for _, h := range o.AllowHosts {
		if h = strings.TrimSpace(strings.ToLower(h)); h != "" {
			s.vendor[h] = true
		}
	}
	for _, list := range o.ExtraHosts {
		for _, h := range strings.Split(list, ",") {
			h = strings.TrimSpace(strings.ToLower(h))
			if h == "" {
				continue
			}
			if strings.ContainsAny(h, "/: \t\r\n?#@\\") {
				return nil, errors.New("extra hosts must be bare hostnames")
			}
			s.extra[h] = true
		}
	}
	for _, p := range o.ExtraHostRegex {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		rx, err := regexp.Compile("^(?:" + p + ")$")
		if err != nil {
			return nil, errors.New("invalid proxy.extra_host_regex (patterns use Go RE2 syntax)")
		}
		s.patterns = append(s.patterns, rx)
	}
	p := strings.TrimSpace(o.SuspicionPattern)
	if p == "" {
		p = DefaultSuspicion
	}
	var err error
	s.suspicion, err = regexp.Compile("(?i)" + p)
	if err != nil {
		return nil, errors.New("invalid proxy.suspicion_pattern (patterns use Go RE2 syntax)")
	}
	return s, nil
}

func (s *Scope) Classify(authority, path string) policy.Route {
	h := policy.Host(authority)
	path, _, _ = strings.Cut(path, "?")
	r := policy.Route{Host: h, Surface: "out-of-scope", API: "unscoped", Passthrough: h == TokenHost, Looking: s.suspicion.MatchString(h), Mode: s.chat, Provisional: true}
	if r.Passthrough {
		r.Surface = "token-passthrough"
		r.API = "token"
		return r
	}
	vendor := s.vendor[h]
	for _, suffix := range s.suffixes {
		vendor = vendor || strings.HasSuffix(h, suffix)
	}
	extra := s.extra[h]
	for _, rx := range s.patterns {
		extra = extra || rx.MatchString(h)
	}
	if !vendor && !extra {
		return r
	}
	r.Scoped = true
	if h == EmbeddingsHost {
		r.Surface = "embeddings"
		r.API = "embeddings"
		r.Mode = "redact"
		r.AllowNonJSON = true
		r.HTTPFailureAction = "embeddings-unscanned"
		r.NonPostRule = "embeddings-bodied-nonpost"
		return r
	}
	r.Surface = "chat"
	if strings.HasPrefix(h, "proxy.") {
		r.Surface = "inline"
		r.Mode = s.inline
	}
	switch {
	case matchesPath(s.inlinePaths, path):
		r.Surface, r.API, r.Mode = "inline", "completions", s.inline
	case matchesPath(s.chatPaths, path):
		r.API = "chat"
	case strings.Contains(path, "/embeddings"):
		r.API = "embeddings"
	case vendor:
		r.Surface = "unknown-path"
		r.API = "unknown"
		r.Unknown = true
	default:
		r.Surface = "chat"
		r.API = "custom"
		r.Mode = s.chat
	}
	return r
}

func matchesPath(patterns []*regexp.Regexp, path string) bool {
	for _, pattern := range patterns {
		if pattern.MatchString(path) {
			return true
		}
	}
	return false
}

// WantsStream and Block own the Copilot-compatible JSON/SSE error protocol.
func (*Scope) WantsStream(body []byte) bool {
	return jsonmeta.Bool(body, "stream")
}

func (*Scope) Block(reason string, stream bool) policy.Response {
	data, _ := json.Marshal(map[string]any{"error": map[string]string{"code": "withhold_blocked", "message": "Request blocked by withhold: " + reason + "."}})
	r := policy.Response{Status: 429, Header: http.Header{"X-Withhold-Block": {"1"}, "Content-Type": {"application/json"}}, Body: data}
	if stream {
		r.Status = 200
		r.Header.Set("Content-Type", "text/event-stream")
		r.Header.Set("Cache-Control", "no-cache")
		r.Body = append(append([]byte("data: "), data...), []byte("\n\ndata: [DONE]\n\n")...)
	}
	return r
}
