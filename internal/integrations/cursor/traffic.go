package cursor

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/cquark7/withhold/internal/connectrpc"
	"github.com/cquark7/withhold/internal/policy"
)

const DefaultSuspicion = `(?i)(cursor\.(sh|com)|cursorapi)`

type Traffic struct {
	chat, inline       string
	extra, allow       map[string]bool
	pattern, suspicion *regexp.Regexp
}

// NewTraffic is intentionally not in the product registry. Supported request
// shapes are independently testable while coverage/lifecycle gates remain open.
func NewTraffic(options policy.ScopeOptions) (*Traffic, error) {
	t := &Traffic{chat: options.ChatMode, inline: options.InlineMode, extra: map[string]bool{}, allow: map[string]bool{}}
	if t.chat == "" {
		t.chat = "redact"
	}
	if t.inline == "" {
		t.inline = "block"
	}
	if !policy.ValidMode(t.chat) || !policy.ValidMode(t.inline) {
		return nil, errors.New("invalid Cursor inspection mode")
	}
	for _, list := range options.ExtraHosts {
		for _, host := range strings.Split(list, ",") {
			host = strings.TrimSpace(strings.ToLower(host))
			if host == "" {
				continue
			}
			if strings.ContainsAny(host, "/: \t\r\n?#@\\") {
				return nil, errors.New("extra hosts must be bare hostnames")
			}
			t.extra[host] = true
		}
	}
	for _, host := range options.AllowHosts {
		t.allow[strings.ToLower(host)] = true
	}
	var err error
	if len(options.ExtraHostRegex) > 0 {
		t.pattern, err = regexp.Compile("^(?:" + strings.Join(options.ExtraHostRegex, "|") + ")$")
		if err != nil {
			return nil, errors.New("invalid extra host pattern")
		}
	}
	pattern := options.SuspicionPattern
	if pattern == "" {
		pattern = DefaultSuspicion
	}
	t.suspicion, err = regexp.Compile(pattern)
	if err != nil {
		return nil, errors.New("invalid Cursor suspicion pattern")
	}
	return t, nil
}

var rpcRoutes = map[string]struct {
	message                string
	stream, duplex, inline bool
}{
	"/aiserver.v1.InferenceService/RunInference":        {clientMessage, true, true, false},
	"/aiserver.v1.AiService/NameTab":                    {"aiserver.v1.NameTabRequest", false, false, false},
	"/agent.v1.AgentService/UpdateConversationMetadata": {"agent.v1.UpdateConversationMetadataRequest", false, false, false},
	"/aiserver.v1.AiService/ClassifyAgentAutoReview":    {"aiserver.v1.ClassifyAgentAutoReviewRequest", false, false, false},
	"/aiserver.v1.AiService/StreamCpp":                  {"aiserver.v1.StreamCppRequest", true, false, true},
}

func (t *Traffic) Classify(authority, path string) policy.Route {
	host := policy.Host(authority)
	route := policy.Route{Host: host, Surface: "chat", API: "unknown", Mode: t.chat, Looking: t.suspicion.MatchString(host)}
	// Scope all subdomains: regional/agent host rotation cannot create a
	// bodyless or unknown-RPC escape hatch on a known Cursor service.
	route.Scoped = host == "cursor.sh" || strings.HasSuffix(host, ".cursor.sh") ||
		host == "cursor.com" || strings.HasSuffix(host, ".cursor.com") ||
		t.extra[host] || t.allow[host] || t.pattern != nil && t.pattern.MatchString(host)
	if !route.Scoped {
		return route
	}
	u, err := url.ParseRequestURI(path)
	if err == nil && u.RawPath == "" {
		if rpc, ok := rpcRoutes[u.Path]; ok {
			route.API = strings.TrimPrefix(u.Path, "/")
			if rpc.inline {
				route.Surface, route.Mode = "inline", t.inline
			}
			route.Codec = &policy.RPCCodec{Streaming: rpc.stream, Duplex: rpc.duplex,
				Decode: func(body []byte, limits policy.DecodeLimits) (policy.Message, error) {
					return decodeMessage(rpc.message, body, limits)
				}}
			return route
		}
	}
	route.Unknown = true
	// Unknown guarded RPCs must not reach the ordinary bodyless-GET pass.
	route.Codec = &policy.RPCCodec{Decode: func([]byte, policy.DecodeLimits) (policy.Message, error) { return nil, ErrUnsupported }}
	return route
}

func (*Traffic) WantsStream([]byte) bool { return false }

func (*Traffic) Block(reason string, stream bool) policy.Response {
	// Reasons originate in the proxy's fixed vocabulary, never request values.
	body, _ := json.Marshal(map[string]any{"code": "permission_denied", "message": "withhold blocked request: " + reason})
	header := http.Header{"Content-Type": []string{"application/json"}}
	status := http.StatusForbidden
	if stream {
		end, _ := json.Marshal(map[string]any{"error": json.RawMessage(body)})
		body, _ = connectrpc.Envelope(2, end, 4096)
		header.Set("Content-Type", "application/connect+proto")
		status = http.StatusOK
	}
	return policy.Response{Status: status, Header: header, Body: body}
}

func (t *Traffic) BlockRequest(r *http.Request, route policy.Route, reason string) policy.Response {
	stream := route.Codec != nil && route.Codec.Streaming && r.Header.Get("Content-Type") == "application/connect+proto"
	return t.Block(reason, stream)
}
