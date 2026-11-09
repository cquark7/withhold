package copilot

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/cquark7/withhold/internal/policy"
)

func TestCopilotRoutingContract(t *testing.T) {
	scope, err := NewTraffic(policy.ScopeOptions{ExtraHosts: []string{"custom.example", "proxy.custom.example"}, ExtraHostRegex: []string{`models\.example`}})
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		host, path, surface, api, mode string
		scoped, pass, unknown          bool
	}{
		{"api.githubcopilot.com", "/chat/completions", "chat", "chat", "redact", true, false, false},
		{"api.enterprise.githubcopilot.com", "/v1/messages", "chat", "chat", "redact", true, false, false},
		{"proxy.business.githubcopilot.com", "/responses", "inline", "chat", "block", true, false, false},
		{"proxy.individual.githubcopilot.com", "/v1/engines/copilot-codex/completions", "inline", "completions", "block", true, false, false},
		{"proxy.business.githubcopilot.com", "/v1/engines/gpt-41-copilot/completions", "inline", "completions", "block", true, false, false},
		{"proxy.enterprise.githubcopilot.com", "/v1/engines/copilot-codex/completions?request=synthetic", "inline", "completions", "block", true, false, false},
		{"api.githubcopilot.com", "/v1/engines/copilot-codex/completions", "inline", "completions", "block", true, false, false},
		{"api.githubcopilot.com", "/chat/completions?request=synthetic", "chat", "chat", "redact", true, false, false},
		{"proxy.individual.githubcopilot.com", "/v1/engines//completions", "unknown-path", "unknown", "block", true, false, true},
		{"proxy.individual.githubcopilot.com", "/v1/engines/model/other/completions", "unknown-path", "unknown", "block", true, false, true},
		{"proxy.individual.githubcopilot.com", "/v1/engines/model/completions/other", "unknown-path", "unknown", "block", true, false, true},
		{"proxy.individual.githubcopilot.com", "/other/v1/engines/model/completions", "unknown-path", "unknown", "block", true, false, true},
		{"api.githubcopilot.com", "/unknown?next=/v1/engines/model/completions", "unknown-path", "unknown", "redact", true, false, true},
		{"api.individual.githubcopilot.com", "/new", "unknown-path", "unknown", "redact", true, false, true},
		{EmbeddingsHost, "/anything", "embeddings", "embeddings", "redact", true, false, false},
		{TokenHost, "/copilot_internal/v2/token", "token-passthrough", "token", "redact", false, true, false},
		{"custom.example", "/new", "chat", "custom", "redact", true, false, false},
		{"proxy.custom.example", "/new", "chat", "custom", "redact", true, false, false},
		{"custom.example", "/v1/engines/copilot-codex/completions", "inline", "completions", "block", true, false, false},
		{"models.example", "/new", "chat", "custom", "redact", true, false, false},
		{"unrelated.example", "/new", "out-of-scope", "unscoped", "redact", false, false, false},
		{"unrelated.example", "/v1/engines/copilot-codex/completions", "out-of-scope", "unscoped", "redact", false, false, false},
	} {
		r := scope.Classify(test.host, test.path)
		if r.Surface != test.surface || r.API != test.api || r.Mode != test.mode || r.Scoped != test.scoped || r.Passthrough != test.pass || r.Unknown != test.unknown {
			t.Errorf("route %s%s = %+v", test.host, test.path, r)
		}
	}
	if !scope.Classify("rotated.copilot.invalid", "/new").Looking {
		t.Fatal("rotated provider host lost suspicion gate")
	}
	for _, o := range []policy.ScopeOptions{{ExtraHosts: []string{"https://bad.example"}}, {ExtraHostRegex: []string{"["}}, {SuspicionPattern: "["}} {
		if _, err := NewTraffic(o); err == nil {
			t.Fatal("invalid scope accepted")
		}
	}
}

func TestConfiguredHostsAndPathsPreserveFailClosedClassification(t *testing.T) {
	input := json.RawMessage(`{"traffic":{"extra_hosts":["new-provider.example"],"extra_chat_paths":["/v2/chat","/v2/inline"],"extra_inline_paths":["/v2/inline"]}}`)
	frozen, err := Configure(input, nil)
	if err != nil {
		t.Fatal(err)
	}
	scope, err := TrafficFromSettings(policy.ScopeOptions{}, frozen)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		host, path, surface, mode string
		unknown                   bool
	}{
		{"api.githubcopilot.com", "/chat/completions", "chat", "redact", false},
		{"api.githubcopilot.com", "/v2/chat?secret=ignored", "chat", "redact", false},
		{"new-provider.example", "/v2/chat", "chat", "redact", false},
		{"new-provider.example", "/v2/inline", "inline", "block", false},
		{"new-provider.example", "/v2/inline/other", "unknown-path", "redact", true},
		{"proxy.enterprise.githubcopilot.com", "/v2/chat", "inline", "block", false},
	} {
		r := scope.Classify(test.host, test.path)
		if !r.Scoped || r.Surface != test.surface || r.Mode != test.mode || r.Unknown != test.unknown {
			t.Errorf("unexpected route %s%s: %+v", test.host, test.path, r)
		}
	}

	// Explicit replacement removes the old rule; unknown vendor paths remain blocked.
	replacement := json.RawMessage(`{"traffic":{"chat_paths":["/v3/chat"],"inline_paths":[]}}`)
	scope, err = TrafficFromSettings(policy.ScopeOptions{}, replacement)
	if err != nil {
		t.Fatal(err)
	}
	if !scope.Classify("api.githubcopilot.com", "/chat/completions").Unknown || scope.Classify("api.githubcopilot.com", "/v3/chat").Unknown {
		t.Fatal("explicit path replacement was not applied")
	}
	if !scope.Classify("api.githubcopilot.com", "/v1/engines/model/completions").Unknown {
		t.Fatal("empty inline replacement did not fail closed")
	}

	scope, err = TrafficFromSettings(policy.ScopeOptions{}, json.RawMessage(`{"traffic":{"hosts":["fresh.example"],"host_suffixes":[]}}`))
	if err != nil {
		t.Fatal(err)
	}
	if !scope.Classify("fresh.example", "/chat/completions").Scoped || scope.Classify("api.githubcopilot.com", "/chat/completions").Scoped || scope.Classify("proxy.business.githubcopilot.com", "/responses").Scoped {
		t.Fatal("host and suffix replacements were not applied")
	}
	if !scope.Classify(TokenHost, "/copilot_internal/v2/token").Passthrough {
		t.Fatal("host replacement changed the fixed token exception")
	}
}

func TestInlineCompletionPathsUseConfiguredInlineMode(t *testing.T) {
	scope, err := NewTraffic(policy.ScopeOptions{ChatMode: "block", InlineMode: "redact"})
	if err != nil {
		t.Fatal(err)
	}
	for _, host := range []string{"api.githubcopilot.com", "proxy.individual.githubcopilot.com"} {
		r := scope.Classify(host, "/v1/engines/copilot-codex/completions")
		if r.Unknown || r.Surface != "inline" || r.API != "completions" || r.Mode != "redact" {
			t.Fatalf("inline configuration not applied: %+v", r)
		}
	}
}

func TestCopilotBlockProtocolContract(t *testing.T) {
	scope, _ := NewTraffic(policy.ScopeOptions{})
	for _, stream := range []bool{false, true} {
		r := scope.Block("secret-found", stream)
		if r.Header.Get("x-withhold-block") != "1" || !strings.Contains(string(r.Body), "withhold_blocked") {
			t.Fatal("block response shape changed")
		}
		if stream {
			if r.Status != 200 || r.Header.Get("Content-Type") != "text/event-stream" || !strings.HasSuffix(string(r.Body), "data: [DONE]\n\n") {
				t.Fatal("stream error framing changed")
			}
		} else if r.Status != 429 || r.Header.Get("Content-Type") != "application/json" {
			t.Fatal("JSON block response changed")
		}
	}
	if !scope.WantsStream([]byte(`{"stream":true}`)) || scope.WantsStream([]byte(`{"Stream":true}`)) || scope.WantsStream([]byte(`{"stream":"true"}`)) {
		t.Fatal("stream selection changed")
	}
}
