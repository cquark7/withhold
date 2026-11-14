package cursor

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"testing"

	"github.com/cquark7/withhold/internal/policy"
	"google.golang.org/protobuf/encoding/protowire"
)

func agentRun(user, requestContext []byte) []byte {
	action := byteField(1, user)
	if requestContext != nil {
		action = concat(action, byteField(2, requestContext))
	}
	return byteField(1, concat(
		byteField(1, nil), // Fresh conversation, without uninspected state references.
		byteField(2, byteField(1, action)),
		byteField(3, byteField(1, []byte("fixture-model"))),
		byteField(5, []byte("fixture-conversation")),
	))
}

func agentExec(number protowire.Number, result []byte) []byte {
	return byteField(2, concat(
		uintField(1, 7), byteField(15, []byte("fixture-exec")), byteField(number, result),
	))
}

func TestAgentSelfContainedContentPreservesBytesAndBlocksRewriting(t *testing.T) {
	const secret = "sk_live_4eC39HqLyjWDarjtT1zdp7dc"
	scan := newScanner(t, "")
	fixtures := map[string][]byte{
		"prompt": agentRun(concat(
			byteField(1, []byte(secret)), byteField(2, []byte("fixture-message")), byteField(8, []byte("ordinary rich text")),
		), nil),
		"file": agentRun(byteField(3, byteField(4, concat(
			byteField(1, []byte(secret)), byteField(2, []byte("fixture.go")),
		))), nil),
		"selection": agentRun(byteField(3, byteField(5, concat(
			byteField(1, []byte(secret)), byteField(2, []byte("fixture.go")),
			byteField(4, concat(byteField(1, uintField(1, 1)), byteField(2, uintField(1, 2)))),
		))), nil),
		"extra-context": agentRun(byteField(3, byteField(16, byteField(1, []byte(secret)))), nil),
		"rules": agentRun(nil, byteField(2, concat(
			byteField(2, []byte(secret)), byteField(3, byteField(1, nil)),
		))),
		"context-file-map": agentRun(nil, byteField(20, concat(
			byteField(1, []byte("fixture.go")), byteField(2, []byte(secret)),
		))),
		"context-map-key": agentRun(nil, byteField(20, concat(
			byteField(1, []byte(secret)), byteField(2, []byte("ordinary contents")),
		))),
		"shell-success": agentExec(2, byteField(1, concat(
			byteField(1, []byte("fixture command")), byteField(5, []byte(secret)), uintField(3, 0),
		))),
		"shell-failure": agentExec(2, byteField(2, byteField(6, []byte(secret)))),
		"read-with-integrity": agentExec(7, byteField(1, concat(
			byteField(1, []byte("fixture.go")), byteField(2, []byte(secret)),
			uintField(3, 1), uintField(4, uint64(len(secret))),
			byteField(9, []byte("original-full-file-hash")), uintField(10, uint64(len(secret))),
		))),
		"write":    agentExec(3, byteField(1, byteField(4, []byte(secret)))),
		"delete":   agentExec(4, byteField(1, byteField(4, []byte(secret)))),
		"mcp-text": agentExec(11, byteField(1, byteField(1, byteField(1, byteField(1, []byte(secret)))))),
		"mcp-structured": agentExec(11, byteField(1, byteField(3, byteField(1, concat(
			byteField(1, []byte("token")), byteField(2, byteField(3, []byte(secret))),
		))))),
		"hook-context": byteField(2, concat(uintField(1, 7), byteField(45, concat(
			byteField(1, []byte("afterShellExecution")), byteField(2, []byte(secret)),
		)))),
	}
	for name, body := range fixtures {
		t.Run(name, func(t *testing.T) {
			message, err := decodeMessage(agentClientMessage, body, policy.DecodeLimits{MaxBytes: testCap})
			if err != nil {
				t.Fatal(err)
			}
			if !message.HasContent() && name != "context-map-key" {
				t.Fatal("model content was misclassified as control")
			}
			unchanged, err := message.Rewrite(message.ScanInput())
			if err != nil || !bytes.Equal(unchanged, body) {
				t.Fatal("unchanged content, identifiers, positions, or integrity metadata changed")
			}
			report := scan.Scan(message.ScanInput(), testCap)
			if report["status"] != "redacted" {
				t.Fatal("Agent content did not reach the shared scanner")
			}
			projection, err := base64.StdEncoding.DecodeString(report["body_base64"].(string))
			if err != nil {
				t.Fatal(err)
			}
			if rewritten, err := message.Rewrite(projection); rewritten != nil || !errors.Is(err, ErrUnsupported) {
				t.Fatal("Agent reference/integrity-bound text was rewritten")
			}
		})
	}
}

func TestAgentMcpTextCannotHideSecretAcrossItems(t *testing.T) {
	const secret = "sk_live_4eC39HqLyjWDarjtT1zdp7dc"
	text := func(s string) []byte { return byteField(1, byteField(1, byteField(1, []byte(s)))) }
	wire := agentExec(11, byteField(1, concat(text(secret[:12]), text(secret[12:]))))
	message, err := decodeMessage(agentClientMessage, wire, policy.DecodeLimits{MaxBytes: testCap})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(message.ScanInput(), []byte(secret)) {
		t.Fatal("ordered MCP text was not inspected together")
	}
	if newScanner(t, "").Scan(message.ScanInput(), testCap)["status"] != "redacted" {
		t.Fatal("secret crossing MCP text item boundaries was missed")
	}
}

func TestAgentUnresolvedContentAndStreamsFailClosed(t *testing.T) {
	for name, wire := range map[string][]byte{
		"empty-envelope":          nil,
		"unknown-envelope":        byteField(99, nil),
		"duplicate-envelope":      concat(byteField(7, nil), byteField(7, nil)),
		"conflicting-envelope":    concat(byteField(7, nil), agentRun(nil, nil)),
		"prefetched-blob":         byteField(1, byteField(17, byteField(2, []byte("uninspected")))),
		"state-blob":              byteField(1, byteField(1, byteField(1, []byte("state-id")))),
		"file-state":              byteField(1, byteField(1, byteField(12, nil))),
		"prompt-blob":             agentRun(byteField(18, []byte("prompt-id")), nil),
		"rich-text-blob":          agentRun(byteField(19, []byte("rich-text-id")), nil),
		"context-blob":            agentRun(byteField(3, byteField(16, byteField(2, []byte("context-id")))), nil),
		"omitted-rule-body":       agentRun(nil, byteField(2, uintField(17, 1))),
		"request-context-parts":   byteField(4, byteField(17, nil)),
		"kv-blob-result":          byteField(3, byteField(2, byteField(1, []byte("uninspected")))),
		"read-blob":               agentExec(7, byteField(1, byteField(7, []byte("read-id")))),
		"read-bytes":              agentExec(7, byteField(1, byteField(5, []byte("uninspected")))),
		"shell-stream-first-half": agentExec(14, byteField(1, byteField(1, []byte("sk_live_4eC3")))),
		"shell-stream-last-half":  agentExec(14, byteField(1, byteField(1, []byte("9HqLyjWDarjtT1zdp7dc")))),
		"mcp-image":               agentExec(11, byteField(1, byteField(1, byteField(2, nil)))),
		"credentials":             byteField(1, byteField(3, byteField(8, nil))),
		"unknown-tool-field":      agentExec(7, byteField(1, byteField(99, nil))),
		"invalid-mode":            agentRun(uintField(4, 999), nil),
		"duplicate-prompt":        agentRun(concat(byteField(1, []byte("first")), byteField(1, []byte("second"))), nil),
		"duplicate-file-key": agentRun(nil, concat(
			byteField(20, concat(byteField(1, []byte("file")), byteField(2, []byte("first")))),
			byteField(20, concat(byteField(1, []byte("file")), byteField(2, []byte("second")))),
		)),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeMessage(agentClientMessage, wire, policy.DecodeLimits{MaxBytes: testCap}); !errors.Is(err, ErrUnsupported) {
				t.Fatalf("unresolved content was not rejected: %v", err)
			}
		})
	}
}

func TestAgentControlsDoNotEstablishContentCoverage(t *testing.T) {
	for _, wire := range [][]byte{
		byteField(7, nil),
		byteField(5, byteField(1, uintField(1, 7))),
		byteField(5, byteField(3, uintField(1, 7))),
		byteField(4, byteField(3, byteField(1, []byte("user cancelled")))),
	} {
		message, err := decodeMessage(agentClientMessage, wire, policy.DecodeLimits{MaxBytes: testCap})
		if err != nil || message.HasContent() {
			t.Fatalf("control counted as inspected model content: %v", err)
		}
		unchanged, err := message.Rewrite(message.ScanInput())
		if err != nil || !bytes.Equal(unchanged, wire) {
			t.Fatal("control changed")
		}
	}
}

func TestAgentSupportedFieldGraphIsReviewed(t *testing.T) {
	for name, numbers := range agentFields {
		definitions, ok := pinned.fields[name]
		if !ok {
			t.Fatalf("missing reviewed message %s", name)
		}
		seen := map[int]bool{}
		for _, number := range numbers {
			field, ok := definitions[protowire.Number(number)]
			if !ok || seen[number] {
				t.Fatalf("invalid or duplicate reviewed field %s.%d", name, number)
			}
			seen[number] = true
			if field.Type == "bytes" {
				t.Fatalf("unresolved byte field admitted: %s.%s", name, field.Name)
			}
			if scalarWire(field.Type) == protowire.BytesType && field.Type != "string" {
				if _, ok := pinned.fields[field.Type]; !ok {
					t.Fatalf("unreviewed child descriptor: %s.%s -> %s", name, field.Name, field.Type)
				}
			}
		}
	}
}

func TestAgentAdmissionAndCancellation(t *testing.T) {
	body := agentRun(byteField(1, []byte("ordinary prompt")), nil)
	capacity := errors.New("test capacity")
	if _, err := decodeMessage(agentClientMessage, body, policy.DecodeLimits{
		MaxBytes: testCap, Reserve: func(int) error { return capacity },
	}); !errors.Is(err, capacity) {
		t.Fatal("lost transport admission failure")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := decodeMessage(agentClientMessage, body, policy.DecodeLimits{
		MaxBytes: testCap, Context: ctx,
	}); !errors.Is(err, context.Canceled) {
		t.Fatal("ignored cancellation")
	}
	if _, err := decodeMessage(agentClientMessage, body, policy.DecodeLimits{MaxBytes: int64(len(body) - 1)}); !errors.Is(err, ErrLimit) {
		t.Fatal("ignored size limit")
	}
}

func FuzzDecodeAgent(f *testing.F) {
	f.Add(agentRun(byteField(1, []byte("ordinary prompt")), nil))
	f.Add(agentExec(7, byteField(1, byteField(2, []byte("ordinary file contents")))))
	f.Add(byteField(7, nil))
	f.Add([]byte{0x0a, 0x80})
	f.Fuzz(func(t *testing.T, body []byte) {
		message, err := decodeMessage(agentClientMessage, body, policy.DecodeLimits{MaxBytes: testCap})
		if err != nil {
			return
		}
		unchanged, err := message.Rewrite(message.ScanInput())
		if err != nil || !bytes.Equal(unchanged, body) {
			t.Fatalf("accepted Agent message did not retain exact bytes: %v", err)
		}
	})
}
