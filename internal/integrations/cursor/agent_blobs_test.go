package cursor

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"testing"

	"github.com/cquark7/withhold/internal/policy"
	"google.golang.org/protobuf/encoding/protowire"
)

func agentBlob(data []byte) ([]byte, []byte) {
	id := sha256.Sum256(data)
	return id[:], byteField(17, concat(byteField(1, id[:]), byteField(2, data)))
}

func agentGraph(state []byte, blobs ...[]byte) []byte {
	return byteField(1, concat(byteField(1, state), concat(blobs...)))
}

func agentHistory(user, step []byte) []byte {
	userID, userBlob := agentBlob(user)
	stepID, stepBlob := agentBlob(step)
	turnID, turnBlob := agentBlob(byteField(1, concat(byteField(1, userID), byteField(2, stepID))))
	return agentGraph(byteField(8, turnID), turnBlob, stepBlob, userBlob)
}

func assertAgentInspection(t *testing.T, wire []byte, content string) {
	t.Helper()
	message, err := decodeMessage(agentClientMessage, wire, policy.DecodeLimits{MaxBytes: testCap})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(message.ScanInput(), []byte(content)) {
		t.Fatal("typed content was not included in inspection")
	}
	clean, err := message.Rewrite(message.ScanInput())
	if err != nil || !bytes.Equal(clean, wire) {
		t.Fatal("immutable content, references, or hashes changed")
	}
	report := newScanner(t, "").Scan(message.ScanInput(), testCap)
	if report["status"] != "redacted" {
		t.Fatal("typed content did not reach the shared detector")
	}
	rewrite, err := base64.StdEncoding.DecodeString(report["body_base64"].(string))
	if err != nil {
		t.Fatal(err)
	}
	if output, err := message.Rewrite(rewrite); output != nil || !errors.Is(err, ErrUnsupported) {
		t.Fatal("content-addressed Agent text was rewritten")
	}
}

func TestAgentPrefetchedGraphInspectsTypedContent(t *testing.T) {
	const secret = "sk_live_4eC39HqLyjWDarjtT1zdp7dc"
	for name, wire := range map[string][]byte{
		"prior-user":      agentHistory(byteField(1, []byte(secret)), byteField(1, byteField(1, []byte("ordinary answer")))),
		"prior-assistant": agentHistory(byteField(1, []byte("ordinary prompt")), byteField(1, byteField(1, []byte(secret)))),
		"prior-thinking":  agentHistory(byteField(1, []byte("ordinary prompt")), byteField(3, byteField(1, []byte(secret)))),
	} {
		t.Run(name, func(t *testing.T) { assertAgentInspection(t, wire, secret) })
	}
	for name, field := range map[string]protowire.Number{"todo": 3, "summary": 6, "plan": 7} {
		t.Run(name, func(t *testing.T) {
			textField := protowire.Number(1)
			if name == "todo" {
				textField = 2
			}
			id, blob := agentBlob(byteField(textField, []byte(secret)))
			assertAgentInspection(t, agentGraph(byteField(field, id), blob), secret)
		})
	}
	commandID, commandBlob := agentBlob(byteField(1, []byte("ordinary shell command")))
	outputID, outputBlob := agentBlob(byteField(1, []byte(secret)))
	turnID, turnBlob := agentBlob(byteField(2, concat(byteField(1, commandID), byteField(2, outputID))))
	assertAgentInspection(t, agentGraph(byteField(8, turnID), outputBlob, commandBlob, turnBlob), secret)

	// A historical user message can reference a previous state snapshot, itself
	// containing references. The decoder must follow that edge, not scan its ID.
	summaryID, summaryBlob := agentBlob(byteField(1, []byte(secret)))
	stateID, stateBlob := agentBlob(byteField(6, summaryID))
	userID, userBlob := agentBlob(byteField(10, stateID))
	turnID, turnBlob = agentBlob(byteField(1, byteField(1, userID)))
	assertAgentInspection(t, agentGraph(byteField(8, turnID), turnBlob, userBlob, stateBlob, summaryBlob), secret)
}

func TestAgentPrefetchedGraphRejectsUninspectedOrUnboundBlobs(t *testing.T) {
	id, blob := agentBlob(byteField(1, []byte("ordinary summary")))
	missing := sha256.Sum256([]byte("missing"))
	unknownID, unknown := agentBlob(byteField(99, []byte("unreviewed content")))
	truncatedID, truncated := agentBlob([]byte{0x0a, 0x80})
	invalidUTF8ID, invalidUTF8 := agentBlob(byteField(1, []byte{0xff}))
	nestedID, nested := agentBlob(byteField(1, byteField(1, missing[:])))
	for name, wire := range map[string][]byte{
		"missing":            agentGraph(byteField(6, id)),
		"short-id":           agentGraph(byteField(6, id[:16]), blob),
		"empty-id":           agentGraph(byteField(6, nil), blob),
		"hash-mismatch":      agentGraph(byteField(6, id), bytes.Replace(blob, id, missing[:], 1)),
		"changed-value":      agentGraph(byteField(6, id), bytes.Replace(blob, []byte("ordinary"), []byte("modified"), 1)),
		"unknown-child":      agentGraph(byteField(6, unknownID), unknown),
		"truncated-child":    agentGraph(byteField(6, truncatedID), truncated),
		"invalid-utf8":       agentGraph(byteField(6, invalidUTF8ID), invalidUTF8),
		"missing-child":      agentGraph(byteField(8, nestedID), nested),
		"unreferenced":       agentGraph(nil, blob),
		"extra-unreferenced": agentGraph(byteField(6, id), blob, unknown),
		"missing-value":      agentGraph(byteField(6, id), byteField(17, byteField(1, id))),
		"missing-identity":   agentGraph(byteField(6, id), byteField(17, byteField(2, []byte("ordinary")))),
		"duplicate-identity": agentGraph(byteField(6, id), byteField(17, concat(byteField(1, id), byteField(1, id), byteField(2, nil)))),
		"kv-no-binding":      byteField(3, byteField(2, byteField(1, []byte("ordinary summary")))),
	} {
		t.Run(name, func(t *testing.T) {
			if message, err := decodeMessage(agentClientMessage, wire, policy.DecodeLimits{MaxBytes: testCap}); err == nil || message != nil {
				t.Fatal("unbound or uninspected bytes were admitted")
			}
		})
	}
	// Successful decoding cannot seed another request or retry with implicit trust.
	if _, err := decodeMessage(agentClientMessage, agentGraph(byteField(6, id), blob), policy.DecodeLimits{MaxBytes: testCap}); err != nil {
		t.Fatal(err)
	}
	if _, err := decodeMessage(agentClientMessage, agentGraph(byteField(6, id)), policy.DecodeLimits{MaxBytes: testCap}); !errors.Is(err, ErrUnsupported) {
		t.Fatal("another request's blob established inspection")
	}
}

func TestAgentPrefetchedGraphDeduplicatesByIdentityAndExpectedType(t *testing.T) {
	data := byteField(1, []byte("ordinary text"))
	id, blob := agentBlob(data)
	// The same wire value is valid for summary and plan. Inspect both expected
	// types; an identity-only cache must not silently skip a new interpretation.
	wire := agentGraph(concat(byteField(6, id), byteField(7, id)), blob, blob)
	message, err := decodeMessage(agentClientMessage, wire, policy.DecodeLimits{MaxBytes: testCap})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(message.ScanInput(), []byte(`"summary":"ordinary text"`)) ||
		!bytes.Contains(message.ScanInput(), []byte(`"plan":"ordinary text"`)) {
		t.Fatal("blob reuse skipped an expected type")
	}
	if bytes.Count(message.ScanInput(), []byte("ordinary text")) != 2 {
		t.Fatal("duplicate uploads amplified inspection")
	}
	// Repeated DAG edges must not expand exponentially into the projection.
	stepID, stepBlob := agentBlob(byteField(1, data))
	var edges []byte
	for range 100 {
		edges = append(edges, byteField(2, stepID)...)
	}
	turnID, turnBlob := agentBlob(byteField(1, edges))
	message, err = decodeMessage(agentClientMessage, agentGraph(byteField(8, turnID), turnBlob, stepBlob), policy.DecodeLimits{MaxBytes: testCap})
	if err != nil || bytes.Count(message.ScanInput(), []byte("ordinary text")) != 1 {
		t.Fatal("repeated references amplified the graph")
	}
}

func TestAgentPrefetchedGraphLimitsAndAdmission(t *testing.T) {
	id, blob := agentBlob(nil)
	blobs := make([][]byte, maxAgentBlobs+1)
	for i := range blobs {
		blobs[i] = blob
	}
	if _, err := decodeMessage(agentClientMessage, agentGraph(byteField(6, id), blobs...), policy.DecodeLimits{MaxBytes: testCap}); !errors.Is(err, ErrLimit) {
		t.Fatal("ignored upload count limit")
	}
	// Successive state snapshots cross multiple protobuf and reference edges.
	var state []byte
	blobs = nil
	for range maxDepth {
		stateID, stateBlob := agentBlob(state)
		userID, userBlob := agentBlob(byteField(10, stateID))
		turnID, turnBlob := agentBlob(byteField(1, byteField(1, userID)))
		state = byteField(8, turnID)
		blobs = append(blobs, stateBlob, userBlob, turnBlob)
	}
	if _, err := decodeMessage(agentClientMessage, agentGraph(state, blobs...), policy.DecodeLimits{MaxBytes: testCap}); !errors.Is(err, ErrLimit) {
		t.Fatal("ignored graph depth limit")
	}
	// Projection escaping is bounded even when raw blobs fit on the wire.
	id, blob = agentBlob(byteField(1, bytes.Repeat([]byte{0}, 500)))
	if _, err := decodeMessage(agentClientMessage, agentGraph(byteField(6, id), blob), policy.DecodeLimits{MaxBytes: 1000}); !errors.Is(err, ErrLimit) {
		t.Fatal("ignored escaped blob projection limit")
	}
	capacity := errors.New("test capacity")
	id, blob = agentBlob(byteField(1, []byte("ordinary summary")))
	calls := 0
	_, err := decodeMessage(agentClientMessage, agentGraph(byteField(6, id), blob), policy.DecodeLimits{
		MaxBytes: testCap, Reserve: func(int) error {
			calls++
			if calls > 1 {
				return capacity
			}
			return nil
		},
	})
	if !errors.Is(err, capacity) {
		t.Fatal("graph projection ignored retained-input admission")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = decodeMessage(agentClientMessage, agentGraph(byteField(6, id), blob), policy.DecodeLimits{MaxBytes: testCap, Context: ctx})
	if !errors.Is(err, context.Canceled) {
		t.Fatal("graph ignored cancellation")
	}
}

func TestAgentBlobFieldPermissionsMatchTypedReferences(t *testing.T) {
	for name, fields := range agentBlobTypes {
		for number, kind := range fields {
			field := pinned.fields[name][number]
			if field.Type != "bytes" || !supportedField(name, field) || kind != agentBlobText && pinned.fields[kind] == nil {
				t.Fatalf("invalid reviewed blob edge %s.%d -> %s", name, number, kind)
			}
		}
	}
}

func TestAgentBlobContentCoverageDoesNotCountOnlyReferences(t *testing.T) {
	for _, content := range [][]byte{nil, byteField(1, []byte("ordinary summary"))} {
		id, blob := agentBlob(content)
		message, err := decodeMessage(agentClientMessage, agentGraph(byteField(6, id), blob), policy.DecodeLimits{MaxBytes: testCap})
		if err != nil || message.HasContent() != (len(content) > 0) {
			t.Fatalf("blob identifiers established content coverage: %v", err)
		}
	}
}
