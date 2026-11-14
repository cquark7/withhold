package cursor

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"testing"

	"github.com/cquark7/withhold/internal/policy"
	"google.golang.org/protobuf/encoding/protowire"
)

func testAgentStream(t testing.TB, reserve func(int) error) *agentStream {
	t.Helper()
	stream, err := openAgentStream(policy.DecodeLimits{MaxBytes: testCap, Reserve: reserve})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(stream.Close)
	return stream.(*agentStream)
}

func agentReplayFixture(text string) (first, later []byte) {
	summaryID, summary := agentBlob(byteField(1, []byte(text)))
	stateID, state := agentBlob(byteField(6, summaryID))
	userID, user := agentBlob(byteField(10, stateID))
	turnID, turn := agentBlob(byteField(1, byteField(1, userID)))
	first = agentGraph(byteField(8, turnID), summary, state, user, turn)
	later = byteField(4, byteField(1, byteField(1, byteField(10, stateID))))
	return first, later
}

func TestAgentStreamReinspectsCompleteGraphsAndPreservesBytes(t *testing.T) {
	const secret = "sk_live_4eC39HqLyjWDarjtT1zdp7dc"
	first, later := agentReplayFixture(secret)
	reserved, calls := 0, 0
	stream := testAgentStream(t, func(n int) error { reserved += n; calls++; return nil })
	for _, wire := range [][]byte{first, later, later} {
		message, err := stream.Decode(wire, policy.DecodeLimits{MaxBytes: testCap})
		if err != nil {
			t.Fatal(err)
		}
		if !message.HasContent() || !bytes.Contains(message.ScanInput(), []byte(secret)) {
			t.Fatal("a repeated reference bypassed content inspection")
		}
		if newScanner(t, "").Scan(message.ScanInput(), testCap)["status"] != "redacted" {
			t.Fatal("replayed content did not reach the shared detector")
		}
		unchanged, err := message.Rewrite(message.ScanInput())
		if err != nil || !bytes.Equal(unchanged, wire) {
			t.Fatal("replayed references or original bytes changed")
		}
	}
	if len(stream.blobs) != 4 || stream.used != int64(reserved) || calls != 1 {
		t.Fatal("replays amplified retained state or escaped admission")
	}
	// Retaining sub-slices of the input would keep an entire envelope alive and
	// make later inspection depend on the caller's mutable buffer.
	clear(first)
	message, err := stream.Decode(later, policy.DecodeLimits{MaxBytes: testCap})
	if err != nil || !bytes.Contains(message.ScanInput(), []byte(secret)) {
		t.Fatal("retained blobs did not own their bytes")
	}
}

func TestAgentStreamDoesNotTrustOtherRequestsOrPriorTypes(t *testing.T) {
	first, later := agentReplayFixture("ordinary historical context")
	stream := testAgentStream(t, nil)
	if _, err := stream.Decode(first, policy.DecodeLimits{MaxBytes: testCap}); err != nil {
		t.Fatal(err)
	}
	other := testAgentStream(t, nil)
	if _, err := other.Decode(later, policy.DecodeLimits{MaxBytes: testCap}); !errors.Is(err, ErrUnsupported) {
		t.Fatal("another HTTP request inherited blob state")
	}
	if _, err := decodeMessage(agentClientMessage, later, policy.DecodeLimits{MaxBytes: testCap}); !errors.Is(err, ErrUnsupported) {
		t.Fatal("stateless decoding inherited stream state")
	}
	id, blob := agentBlob(byteField(1, []byte("ordinary summary")))
	if _, err := stream.Decode(agentGraph(byteField(6, id), blob), policy.DecodeLimits{MaxBytes: testCap}); err != nil {
		t.Fatal(err)
	}
	if _, err := stream.Decode(agentGraph(byteField(8, id)), policy.DecodeLimits{MaxBytes: testCap}); err == nil {
		t.Fatal("a prior type authorized a different interpretation")
	}
	if _, err := stream.Decode(agentGraph(nil, blob), policy.DecodeLimits{MaxBytes: testCap}); !errors.Is(err, ErrUnsupported) {
		t.Fatal("a previously inspected identity authorized an unused upload")
	}
	stream.Close()
	stream.Close()
	if stream.blobs != nil || stream.used != 0 {
		t.Fatal("closed stream retained conversation content")
	}
	if _, err := stream.Decode(later, policy.DecodeLimits{MaxBytes: testCap}); !errors.Is(err, ErrUnsupported) {
		t.Fatal("closed state was reusable")
	}
}

func TestAgentStreamRetainsOnlyFullyDecodedBoundedUploads(t *testing.T) {
	stream := testAgentStream(t, nil)
	id, blob := agentBlob(byteField(1, bytes.Repeat([]byte{0}, 200)))
	if _, err := stream.Decode(agentGraph(byteField(6, id), blob), policy.DecodeLimits{MaxBytes: 600}); !errors.Is(err, ErrLimit) {
		t.Fatal("projection overflow was accepted")
	}
	if len(stream.blobs) != 0 {
		t.Fatal("failed projection seeded stream state")
	}
	capacity := errors.New("test capacity")
	full := testAgentStream(t, func(int) error { return capacity })
	id, blob = agentBlob(byteField(1, []byte("ordinary summary")))
	if _, err := full.Decode(agentGraph(byteField(6, id), blob), policy.DecodeLimits{MaxBytes: testCap}); !errors.Is(err, capacity) {
		t.Fatal("lost retained-state admission failure")
	}
	if len(full.blobs) != 0 || full.used != 0 {
		t.Fatal("failed admission retained uploads")
	}
	stream.maxBytes = int64(sha256.Size + len(byteField(1, []byte("ordinary summary"))))
	wire := agentGraph(byteField(6, id), blob)
	if _, err := stream.Decode(wire, policy.DecodeLimits{MaxBytes: testCap}); err != nil {
		t.Fatal(err)
	}
	if _, err := stream.Decode(wire, policy.DecodeLimits{MaxBytes: testCap}); err != nil {
		t.Fatal("duplicate upload consumed capacity twice")
	}
	otherID, otherBlob := agentBlob(byteField(1, []byte("another summary")))
	if _, err := stream.Decode(agentGraph(byteField(6, otherID), otherBlob), policy.DecodeLimits{MaxBytes: testCap}); !errors.Is(err, ErrLimit) {
		t.Fatal("ignored cumulative retained-state byte cap")
	}
	// The count limit also bounds metadata for tiny and empty blobs.
	stream.maxBytes = testCap
	for n := len(stream.blobs); n < maxAgentBlobs; n++ {
		digest := sha256.Sum256(uintField(1, uint64(n)))
		stream.blobs[digest] = nil
	}
	if _, err := stream.Decode(agentGraph(byteField(6, otherID), otherBlob), policy.DecodeLimits{MaxBytes: testCap}); !errors.Is(err, ErrLimit) {
		t.Fatal("ignored cumulative blob count cap")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := stream.Decode(wire, policy.DecodeLimits{MaxBytes: testCap, Context: ctx}); !errors.Is(err, context.Canceled) {
		t.Fatal("replay ignored cancellation")
	}
}

func TestAgentTextBlobsUseReviewedUTF8Semantics(t *testing.T) {
	const secret = "sk_live_4eC39HqLyjWDarjtT1zdp7dc"
	id, blob := agentBlob([]byte(secret))
	for name, action := range map[string][]byte{
		"prompt":    byteField(1, byteField(1, byteField(18, id))),
		"rich-text": byteField(1, byteField(1, byteField(19, id))),
		"extra":     byteField(1, byteField(1, byteField(3, byteField(16, byteField(2, id))))),
	} {
		t.Run(name, func(t *testing.T) {
			assertAgentInspection(t, byteField(1, concat(byteField(2, action), blob)), secret)
		})
	}
	userID, userBlob := agentBlob(byteField(18, id))
	turnID, turnBlob := agentBlob(byteField(1, byteField(1, userID)))
	assertAgentInspection(t, agentGraph(byteField(8, turnID), turnBlob, userBlob, blob), secret)
	read := byteField(2, byteField(8, byteField(2, byteField(1, byteField(10, id)))))
	assertAgentInspection(t, appendAgentBlob(agentHistory(nil, read), blob), secret)
	badID, bad := agentBlob([]byte{0xff})
	wire := byteField(1, concat(byteField(2, byteField(1, byteField(1, byteField(18, badID)))), bad))
	if _, err := decodeMessage(agentClientMessage, wire, policy.DecodeLimits{MaxBytes: testCap}); !errors.Is(err, ErrMalformed) {
		t.Fatal("non-UTF-8 prompt blob was admitted")
	}
}

func appendAgentBlob(wire, blob []byte) []byte {
	_, _, n := protowire.ConsumeTag(wire)
	payload, _ := protowire.ConsumeBytes(wire[n:])
	return byteField(1, concat(payload, blob))
}

func agentContextParts(parts [4][]byte, dynamic []byte) (wire, refs []byte) {
	var blobs []byte
	for i, part := range parts {
		id, blob := agentBlob(part)
		number := protowire.Number(1 + 2*i)
		refs = concat(refs, byteField(number, id), uintField(number+1, uint64(len(part))))
		blobs = concat(blobs, blob)
	}
	if dynamic != nil {
		refs = concat(refs, byteField(9, dynamic))
	}
	return byteField(1, concat(byteField(2, byteField(17, refs)), blobs)), refs
}

func TestAgentSplitContextPartsAreTypedAndInspected(t *testing.T) {
	const secret = "sk_live_4eC39HqLyjWDarjtT1zdp7dc"
	for name, parts := range map[string][4][]byte{
		"rules":     {byteField(1, byteField(2, []byte(secret))), nil, nil, nil},
		"skills":    {nil, byteField(1, byteField(2, []byte(secret))), nil, nil},
		"subagents": {nil, nil, byteField(1, byteField(6, []byte(secret))), nil},
		"mcp":       {nil, nil, nil, byteField(2, byteField(2, []byte(secret)))},
	} {
		t.Run(name, func(t *testing.T) {
			wire, _ := agentContextParts(parts, nil)
			assertAgentInspection(t, wire, secret)
		})
	}
	wire, _ := agentContextParts([4][]byte{}, byteField(20, concat(byteField(1, []byte("file")), byteField(2, []byte(secret)))))
	assertAgentInspection(t, wire, secret)
	wire, refs := agentContextParts([4][]byte{byteField(3, []byte("ordinary cloud rule"))}, nil)
	stream := testAgentStream(t, nil)
	if _, err := stream.Decode(wire, policy.DecodeLimits{MaxBytes: testCap}); err != nil {
		t.Fatal(err)
	}
	// A later action can reuse the same parts, but each length and expected type
	// is still checked, even when another part references the same identity.
	replay := byteField(4, byteField(17, refs))
	if message, err := stream.Decode(replay, policy.DecodeLimits{MaxBytes: testCap}); err != nil ||
		!bytes.Contains(message.ScanInput(), []byte("ordinary cloud rule")) {
		t.Fatal("context part replay was not inspected")
	}
	wrongLength := bytes.Replace(refs, uintField(2, uint64(len(byteField(3, []byte("ordinary cloud rule"))))), uintField(2, 999), 1)
	if _, err := stream.Decode(byteField(4, byteField(17, wrongLength)), policy.DecodeLimits{MaxBytes: testCap}); !errors.Is(err, ErrUnsupported) {
		t.Fatal("replay ignored a conflicting part length")
	}
	for _, parts := range [][4][]byte{
		{byteField(99, nil)},
		{nil, nil, nil, byteField(3, nil)}, // Unreviewed MCP filesystem options.
	} {
		wire, _ := agentContextParts(parts, nil)
		if _, err := decodeMessage(agentClientMessage, wire, policy.DecodeLimits{MaxBytes: testCap}); !errors.Is(err, ErrUnsupported) {
			t.Fatal("unreviewed context part was accepted")
		}
	}
}

func FuzzDecodeAgentStream(f *testing.F) {
	first, later := agentReplayFixture("ordinary historical context")
	f.Add(first, later)
	f.Add([]byte{0x0a, 0x80}, later)
	f.Fuzz(func(t *testing.T, first, later []byte) {
		stream := testAgentStream(t, nil)
		for _, body := range [][]byte{first, later} {
			message, err := stream.Decode(body, policy.DecodeLimits{MaxBytes: testCap})
			if err != nil {
				return
			}
			unchanged, err := message.Rewrite(message.ScanInput())
			if err != nil || !bytes.Equal(unchanged, body) {
				t.Fatalf("accepted stream message did not retain exact bytes: %v", err)
			}
		}
	})
}
