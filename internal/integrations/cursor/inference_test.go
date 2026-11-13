package cursor

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"slices"
	"strings"
	"testing"

	"github.com/cquark7/withhold/internal/detector"
	"github.com/cquark7/withhold/internal/scanner"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"
)

const testCap = 1024 * 1024

func byteField(number protowire.Number, payload []byte) []byte {
	return protowire.AppendBytes(protowire.AppendTag(nil, number, protowire.BytesType), payload)
}

func uintField(number protowire.Number, value uint64) []byte {
	return protowire.AppendVarint(protowire.AppendTag(nil, number, protowire.VarintType), value)
}

func concat(parts ...[]byte) []byte { return bytes.Join(parts, nil) }

func invocation(request []byte) []byte {
	return byteField(2, concat(byteField(1, []byte("synthetic-invocation")), request))
}

func fullRequest(request []byte) []byte { return invocation(byteField(2, request)) }

func textRequest(text string) []byte {
	return byteField(1, concat(uintField(1, 2), byteField(2, []byte(text))))
}

func segmentedRequest(parts ...[]byte) []byte {
	var encodedParts [][]byte
	for _, part := range parts {
		encodedParts = append(encodedParts, byteField(1, part))
	}
	contentParts := byteField(3, concat(encodedParts...))
	return fullRequest(byteField(1, contentParts))
}

func textContentPart(text string) []byte {
	return byteField(1, byteField(1, []byte(text)))
}

func marshalProto(t *testing.T, message proto.Message) []byte {
	t.Helper()
	result, err := proto.Marshal(message)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

// Read the actual protobuf bytes independently of the adapter's wire tree.
func byteFields(t *testing.T, body []byte, number protowire.Number) [][]byte {
	t.Helper()
	var result [][]byte
	for len(body) > 0 {
		n, wire, tag := protowire.ConsumeTag(body)
		if tag < 0 {
			t.Fatal("invalid output tag")
		}
		size := protowire.ConsumeFieldValue(n, wire, body[tag:])
		if size < 0 {
			t.Fatal("invalid output value")
		}
		if n == number && wire == protowire.BytesType {
			value, _ := protowire.ConsumeBytes(body[tag:])
			result = append(result, value)
		}
		body = body[tag+size:]
	}
	return result
}

func compressedFixture(t *testing.T, request []byte, encoding uint64) []byte {
	t.Helper()
	data, err := compress(request, encoding, testCap)
	if err != nil {
		t.Fatal(err)
	}
	return byteField(7, concat(uintField(1, encoding), uintField(2, uint64(len(request))), byteField(3, data)))
}

func newScanner(t *testing.T, pii string) *scanner.Scanner {
	t.Helper()
	d, err := detector.New(pii)
	if err != nil {
		t.Fatal(err)
	}
	return scanner.New(d, func() []byte { return []byte("isolated-cursor-test") })
}

func scanRewrite(t *testing.T, scan *scanner.Scanner, wire []byte) ([]byte, scanner.Report) {
	t.Helper()
	message, err := DecodeRunInference(wire, testCap)
	if err != nil {
		t.Fatal(err)
	}
	report := scan.Scan(message.ScanInput(), testCap)
	if report["status"] != "redacted" {
		t.Fatalf("expected detection, got %v", report["status"])
	}
	scanned, err := base64.StdEncoding.Strict().DecodeString(report["body_base64"].(string))
	if err != nil {
		t.Fatal(err)
	}
	rewritten, err := message.Rewrite(scanned)
	if err != nil {
		t.Fatal(err)
	}
	second, err := DecodeRunInference(rewritten, testCap)
	if err != nil {
		t.Fatal(err)
	}
	if report := scan.Scan(second.ScanInput(), testCap); report["status"] != "clean" {
		t.Fatalf("rewritten projection did not rescan clean: %v", report["status"])
	}
	return rewritten, report
}

func TestInferenceDetectionAndRedaction(t *testing.T) {
	scan := newScanner(t, "")
	secrets := []string{
		"AKIA4X7Q2W8K9MNDZZZZ",
		"AKIA4X7Q2W3K7MNDZBXP",
		"AKIA5Z9P6R7T8UVWXXXX",
		"sk_live_4eC39HqLyjWDarjtT1zdp7dc",
	}
	toolResult := marshalProto(t, structpb.NewStringValue(`shell output token = "`+secrets[2]+`"`))
	arguments, err := structpb.NewStruct(map[string]any{"api_key": secrets[3]})
	if err != nil {
		t.Fatal(err)
	}
	request := concat(
		textRequest(`prompt token = "`+secrets[0]+`"`),
		textRequest(`file contents token = "`+secrets[1]+`"`),
		byteField(1, concat(
			uintField(1, 4),
			byteField(6, byteField(1, concat(
				byteField(1, []byte("shell-call")),
				byteField(2, []byte("Shell")),
				byteField(3, toolResult),
			))),
		)),
		byteField(1, concat(
			uintField(1, 3),
			byteField(4, concat(
				byteField(1, []byte("mcp-call")),
				byteField(2, []byte("MCP")),
				byteField(3, marshalProto(t, arguments)),
			)),
		)),
		byteField(5, []byte("synthetic-model")),
	)
	for _, test := range []struct {
		name     string
		encoding uint64
	}{{"plain", 0}, {"gzip", 2}, {"zstd", 1}} {
		t.Run(test.name, func(t *testing.T) {
			payload := byteField(2, request)
			if test.encoding != 0 {
				payload = compressedFixture(t, request, test.encoding)
			}
			rewritten, report := scanRewrite(t, scan, invocation(payload))
			rules := report["rule_ids"].([]string)
			if !slices.Contains(rules, "aws-access-token") || !slices.Contains(rules, "stripe-access-token") {
				t.Fatal("expected secret rules were not applied")
			}
			invoke := byteFields(t, rewritten, 2)[0]
			var decoded []byte
			if test.encoding == 0 {
				decoded = byteFields(t, invoke, 2)[0]
			} else {
				compressed := byteFields(t, invoke, 7)[0]
				// Expand with the standard/library decoder, not the adapter.
				reader, closeReader := fixtureReader(t, byteFields(t, compressed, 3)[0], test.encoding)
				decoded, err = io.ReadAll(reader)
				closeReader()
				if err != nil {
					t.Fatal(err)
				}
				size := uintValue(t, compressed, 2)
				if size != uint64(len(decoded)) {
					t.Fatal("decoded_size was not updated")
				}
			}
			for index, secret := range secrets {
				if bytes.Contains(decoded, []byte(secret)) {
					t.Errorf("synthetic sentinel %d survived in decoded protobuf", index)
				}
			}
			if !bytes.Contains(decoded, []byte("<WITHHELD_")) || !bytes.Contains(decoded, []byte("synthetic-model")) {
				t.Fatal("placeholder or preserved model missing")
			}
			messages := byteFields(t, decoded, 1)
			result := byteFields(t, byteFields(t, messages[2], 6)[0], 1)[0]
			var value structpb.Value
			if proto.Unmarshal(byteFields(t, result, 3)[0], &value) != nil || !strings.Contains(value.GetStringValue(), "<WITHHELD_") {
				t.Fatal("tool result did not survive independent protobuf decoding")
			}
			call := byteFields(t, messages[3], 4)[0]
			var args structpb.Struct
			if proto.Unmarshal(byteFields(t, call, 3)[0], &args) != nil || !strings.HasPrefix(args.Fields["api_key"].GetStringValue(), "<WITHHELD_") {
				t.Fatal("tool arguments did not survive independent protobuf decoding")
			}
		})
	}
}

func TestInferenceCleanWirePreservation(t *testing.T) {
	// Field order, explicit defaults, packed enums, and nonminimal valid
	// varints must survive without protobuf normalization.
	request := concat(
		[]byte{0x88, 0x01, 0x80, 0x00}, // compaction_epoch = 0, nonminimal value.
		byteField(1, concat(byteField(2, []byte("Explain this function.")), uintField(1, 2), uintField(13, 0), byteField(16, []byte{1, 2}))),
	)
	for _, encoding := range []uint64{0, 2, 1} {
		payload := byteField(2, request)
		if encoding != 0 {
			payload = compressedFixture(t, request, encoding)
		}
		wire := invocation(payload)
		message, err := DecodeRunInference(wire, testCap)
		if err != nil {
			t.Fatal(err)
		}
		// Neither the caller's input nor a returned projection can mutate the
		// codec's retained data.
		original := bytes.Clone(wire)
		wire[0] ^= 1
		projection := message.ScanInput()
		projection[0] ^= 1
		output, err := message.Rewrite(message.ScanInput())
		if err != nil || !bytes.Equal(output, original) {
			t.Fatalf("clean bytes changed for encoding %d: %v", encoding, err)
		}
		output[0] ^= 1
		again, err := message.Rewrite(message.ScanInput())
		if err != nil || !bytes.Equal(again, original) {
			t.Fatal("rewriting mutated retained wire bytes")
		}
	}
}

func TestInferenceSegmentedTextRedaction(t *testing.T) {
	const secret = "sk_live_4eC39HqLyjWDarjtT1zdp7dc"
	wire := segmentedRequest(
		textContentPart(secret[:6]),
		textContentPart(secret[6:14]),
		textContentPart(secret[14:]),
	)
	original := bytes.Clone(wire)
	message, err := DecodeRunInference(wire, testCap)
	if err != nil {
		t.Fatal(err)
	}
	if !message.HasContent() || !bytes.Contains(message.ScanInput(), []byte(secret)) {
		t.Fatal("segmented text was not projected as one logical string")
	}
	report := newScanner(t, "").Scan(message.ScanInput(), testCap)
	if report["status"] != "redacted" {
		t.Fatalf("split secret was not detected: %v", report["status"])
	}
	rewrittenProjection, err := base64.StdEncoding.DecodeString(report["body_base64"].(string))
	if err != nil {
		t.Fatal(err)
	}
	rewritten, err := message.Rewrite(rewrittenProjection)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(rewritten, []byte(secret)) || !bytes.Contains(rewritten, []byte("<WITHHELD_")) {
		t.Fatal("split secret survived rewritten protobuf")
	}
	if bytes.Equal(rewritten, original) {
		t.Fatal("redaction did not update the protobuf")
	}
	invoke := byteFields(t, rewritten, 2)[0]
	request := byteFields(t, invoke, 2)[0]
	coreMessage := byteFields(t, request, 1)[0]
	content := byteFields(t, coreMessage, 3)[0]
	parts := byteFields(t, content, 1)
	if len(parts) != 3 {
		t.Fatalf("rewritten part count changed: %d", len(parts))
	}
	var joined []byte
	for _, part := range parts {
		selected := byteFields(t, part, 1)[0]
		joined = append(joined, byteFields(t, selected, 1)[0]...)
	}
	if bytes.Contains(joined, []byte(secret)) || !bytes.Contains(joined, []byte("<WITHHELD_")) ||
		len(byteFields(t, parts[1], 1)) != 1 || len(byteFields(t, byteFields(t, parts[1], 1)[0], 1)[0]) != 0 {
		t.Fatal("segmented rewrite did not preserve the joined text safely")
	}
	verified, err := DecodeRunInference(rewritten, testCap)
	if err != nil {
		t.Fatal(err)
	}
	if report := newScanner(t, "").Scan(verified.ScanInput(), testCap); report["status"] != "clean" {
		t.Fatalf("rewritten segmented content did not rescan clean: %v", report["status"])
	}
}

func TestInferenceSegmentedTextCleanPreservationAndUnsupportedParts(t *testing.T) {
	wire := segmentedRequest(textContentPart("Explain "), textContentPart("this function."))
	message, err := DecodeRunInference(wire, testCap)
	if err != nil {
		t.Fatal(err)
	}
	clean, err := message.Rewrite(message.ScanInput())
	if err != nil || !bytes.Equal(clean, wire) {
		t.Fatalf("clean segmented wire bytes changed: %v", err)
	}
	providerOptions := byteField(1, concat(
		byteField(1, []byte("safe text")),
		byteField(2, nil),
	))
	image := byteField(2, byteField(1, []byte("opaque image bytes")))
	empty := []byte(nil)
	for name, part := range map[string][]byte{
		"provider-options": providerOptions,
		"image":            image,
		"unset-oneof":      empty,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeRunInference(segmentedRequest(part), testCap); !errors.Is(err, ErrUnsupported) {
				t.Fatalf("unsupported segmented variant accepted: %v", err)
			}
		})
	}
}

func TestInferenceMapKeyRedaction(t *testing.T) {
	const secret = "sk_live_4eC39HqLyjWDarjtT1zdp7dc"
	result, err := structpb.NewStruct(map[string]any{
		secret: map[string]any{"nested": []any{"safe text", secret}},
	})
	if err != nil {
		t.Fatal(err)
	}
	call := byteField(3, marshalProto(t, result))
	wire := fullRequest(byteField(1, byteField(4, call)))
	rewritten, _ := scanRewrite(t, newScanner(t, ""), wire)
	request := byteFields(t, byteFields(t, rewritten, 2)[0], 2)[0]
	var decoded structpb.Struct
	args := byteFields(t, byteFields(t, request, 1)[0], 4)[0]
	if proto.Unmarshal(byteFields(t, args, 3)[0], &decoded) != nil || len(decoded.Fields) != 1 {
		t.Fatal("rewritten map cannot be decoded")
	}
	for key := range decoded.Fields {
		if !strings.HasPrefix(key, "<WITHHELD_") {
			t.Fatal("map key was not rewritten")
		}
	}
}

func TestInferenceRejectsUnsupportedAndMalformedContent(t *testing.T) {
	plain := textRequest("Explain this function.")
	duplicateEntry := byteField(1, concat(byteField(1, []byte("same")), byteField(2, byteField(3, []byte("text")))))
	cases := []struct {
		name string
		wire []byte
		want error
	}{
		{"unknown-client-field", byteField(99, nil), ErrUnsupported},
		{"unknown-nested-field", fullRequest(concat(plain, byteField(99, []byte("unreviewed")))), ErrUnsupported},
		{"unknown-numeric-field", fullRequest(concat(plain, uintField(99, 0))), ErrUnsupported},
		{"unknown-enum", fullRequest(byteField(1, uintField(1, 99))), ErrUnsupported},
		{"unknown-packed-enum", fullRequest(byteField(1, byteField(16, []byte{1, 99}))), ErrUnsupported},
		{"delta", invocation(concat(byteField(2, plain), byteField(5, nil))), ErrUnsupported},
		{"fingerprint", invocation(concat(byteField(2, plain), byteField(6, nil))), ErrUnsupported},
		{"seed", byteField(11, nil), ErrUnsupported},
		{"run-request-cache", byteField(1, byteField(19, nil)), ErrUnsupported},
		{"log-bytes", byteField(7, byteField(1, []byte{0xff})), ErrUnsupported},
		{"signed-reasoning", fullRequest(byteField(1, byteField(7, nil))), ErrUnsupported},
		{"native-content", fullRequest(byteField(1, byteField(18, nil))), ErrUnsupported},
		{"static-prefix-length", fullRequest(concat(plain, uintField(26, 0))), ErrUnsupported},
		{"duplicate-singular", fullRequest(byteField(1, concat(byteField(2, nil), byteField(2, nil)))), ErrUnsupported},
		{"multiple-oneof", fullRequest(byteField(1, concat(byteField(2, nil), byteField(6, nil)))), ErrUnsupported},
		{"duplicate-map-key", fullRequest(byteField(1, byteField(4, byteField(3, concat(duplicateEntry, duplicateEntry))))), ErrUnsupported},
		{"missing-map-value", fullRequest(byteField(1, byteField(4, byteField(3, byteField(1, byteField(1, []byte("key"))))))), ErrUnsupported},
		{"two-requests", invocation(concat(byteField(2, plain), compressedFixture(t, plain, 2))), ErrUnsupported},
		{"no-request", invocation(nil), ErrUnsupported},
		{"invalid-utf8", fullRequest(textRequest(string([]byte{0xff}))), ErrMalformed},
		{"wrong-wire-type", fullRequest(uintField(1, 1)), ErrMalformed},
		{"truncated-value", []byte{0x12, 0x80}, ErrMalformed},
		{"invalid-tag", []byte{0x00}, ErrMalformed},
		{"empty-value", fullRequest(byteField(1, byteField(6, byteField(1, byteField(3, nil))))), ErrMalformed},
		{"invalid-bool", fullRequest(byteField(1, uintField(13, 2))), ErrMalformed},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			message, err := DecodeRunInference(test.wire, testCap)
			if message != nil || !errors.Is(err, test.want) {
				t.Fatalf("got message=%t, error=%v; want %v", message != nil, err, test.want)
			}
		})
	}
}

func TestInferenceRewriteValidation(t *testing.T) {
	message, err := DecodeRunInference(fullRequest(textRequest("Explain this function.")), testCap)
	if err != nil {
		t.Fatal(err)
	}
	for _, body := range []string{
		`{}`, `{"fields":null}`, `{"fields":[]}`, `{"fields":[{"text":null}]}`,
		`{"fields":[{"text":"a","text":"b"}]}`, `{"fields":[{"wrong":"a"}]}`,
		`{"fields":[{"text":"a"}],"fields":[]}`, `{"fields":[{"text":"a"}]} {}`,
	} {
		if output, err := message.Rewrite([]byte(body)); output != nil || !errors.Is(err, ErrRewrite) {
			t.Fatalf("invalid projection accepted: %v", err)
		}
	}
	t.Run("immutable-identifier", func(t *testing.T) {
		projection := bytes.ReplaceAll(message.ScanInput(), []byte("synthetic-invocation"), []byte("changed-invocation"))
		if _, err := message.Rewrite(projection); !errors.Is(err, ErrUnsupported) {
			t.Fatalf("identifier mutation accepted: %v", err)
		}
	})
	t.Run("map-key-collision", func(t *testing.T) {
		args, err := structpb.NewStruct(map[string]any{"first": "one", "second": "two"})
		if err != nil {
			t.Fatal(err)
		}
		m, err := DecodeRunInference(fullRequest(byteField(1, byteField(4, byteField(3, marshalProto(t, args))))), testCap)
		if err != nil {
			t.Fatal(err)
		}
		projection := bytes.ReplaceAll(m.ScanInput(), []byte("second"), []byte("first"))
		if output, err := m.Rewrite(projection); output != nil || err == nil {
			t.Fatal("map key collision accepted")
		}
	})
}

func TestInferenceLimits(t *testing.T) {
	wire := fullRequest(textRequest("Explain this function."))
	for _, capBytes := range []int64{-1, 0, 128*1024*1024 + 1, 1, int64(len(wire))} {
		if _, err := DecodeRunInference(wire, capBytes); !errors.Is(err, ErrLimit) {
			t.Fatalf("limit %d was not enforced: %v", capBytes, err)
		}
	}
	value := byteField(3, []byte("nested value"))
	for range maxDepth {
		value = byteField(5, byteField(1, concat(byteField(1, []byte("nested")), byteField(2, value))))
	}
	if _, err := DecodeRunInference(fullRequest(byteField(1, byteField(6, byteField(1, byteField(3, value))))), testCap); !errors.Is(err, ErrLimit) {
		t.Fatalf("nesting limit not enforced: %v", err)
	}
	request := bytes.Repeat(byteField(9, nil), maxFields+1)
	if _, err := DecodeRunInference(fullRequest(request), testCap); !errors.Is(err, ErrLimit) {
		t.Fatalf("field count limit not enforced: %v", err)
	}
	message, err := DecodeRunInference(wire, testCap)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := message.Rewrite(bytes.Repeat([]byte(" "), testCap+1)); !errors.Is(err, ErrLimit) {
		t.Fatalf("rewritten projection cap not enforced: %v", err)
	}
}

func TestProjectionSizeIsBoundedBeforeMarshaling(t *testing.T) {
	for _, text := range []string{"plain text", "\"\\\n\t\b\f\r", "\x00\x01<&>", "世界\u2028\u2029"} {
		encoded, err := json.Marshal(text)
		if err != nil || jsonStringSize([]byte(text)) != int64(len(encoded)) {
			t.Fatal("projection accounting disagrees with JSON encoding")
		}
	}
	key := strings.Repeat("context", 100)
	values := make([]any, 40)
	for i := range values {
		values[i] = "short value"
	}
	args, err := structpb.NewStruct(map[string]any{key: values})
	if err != nil {
		t.Fatal(err)
	}
	request := byteField(1, byteField(4, byteField(3, marshalProto(t, args))))
	// Input fits, but repeating the user key as detector context would exceed
	// this projection budget. Reject before allocating that expanded JSON.
	if message, err := DecodeRunInference(fullRequest(request), 4096); message != nil || !errors.Is(err, ErrLimit) {
		t.Fatalf("amplified projection accepted: %v", err)
	}
	// Control characters can expand sixfold under JSON escaping.
	if _, err := DecodeRunInference(fullRequest(textRequest(strings.Repeat("\x00", 1000))), 4096); !errors.Is(err, ErrLimit) {
		t.Fatalf("escaped projection overflow accepted: %v", err)
	}
}

func TestInferencePIIReusesScanner(t *testing.T) {
	wire := fullRequest(textRequest("Contact user@example.com for details."))
	rewritten, _ := scanRewrite(t, newScanner(t, "email"), wire)
	if bytes.Contains(rewritten, []byte("user@example.com")) || !bytes.Contains(rewritten, []byte("<WITHHELD_")) {
		t.Fatal("PII did not use the shared rewrite pipeline")
	}
}

func FuzzDecodeRunInference(f *testing.F) {
	f.Add(fullRequest(textRequest("Explain this function.")))
	f.Add([]byte{0x12, 0x80})
	f.Fuzz(func(t *testing.T, input []byte) {
		message, err := DecodeRunInference(input, testCap)
		if err != nil {
			return
		}
		output, err := message.Rewrite(message.ScanInput())
		if err != nil || !bytes.Equal(output, input) {
			t.Fatalf("accepted clean message did not round-trip: %v", err)
		}
	})
}

func TestEmbeddedSchemaReferences(t *testing.T) {
	if pinned.Root != clientMessage || pinned.CursorVersion == "" || len(pinned.BundleSHA256) != 64 {
		t.Fatal("missing schema provenance")
	}
	for name, fields := range pinned.fields {
		for number, field := range fields {
			if number != field.Number || !number.IsValid() || field.Name == "" {
				t.Fatalf("invalid field in %s", name)
			}
			if scalarWire(field.Type) == protowire.BytesType && field.Type != "string" && field.Type != "bytes" && pinned.fields[field.Type] == nil {
				t.Fatalf("unresolved message type in %s", name)
			}
		}
	}
	// No editor version is passed to decoding; older subsets do not require
	// optional fields added by the source application's newer schema.
	wire := byteField(2, byteField(2, textRequest("Explain this function.")))
	message, err := DecodeRunInference(wire, testCap)
	if err != nil {
		t.Fatal(err)
	}
	var projection any
	if json.Unmarshal(message.ScanInput(), &projection) != nil {
		t.Fatal("older protocol subset did not produce scanner input")
	}
}
