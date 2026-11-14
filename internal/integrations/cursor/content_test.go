package cursor

import (
	"bytes"
	"encoding/base64"
	"errors"
	"testing"

	"github.com/cquark7/withhold/internal/policy"
	"google.golang.org/protobuf/encoding/protowire"
)

func TestNameTabAttachedCodeAndToolResults(t *testing.T) {
	const secret = "sk_live_4eC39HqLyjWDarjtT1zdp7dc"
	scan := newScanner(t, "")
	for name, conversation := range map[string][]byte{
		"attached-code": byteField(3, concat(
			byteField(1, []byte("fixture.go")),
			uintField(2, 1),
			byteField(3, []byte(`token = "`+secret+`"`)),
			byteField(3, []byte("ordinary second line")),
		)),
		"tool-content": byteField(18, concat(
			byteField(1, []byte("call-id")),
			byteField(2, []byte("Shell")),
			byteField(7, []byte(secret)),
		)),
		"tool-arguments": byteField(18, byteField(5, []byte(`{"token":"`+secret+`"}`))),
		"shell-result":   byteField(18, byteField(8, byteField(24, byteField(12, []byte(secret))))),
		"mcp-result":     byteField(18, byteField(8, byteField(28, byteField(2, []byte(secret))))),
	} {
		t.Run(name, func(t *testing.T) {
			wire := byteField(1, conversation)
			message, err := decodeMessage("aiserver.v1.NameTabRequest", wire, policy.DecodeLimits{MaxBytes: testCap})
			if err != nil {
				t.Fatal(err)
			}
			if !message.HasContent() {
				t.Fatal("attached content did not establish inspected-content coverage")
			}
			unchanged, err := message.Rewrite(message.ScanInput())
			if err != nil || !bytes.Equal(unchanged, wire) {
				t.Fatal("unchanged attached context did not retain exact protobuf bytes")
			}
			report := scan.Scan(message.ScanInput(), testCap)
			if report["status"] != "redacted" {
				t.Fatal("attached content was not detected")
			}
			projection, err := base64.StdEncoding.DecodeString(report["body_base64"].(string))
			if err != nil {
				t.Fatal(err)
			}
			rewritten, err := message.Rewrite(projection)
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Contains(rewritten, []byte(secret)) || !bytes.Contains(rewritten, []byte("<WITHHELD_")) {
				t.Fatal("attached content was not redacted in protobuf")
			}
			verified, err := decodeMessage("aiserver.v1.NameTabRequest", rewritten, policy.DecodeLimits{MaxBytes: testCap})
			if err != nil || scan.Scan(verified.ScanInput(), testCap)["status"] != "clean" {
				t.Fatal("rewritten attached content did not rescan clean")
			}
			for _, slot := range message.slots {
				if slot.writable {
					continue
				}
				if !bytes.Contains(verified.ScanInput(), []byte(slot.text())) {
					t.Fatal("structural metadata changed")
				}
			}
		})
	}
}

func TestInlineContextAndHashesRetainOriginalBytes(t *testing.T) {
	wire := concat(
		byteField(1, concat(
			byteField(2, []byte("ordinary file contents")),
			byteField(6, concat(
				byteField(1, concat(uintField(1, 2), uintField(2, 3))),
				byteField(2, concat(uintField(1, 4), uintField(2, 5))),
			)),
			uintField(11, 3),
			uintField(14, 4),
			byteField(17, []byte("full-file-hash-for-an-inline-window")),
			uintField(18, 0),
		)),
		byteField(13, concat(byteField(1, []byte("nearby symbol contents")), byteField(3, []byte("other.go")))),
		byteField(19, concat(byteField(1, []byte("visible.go")), byteField(3, []byte("visible range contents")))),
	)
	message, err := decodeMessage("aiserver.v1.StreamCppRequest", wire, policy.DecodeLimits{MaxBytes: testCap})
	if err != nil {
		t.Fatal(err)
	}
	unchanged, err := message.Rewrite(message.ScanInput())
	if err != nil || !bytes.Equal(unchanged, wire) {
		t.Fatal("inline context or hashes changed")
	}
	for _, content := range []string{"ordinary file contents", "nearby symbol contents", "visible range contents"} {
		if !bytes.Contains(message.ScanInput(), []byte(content)) {
			t.Fatal("inline context was not projected")
		}
		if rewritten, err := message.Rewrite(bytes.ReplaceAll(message.ScanInput(), []byte(content), []byte("changed"))); rewritten != nil || !errors.Is(err, ErrUnsupported) {
			t.Fatal("inline context rewrite could invalidate positions or hashes")
		}
	}
}

func TestInferenceFilePartsUseSharedBase64Inspection(t *testing.T) {
	const secret = "sk_live_4eC39HqLyjWDarjtT1zdp7dc"
	text := `{"token":"` + secret + `","padding":"enough ordinary text to exercise base64 extraction"}`
	data := base64.StdEncoding.EncodeToString([]byte(text))
	file := byteField(3, concat(
		byteField(1, []byte(data)),
		byteField(2, []byte("text/plain")),
		byteField(3, []byte("fixture.txt")),
	))
	wire := segmentedRequest(textContentPart("Review this attachment."), file, textContentPart("Explain the result."))
	message, err := DecodeRunInference(wire, testCap)
	if err != nil {
		t.Fatal(err)
	}
	unchanged, err := message.Rewrite(message.ScanInput())
	if err != nil || !bytes.Equal(unchanged, wire) {
		t.Fatal("unchanged file attachment bytes changed")
	}
	rewritten, _ := scanRewrite(t, newScanner(t, ""), wire)
	request := byteFields(t, byteFields(t, rewritten, 2)[0], 2)[0]
	core := byteFields(t, request, 1)[0]
	parts := byteFields(t, byteFields(t, core, 3)[0], 1)
	if len(parts) != 3 || !bytes.Equal(parts[0], textContentPart("Review this attachment.")) ||
		!bytes.Equal(parts[2], textContentPart("Explain the result.")) {
		t.Fatal("file attachment rewrite changed surrounding content or part order")
	}
	attachment := byteFields(t, parts[1], 3)[0]
	decoded, err := base64.StdEncoding.DecodeString(string(byteFields(t, attachment, 1)[0]))
	if err != nil || bytes.Contains(decoded, []byte(secret)) || !bytes.Contains(decoded, []byte("<WITHHELD_")) {
		t.Fatal("file attachment did not contain a verified base64 rewrite")
	}
	if !bytes.Equal(rawWireField(t, attachment, 2), rawWireField(t, byteFields(t, file, 3)[0], 2)) ||
		!bytes.Equal(rawWireField(t, attachment, 3), rawWireField(t, byteFields(t, file, 3)[0], 3)) {
		t.Fatal("file metadata changed")
	}
}

func TestImagesRetainBytesWithoutClaimingTextInspection(t *testing.T) {
	png, err := base64.StdEncoding.DecodeString("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAusB9Y9ZlYkAAAAASUVORK5CYII=")
	if err != nil {
		t.Fatal(err)
	}
	for name, fixture := range map[string]struct {
		root string
		body []byte
	}{
		"NameTab": {
			"aiserver.v1.NameTabRequest",
			byteField(1, byteField(10, concat(
				byteField(1, png),
				byteField(2, concat(uintField(1, 1), uintField(2, 1))),
				byteField(3, []byte("image-id")),
			))),
		},
		"RunInference": {
			clientMessage,
			segmentedRequest(byteField(2, concat(
				byteField(1, []byte(base64.StdEncoding.EncodeToString(png))),
				byteField(2, []byte("image/png")),
			))),
		},
	} {
		t.Run(name, func(t *testing.T) {
			message, err := decodeMessage(fixture.root, fixture.body, policy.DecodeLimits{MaxBytes: testCap})
			if err != nil {
				t.Fatal(err)
			}
			if message.HasContent() {
				t.Fatal("opaque image alone established inspected-text coverage")
			}
			if report := newScanner(t, "").Scan(message.ScanInput(), testCap); report["status"] != "clean" {
				t.Fatal("ordinary opaque image was not accepted")
			}
			unchanged, err := message.Rewrite(message.ScanInput())
			if err != nil || !bytes.Equal(unchanged, fixture.body) {
				t.Fatal("opaque image bytes or metadata changed")
			}
		})
	}
	for name, image := range map[string][]byte{
		"unrecognized-bytes": byteField(1, []byte("not an image")),
		"unknown-field":      byteField(99, png),
		"truncated-png":      byteField(1, png[:4]),
		"duplicate-data":     concat(byteField(1, png), byteField(1, png)),
	} {
		t.Run(name, func(t *testing.T) {
			wire := byteField(1, byteField(10, image))
			if _, err := decodeMessage("aiserver.v1.NameTabRequest", wire, policy.DecodeLimits{MaxBytes: testCap}); !errors.Is(err, ErrUnsupported) {
				t.Fatal("unsupported image bytes were accepted")
			}
		})
	}
}

func TestInlineContextOnlyStillEstablishesContentCoverage(t *testing.T) {
	for _, wire := range [][]byte{
		byteField(13, byteField(1, []byte("nearby symbol contents"))),
		byteField(19, byteField(3, []byte("visible range contents"))),
	} {
		message, err := decodeMessage("aiserver.v1.StreamCppRequest", wire, policy.DecodeLimits{MaxBytes: testCap})
		if err != nil || !message.HasContent() {
			t.Fatal("inline context was misclassified as control metadata")
		}
	}
}

func TestReviewedAuxiliaryFieldsExist(t *testing.T) {
	for name, numbers := range auxiliaryFields {
		definitions := pinned.fields[name]
		if definitions == nil {
			t.Fatalf("missing reviewed message %s", name)
		}
		seen := map[int]bool{}
		for _, number := range numbers {
			if _, ok := definitions[protowire.Number(number)]; !ok || seen[number] {
				t.Fatalf("invalid or duplicate reviewed field %s.%d", name, number)
			}
			seen[number] = true
		}
	}
}
