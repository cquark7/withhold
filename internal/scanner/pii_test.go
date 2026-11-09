package scanner

import (
	"encoding/base64"
	"encoding/json"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/cquark7/withhold/internal/detector"
)

func scanPII(t *testing.T, selection string, body any, status string) Report {
	t.Helper()
	d, err := detector.New(selection)
	if err != nil {
		t.Fatal(err)
	}
	input, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	s := New(d, func() []byte { return []byte("isolated-scanner-test-only") })
	report := s.Scan(input, DefaultMaxBytes)
	if report["status"] != status {
		t.Fatalf("status = %v, want %s; reason = %v", report["status"], status, report["reason"])
	}
	return report
}

func rewrittenObject(t *testing.T, report Report) map[string]any {
	t.Helper()
	body, err := base64.StdEncoding.DecodeString(report["body_base64"].(string))
	if err != nil {
		t.Fatal(err)
	}
	var object map[string]any
	if err := json.Unmarshal(body, &object); err != nil {
		t.Fatal(err)
	}
	return object
}

func TestPIIRedactsAllCategoriesAndSecretsWithoutPublicValues(t *testing.T) {
	const secret = "sk_live_4eC39HqLyjWDarjtT1zdp7dc"
	values := []string{"2341 2341 2346", "4111111111111111", "dev@example.com", "192.0.2.42", "+1 (202) 555-0198", "219-09-9999", secret}
	report := scanPII(t, "all", map[string]string{"input": strings.Join(values, "; ")}, "redacted")
	rules := report["rule_ids"].([]string)
	for _, category := range []string{"aadhaar", "credit-card", "email", "ip-address", "phone", "us-ssn"} {
		if !slices.Contains(rules, "pii-"+category) {
			t.Errorf("missing rule for %s", category)
		}
	}
	if !slices.ContainsFunc(rules, func(rule string) bool { return !strings.HasPrefix(rule, "pii-") }) {
		t.Error("PII selection disabled secret detection")
	}
	text := rewrittenObject(t, report)["input"].(string)
	if strings.Count(text, "<WITHHELD_") < len(values) {
		t.Error("missing redaction placeholders")
	}
	metadata := Report{}
	for key, value := range report {
		if key != "body_base64" {
			metadata[key] = value
		}
	}
	public, err := json.Marshal(metadata)
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range values {
		if strings.Contains(text, value) || strings.Contains(string(public), value) {
			t.Error("detected value survived rewriting or entered public metadata")
		}
	}
}

func TestPIIRedactsShortKeysBase64AndChunkBoundaries(t *testing.T) {
	const email, aadhaar = "a@b.c", "234123412346"
	encoded := base64.StdEncoding.EncodeToString([]byte("aadhaar: " + aadhaar))
	// Cross a window boundary and exceed the large-leaf threshold.
	text := strings.Repeat("x", chunkSize-6) + " " + aadhaar + " " + strings.Repeat("tail ", chunkSize/5)
	report := scanPII(t, "aadhaar,email", map[string]any{
		email: email, "blob": encoded, "nested": []any{map[string]string{"input": text}},
	}, "redacted")
	stats := report["stats"].(map[string]int)
	if stats["chunked_large"] != 1 || stats["b64_roundtrip"] != 1 {
		t.Fatal("chunked text and short base64 did not use their rewrite paths")
	}
	rewritten := rewrittenObject(t, report)
	placeholder := regexp.MustCompile(`^<WITHHELD_[0-9a-f]{16}>$`)
	for key, value := range rewritten {
		if key == "blob" || key == "nested" {
			continue
		}
		if !placeholder.MatchString(key) || value != key {
			t.Error("short email key and value did not receive the same placeholder")
		}
	}
	if len(rewritten) != 3 {
		t.Fatal("rewriting changed the number of fields")
	}
	decoded, err := base64.StdEncoding.DecodeString(rewritten["blob"].(string))
	if err != nil {
		t.Fatal(err)
	}
	aadhaarPlaceholder := strings.TrimPrefix(string(decoded), "aadhaar: ")
	if !placeholder.MatchString(aadhaarPlaceholder) {
		t.Fatal("short base64 payload was not fully redacted")
	}
	nested := rewritten["nested"].([]any)[0].(map[string]any)["input"]
	if nested != strings.ReplaceAll(text, aadhaar, aadhaarPlaceholder) {
		t.Error("chunk-boundary rewrite lost text or left PII behind")
	}
}

func TestPIISelectionAndChecksumControlWholeRequestScanning(t *testing.T) {
	for _, test := range []struct {
		name, selection, input, status string
	}{
		{"invalid checksum", "aadhaar", "aadhaar: 234123412347; dev@example.com", "clean"},
		{"disabled", "off", "aadhaar: 234123412346; dev@example.com", "clean"},
		{"selected only", "aadhaar", "aadhaar: 234123412346; dev@example.com", "redacted"},
	} {
		t.Run(test.name, func(t *testing.T) {
			report := scanPII(t, test.selection, map[string]string{"input": test.input}, test.status)
			if test.status == "clean" {
				if _, ok := report["body_base64"]; ok {
					t.Fatal("clean request was rewritten")
				}
				return
			}
			text := rewrittenObject(t, report)["input"].(string)
			if strings.Contains(text, "234123412346") || !strings.Contains(text, "dev@example.com") {
				t.Error("selected PII was retained or an unselected category was changed")
			}
			if !reflect.DeepEqual(report["rule_ids"], []string{"pii-aadhaar"}) {
				t.Error("unexpected category in scanner report")
			}
		})
	}
}
