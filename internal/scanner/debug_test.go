package scanner

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/cquark7/withhold/internal/detector"
)

func TestDebugFindingIsOptInAndMatchesWrittenPlaceholder(t *testing.T) {
	const secret = "AKIA4X7Q2W8K9MNDZZZZ"
	d, err := detector.New("email")
	if err != nil {
		t.Fatal(err)
	}
	loadKey := func() []byte { return []byte("isolated-debug-test-key") }
	body := []byte(`{"text":"token = ` + secret + ` and dev@example.com"}`)

	for _, debug := range []bool{false, true} {
		report := NewWithDebug(d, loadKey, debug).Scan(body, DefaultMaxBytes)
		if report["status"] != "redacted" {
			t.Fatalf("status = %v", report["status"])
		}
		rows, ok := report["debug_findings"]
		if !debug {
			if ok {
				t.Fatalf("default scan exposed sensitive debug data: %v", rows)
			}
			continue
		}
		findings, ok := rows.([]DebugFinding)
		if !ok || len(findings) != 2 {
			t.Fatalf("debug findings = %#v", rows)
		}
		encoded, ok := report["body_base64"].(string)
		if !ok {
			t.Fatalf("redacted report body missing: %v", report)
		}
		output, err := base64.StdEncoding.Strict().DecodeString(encoded)
		if err != nil {
			t.Fatal(err)
		}
		masks := map[string]bool{"AKI…": true, "dev…": true}
		for _, finding := range findings {
			if finding.DetectedMasked == "" || finding.Placeholder == "" || !bytes.Contains(output, []byte(finding.Placeholder)) {
				t.Fatalf("debug finding does not describe rewritten body: %+v; %s", finding, output)
			}
			if !masks[finding.DetectedMasked] {
				t.Fatalf("unexpected detected mask %q", finding.DetectedMasked)
			}
			delete(masks, finding.DetectedMasked)
		}
		if len(masks) != 0 {
			t.Fatalf("missing expected masks: %v", masks)
		}
		encodedReport, err := json.Marshal(report)
		if err != nil {
			t.Fatal(err)
		}
		for _, value := range []string{secret, "dev@example.com"} {
			if bytes.Contains(encodedReport, []byte(value)) {
				t.Fatalf("full detected value entered debug report: %s", value)
			}
		}
	}
}

func TestMaskDetectedAlwaysHidesAtLeastOneCharacter(t *testing.T) {
	for _, test := range []struct{ value, want string }{
		{"", "***"},
		{"x", "***"},
		{"ab", "***"},
		{"abc", "***"},
		{"abcd", "abc…"},
		{"秘密秘密", "秘密秘…"},
	} {
		if got := maskDetected(test.value); got != test.want {
			t.Errorf("maskDetected(%q) = %q, want %q", test.value, got, test.want)
		}
		if !ValidDebugMask(test.want) {
			t.Errorf("ValidDebugMask(%q) = false", test.want)
		}
	}
	for _, value := range []string{"secret", "abc", "unmasked-too-long", "ab…"} {
		if ValidDebugMask(value) {
			t.Errorf("accepted invalid debug mask %q", value)
		}
	}
}
