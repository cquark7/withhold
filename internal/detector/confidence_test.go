package detector

import (
	"context"
	"reflect"
	"strings"
	"testing"
)

func TestConfidenceNormalizationRejectsInvalidValuesWithoutEchoingThem(t *testing.T) {
	for input, want := range map[string]string{"": "", "low": "low", " Medium ": "medium", "HIGH": "high"} {
		got, err := ParseConfidence(input)
		if err != nil || got != want {
			t.Fatalf("ParseConfidence(%q)=%q, %v", input, got, err)
		}
	}
	if _, err := NewInspection(false, "email", "private-invalid-value"); err == nil || strings.Contains(err.Error(), "private-invalid-value") {
		t.Fatal("invalid confidence accepted or echoed")
	}
}

func TestInspectionUsesUpstreamConfidenceThresholdWithoutFilteringPII(t *testing.T) {
	const value = "Zf3D0LXCM3EIMbgJpUNnkRtOfOueHznB"
	text := "api_key = \"" + value + "\"\nservice_token = \"" + value + "\"\nAKIA4X7Q2W3K7MNDZBXP\ndev@example.com\n"
	for _, test := range []struct {
		confidence string
		want       []string
	}{
		{"", []string{"generic-api-key", "generic-api-key", "aws-access-token", "pii-email"}},
		{"low", []string{"generic-api-key", "generic-api-key", "aws-access-token", "pii-email"}},
		{"medium", []string{"generic-api-key", "aws-access-token", "pii-email"}},
		{"high", []string{"aws-access-token", "pii-email"}},
	} {
		t.Run(test.confidence, func(t *testing.T) {
			d, err := NewInspection(true, "email", test.confidence)
			if err != nil {
				t.Fatal(err)
			}
			if d.engine.MinConfidence != test.confidence {
				t.Fatal("confidence was not passed to Betterleaks")
			}
			findings, err := d.Inspect(context.Background(), text)
			if err != nil {
				t.Fatal(err)
			}
			var rules []string
			for _, finding := range findings {
				rules = append(rules, finding.RuleID)
			}
			if !reflect.DeepEqual(rules, test.want) {
				t.Fatalf("rules=%v, want %v", rules, test.want)
			}
		})
	}
	d, err := NewInspection(false, "email", "high")
	if err != nil || d.engine != nil {
		t.Fatalf("PII-only confidence initialized secrets: %v", err)
	}
	findings, err := d.Inspect(context.Background(), text)
	if err != nil || len(findings) != 1 || findings[0].RuleID != "pii-email" {
		t.Fatalf("PII-only confidence changed detection: %v, %v", findings, err)
	}
}

func TestInspectionKeepsUnclassifiedFindingsAndMultipartComponents(t *testing.T) {
	d, err := NewInspection(true, "off", "high")
	if err != nil {
		t.Fatal(err)
	}
	// A high-confidence primary retains its medium-confidence component, as
	// Betterleaks reports them together rather than independently filtering it.
	text := "AWS_ACCESS_KEY_ID=AKIA4X7Q2W3K7MNDZBXP\nAWS_SECRET_ACCESS_KEY=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"
	findings, err := d.Inspect(context.Background(), text)
	if err != nil || len(findings) != 2 {
		t.Fatalf("multipart findings lost: %v, %v", findings, err)
	}
	for _, confidence := range []string{"", "custom"} {
		rule := d.engine.Config.Rules["aws-access-token"]
		rule.Confidence = confidence
		d.engine.Config.Rules[rule.RuleID] = rule
		findings, err := d.Inspect(context.Background(), "AKIA4X7Q2W3K7MNDZBXP")
		if err != nil || len(findings) != 1 {
			t.Fatalf("unclassified finding removed: %v, %v", findings, err)
		}
	}
}

func TestInspectionConfidenceDoesNotChangeProxyDefaults(t *testing.T) {
	if _, err := NewInspection(true, "off", "high"); err != nil {
		t.Fatal(err)
	}
	proxy, err := New("off")
	if err != nil || proxy.engine.MinConfidence != "" {
		t.Fatalf("offline minimum changed proxy defaults: %v", err)
	}
	findings, err := proxy.Scan(`api_key = "Zf3D0LXCM3EIMbgJpUNnkRtOfOueHznB"`)
	if err != nil || len(findings) != 1 || findings[0].RuleID != "generic-api-key" {
		t.Fatalf("proxy lost low-confidence findings: %v, %v", findings, err)
	}
}
