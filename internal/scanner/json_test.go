package scanner

import "testing"

func TestDuplicateObjectKeysFailClosed(t *testing.T) {
	s := syntheticScanner(t)
	for _, test := range []struct {
		name, body string
	}{
		{"overwritten secret", `{"input":"` + syntheticAWSID + `","input":"ordinary content"}`},
		{"last value secret", `{"input":"ordinary content","input":"` + syntheticAWSID + `"}`},
		{"overwritten object", `{"payload":{"input":"` + syntheticAWSID + `"},"payload":null}`},
		{"nested object", `{"payload":{"input":"` + syntheticAWSID + `","input":"ordinary content"}}`},
		{"array element", `{"payload":[{"input":"` + syntheticAWSID + `","input":"ordinary content"}]}`},
		{"escaped key", `{"input":"` + syntheticAWSID + `","\u0069nput":"ordinary content"}`},
		{"unicode key", `{"é":"ordinary content","\u00e9":"ordinary content"}`},
		{"empty key", `{"":"ordinary content","":"ordinary content"}`},
		{"identical values", `{"input":"ordinary content","input":"ordinary content"}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			report := s.Scan([]byte(test.body), DefaultMaxBytes)
			if report["status"] != "scanner-error" || report["reason"] != "duplicate JSON object key" {
				t.Fatalf("unexpected duplicate-key report: %v", report)
			}
			if len(report) != 2 {
				t.Fatalf("duplicate-key report contains request data: %v", report)
			}
		})
	}
}

func TestKeysInSeparateObjectsAndDistinctCaseRemainValid(t *testing.T) {
	s := syntheticScanner(t)
	for _, body := range []string{
		`{"input":"ordinary content","Input":"different content"}`,
		`{"first":{"input":"ordinary content"},"second":{"input":"different content"}}`,
		`{"payload":[{"input":"ordinary content"},{"input":"different content"}]}`,
	} {
		if report := s.Scan([]byte(body), DefaultMaxBytes); report["status"] != "clean" {
			t.Fatalf("distinct object keys rejected: %v", report)
		}
	}
}
