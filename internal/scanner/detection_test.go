package scanner

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/cquark7/withhold/internal/detector"
)

const (
	syntheticAWSID     = "AKIA4X7Q2W3K7MNDZBXP"
	syntheticAWSSecret = "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"
	syntheticDBSecret  = "H7m2Q9v4K6r1D8x5"
)

func syntheticScanner(t *testing.T) *Scanner {
	t.Helper()
	d, err := detector.New("")
	if err != nil {
		t.Fatal(err)
	}
	return New(d, func() []byte { return []byte("synthetic-detection-test-key") })
}

func scanSynthetic(t *testing.T, s *Scanner, body any, want string) Report {
	t.Helper()
	input, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	report := s.Scan(input, DefaultMaxBytes)
	if report["status"] != want {
		t.Fatalf("status = %v, want %s; reason = %v", report["status"], want, report["reason"])
	}
	return report
}

func TestDatabaseCredentialURIs(t *testing.T) {
	s := syntheticScanner(t)
	for _, scheme := range []string{"psql", "PSQL", "postgres", "postgresql"} {
		for _, suffix := range []string{"", " # gitleaks:allow", " # betterleaks:allow"} {
			t.Run(scheme+suffix, func(t *testing.T) {
				text := "DB_URI=" + scheme + "://dbuser:" + syntheticDBSecret + "@db.internal:5432/app" + suffix
				report := scanSynthetic(t, s, map[string]string{"input": text}, "redacted")
				got := rewrittenObject(t, report)["input"].(string)
				if strings.Contains(got, syntheticDBSecret) || !strings.Contains(got, "<WITHHELD_") {
					t.Error("database password was not redacted")
				}
				if !strings.Contains(got, scheme+"://dbuser:") || !strings.Contains(got, "@db.internal:5432/app"+suffix) {
					t.Error("redaction changed the surrounding URI")
				}
			})
		}
	}
	for _, text := range []string{
		"psql://dbuser@db.internal:5432/app",
		"psql://dbuser:${DB_PASSWORD}@db.internal:5432/app",
	} {
		scanSynthetic(t, s, map[string]string{"input": text}, "clean")
	}
}

func TestEncodedDatabaseCredentialURIIsRedacted(t *testing.T) {
	s := syntheticScanner(t)
	uri := "DB_URI=psql://dbuser:" + syntheticDBSecret + "@db.internal:5432/app"
	encoded := base64.StdEncoding.EncodeToString([]byte(uri))
	report := scanSynthetic(t, s, map[string]string{"input": encoded}, "redacted")
	rewritten := rewrittenObject(t, report)["input"].(string)
	decoded, err := base64.StdEncoding.DecodeString(rewritten)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(decoded), syntheticDBSecret) || !strings.Contains(string(decoded), "<WITHHELD_") {
		t.Error("encoded database password was not redacted")
	}
}

func TestAWSAccessIDAndSecretAreRedacted(t *testing.T) {
	s := syntheticScanner(t)
	cases := []struct {
		name string
		body map[string]string
	}{
		{"standalone", map[string]string{"input": syntheticAWSID}},
		{"named", map[string]string{"AWS_ACCESS_KEY_ID": syntheticAWSID}},
		{"pair in text", map[string]string{"input": "AWS_ACCESS_KEY_ID=" + syntheticAWSID + "\nAWS_SECRET_ACCESS_KEY=" + syntheticAWSSecret}},
		{"pair in fields", map[string]string{"AWS_ACCESS_KEY_ID": syntheticAWSID, "AWS_SECRET_ACCESS_KEY": syntheticAWSSecret}},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			report := scanSynthetic(t, s, test.body, "redacted")
			rewritten, err := json.Marshal(rewrittenObject(t, report))
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(rewritten), syntheticAWSID) || strings.Contains(string(rewritten), syntheticAWSSecret) {
				t.Error("AWS credential material survived the rewritten body")
			}
		})
	}
}

func TestMultipleMultipartValuesAreRedacted(t *testing.T) {
	s := syntheticScanner(t)
	second := syntheticAWSSecret[:37] + "987"
	text := "AWS_ACCESS_KEY_ID=" + syntheticAWSID + " AWS_SECRET_ACCESS_KEY=" + syntheticAWSSecret + " AWS_SECRET_ACCESS_KEY=" + second
	for _, encoded := range []bool{false, true} {
		input := text
		if encoded {
			input = base64.StdEncoding.EncodeToString([]byte(input))
		}
		report := scanSynthetic(t, s, map[string]string{"input": input}, "redacted")
		output := rewrittenObject(t, report)["input"].(string)
		if encoded {
			decoded, err := base64.StdEncoding.DecodeString(output)
			if err != nil {
				t.Fatal(err)
			}
			output = string(decoded)
		}
		for _, value := range []string{syntheticAWSID, syntheticAWSSecret, second} {
			if strings.Contains(output, value) {
				t.Error("a multipart value survived redaction")
			}
		}
	}
}

func TestMultipartCombinationLimitFailsClosed(t *testing.T) {
	s := syntheticScanner(t)
	var input strings.Builder
	input.WriteString("AWS_ACCESS_KEY_ID=" + syntheticAWSID + " ")
	for i := 0; i < 100; i++ {
		fmt.Fprintf(&input, "AWS_SECRET_ACCESS_KEY=%s%03d ", syntheticAWSSecret[:37], i)
	}
	report := scanSynthetic(t, s, map[string]string{"input": input.String()}, "scanner-error")
	if _, ok := report["body_base64"]; ok {
		t.Error("incomplete component results produced a forwarded body")
	}
	scanSynthetic(t, s, map[string]string{"input": "ordinary text"}, "clean")
	scanSynthetic(t, s, map[string]string{"input": syntheticAWSID}, "redacted")
}

func TestNonSecretComponentsAreConservativelyRedacted(t *testing.T) {
	s := syntheticScanner(t)
	const username = "service-user"
	text := "username = \"" + username + "\"\npassword = \"" + syntheticDBSecret + "\""
	report := scanSynthetic(t, s, map[string]string{"input": text}, "redacted")
	got := rewrittenObject(t, report)["input"].(string)
	if strings.Contains(got, username) || strings.Contains(got, syntheticDBSecret) {
		t.Error("a multipart value survived redaction")
	}
}
