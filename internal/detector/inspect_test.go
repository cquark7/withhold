package detector

import (
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
)

func TestInspectionPreservesOccurrencesAndByteLocations(t *testing.T) {
	const token = "AKIA4X7Q2W3K7MNDZBXP"
	const prefix = "heading\r\n用户 🚀 "
	text := prefix + token + " dev@example.com " + token + "\r\n"
	for _, test := range []struct {
		name    string
		secrets bool
		pii     string
		count   int
	}{
		{"secrets", true, "off", 2},
		{"pii", false, "email", 1},
		{"both", true, "email", 3},
	} {
		t.Run(test.name, func(t *testing.T) {
			d, err := NewInspection(test.secrets, test.pii, "")
			if err != nil {
				t.Fatal(err)
			}
			if !test.secrets && d.engine != nil {
				t.Fatal("PII-only scan initialized the secret engine")
			}
			findings, err := d.Inspect(context.Background(), text)
			if err != nil || len(findings) != test.count {
				t.Fatalf("findings=%v error=%v", findings, err)
			}
			for _, f := range findings {
				value := text[f.Start:f.End]
				if f.StartLine != 2 || f.EndLine != 2 || f.StartColumn != f.Start-len("heading\r\n")+1 || f.EndColumn != f.End-len("heading\r\n")+1 || f.Encoded {
					t.Fatalf("incorrect original location: %+v", f)
				}
				if f.RuleID == "aws-access-token" && value != token || f.RuleID == "pii-email" && value != "dev@example.com" {
					t.Fatal("span does not cover the original match")
				}
			}
		})
	}
}

func TestInspectionReportsEncodedSourceAndDistinctMultipartComponents(t *testing.T) {
	d, err := NewInspection(true, "off", "")
	if err != nil {
		t.Fatal(err)
	}
	const token = "AKIA4X7Q2W3K7MNDZBXP"
	const secret = "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"
	encoded := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("padding ", 8) + token))
	findings, err := d.Inspect(context.Background(), "encoded="+encoded)
	if err != nil || len(findings) != 1 || !findings[0].Encoded || findings[0].Start < len("encoded=") || findings[0].End > len("encoded=")+len(encoded) {
		t.Fatalf("encoded source location: %v, %v", findings, err)
	}
	text := "AWS_ACCESS_KEY_ID=" + token + "\nAWS_SECRET_ACCESS_KEY=" + secret
	findings, err = d.Inspect(context.Background(), text)
	if err != nil || len(findings) != 2 {
		t.Fatalf("multipart findings: %v, %v", findings, err)
	}
	if findings[0].RuleID != "aws-access-token" || findings[0].StartLine != 1 || findings[1].RuleID != "aws-secret-access-key" || findings[1].StartLine != 2 {
		t.Fatal("multipart locations were not preserved")
	}
}

func TestInspectionRejectsTruncatedFindings(t *testing.T) {
	for _, secrets := range []bool{false, true} {
		d, err := NewInspection(secrets, "email", "")
		if err != nil {
			t.Fatal(err)
		}
		value := "dev@example.com"
		if secrets {
			value = "AKIA4X7Q2W3K7MNDZBXP"
		}
		if _, err := d.Inspect(context.Background(), strings.Repeat(value+"\n", MaxTextFindings+1)); !errors.Is(err, ErrFindingLimit) {
			t.Fatalf("expected finding limit, got %v", err)
		}
		if hits, err := d.Inspect(context.Background(), "ordinary text"); err != nil || len(hits) != 0 {
			t.Fatalf("failed scan prevented clean engine reuse: %v", err)
		}
	}
}

func TestSourceLocationsAcrossCheckpointsAndLongLines(t *testing.T) {
	text := "用户\r\n" + strings.Repeat("x", sourceBlock*2) + strings.Repeat("\n", sourceBlock) + "end\n"
	index := indexSource(text)
	for _, offset := range []int{0, 1, sourceBlock - 1, sourceBlock, sourceBlock + 1, len(text) - 1, len(text)} {
		prefix := text[:offset]
		line, column := index.position(offset)
		if line != strings.Count(prefix, "\n")+1 || column != offset-strings.LastIndexByte(prefix, '\n') {
			t.Fatalf("incorrect position for byte %d: %d:%d", offset, line, column)
		}
		if actual, err := index.offset(line, column); err != nil || actual != offset {
			t.Fatalf("location roundtrip for %d: %d, %v", offset, actual, err)
		}
	}
}

func BenchmarkInspectText(b *testing.B) {
	d, err := NewInspection(true, "off", "")
	if err != nil {
		b.Fatal(err)
	}
	for _, test := range []struct{ name, text string }{
		{"small", "ordinary application configuration\n"},
		{"source", strings.Repeat("export const greeting = 'hello world';\n", 1024)},
	} {
		b.Run(test.name, func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(len(test.text)))
			for b.Loop() {
				findings, err := d.Inspect(context.Background(), test.text)
				if err != nil || len(findings) != 0 {
					b.Fatalf("findings=%v error=%v", findings, err)
				}
			}
		})
	}
}
