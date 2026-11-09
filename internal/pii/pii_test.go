package pii

import (
	"reflect"
	"testing"
)

func TestSelectionAndDisabledConfiguration(t *testing.T) {
	for _, value := range []string{"", " off ", "OFF"} {
		d, err := New(value)
		if err != nil || d.Enabled() || d.Metadata() != nil || len(d.Scan("dev@example.com")) != 0 {
			t.Fatal("disabled configuration enabled PII")
		}
	}
	got, err := Selection(" EMAIL, aadhaar,email ")
	if err != nil || !reflect.DeepEqual(got, []string{"aadhaar", "email"}) {
		t.Fatal("category selection is not canonical")
	}
	for _, value := range []string{"emails", "email,", "all,email", "off,email", ",", "PRIVATE_INVALID_VALUE"} {
		if _, err := Selection(value); err == nil {
			t.Fatal("invalid configuration accepted")
		}
	}
}

func TestSelectedRecognizersReturnCompletePrivateValues(t *testing.T) {
	// Public synthetic examples are used to check span-to-finding adaptation.
	for _, c := range categories {
		t.Run(c.name, func(t *testing.T) {
			d, err := New(c.name)
			if err != nil {
				t.Fatal(err)
			}
			findings := d.Scan("用户 🚀 value: " + c.canary + " end")
			if len(findings) != 1 || findings[0] != (Finding{"pii-" + c.name, c.canary, c.canary}) {
				t.Fatal("expected complete value and category-specific rule")
			}
			if c.name != "email" && len(d.Scan("dev@example.com")) != 0 {
				t.Fatal("unselected category produced findings")
			}
		})
	}
}

func TestAadhaarFormatsAndChecksums(t *testing.T) {
	d, err := New("aadhaar")
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{"234123412346", "2341 2341 2346", "2341\u00a02341\u00a02346"} {
		hits := d.Scan("aadhaar: " + value)
		if len(hits) != 1 || hits[0].Secret != value {
			t.Fatal("valid synthetic Aadhaar format was not fully found")
		}
	}
	for _, value := range []string{"234123412347", "2341 2341 2347", "23412341234", "1234123412346"} {
		if len(d.Scan("aadhaar: "+value)) != 0 {
			t.Fatal("invalid checksum or digit count produced an Aadhaar finding")
		}
	}
}

func TestShortValuesAndAllSelection(t *testing.T) {
	d, err := New("all")
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Metadata().Categories) != 6 {
		t.Fatal("all must include Aadhaar and the other five types")
	}
	for _, value := range []string{"a@b.c", "1.1.1.1"} {
		hits := d.Scan(value)
		if len(hits) != 1 || hits[0].Secret != value {
			t.Fatal("short PII was not found")
		}
	}
}
