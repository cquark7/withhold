package scanpool

import (
	"encoding/json"
	"testing"

	"github.com/cquark7/withhold/internal/detector"
	"github.com/cquark7/withhold/internal/worker"
)

func TestInspectionRejectsIncompatibleMetadataAndUnsafeFindings(t *testing.T) {
	p := NewInspection("unused", nil, false, "email")
	defer p.Close()
	hello := worker.TextGreeting{Schema: 1, Engine: "withhold-text-scanner", PII: p.pii}
	data, _ := json.Marshal(hello)
	if !p.validGreeting(data) {
		t.Fatal("valid PII-only metadata rejected")
	}
	hello.Secrets = true
	data, _ = json.Marshal(hello)
	if p.validGreeting(data) || decodeText([]byte(`{"schema":1,"findings":[],"secret":"private"}`), new(worker.TextResponse)) == nil {
		t.Fatal("incompatible or secret-bearing protocol accepted")
	}
	f := detector.TextFinding{RuleID: "pii-email", Kind: "pii", Start: 1, End: 4, StartLine: 1, EndLine: 1, StartColumn: 2, EndColumn: 5}
	if !p.validTextFinding(f, 8) {
		t.Fatal("valid location rejected")
	}
	for _, bad := range []detector.TextFinding{
		{RuleID: "pii-phone", Kind: "pii", Start: 1, End: 4, StartLine: 1, EndLine: 1, StartColumn: 2, EndColumn: 5},
		{RuleID: "pii-email", Kind: "pii", Start: 1, End: 9, StartLine: 1, EndLine: 1, StartColumn: 2, EndColumn: 10},
		{RuleID: "aws-access-token", Kind: "secret", Start: 1, End: 4, StartLine: 1, EndLine: 1, StartColumn: 2, EndColumn: 5},
	} {
		if p.validTextFinding(bad, 8) {
			t.Fatal("invalid or unselected finding accepted")
		}
	}
}
