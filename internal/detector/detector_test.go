package detector

import (
	"testing"

	"github.com/betterleaks/betterleaks/report"
)

func TestAppendFindingRetainsDistinctComponents(t *testing.T) {
	first := &report.ComponentFinding{RuleID: "first", Secret: "first-value", Match: "first-match"}
	second := &report.ComponentFinding{RuleID: "second", Secret: "second-value", Match: "second-match"}
	input := report.Finding{
		RuleID: "primary", Secret: "primary-value", Match: "primary-match",
		ComponentSets: []report.ComponentSet{
			{Components: []*report.ComponentFinding{first, second}},
			{Components: []*report.ComponentFinding{first, second}},
		},
	}
	findings, err := appendFinding(nil, input)
	if err != nil {
		t.Fatal(err)
	}
	want := []Finding{
		{RuleID: "primary", Secret: "primary-value", Match: "primary-match"},
		{RuleID: "first", Secret: "first-value", Match: "first-match"},
		{RuleID: "second", Secret: "second-value", Match: "second-match"},
	}
	if len(findings) != len(want) {
		t.Fatalf("got %d findings, want %d", len(findings), len(want))
	}
	for i := range want {
		if findings[i] != want[i] {
			t.Errorf("finding %d was not preserved", i)
		}
	}
}

func TestAppendFindingRejectsIncompleteComponents(t *testing.T) {
	component := &report.ComponentFinding{RuleID: "component", Secret: "value"}
	belowLimit := report.Finding{ComponentSets: make([]report.ComponentSet, maxComponentSets-1)}
	for i := range belowLimit.ComponentSets {
		belowLimit.ComponentSets[i].Components = []*report.ComponentFinding{component}
	}
	if _, err := appendFinding(nil, belowLimit); err != nil {
		t.Fatal(err)
	}
	atLimit := report.Finding{ComponentSets: make([]report.ComponentSet, maxComponentSets)}
	if _, err := appendFinding(nil, atLimit); err == nil {
		t.Error("accepted component sets that may have been truncated")
	}
	invalid := report.Finding{ComponentSets: []report.ComponentSet{{Components: []*report.ComponentFinding{nil}}}}
	if _, err := appendFinding(nil, invalid); err == nil {
		t.Error("accepted a missing component")
	}
}
