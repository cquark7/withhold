// Package pii adapts pinned Alcatraz recognizers to the guard's private findings.
package pii

import (
	"errors"
	"strings"

	"github.com/hoophq/alcatraz/analyzer"
	"github.com/hoophq/alcatraz/entities"
	"github.com/hoophq/alcatraz/recognizers"
)

const Version = "0.23.0"

type Metadata struct {
	Engine     string   `json:"engine"`
	Version    string   `json:"version"`
	Categories []string `json:"categories"`
}

type category struct {
	name, entity string
	recognizer   func() analyzer.Recognizer
	canary       string
}

// Canary values are public synthetic examples; none requires an online check.
var categories = []category{
	{"aadhaar", entities.INAadhaar, recognizers.INAadhaar, "2341 2341 2346"},
	{"credit-card", entities.CreditCard, recognizers.CreditCard, "4111111111111111"},
	{"email", entities.EmailAddress, recognizers.Email, "dev@example.com"},
	{"ip-address", entities.IPAddress, recognizers.IP, "192.0.2.42"},
	{"phone", entities.PhoneNumber, recognizers.Phone, "+1 (202) 555-0198"},
	{"us-ssn", entities.USSSN, recognizers.USSSN, "219-09-9999"},
}

// Selection validates names and returns a stable order for worker negotiation.
// An explicit typo must never silently disable a protection category.
func Selection(value string) ([]string, error) {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" || value == "off" {
		return nil, nil
	}
	selected := map[string]bool{}
	for _, name := range strings.Split(value, ",") {
		selected[strings.TrimSpace(name)] = true
	}
	var result []string
	for _, c := range categories {
		if selected[c.name] || value == "all" {
			result = append(result, c.name)
		}
		delete(selected, c.name)
	}
	if value != "all" && len(selected) != 0 {
		return nil, errors.New("invalid PII selection; use all, off, or aadhaar,credit-card,email,ip-address,phone,us-ssn")
	}
	return result, nil
}

func ConfigurationFor(value string) (*Metadata, error) {
	selected, err := Selection(value)
	if err != nil || len(selected) == 0 {
		return nil, err
	}
	return &Metadata{Engine: "alcatraz", Version: Version, Categories: selected}, nil
}

type Finding struct{ RuleID, Secret, Match string }

type Detector struct {
	engine *analyzer.Engine
	meta   *Metadata
	rules  map[string]string
}

func New(selection string) (*Detector, error) {
	meta, err := ConfigurationFor(selection)
	if err != nil {
		return nil, err
	}
	d := &Detector{meta: meta}
	if meta == nil {
		return d, nil
	}
	registry := analyzer.NewRegistry("en")
	d.rules = make(map[string]string)
	for _, c := range categories {
		for _, name := range meta.Categories {
			if name == c.name {
				registry.Add("en", c.recognizer())
				d.rules[c.entity] = "pii-" + c.name
			}
		}
	}
	d.engine = analyzer.NewEngine(registry, []string{"en"})
	// Every enabled type must return its complete known canary before greeting.
	for _, c := range categories {
		if d.rules[c.entity] == "" {
			continue
		}
		found := false
		for _, hit := range d.engine.Analyze(c.canary, analyzer.Options{}) {
			if hit.EntityType == c.entity && hit.Text == c.canary {
				found = true
			}
		}
		if !found {
			return nil, errors.New("PII detector self-test failed")
		}
	}
	return d, nil
}

func (d *Detector) Metadata() *Metadata { return d.meta }
func (d *Detector) Enabled() bool       { return d.engine != nil }

// Scan reuses compiled upstream recognizers. Scores remain at upstream defaults;
// scan deadlines and process reclamation are enforced by the existing worker pool.
func (d *Detector) Scan(text string) []Finding {
	if !d.Enabled() {
		return nil
	}
	results := d.engine.Analyze(text, analyzer.Options{})
	findings := make([]Finding, 0, len(results))
	for _, hit := range results {
		findings = append(findings, Finding{d.rules[hit.EntityType], hit.Text, hit.Text})
	}
	return findings
}
