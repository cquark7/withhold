// Package detector owns offline secrets and optional PII engines per worker.
package detector

import (
	"context"
	"errors"
	"strings"

	"github.com/cquark7/withhold/internal/pii"

	"github.com/betterleaks/betterleaks/config"
	"github.com/betterleaks/betterleaks/detect"
	"github.com/betterleaks/betterleaks/logging"
	blregexp "github.com/betterleaks/betterleaks/regexp"
	"github.com/betterleaks/betterleaks/report"
	"github.com/betterleaks/betterleaks/sources"
	"github.com/rs/zerolog"
)

const Version = "1.10.0"

// Betterleaks 1.10.0 caps multipart combinations at 100 without reporting
// whether any were omitted. Treat the cap as incomplete rather than clean.
const maxComponentSets = 100

type Finding struct {
	RuleID string
	Secret string
	Match  string
}

// Detector is owned by a single serial worker; it is not shared between scans.
type Detector struct {
	engine *detect.Detector
	pii    *pii.Detector
}

func New(selection string) (*Detector, error) {
	return newDetector(true, selection)
}

// NewInspection can omit the secret engine for a PII-only offline scan.
// Confidence is a scan-only minimum; proxy workers use New without filtering.
func NewInspection(secrets bool, selection, confidence string) (*Detector, error) {
	minimum, err := ParseConfidence(confidence)
	if err != nil {
		return nil, err
	}
	d, err := newDetector(secrets, selection)
	if err == nil && d.engine != nil {
		// Self-tests run without filtering before the scan-only minimum applies.
		d.engine.MinConfidence = minimum
	}
	return d, err
}

func newDetector(secrets bool, selection string) (*Detector, error) {
	p, err := pii.New(selection)
	if err != nil {
		return nil, err
	}
	scanner := &Detector{pii: p}
	if !secrets {
		return scanner, nil
	}
	logging.Logger = zerolog.Nop()
	blregexp.SetEngine(blregexp.Stdlib{})
	cfg, err := detectorConfig()
	if err != nil {
		return nil, err
	}
	d := detect.NewDetectorContext(context.Background(), cfg, detect.ValidationOptions{})
	d.IgnoreGitleaksAllow = true
	d.MaxDecodeDepth = 5
	d.MaxArchiveDepth = 8
	d.SkipFindingAppend = true
	scanner.engine = d
	const canary = "AKIA4X7Q2W8K9MNDZZZZ"
	for _, suffix := range []string{"", " # gitleaks:allow", " # betterleaks:allow"} {
		findings, err := scanner.Scan(`token = "` + canary + `"` + suffix)
		if err != nil || !hasFinding(findings, "", canary) {
			return nil, errors.New("detector self-test failed")
		}
	}
	const awsID = "AKIA4X7Q2W3K7MNDZBXP"
	const awsSecret = "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"
	const dbSecret = "H7m2Q9v4K6r1D8x5"
	for _, test := range []struct {
		text string
		want []Finding
	}{
		{awsID, []Finding{{RuleID: "aws-access-token", Secret: awsID}}},
		{"AWS_ACCESS_KEY_ID=" + awsID + "\nAWS_SECRET_ACCESS_KEY=" + awsSecret, []Finding{
			{RuleID: "aws-access-token", Secret: awsID},
			{RuleID: "aws-secret-access-key", Secret: awsSecret},
		}},
		{"psql://dbuser:" + dbSecret + "@db.internal:5432/app", []Finding{{RuleID: "generic-credential-uri", Secret: dbSecret}}},
	} {
		findings, err := scanner.Scan(test.text)
		if err != nil {
			return nil, errors.New("detector self-test failed")
		}
		for _, want := range test.want {
			if !hasFinding(findings, want.RuleID, want.Secret) {
				return nil, errors.New("detector self-test failed")
			}
		}
	}
	return scanner, nil
}

func detectorConfig() (*config.Config, error) {
	cfg, err := config.Default()
	if err != nil {
		return nil, errors.New("cannot load stock rules")
	}
	aws, ok := cfg.Rules["aws-access-token"]
	if !ok || len(aws.Components) != 1 || aws.Components[0] == nil || aws.Components[0].RuleID != "aws-secret-access-key" {
		return nil, errors.New("cannot configure AWS detection")
	}
	aws.Components[0].Optional = true
	cfg.Rules[aws.RuleID] = aws

	uri, ok := cfg.Rules["generic-credential-uri"]
	if !ok || uri.Regex == nil || strings.Count(uri.Regex.String(), "postgres(?:ql)?|") != 1 {
		return nil, errors.New("cannot configure database URI detection")
	}
	pattern := strings.Replace(uri.Regex.String(), "postgres(?:ql)?|", "postgres(?:ql)?|psql|", 1)
	uri.Regex, err = blregexp.Compile(pattern)
	if err != nil || uri.Regex.Compile() != nil {
		return nil, errors.New("cannot configure database URI detection")
	}
	uri.Keywords = append(uri.Keywords, "psql://")
	cfg.Rules[uri.RuleID] = uri
	cfg.Keywords["psql://"] = struct{}{}
	cfg.KeywordToRules["psql://"] = append(cfg.KeywordToRules["psql://"], uri.RuleID)
	return cfg, nil
}

func hasFinding(findings []Finding, rule, secret string) bool {
	for _, finding := range findings {
		if finding.Secret == secret && (finding.RuleID == rule || rule == "" && !strings.HasPrefix(finding.RuleID, "pii-")) {
			return true
		}
	}
	return false
}

func appendFinding(findings []Finding, finding report.Finding) ([]Finding, error) {
	if len(finding.ComponentSets) >= maxComponentSets {
		return nil, errors.New("detector component combinations exceeded limit")
	}
	findings = append(findings, Finding{RuleID: finding.RuleID, Secret: finding.Secret, Match: finding.Match})
	seen := make(map[*report.ComponentFinding]struct{})
	for _, set := range finding.ComponentSets {
		for _, component := range set.Components {
			if component == nil {
				return nil, errors.New("detector returned an invalid component")
			}
			if _, ok := seen[component]; ok {
				continue
			}
			seen[component] = struct{}{}
			findings = append(findings, Finding{RuleID: component.RuleID, Secret: component.Secret, Match: component.Match})
		}
	}
	return findings, nil
}

func (d *Detector) MinimumUnit() int {
	if d.pii.Enabled() {
		return 2
	}
	return 8
}

func (d *Detector) PII() *pii.Metadata { return d.pii.Metadata() }

func (d *Detector) Scan(text string) ([]Finding, error) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	source := &sources.Stdin{
		Content: strings.NewReader(text), ShouldSkip: d.engine.SkipFunc(), MaxArchiveDepth: 8,
	}
	findings := make([]Finding, 0)
	failed := false
	for result := range d.engine.Run(ctx, source) {
		if failed {
			continue
		}
		if result.Err != nil {
			failed = true
			cancel()
			continue
		}
		var err error
		findings, err = appendFinding(findings, result.Finding)
		if err != nil {
			failed = true
			cancel()
		}
	}
	if failed {
		return nil, errors.New("detector failed")
	}
	for _, f := range d.pii.Scan(text) {
		findings = append(findings, Finding{RuleID: f.RuleID, Secret: f.Secret, Match: f.Match})
	}
	return findings, nil
}
