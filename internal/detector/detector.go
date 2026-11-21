// Package detector owns offline secrets and optional PII engines per worker.
package detector

import (
	"context"
	"errors"
	"runtime/debug"
	"slices"
	"strings"

	"github.com/cquark7/withhold/internal/pii"

	"github.com/betterleaks/betterleaks/v2/config"
	"github.com/betterleaks/betterleaks/v2/report"
	"github.com/betterleaks/betterleaks/v2/scan"
	"github.com/betterleaks/betterleaks/v2/sources"
)

const betterleaksModule = "github.com/betterleaks/betterleaks/v2"

var Version = linkedVersion()

func linkedVersion() string {
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, dep := range info.Deps {
			if dep.Path == betterleaksModule {
				if dep.Replace != nil {
					dep = dep.Replace
				}
				if dep.Version != "" {
					return strings.TrimPrefix(dep.Version, "v")
				}
			}
		}
	}
	return "unknown"
}

var ErrIncompleteFinding = errors.New("detector returned an incomplete finding")

type Finding struct {
	RuleID     string
	Secret     string
	Match      string
	Start, End int
	Encoded    bool
}

// Detector is owned by a single serial worker; it is not shared between scans.
type Detector struct {
	engine, literal *scan.Scanner
	pii             *pii.Detector
	lines           lineBudget
}

func New(selection string) (*Detector, error) {
	return newDetector(true, selection, "")
}

// NewInspection can omit the secret engine for a PII-only offline scan.
// Confidence is a scan-only minimum; proxy workers use New without filtering.
func NewInspection(secrets bool, selection, confidence string) (*Detector, error) {
	minimum, err := ParseConfidence(confidence)
	if err != nil {
		return nil, err
	}
	return newDetector(secrets, selection, minimum)
}

func newDetector(secrets bool, selection, minimum string) (*Detector, error) {
	p, err := pii.New(selection)
	if err != nil {
		return nil, err
	}
	scanner := &Detector{pii: p}
	if !secrets {
		return scanner, nil
	}
	cfg, err := detectorConfig()
	if err != nil {
		return nil, err
	}
	scanner.engine, err = scan.New(cfg, append(engineOptions(minimum), scan.WithRegexEngine(&scanner.lines))...)
	if err != nil {
		return nil, errors.New("cannot initialize stock rules")
	}
	const awsID = "AKIA4X7Q2W3K7MNDZBXP"
	for _, suffix := range []string{"", " # gitleaks:allow", " # betterleaks:allow"} {
		findings, err := scanner.Scan(`token = "` + awsID + `"` + suffix)
		if err != nil || !hasFinding(findings, "aws-access-token", awsID) {
			return nil, errors.New("detector self-test failed")
		}
	}
	const awsSecret = "aB3dE5fG7hI9jK1mN3pQ5rS7tU9vW1xY3zA5BcD6"
	for _, test := range []struct {
		text string
		want []Finding
	}{
		{awsID, []Finding{{RuleID: "aws-access-token", Secret: awsID}}},
		{"AWS_ACCESS_KEY_ID=" + awsID + "\nAWS_SECRET_ACCESS_KEY=" + awsSecret, []Finding{
			{RuleID: "aws-access-token", Secret: awsID},
			{RuleID: "aws-secret-access-key", Secret: awsSecret},
		}},
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
	const dbSecret = "H7m2Q9v4K6r1D8x5"
	uri := "psql://dbuser:" + dbSecret + "@db.internal:5432/app"
	findings, err := scanner.Scan(uri)
	if err != nil || hasFinding(findings, "generic-credential-uri", dbSecret) != (minimum != "high") {
		return nil, errors.New("detector self-test failed")
	}
	if minimum == "high" {
		// Check the patched rule even when the requested minimum suppresses it.
		index := slices.IndexFunc(cfg.Rules, func(r config.Rule) bool { return r.ID == "generic-credential-uri" })
		engine, err := scan.New(&config.Config{Rules: cfg.Rules[index : index+1]}, engineOptions("")...)
		if err != nil {
			return nil, errors.New("detector self-test failed")
		}
		probe := Detector{engine: engine, pii: p}
		findings, err := probe.Scan(uri)
		if err != nil || !hasFinding(findings, "generic-credential-uri", dbSecret) {
			return nil, errors.New("detector self-test failed")
		}
	}
	return scanner, nil
}

func engineOptions(minimum string) []scan.Option {
	return []scan.Option{scan.WithAllowSignatures(), scan.WithMaxDecodeDepth(5),
		scan.WithWorkers(1), scan.WithMinimumConfidence(minimum)}
}

func detectorConfig() (*config.Config, error) {
	cfg, err := config.Default()
	if err != nil {
		return nil, errors.New("cannot load stock rules")
	}
	aws := slices.IndexFunc(cfg.Rules, func(r config.Rule) bool { return r.ID == "aws-access-token" })
	if aws < 0 || len(cfg.Rules[aws].Components) != 1 ||
		cfg.Rules[aws].Components[0].RuleID != "aws-secret-access-key" || !cfg.Rules[aws].Components[0].Optional {
		return nil, errors.New("cannot configure AWS detection")
	}
	uri := slices.IndexFunc(cfg.Rules, func(r config.Rule) bool { return r.ID == "generic-credential-uri" })
	const postgres = "postgres(?:ql)?|"
	if uri < 0 || strings.Count(cfg.Rules[uri].Regex, postgres) != 1 {
		return nil, errors.New("cannot configure database URI detection")
	}
	rule := &cfg.Rules[uri]
	rule.Regex = strings.Replace(rule.Regex, postgres, postgres+"psql|", 1)
	rule.Keywords = append(rule.Keywords, "psql://")
	return cfg, nil
}

func hasFinding(findings []Finding, rule, secret string) bool {
	for _, finding := range findings {
		if finding.Secret == secret && finding.RuleID == rule {
			return true
		}
	}
	return false
}

type textSource string

func (s textSource) Fragments(ctx context.Context, yield sources.FragmentsFunc) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return yield(sources.Fragment{Raw: string(s), StartLine: 1}, nil)
}

func (d *Detector) MinimumUnit() int {
	if d.pii.Enabled() {
		return 2
	}
	return 8
}

func (d *Detector) PII() *pii.Metadata { return d.pii.Metadata() }

func (d *Detector) Scan(text string) ([]Finding, error) {
	return d.scan(text, d.engine)
}

// ScanLiteral checks the original spelling of whole-leaf Base64 that the caller
// already decoded for a separate scan.
func (d *Detector) ScanLiteral(text string) ([]Finding, error) {
	if d.engine != nil && d.literal == nil {
		cfg, err := detectorConfig()
		if err != nil {
			return nil, err
		}
		d.literal, err = scan.New(cfg, append(engineOptions(""), scan.WithMaxDecodeDepth(0), scan.WithRegexEngine(&d.lines))...)
		if err != nil {
			return nil, err
		}
	}
	return d.scan(text, d.literal)
}

func (d *Detector) scan(text string, engine *scan.Scanner) ([]Finding, error) {
	findings := make([]Finding, 0)
	seen := make(map[Finding]struct{})
	var index *sourceIndex
	add := func(rule string, match report.Match, location report.Location, encoded bool) error {
		start, end, err := offsets(&index, text, location, match.Full, encoded)
		if err != nil {
			return ErrIncompleteFinding
		}
		f := Finding{RuleID: rule, Secret: match.Value, Match: match.Full, Start: start, End: end, Encoded: encoded}
		if _, ok := seen[f]; !ok {
			seen[f] = struct{}{}
			findings = append(findings, f)
		}
		return nil
	}
	if engine != nil {
		err := d.scanText(context.Background(), engine, text, func(f report.Finding) error {
			if f.ComponentSetsTruncated {
				return ErrIncompleteFinding
			}
			return visitFinding(f, add)
		})
		if err != nil {
			return nil, err
		}
	}
	for _, f := range d.pii.Scan(text) {
		findings = append(findings, Finding{RuleID: f.RuleID, Secret: f.Secret, Match: f.Match, Start: f.Start, End: f.End})
	}
	return findings, nil
}

func visitFinding(f report.Finding, visit func(string, report.Match, report.Location, bool) error) error {
	if err := visit(f.RuleID, f.Match, f.Location, f.DecodeDepth > 0 || len(f.Encodings) != 0); err != nil {
		return err
	}
	for _, set := range f.ComponentSets {
		for _, component := range set.Components {
			encoded := component.DecodeDepth > 0 || len(component.Encodings) != 0
			if err := visit(component.RuleID, component.Match, component.Location, encoded); err != nil {
				return err
			}
		}
	}
	return nil
}
