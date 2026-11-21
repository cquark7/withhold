// Package scanner extracts, detects, rewrites, and verifies request bodies.
package scanner

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/cquark7/withhold/internal/detector"
)

const DefaultMaxBytes = 32 * 1024 * 1024
const maxScanBytes = 128 * 1024 * 1024

type Report map[string]any

// DebugFinding contains a masked prefix and placeholder for an explicitly
// enabled local debug session; it never contains the full detected value.
type DebugFinding struct {
	DetectedMasked string   `json:"detected_masked"`
	Placeholder    string   `json:"placeholder"`
	RuleIDs        []string `json:"rule_ids"`
}

func maskDetected(value string) string {
	runes := []rune(value)
	if len(runes) <= 3 {
		return "***"
	}
	return string(runes[:3]) + "…"
}

// ValidDebugMask ensures a worker report contains only the documented masked
// representation, not an unmasked or overlong detected value.
func ValidDebugMask(value string) bool {
	return value == "***" || utf8.RuneCountInString(value) == 4 && strings.HasSuffix(value, "…")
}

type Scanner struct {
	detector *detector.Detector
	hmacKey  []byte
	loadKey  func() []byte
	debug    bool
}

func New(d *detector.Detector, loadKey func() []byte) *Scanner {
	return NewWithDebug(d, loadKey, false)
}

func NewWithDebug(d *detector.Detector, loadKey func() []byte, debug bool) *Scanner {
	return &Scanner{detector: d, loadKey: loadKey, debug: debug}
}

func (s *Scanner) key() []byte {
	if len(s.hmacKey) != 0 {
		return s.hmacKey
	}
	s.hmacKey = append([]byte(nil), s.loadKey()...)
	if len(s.hmacKey) == 0 {
		panic("cannot initialize placeholder key")
	}
	return s.hmacKey
}

type replacements struct {
	ordered []string
	mapping map[string]string
	once    *strings.Replacer
}

func (s *Scanner) replacements(values []string) replacements {
	r := replacements{mapping: make(map[string]string)}
	for _, value := range values {
		if value == "" || r.mapping[value] != "" {
			continue
		}
		mac := hmac.New(sha256.New, s.key())
		_, _ = mac.Write([]byte(value))
		r.mapping[value] = "<WITHHELD_" + hex.EncodeToString(mac.Sum(nil))[:16] + ">"
		r.ordered = append(r.ordered, value)
	}
	sort.SliceStable(r.ordered, func(i, j int) bool {
		return len(r.ordered[i]) > len(r.ordered[j])
	})
	pairs := make([]string, 0, len(r.ordered)*2)
	for _, value := range r.ordered {
		pairs = append(pairs, value, r.mapping[value])
	}
	r.once = strings.NewReplacer(pairs...)
	return r
}

func writeKeys(n *node, r replacements) string {
	index := make(map[string]int, len(n.members))
	for i := range n.members {
		key := r.once.Replace(n.members[i].key)
		if _, exists := index[key]; exists {
			return "key rename would collide"
		}
		n.members[i].key = key
		index[key] = i
	}
	n.index = index
	return ""
}

func writeBase64(target *node, text string, r replacements) {
	redacted := r.once.Replace(text)
	if redacted == text {
		if !strings.HasPrefix(target.text, "data:") {
			target.text = r.once.Replace(target.text)
		}
		return
	}
	encoded := target.text
	var prefix string
	if strings.HasPrefix(encoded, "data:") {
		head, payload, _ := strings.Cut(encoded, ",")
		prefix, encoded = head+",", payload
	}
	encoding := base64.RawStdEncoding
	if strings.ContainsAny(encoded, "-_") {
		encoding = base64.RawURLEncoding
	}
	if strings.Contains(encoded, "=") {
		encoding = encoding.WithPadding(base64.StdPadding)
	}
	target.text = prefix + encoding.EncodeToString([]byte(redacted))
}

// Only direct matches in a scan unit can be verified against the emitted
// plaintext or the decoded bytes of a whole-leaf Base64 rewrite. A match inside
// another encoding needs an encoder for that occurrence, even if the same
// value also appeared elsewhere as plaintext.
func attributableValue(units []unit, text string, f detector.Finding, value string) (string, bool) {
	if f.Encoded || f.Start < 0 || f.End > len(text) || f.Start >= f.End {
		return "", false
	}
	first := sort.Search(len(units), func(i int) bool {
		return units[i].start+len(units[i].text) > f.Start
	})
	match := func(start, end int, quoted bool) (string, bool) {
		from, to := max(start, f.Start), min(end, f.End)
		if from >= to {
			return "", false
		}
		if !quoted {
			return value, strings.Contains(text[from:to], value)
		}
		// Check that the capture begins and ends on JSON escape boundaries.
		offset := strings.Index(text[from:to], value)
		if offset < 0 {
			return "", false
		}
		from += offset
		if !json.Valid([]byte(`"` + text[start:from] + `"`)) {
			return "", false
		}
		var decoded string
		quotedValue := `"` + value + `"`
		err := json.Unmarshal([]byte(quotedValue), &decoded)
		return decoded, err == nil && string(appendString(nil, decoded)) == quotedValue
	}
	for _, u := range units[first:] {
		if u.start >= f.End {
			break
		}
		quoted := u.kind == "json-projection"
		if value, ok := match(u.start+u.prefix, u.start+len(u.text)-u.suffix, quoted); ok {
			return value, true
		}
		if value, ok := match(u.start+u.keyStart, u.start+u.keyEnd, quoted); ok {
			return value, true
		}
	}
	return "", false
}

func writeBack(units []unit, r replacements, stats map[string]int) string {
	objects := make(map[*node]bool)
	for _, u := range units {
		switch u.kind {
		case "projection", "json-projection":
			continue
		case "key":
			if !objects[u.target] {
				if reason := writeKeys(u.target, r); reason != "" {
					return reason
				}
				objects[u.target] = true
			}
		case "b64", "b64data":
			writeBase64(u.target, u.text, r)
			stats["b64_roundtrip"]++
		default:
			redacted := r.once.Replace(u.target.text)
			if u.kind == "binary-candidate" && redacted != u.target.text &&
				(u.text == u.target.text || r.once.Replace(u.text) != u.text) {
				// A placeholder in the payload makes it invalid Base64.
				stats["sweep_unrewritable"]--
			}
			u.target.text = redacted
		}
	}
	return ""
}

func joinUnits(units []unit) string {
	var size int
	for _, u := range units {
		size += len(u.text) + len(separator)
	}
	var joined strings.Builder
	joined.Grow(size - len(separator))
	for i := range units {
		if i > 0 {
			joined.WriteString(separator)
		}
		units[i].start = joined.Len()
		joined.WriteString(units[i].text)
	}
	return joined.String()
}

func (s *Scanner) Scan(body []byte, maxBytes int64) Report {
	if int64(len(body)) > maxBytes {
		return Report{"status": "over-cap", "size": len(body), "max_bytes": maxBytes}
	}
	if !utf8.Valid(body) {
		return Report{"status": "skipped-not-json", "reason": "body is not utf-8 text"}
	}
	root, invalidUnicode, err := parse(body)
	if err != nil {
		if err == errDepth || err == errDuplicateKey {
			return Report{"status": "scanner-error", "reason": err.Error()}
		}
		return Report{"status": "skipped-not-json", "reason": "body is not JSON"}
	}
	if root.kind != '{' {
		return Report{"status": "skipped-not-json", "reason": "top-level JSON is not an object"}
	}
	fail := func(reason string) Report {
		return Report{"status": "scanner-error", "reason": reason}
	}
	if invalidUnicode {
		return fail("body contains invalid Unicode")
	}
	e := extract(root, s.detector.MinimumUnit())
	cannotRedact := func(reason string) Report {
		return Report{"status": "redaction-failed", "reason": reason}
	}
	units := e.stats["units"]
	clean := func() Report {
		return Report{"status": "clean", "units": units, "stats": e.stats}
	}
	if e.overCap {
		return fail("scanner input exceeds limit")
	}
	var findings []detector.Finding
	var values []string
	for _, input := range []struct {
		units []unit
		scan  func(string) ([]detector.Finding, error)
	}{{e.units, s.detector.Scan}, {e.literal, s.detector.ScanLiteral}} {
		if len(input.units) == 0 {
			continue
		}
		text := joinUnits(input.units)
		hits, err := input.scan(text)
		if errors.Is(err, detector.ErrIncompleteFinding) {
			return cannotRedact("detector returned an incomplete finding")
		}
		if errors.Is(err, detector.ErrLineWorkLimit) {
			return fail(detector.ErrLineWorkLimit.Error())
		}
		if err != nil {
			return fail("detector failed")
		}
		for _, f := range hits {
			value := f.Secret
			if value == "" {
				value = f.Match
			}
			if value == "" {
				return Report{"status": "finding-without-secret", "reason": "scanner finding lacks both Secret and Match",
					"rule_ids": []string{f.RuleID}}
			}
			value, ok := attributableValue(input.units, text, f, value)
			if !ok {
				return cannotRedact("finding cannot be mapped to a safe rewrite")
			}
			values = append(values, value)
		}
		findings = append(findings, hits...)
	}
	if len(values) == 0 {
		return clean()
	}
	r := s.replacements(values)
	debugRuleIDs := make(map[string]map[string]bool)
	if s.debug {
		for i, finding := range findings {
			placeholder := r.mapping[values[i]]
			if debugRuleIDs[placeholder] == nil {
				debugRuleIDs[placeholder] = make(map[string]bool)
			}
			debugRuleIDs[placeholder][finding.RuleID] = true
		}
	}
	if reason := writeBack(e.units, r, e.stats); reason != "" {
		return cannotRedact(reason)
	}
	var variants []string
	for _, value := range r.ordered {
		for _, variant := range secretVariants(value) {
			variants = append(variants, variant)
		}
	}
	plain, decoded := survives(root, variants)
	if plain {
		return cannotRedact("redaction verification failed: secret bytes survived in body")
	}
	if decoded {
		return cannotRedact("secret survives decoded inside base64/data text")
	}
	out := root.appendJSON(make([]byte, 0, len(body)))
	ids := make(map[string]bool)
	for _, f := range findings {
		ids[f.RuleID] = true
	}
	rules := make([]string, 0, len(ids))
	for id := range ids {
		rules = append(rules, id)
	}
	sort.Strings(rules)
	report := Report{"status": "redacted", "body_base64": base64.StdEncoding.EncodeToString(out),
		"rule_ids": rules, "findings": len(findings), "placeholders": len(r.mapping),
		"units": units, "stats": e.stats}
	if s.debug {
		debugRows := make([]DebugFinding, 0, len(r.ordered))
		for _, value := range r.ordered {
			placeholder := r.mapping[value]
			ids := make([]string, 0, len(debugRuleIDs[placeholder]))
			for id := range debugRuleIDs[placeholder] {
				ids = append(ids, id)
			}
			sort.Strings(ids)
			debugRows = append(debugRows, DebugFinding{DetectedMasked: maskDetected(value), Placeholder: placeholder, RuleIDs: ids})
		}
		report["debug_findings"] = debugRows
	}
	return report
}
