// Package scanner extracts, detects, rewrites, and verifies request bodies.
package scanner

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
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
		return utf8.RuneCountInString(r.ordered[i]) > utf8.RuneCountInString(r.ordered[j])
	})
	pairs := make([]string, 0, len(r.ordered)*2)
	for _, value := range r.ordered {
		pairs = append(pairs, value, r.mapping[value])
	}
	r.once = strings.NewReplacer(pairs...)
	return r
}

func (r replacements) sequential(text string) string {
	for _, value := range r.ordered {
		text = strings.ReplaceAll(text, value, r.mapping[value])
	}
	return text
}

type writeGroup struct {
	target *node
	kinds  map[string]bool
	texts  []string
}

func writeKeys(group *writeGroup, r replacements) string {
	n := group.target
	renames := make(map[string]string)
	for _, text := range group.texts {
		matched := false
		for _, item := range n.members {
			if r.sequential(item.key) != text {
				continue
			}
			matched = true
			if text != item.key {
				if _, exists := n.index[text]; exists {
					return "key rename would collide"
				}
				renames[item.key] = text
			}
			break
		}
		if !matched {
			return "key write-back miss"
		}
	}
	n.index = make(map[string]int, len(n.members))
	for i := range n.members {
		if name, ok := renames[n.members[i].key]; ok {
			n.members[i].key = name
		}
		if _, exists := n.index[n.members[i].key]; exists {
			return "key rename would collide"
		}
		n.index[n.members[i].key] = i
	}
	return ""
}

func writeBase64(target *node, r replacements) string {
	original := target.text
	prefix, encoded := "", original
	if strings.HasPrefix(original, "data:") {
		head, payload, ok := strings.Cut(original, ",")
		if !ok {
			return "base64 write-back on malformed data URL"
		}
		prefix, encoded = head+",", payload
	}
	data, err := decodeBase64(encoded)
	if err != nil || !utf8.Valid(data) {
		return "base64 write-back decode failed"
	}
	redacted := r.sequential(string(data))
	if redacted == string(data) {
		return ""
	}
	out := base64.StdEncoding.EncodeToString([]byte(redacted))
	if strings.ContainsAny(encoded, "-_") {
		out = strings.NewReplacer("+", "-", "/", "_").Replace(out)
	}
	if !strings.Contains(encoded, "=") {
		out = strings.TrimRight(out, "=")
	}
	target.text = prefix + out
	return ""
}

func writeBack(units []unit, r replacements, stats map[string]int) string {
	byPath := make(map[string]*writeGroup)
	var groups []*writeGroup
	for _, u := range units {
		text := r.once.Replace(u.text)
		for _, secret := range r.ordered {
			if strings.Contains(text, secret) {
				return "redaction verification failed: secret fragment survived"
			}
		}
		group := byPath[u.path]
		if group == nil {
			group = &writeGroup{target: u.target, kinds: make(map[string]bool)}
			groups = append(groups, group)
			byPath[u.path] = group
		}
		group.kinds[u.kind] = true
		group.texts = append(group.texts, text)
	}
	for _, keysLast := range []bool{false, true} {
		for _, group := range groups {
			if group.kinds["key"] != keysLast {
				continue
			}
			switch {
			case keysLast:
				if reason := writeKeys(group, r); reason != "" {
					return reason
				}
			case group.kinds["b64"] || group.kinds["b64data"]:
				if reason := writeBase64(group.target, r); reason != "" {
					return reason
				}
				stats["b64_roundtrip"]++
			case group.kinds["kvdetect"] || group.kinds["derived"]:
				group.target.text = r.sequential(group.target.text)
			default:
				group.target.text = strings.Join(group.texts, "")
			}
		}
	}
	return ""
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
	if e.stats["path_collisions"] != 0 {
		result := fail("duplicate JSON path across leaves - write-back would be ambiguous")
		result["stats"] = e.stats
		return result
	}
	clean := func() Report {
		return Report{"status": "clean", "units": len(e.units), "stats": e.stats}
	}
	if len(e.units) == 0 {
		return clean()
	}
	length := 0
	for _, u := range e.units {
		length += len(u.text) + len(separator)
		if length > maxScanBytes {
			return fail("scanner input exceeds limit")
		}
	}
	var joined strings.Builder
	joined.Grow(length)
	for i, u := range e.units {
		if i > 0 {
			joined.WriteString(separator)
		}
		joined.WriteString(u.text)
	}
	findings, err := s.detector.Scan(joined.String())
	if err != nil {
		return fail("detector failed")
	}
	var values []string
	for _, f := range findings {
		value := f.Secret
		if value == "" {
			value = f.Match
		}
		if value == "" {
			return Report{"status": "finding-without-secret", "reason": "scanner finding lacks both Secret and Match",
				"rule_ids": []string{f.RuleID}}
		}
		values = append(values, value)
	}
	if len(values) == 0 {
		return clean()
	}
	r := s.replacements(values)
	debugRuleIDs := make(map[string]map[string]bool)
	if s.debug {
		for _, finding := range findings {
			value := finding.Secret
			if value == "" {
				value = finding.Match
			}
			placeholder := r.mapping[value]
			if debugRuleIDs[placeholder] == nil {
				debugRuleIDs[placeholder] = make(map[string]bool)
			}
			debugRuleIDs[placeholder][finding.RuleID] = true
		}
	}
	if reason := writeBack(e.units, r, e.stats); reason != "" {
		return fail(reason)
	}
	var variants []string
	for _, value := range r.ordered {
		for _, variant := range secretVariants(value) {
			variants = append(variants, variant)
		}
	}
	plain, decoded := survives(root, variants)
	if plain {
		return fail("redaction verification failed: secret bytes survived in body")
	}
	if decoded {
		return fail("secret survives decoded inside base64/data: leaf")
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
		"units": len(e.units), "stats": e.stats}
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
