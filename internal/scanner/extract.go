package scanner

import (
	"encoding/base64"
	"errors"
	"regexp"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	textunicode "golang.org/x/text/encoding/unicode"
)

const (
	minUnit      = 8
	maxInline    = 64 * 1024
	chunkSize    = 48 * 1024
	chunkExtra   = 4 * 1024
	kvMax        = 4096
	minRoundtrip = 24
	separator    = "\n\x00::guard-sep::\n"
)

type unit struct {
	path   string
	text   string
	kind   string
	target *node
}

type extraction struct {
	units   []unit
	stats   map[string]int
	groups  map[string]bool
	opaque  int
	minimum int
}

var simpleKey = regexp.MustCompile(`^[A-Za-z_][A-Za-z_0-9]*$`)

const scanWhitespace = `[\x09-\x0d\x1c-\x20\x{85}\x{a0}\x{1680}\x{2000}-\x{200a}\x{2028}\x{2029}\x{202f}\x{205f}\x{3000}]`

var attachments = regexp.MustCompile(`(?is)<attachment(?:` + scanWhitespace + `[^>]*)?>.*?</attachment` + scanWhitespace + `*>`)

func childPath(parent, key string) string {
	if simpleKey.MatchString(key) {
		return parent + "." + key
	}
	return parent + `["` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(key) + `"]`
}

func chunks(text string) []string {
	length := utf8.RuneCountInString(text)
	var runes []rune
	if length != len(text) {
		runes = []rune(text)
	}
	var result []string
	for start := 0; start < length; start += chunkSize {
		end := min(length, start+chunkSize+chunkExtra)
		if runes == nil {
			result = append(result, text[start:end])
		} else {
			result = append(result, string(runes[start:end]))
		}
	}
	return result
}

func opaque(meta string) bool {
	mime, _, _ := strings.Cut(meta, ";")
	mime = unicodeLower(trimSpace(mime))
	for _, prefix := range []string{"image/", "audio/", "video/", "font/"} {
		if strings.HasPrefix(mime, prefix) {
			return true
		}
	}
	switch mime {
	case "application/octet-stream", "application/pdf", "application/zip", "application/gzip", "application/wasm":
		return true
	}
	return false
}

func trimSpace(text string) string {
	return strings.TrimFunc(text, func(r rune) bool {
		return unicode.IsSpace(r) || (r >= 0x1c && r <= 0x1f)
	})
}

func unicodeLower(text string) string {
	// Preserve the dotted combining mark from U+0130 so a non-ASCII MIME token
	// cannot be misclassified as one of the supported opaque media types.
	return strings.ToLower(strings.ReplaceAll(text, "İ", "i\u0307"))
}

func opaqueData(text string) bool {
	if !strings.HasPrefix(text, "data:") {
		return false
	}
	head, _, ok := strings.Cut(text, ",")
	return ok && opaque(head[5:])
}

func decodeBase64(text string) ([]byte, error) {
	for _, r := range text {
		if (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || strings.ContainsRune("+/-_=", r) || unicode.IsSpace(r) || (r >= 0x1c && r <= 0x1f) {
			continue
		}
		return nil, errors.New("invalid base64")
	}
	text = strings.Map(func(r rune) rune {
		// Treat ASCII information separators as whitespace during normalization.
		if unicode.IsSpace(r) || (r >= 0x1c && r <= 0x1f) {
			return -1
		}
		switch r {
		case '-':
			return '+'
		case '_':
			return '/'
		}
		return r
	}, text)
	text += strings.Repeat("=", (4-len(text)%4)%4)
	return base64.StdEncoding.DecodeString(text)
}

func isBase64Data(head string) bool {
	params := strings.Split(head[5:], ";")
	for _, param := range params[1:] {
		if unicodeLower(trimSpace(param)) == "base64" {
			return true
		}
	}
	return false
}

// Decode valid percent escapes while leaving malformed escapes and '+' literal.
// Invalid UTF-8 is replaced by maximal valid subsequences.
func unquote(text string) string {
	var out strings.Builder
	for i := 0; i < len(text); i++ {
		if text[i] == '%' && i+2 < len(text) {
			if b, err := strconv.ParseUint(text[i+1:i+3], 16, 8); err == nil {
				out.WriteByte(byte(b))
				i += 2
				continue
			}
		}
		out.WriteByte(text[i])
	}
	result, _ := textunicode.UTF8.NewDecoder().String(out.String())
	return result
}

func leafInput(text string) (string, string, bool) {
	if !strings.HasPrefix(text, "data:") {
		if utf8.RuneCountInString(text) < minRoundtrip {
			return text, "", true
		}
		data, err := decodeBase64(text)
		if err != nil {
			return text, "", true
		}
		if utf8.Valid(data) {
			return string(data), "b64", true
		}
		return text, "", utf8.RuneCountInString(text) < 64
	}
	head, payload, ok := strings.Cut(text, ",")
	if !ok {
		return text, "", true
	}
	if opaque(head[5:]) {
		return "", "", false
	}
	if isBase64Data(head) {
		data, err := decodeBase64(payload)
		if err == nil && utf8.Valid(data) {
			return string(data), "b64data", true
		}
		return payload, "", true
	}
	return unquote(payload), "", true
}

func decodedBytes(text string) ([]byte, bool) {
	if strings.HasPrefix(text, "data:") {
		head, payload, ok := strings.Cut(text, ",")
		if !ok {
			return nil, false
		}
		if isBase64Data(head) {
			data, err := decodeBase64(payload)
			return data, err == nil
		}
		return []byte(unquote(payload)), true
	}
	data, err := decodeBase64(text)
	return data, err == nil
}

func carve(text string) []string {
	var parts []string
	pos := 0
	for _, match := range attachments.FindAllStringIndex(text, -1) {
		if match[0] > pos {
			parts = append(parts, text[pos:match[0]])
		}
		envelope := text[match[0]:match[1]]
		open := strings.IndexByte(envelope, '>') + 1
		close := strings.LastIndex(envelope, "</attachment")
		// Match the reference's exact partition even for upper-case closing
		// tags (its case-sensitive rfind returns -1 in that case).
		if close < 0 {
			_, size := utf8.DecodeLastRuneInString(envelope)
			close = len(envelope) - size
		}
		for _, piece := range []string{envelope[:open], envelope[open:close], envelope[close:]} {
			if piece != "" {
				parts = append(parts, piece)
			}
		}
		pos = match[1]
	}
	if pos < len(text) {
		parts = append(parts, text[pos:])
	}
	if len(parts) == 0 {
		return []string{text}
	}
	return parts
}

func (e *extraction) add(path string, target *node, items []unit) {
	if e.groups[path] {
		e.stats["path_collisions"]++
	}
	e.groups[path] = true
	for _, item := range items {
		parts := chunks(item.text)
		if item.kind == "piece" {
			parts = carve(item.text)
			if len(parts) > 1 {
				e.stats["carved_attachments"]++
			}
		}
		for _, text := range parts {
			e.units = append(e.units, unit{path, text, item.kind, target})
		}
	}
}

func (e *extraction) walk(path string, target *node, key string, hasKey bool) {
	switch target.kind {
	case 's':
		text := target.text
		declared := target.opaque || opaqueData(text)
		if declared || binaryAttachment(text) {
			target.opaque = true
			e.opaque++
			if declared {
				e.stats["skipped_data_media"]++
			} else {
				e.stats["skipped_base64_blobs"]++
			}
			return
		}
		length := utf8.RuneCountInString(text)
		if length == 0 {
			return
		}
		if length < e.minimum {
			e.stats["skipped_short"]++
			return
		}
		scanText, kind := text, ""
		decodeMinimum := 64
		if e.minimum < minUnit {
			decodeMinimum = minRoundtrip
		}
		if strings.HasPrefix(text, "data:") || length >= decodeMinimum {
			var ok bool
			scanText, kind, ok = leafInput(text)
			if !ok && length > maxInline {
				scanText, kind, ok = text, "", true
			}
			if !ok {
				if strings.HasPrefix(text, "data:") {
					e.stats["skipped_data_media"]++
				} else {
					e.stats["skipped_base64_blobs"]++
				}
				return
			}
		}
		if length > maxInline {
			e.stats["chunked_large"]++
			if kind == "" {
				kind = "derived"
			}
		}
		var items []unit
		if hasKey && key != "" && utf8.RuneCountInString(scanText) <= kvMax {
			items = append(items, unit{text: key + ": " + scanText, kind: "kvdetect"})
		}
		if kind == "" {
			kind = "piece"
			if strings.HasPrefix(text, "data:") {
				kind = "derived"
			}
		}
		e.add(path, target, append(items, unit{text: scanText, kind: kind}))
	case '[':
		for i, child := range target.array {
			e.walk(path+"["+strconv.Itoa(i)+"]", child, key, hasKey)
		}
	case '{':
		for _, item := range target.members {
			item.value.opaque = item.value.kind == 's' && opaqueField(target, item.key)
			if utf8.RuneCountInString(item.key) >= e.minimum {
				e.units = append(e.units, unit{path, item.key, "key", target})
			}
			e.walk(childPath(path, item.key), item.value, item.key, true)
		}
	}
}

func extract(root *node, minimum int) *extraction {
	e := &extraction{
		minimum: minimum,
		stats: map[string]int{"units": 0, "skipped_data_media": 0, "skipped_base64_blobs": 0,
			"skipped_tools": 0, "skipped_short": 0, "chunked_large": 0,
			"carved_attachments": 0, "path_collisions": 0, "b64_roundtrip": 0},
		groups: make(map[string]bool),
	}
	e.walk("$", root, "", false)
	e.stats["units"] = len(e.units)
	e.stats["sweep_unrewritable"] = e.stats["skipped_base64_blobs"] + e.stats["skipped_data_media"] - e.opaque
	return e
}

func secretVariants(secret string) []string {
	// PathEscape has a different safe set from quote(..., safe="").
	var encoded strings.Builder
	for _, b := range []byte(secret) {
		if (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9') || strings.ContainsRune("_.-~", rune(b)) {
			encoded.WriteByte(b)
		} else {
			encoded.WriteByte('%')
			encoded.WriteByte("0123456789ABCDEF"[b>>4])
			encoded.WriteByte("0123456789ABCDEF"[b&15])
		}
	}
	return []string{secret, encoded.String(), base64.StdEncoding.EncodeToString([]byte(secret))}
}
