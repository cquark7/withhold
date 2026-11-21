package scanner

import (
	"encoding/base64"
	"errors"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	textunicode "golang.org/x/text/encoding/unicode"
)

const (
	kvMax        = 4096
	minRoundtrip = 24
	separator    = "\n\x00::guard-sep::\n"
)

type unit struct {
	text   string
	kind   string
	target *node
	start  int
	// Projections include syntax outside the original key and value.
	keyStart, keyEnd, prefix, suffix int
}

type extraction struct {
	units   []unit
	stats   map[string]int
	minimum int
	bytes   int
	overCap bool
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

func leafInput(text string) (string, string) {
	if !strings.HasPrefix(text, "data:") {
		data, err := decodeBase64(text)
		if err != nil {
			return text, ""
		}
		if utf8.Valid(data) {
			return string(data), "b64"
		}
		return text, "binary-candidate"
	}
	head, payload, ok := strings.Cut(text, ",")
	if !ok {
		return text, ""
	}
	if isBase64Data(head) {
		data, err := decodeBase64(payload)
		if err != nil {
			return payload, ""
		}
		if utf8.Valid(data) {
			return string(data), "b64data"
		}
		return payload, "binary-candidate"
	}
	return unquote(payload), ""
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

func (e *extraction) add(u unit) {
	e.bytes += len(u.text) + len(separator)
	if e.bytes > maxScanBytes {
		e.overCap = true
		return
	}
	e.units = append(e.units, u)
}

func (e *extraction) addCredentialProjection(name, value string, sibling bool) {
	if name == "" || len(name) > 64 {
		return
	}
	head, delimiter := "{", ":{"
	if sibling {
		head, delimiter = `{"name":`, ","
	}
	projection := appendString([]byte(head), name)
	keyEnd := len(projection) - 1
	projection = append(projection, delimiter...)
	projection = append(projection, `"value":`...)
	valueStart := len(projection) + 1
	projection = appendString(projection, value)
	valueEnd := len(projection) - 1
	projection = append(projection, '}')
	if !sibling {
		projection = append(projection, '}')
	}
	e.add(unit{text: string(projection), kind: "json-projection", keyStart: len(head) + 1,
		keyEnd: keyEnd, prefix: valueStart, suffix: len(projection) - valueEnd})
}

func (e *extraction) walk(target, parent *node, key, parentKey string) {
	if e.overCap {
		return
	}
	switch target.kind {
	case 's':
		text := target.text
		declared := target.opaque || opaqueData(text)
		if declared || binaryAttachment(text) {
			target.opaque = true
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
		if strings.HasPrefix(text, "data:") || len(text) >= minRoundtrip {
			scanText, kind = leafInput(text)
			if kind == "binary-candidate" {
				// A URL-safe token can look like Base64 for binary bytes.
				// Inspect the original text and count the unscanned decoded bytes.
				e.stats["sweep_unrewritable"]++
			}
		}
		if key != "" && len(key) <= kvMax && utf8.RuneCountInString(scanText) <= kvMax {
			e.add(unit{text: key + ": " + scanText, kind: "projection", target: target, keyEnd: len(key), prefix: len(key) + 2})
			if key == "value" {
				e.addCredentialProjection(parentKey, scanText, false)
				if name := parent.get("name"); name != nil && name.kind == 's' && len(name.text) <= 64 && !opaqueLeaf(name.text) {
					e.addCredentialProjection(name.text, scanText, true)
				}
			}
		}
		e.add(unit{text: scanText, kind: kind, target: target})
	case '[':
		for _, child := range target.array {
			e.walk(child, parent, key, parentKey)
		}
	case '{':
		for _, item := range target.members {
			item.value.opaque = item.value.kind == 's' && opaqueField(target, item.key)
			if utf8.RuneCountInString(item.key) >= e.minimum {
				e.add(unit{text: item.key, kind: "key", target: target})
			}
			e.walk(item.value, target, item.key, key)
		}
	}
}

func extract(root *node, minimum int) *extraction {
	e := &extraction{
		minimum: minimum,
		stats: map[string]int{"units": 0, "skipped_data_media": 0, "skipped_base64_blobs": 0,
			"skipped_short": 0, "b64_roundtrip": 0, "sweep_unrewritable": 0},
	}
	e.walk(root, nil, "", "")
	e.stats["units"] = len(e.units)
	return e
}

func secretVariants(secret string) []string {
	// PathEscape has a different safe set from quote(..., safe="").
	var encoded, lower strings.Builder
	for _, b := range []byte(secret) {
		if (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9') || strings.ContainsRune("_.-~", rune(b)) {
			encoded.WriteByte(b)
			lower.WriteByte(b)
		} else {
			encoded.WriteByte('%')
			encoded.WriteByte("0123456789ABCDEF"[b>>4])
			encoded.WriteByte("0123456789ABCDEF"[b&15])
			lower.WriteByte('%')
			lower.WriteByte("0123456789abcdef"[b>>4])
			lower.WriteByte("0123456789abcdef"[b&15])
		}
	}
	variants := []string{secret, encoded.String(), lower.String()}
	for _, encoding := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		variants = append(variants, encoding.EncodeToString([]byte(secret)))
	}
	return variants
}
