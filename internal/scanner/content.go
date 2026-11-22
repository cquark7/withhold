package scanner

import (
	"bytes"
	"encoding/base64"
	"strings"
	"unicode"
)

// Recognize common binary attachments without decoding their full payload.
// Validate the entire base64 alphabet so a binary prefix cannot hide prose.
func binaryAttachment(text string) bool {
	var prefix [128]byte
	n := 0
	padding := false
	pads := 0
	for _, r := range text {
		if unicode.IsSpace(r) || (r >= 0x1c && r <= 0x1f) {
			continue
		}
		if r == '=' {
			padding = true
			pads++
			if pads > 2 {
				return false
			}
		} else if padding || !((r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || strings.ContainsRune("+/-_", r)) {
			return false
		}
		if n < len(prefix) {
			prefix[n] = byte(r)
		}
		n++
	}
	if n < 16 || (n-pads)%4 == 1 || pads > 0 && (n%4 != 0 || (n-pads)%4 == 0) {
		return false
	}
	sample := strings.NewReplacer("-", "+", "_", "/").Replace(string(prefix[:min(n, len(prefix))]))
	sample = strings.TrimRight(sample, "=")
	data, err := base64.RawStdEncoding.DecodeString(sample)
	if err != nil {
		return false
	}
	for _, magic := range [][]byte{[]byte("\x89PNG\r\n\x1a\n"), []byte("\xff\xd8\xff"), []byte("GIF87a"), []byte("GIF89a"), []byte("%PDF-"), []byte("PK\x03\x04"), []byte("\x1f\x8b\x08"), []byte("\x00asm")} {
		if bytes.HasPrefix(data, magic) {
			return true
		}
	}
	return len(data) >= 12 && string(data[:4]) == "RIFF" && (string(data[8:12]) == "WEBP" || string(data[8:12]) == "WAVE")
}

func opaqueLeaf(text string) bool { return opaqueData(text) || binaryAttachment(text) }

func opaqueField(parent *node, key string) bool {
	if key != "data" && key != "file_data" && key != "image_data" {
		return false
	}
	for _, name := range []string{"media_type", "mime_type", "mimeType"} {
		if mime := parent.get(name); mime != nil && mime.kind == 's' && opaque(mime.text) {
			return true
		}
	}
	return false
}

type byteCount int

func (n *byteCount) Write(p []byte) (int, error) {
	*n += byteCount(len(p))
	return len(p), nil
}

func (n *byteCount) WriteString(s string) (int, error) {
	*n += byteCount(len(s))
	return len(s), nil
}

// Verify only inspected text. Opaque attachments remain byte-for-byte data,
// including when another field in the request needs redaction.
func survives(root *node, variants []string) (plain, decoded bool) {
	stack := []*node{root}
	pairs := make([]string, 0, 2*len(variants))
	seen := make(map[string]bool)
	for _, variant := range variants {
		if !seen[variant] {
			pairs = append(pairs, variant, "")
			seen[variant] = true
		}
	}
	remove := strings.NewReplacer(pairs...)
	contains := func(text string) bool {
		var bytes byteCount
		_, _ = remove.WriteString(&bytes, text)
		return int(bytes) != len(text)
	}
	containsDecoded := func(text string) bool {
		if len(text) < minRoundtrip && !strings.HasPrefix(text, "data:") {
			return false
		}
		data, ok := decodedBytes(text)
		return ok && contains(string(data))
	}
	for len(stack) > 0 {
		n := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		switch n.kind {
		case 's':
			if n.opaque {
				continue
			}
			if contains(n.text) {
				return true, false
			}
			if containsDecoded(n.text) {
				return false, true
			}
		case '[':
			stack = append(stack, n.array...)
		case '{':
			for _, item := range n.members {
				if contains(item.key) {
					return true, false
				}
				if containsDecoded(item.key) {
					return false, true
				}
				stack = append(stack, item.value)
			}
		}
	}
	return false, false
}
