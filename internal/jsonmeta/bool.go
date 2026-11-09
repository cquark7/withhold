// Package jsonmeta reads small protocol metadata without retaining payload
// copies. It is separate from the redactor and never determines inspection scope.
package jsonmeta

import (
	"bytes"
	"encoding/json"
)

// Bool returns an exact, case-sensitive top-level boolean field. JSON is
// validated first; duplicate names follow encoding/json's last-value behavior.
// Unknown values are skipped in place, including large attachment strings.
func Bool(body []byte, field string) bool {
	body = bytes.TrimSpace(body)
	if len(body) == 0 || body[0] != '{' || !json.Valid(body) {
		return false
	}
	space := func(i int) int {
		for i < len(body) && (body[i] == ' ' || body[i] == '\t' || body[i] == '\r' || body[i] == '\n') {
			i++
		}
		return i
	}
	quotedEnd := func(i int) int {
		for i++; i < len(body); i++ {
			if body[i] == '\\' {
				i++
			} else if body[i] == '"' {
				return i + 1
			}
		}
		return len(body)
	}
	result := false
	for i := space(1); i < len(body) && body[i] != '}'; {
		end := quotedEnd(i)
		var key string
		matches := false
		if end-i <= 6*len(field)+2 {
			_ = json.Unmarshal(body[i:end], &key)
			matches = key == field
		}
		start := space(space(end) + 1) // Skip the validated colon.
		depth := 0
		i = start
		for ; i < len(body); i++ {
			c := body[i]
			if c == '"' {
				i = quotedEnd(i) - 1
				continue
			}
			if c == '{' || c == '[' {
				depth++
			}
			if c == '}' || c == ']' {
				if depth == 0 {
					break
				}
				depth--
			}
			if c == ',' && depth == 0 {
				break
			}
		}
		if matches {
			result = bytes.Equal(bytes.TrimSpace(body[start:i]), []byte("true"))
		}
		if i < len(body) && body[i] == ',' {
			i = space(i + 1)
		}
	}
	return result
}
