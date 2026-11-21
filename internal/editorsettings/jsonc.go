package editorsettings

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"maps"
	"slices"
)

type jsoncEntry struct {
	key                      string
	start, value, end, comma int
}

type jsoncContainer struct {
	data, masked []byte
	entries      []jsoncEntry
	close        int
}

// Decode against length-preserving JSON, then edit the original bytes.
func parseContainer(data []byte, kind json.Delim) (jsoncContainer, error) {
	invalid := errors.New("settings must be a valid JSONC object or array")
	masked, err := maskComments(data)
	if err != nil {
		return jsoncContainer{}, err
	}
	clean := bytes.Clone(masked)
	stripTrailingCommas(clean)
	d := json.NewDecoder(bytes.NewReader(clean))
	if token, err := d.Token(); err != nil || token != kind {
		return jsoncContainer{}, invalid
	}
	doc := jsoncContainer{data: data, masked: masked}
	for d.More() {
		offset := int(d.InputOffset())
		start := len(clean) - len(bytes.TrimLeft(clean[offset:], " \t\r\n,"))
		var key string
		if kind == '{' {
			token, err := d.Token()
			if err != nil {
				return jsoncContainer{}, invalid
			}
			key = token.(string)
		}
		var value json.RawMessage
		if err := d.Decode(&value); err != nil {
			return jsoncContainer{}, invalid
		}
		end := int(d.InputOffset())
		comma := len(masked) - len(bytes.TrimLeft(masked[end:], " \t\r\n"))
		if comma == len(masked) || masked[comma] != ',' {
			comma = -1
		}
		doc.entries = append(doc.entries, jsoncEntry{key, start, end - len(value), end, comma})
	}
	if _, err := d.Token(); err != nil {
		return jsoncContainer{}, invalid
	}
	doc.close = int(d.InputOffset()) - 1
	if _, err := d.Token(); err != io.EOF {
		return jsoncContainer{}, invalid
	}
	return doc, nil
}

func (doc jsoncContainer) value(key string) []byte {
	for _, entry := range slices.Backward(doc.entries) {
		if entry.key == key {
			return doc.data[entry.value:entry.end]
		}
	}
	return nil
}

func (doc jsoncContainer) update(changes map[string][]byte) []byte {
	edits := make(map[int][]byte)
	replaced := make(map[string]bool)
	for i, entry := range slices.Backward(doc.entries) {
		if value, ok := changes[entry.key]; ok {
			edits[i] = value
			delete(changes, entry.key)
			replaced[entry.key] = true
		} else if replaced[entry.key] {
			// Keep a single managed setting even when the input repeats its key.
			edits[i] = nil
		}
	}
	var added [][]byte
	for _, key := range slices.Sorted(maps.Keys(changes)) {
		if value := changes[key]; value != nil {
			name, _ := json.Marshal(key)
			added = append(added, append(append(name, ": "...), value...))
		}
	}
	return doc.edit(edits, added, "    ")
}

func (doc jsoncContainer) edit(edits map[int][]byte, added [][]byte, indent string) []byte {
	var out []byte
	last := 0
	needComma := false
	lastKept := len(doc.entries) - 1
	for lastKept >= 0 {
		if value, changed := edits[lastKept]; !changed || value != nil {
			break
		}
		lastKept--
	}
	for i, entry := range doc.entries {
		value, changed := edits[i]
		if changed && value == nil {
			start, end := entry.start, entry.end
			if bytes.Equal(doc.data[start:end], doc.masked[start:end]) {
				line := bytes.LastIndexByte(doc.data[:start], '\n') + 1
				after := max(entry.comma+1, end)
				next := bytes.IndexByte(doc.data[after:], '\n')
				if line >= last && len(bytes.TrimSpace(doc.data[line:start])) == 0 &&
					next >= 0 && len(bytes.TrimSpace(doc.data[after:after+next])) == 0 &&
					bytes.Equal(doc.data[end:after], doc.masked[end:after]) {
					out = append(out, doc.data[last:line]...)
					last = after + next + 1
					continue
				}
			}
			out = append(out, doc.data[last:start]...)
			for j := start; j < end; j++ {
				switch doc.masked[j] {
				case ' ', '\t', '\r', '\n':
					out = append(out, doc.data[j])
				}
			}
			last = end
			if entry.comma >= 0 {
				out = append(out, doc.data[last:entry.comma]...)
				last = entry.comma + 1
			}
			continue
		}
		if changed {
			out = append(out, doc.data[last:entry.value]...)
			out = append(out, value...)
		} else {
			out = append(out, doc.data[last:entry.end]...)
		}
		last = entry.end
		needComma = entry.comma < 0
		if len(added) == 0 && i == lastKept && i+1 < len(doc.entries) && entry.comma >= 0 {
			out = append(out, doc.data[last:entry.comma]...)
			last = entry.comma + 1
		}
	}
	if len(added) == 0 {
		return append(out, doc.data[last:]...)
	}
	if needComma {
		out = append(out, ',')
	}
	line := bytes.LastIndexByte(doc.data[:doc.close], '\n') + 1
	if line < last || len(bytes.TrimSpace(doc.data[line:doc.close])) != 0 {
		out = append(out, doc.data[last:doc.close]...)
		out = append(out, '\n')
		line = doc.close
	} else {
		out = append(out, doc.data[last:line]...)
	}
	for i, value := range added {
		out = append(out, indent...)
		out = append(out, value...)
		if i < len(added)-1 {
			out = append(out, ',')
		}
		out = append(out, '\n')
	}
	return append(out, doc.data[line:]...)
}

func syncList(data []byte) jsoncContainer {
	doc, err := parseContainer(data, '[')
	if err != nil {
		doc = jsoncContainer{data: []byte("[]"), close: 1}
	}
	return doc
}

func (doc jsoncContainer) string(entry jsoncEntry) string {
	var value string
	_ = json.Unmarshal(doc.data[entry.value:entry.end], &value)
	return value
}

func (doc jsoncContainer) strings() map[string]bool {
	values := make(map[string]bool)
	for _, entry := range doc.entries {
		values[doc.string(entry)] = true
	}
	return values
}
