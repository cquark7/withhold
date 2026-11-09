package scanner

import (
	"encoding/json"
	"errors"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf16"
)

// Preserve object order and scalar types during rewriting. Maps alone would
// reorder keys, and float64 would lose integers.
type member struct {
	key   string
	value *node
}

type node struct {
	opaque  bool
	kind    byte
	text    string
	array   []*node
	members []member
	index   map[string]int
}

func (n *node) get(key string) *node {
	if n.kind != '{' {
		return nil
	}
	if i, ok := n.index[key]; ok {
		return n.members[i].value
	}
	return nil
}

var numberPattern = regexp.MustCompile(`^-?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?$`)
var errJSON = errors.New("body is not JSON")
var errDepth = errors.New("JSON too deeply nested")
var errDuplicateKey = errors.New("duplicate JSON object key")

type parser struct {
	data           []byte
	pos            int
	invalidUnicode bool
}

func (p *parser) whitespace() {
	for p.pos < len(p.data) && strings.ContainsRune(" \t\r\n", rune(p.data[p.pos])) {
		p.pos++
	}
}

func (p *parser) string() (string, error) {
	start := p.pos
	escaped := false
	p.pos++
	for p.pos < len(p.data) {
		c := p.data[p.pos]
		p.pos++
		if c == '\\' {
			escaped = true
			p.pos++
			continue
		}
		if c == '"' {
			raw := p.data[start:p.pos]
			if !escaped {
				return string(raw[1 : len(raw)-1]), nil
			}
			var value string
			if json.Unmarshal(raw, &value) != nil {
				return "", errJSON
			}
			// encoding/json replaces unpaired surrogates silently. Record them
			// explicitly so replacement cannot turn uninspectable input clean.
			for i := 1; i < len(raw)-1; i++ {
				if raw[i] != '\\' {
					continue
				}
				i++
				if raw[i] != 'u' {
					continue
				}
				u, _ := strconv.ParseUint(string(raw[i+1:i+5]), 16, 16)
				i += 4
				if u >= 0xd800 && u <= 0xdbff {
					if i+6 < len(raw) && string(raw[i+1:i+3]) == `\u` {
						low, _ := strconv.ParseUint(string(raw[i+3:i+7]), 16, 16)
						if low >= 0xdc00 && low <= 0xdfff {
							i += 6
							continue
						}
					}
					p.invalidUnicode = true
				} else if u >= 0xdc00 && u <= 0xdfff {
					p.invalidUnicode = true
				}
			}
			return value, nil
		}
		if c < 0x20 {
			return "", errJSON
		}
	}
	return "", errJSON
}

func (p *parser) value(depth int) (*node, error) {
	if depth > 1000 {
		return nil, errDepth
	}
	p.whitespace()
	if p.pos >= len(p.data) {
		return nil, errJSON
	}
	c := p.data[p.pos]
	if c == '"' {
		s, err := p.string()
		return &node{kind: 's', text: s}, err
	}
	if c == '{' || c == '[' {
		p.pos++
		n := &node{kind: c}
		close := byte(']')
		if c == '{' {
			n.index = make(map[string]int)
			close = '}'
		}
		p.whitespace()
		if p.pos < len(p.data) && p.data[p.pos] == close {
			p.pos++
			return n, nil
		}
		for {
			var key string
			if c == '{' {
				p.whitespace()
				if p.pos >= len(p.data) || p.data[p.pos] != '"' {
					return nil, errJSON
				}
				var err error
				key, err = p.string()
				if err != nil {
					return nil, err
				}
				if _, exists := n.index[key]; exists {
					return nil, errDuplicateKey
				}
				p.whitespace()
				if p.pos >= len(p.data) || p.data[p.pos] != ':' {
					return nil, errJSON
				}
				p.pos++
			}
			v, err := p.value(depth + 1)
			if err != nil {
				return nil, err
			}
			if c == '{' {
				n.index[key] = len(n.members)
				n.members = append(n.members, member{key, v})
			} else {
				n.array = append(n.array, v)
			}
			p.whitespace()
			if p.pos >= len(p.data) {
				return nil, errJSON
			}
			sep := p.data[p.pos]
			p.pos++
			if sep == close {
				return n, nil
			}
			if sep != ',' {
				return nil, errJSON
			}
		}
	}
	start := p.pos
	for p.pos < len(p.data) && !strings.ContainsRune(" \t\r\n,]}", rune(p.data[p.pos])) {
		p.pos++
	}
	text := string(p.data[start:p.pos])
	switch text {
	case "true", "false", "null":
		return &node{kind: 'v', text: text}, nil
	}
	if !numberPattern.MatchString(text) {
		return nil, errJSON
	}
	return &node{kind: 'n', text: text}, nil
}

func parse(data []byte) (*node, bool, error) {
	p := parser{data: data}
	n, err := p.value(0)
	p.whitespace()
	if err == nil && p.pos != len(data) {
		err = errJSON
	}
	return n, p.invalidUnicode, err
}

const hexDigits = "0123456789abcdef"

func appendHex(out []byte, r rune) []byte {
	return append(out, '\\', 'u', hexDigits[r>>12&15], hexDigits[r>>8&15], hexDigits[r>>4&15], hexDigits[r&15])
}

func appendString(out []byte, s string) []byte {
	out = append(out, '"')
	plain := true
	for i := 0; i < len(s); i++ {
		if s[i] < 32 || s[i] >= 127 || s[i] == '"' || s[i] == '\\' {
			plain = false
			break
		}
	}
	if plain {
		return append(append(out, s...), '"')
	}
	for _, r := range s {
		switch r {
		case '"', '\\':
			out = append(out, '\\', byte(r))
		case '\b':
			out = append(out, `\b`...)
		case '\f':
			out = append(out, `\f`...)
		case '\n':
			out = append(out, `\n`...)
		case '\r':
			out = append(out, `\r`...)
		case '\t':
			out = append(out, `\t`...)
		default:
			if r < 32 || r >= 127 {
				if r > 0xffff {
					high, low := utf16.EncodeRune(r)
					out = appendHex(appendHex(out, high), low)
				} else {
					out = appendHex(out, r)
				}
			} else {
				out = append(out, byte(r))
			}
		}
	}
	return append(out, '"')
}

func (n *node) appendJSON(out []byte) []byte {
	switch n.kind {
	case 's':
		return appendString(out, n.text)
	case 'n':
		return append(out, n.text...)
	case 'v':
		return append(out, n.text...)
	case '[':
		out = append(out, '[')
		for i, child := range n.array {
			if i > 0 {
				out = append(out, ',')
			}
			out = child.appendJSON(out)
		}
		return append(out, ']')
	default:
		out = append(out, '{')
		for i, item := range n.members {
			if i > 0 {
				out = append(out, ',')
			}
			out = appendString(out, item.key)
			out = append(out, ':')
			out = item.value.appendJSON(out)
		}
		return append(out, '}')
	}
}
