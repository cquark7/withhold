package cursor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"slices"
	"strconv"
	"unicode/utf8"

	"github.com/cquark7/withhold/internal/policy"
	"google.golang.org/protobuf/encoding/protowire"
)

var (
	ErrMalformed   = errors.New("malformed Cursor inference message")
	ErrUnsupported = errors.New("unsupported Cursor inference content")
	ErrLimit       = errors.New("Cursor inference limit exceeded")
	ErrRewrite     = errors.New("invalid Cursor inference rewrite")
)

const (
	maxDepth              = 64
	maxFields             = 100000
	inferenceContentParts = "aiserver.v1.InferenceContentParts"
)

type wireField struct {
	def     fieldDef
	raw     []byte
	tagSize int
	payload []byte
	child   *wireMessage
}

type wireMessage struct {
	name        string
	raw         []byte
	fields      []*wireField
	compression uint64
	ctx         context.Context
}

func (m *wireMessage) field(number protowire.Number) *wireField {
	for _, field := range m.fields {
		if field.def.Number == number {
			return field
		}
	}
	return nil
}

func (f *wireField) uint() uint64 {
	value, _ := protowire.ConsumeVarint(f.raw[f.tagSize:])
	return value
}

type textSlot struct {
	name     string
	targets  []*wireField
	key      *wireField
	writable bool
}

// InferenceMessage owns one reviewed, already-unframed protobuf request.
// Its ordered text projection is scanner input, not protobuf JSON: bytes are
// decoded explicitly, and numeric fields never become text.
type InferenceMessage struct {
	root        *wireMessage
	slots       []textSlot
	projection  []byte
	maxBytes    int64
	jsonBytes   int64
	messageType string
	ctx         context.Context
}

type decoder struct {
	maxBytes int64
	decoded  int64
	fields   int
	reserve  func(int) error
	ctx      context.Context
}

// DecodeRunInference accepts full invoke_model requests with reviewed wire
// semantics, independently of the editor's version string. Connect framing and
// outer HTTP/message compression belong to transport.
func DecodeRunInference(body []byte, maxBytes int64) (*InferenceMessage, error) {
	return decodeMessage(clientMessage, body, policy.DecodeLimits{MaxBytes: maxBytes})
}

func decodeMessage(name string, body []byte, limits policy.DecodeLimits) (*InferenceMessage, error) {
	maxBytes := limits.MaxBytes
	if maxBytes <= 0 || maxBytes > 128*1024*1024 || int64(len(body)) > maxBytes {
		return nil, ErrLimit
	}
	reserve := limits.Reserve
	if reserve == nil {
		reserve = func(int) error { return nil }
	}
	if err := reserve(len(body)); err != nil {
		return nil, err
	}
	ctx := limits.Context
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	d := decoder{maxBytes: maxBytes, reserve: reserve, ctx: ctx}
	root, err := d.message(name, bytes.Clone(body), 0)
	if err != nil {
		return nil, err
	}
	result := &InferenceMessage{root: root, maxBytes: maxBytes, jsonBytes: int64(len(`{"fields":[]}`)), messageType: name, ctx: ctx}
	if err := result.collect(root, nil); err != nil {
		return nil, err
	}
	// Include the scanner-facing independent copy in retained-input admission.
	if err := reserve(2 * int(result.jsonBytes)); err != nil {
		return nil, err
	}
	fields := make([]map[string]string, 0, len(result.slots))
	for _, slot := range result.slots {
		fields = append(fields, map[string]string{slot.name: slot.text()})
	}
	result.projection, err = json.Marshal(struct {
		Fields []map[string]string `json:"fields"`
	}{fields})
	if err != nil {
		return nil, ErrMalformed
	}
	if int64(len(result.projection)) > maxBytes {
		return nil, ErrLimit
	}
	return result, nil
}

// ScanInput returns an independent JSON body for the existing scanner/pool.
func (m *InferenceMessage) ScanInput() []byte { return bytes.Clone(m.projection) }

func (m *InferenceMessage) HasContent() bool {
	for _, slot := range m.slots {
		if len(slot.text()) > 0 && (slot.writable ||
			m.messageType == "aiserver.v1.StreamCppRequest" && slot.targets[0].def.Name == "contents") {
			return true
		}
	}
	return false
}

func (s textSlot) text() string {
	var result []byte
	for _, target := range s.targets {
		result = append(result, target.payload...)
	}
	return string(result)
}

func (d *decoder) message(name string, body []byte, depth int) (*wireMessage, error) {
	if d.ctx != nil {
		if err := d.ctx.Err(); err != nil {
			return nil, err
		}
	}
	if depth > maxDepth {
		return nil, ErrLimit
	}
	definitions := pinned.fields[name]
	if definitions == nil {
		return nil, ErrUnsupported
	}
	m := &wireMessage{name: name, raw: body, ctx: d.ctx}
	seen, oneofs := make(map[protowire.Number]bool), make(map[string]bool)
	for rest := body; len(rest) != 0; {
		if d.ctx != nil && d.fields%64 == 0 {
			if err := d.ctx.Err(); err != nil {
				return nil, err
			}
		}
		d.fields++
		if d.fields > maxFields {
			return nil, ErrLimit
		}
		number, wire, tagSize := protowire.ConsumeTag(rest)
		if tagSize < 0 || !number.IsValid() {
			return nil, ErrMalformed
		}
		def, ok := definitions[number]
		if !ok || !supportedField(name, def) {
			return nil, ErrUnsupported
		}
		if seen[number] && !def.Repeated || def.Oneof != "" && oneofs[def.Oneof] {
			return nil, ErrUnsupported
		}
		seen[number], oneofs[def.Oneof] = true, true
		expected := scalarWire(def.Type)
		packed := def.Repeated && wire == protowire.BytesType && expected != protowire.BytesType
		if wire != expected && !packed {
			return nil, ErrMalformed
		}
		size := protowire.ConsumeFieldValue(number, wire, rest[tagSize:])
		if size < 0 {
			return nil, ErrMalformed
		}
		field := &wireField{def: def, raw: rest[:tagSize+size], tagSize: tagSize}
		if wire == protowire.BytesType {
			field.payload, _ = protowire.ConsumeBytes(rest[tagSize:])
		}
		switch {
		case packed:
			for values := field.payload; len(values) != 0; {
				n, err := validateScalar(def.Type, values)
				if err != nil {
					return nil, err
				}
				values = values[n:]
			}
		case expected != protowire.BytesType:
			if _, err := validateScalar(def.Type, rest[tagSize:]); err != nil {
				return nil, err
			}
		case def.Type == "string":
			if !utf8.Valid(field.payload) {
				return nil, ErrMalformed
			}
		case pinned.fields[def.Type] != nil:
			var err error
			field.child, err = d.message(def.Type, field.payload, depth+1)
			if err != nil {
				return nil, err
			}
		}
		m.fields = append(m.fields, field)
		rest = rest[tagSize+size:]
	}
	switch name {
	case clientMessage:
		if len(m.fields) != 1 {
			return nil, ErrUnsupported
		}
	case "aiserver.v1.CurrentFileInfo":
		if field := m.field(18); field != nil && field.uint() != 0 {
			return nil, ErrUnsupported // Server-side file state was not inspected.
		}
	case invokeModel:
		if (m.field(2) == nil) == (m.field(7) == nil) {
			return nil, ErrUnsupported
		}
	case compressedRequest:
		if err := d.expand(m, depth); err != nil {
			return nil, err
		}
	case "google.protobuf.Value":
		if len(m.fields) != 1 {
			return nil, ErrMalformed
		}
	}
	// Reject duplicate/defaulted map entries instead of losing wire semantics in
	// a generated protobuf-to-JSON conversion.
	keys := make(map[protowire.Number]map[string]bool)
	for _, field := range m.fields {
		if field.def.MapKey == "" {
			continue
		}
		key, value := field.child.field(1), field.child.field(2)
		if key == nil || value == nil {
			return nil, ErrUnsupported
		}
		identity := string(key.payload)
		if key.def.Type != "string" {
			identity = strconv.FormatInt(int64(int32(key.uint())), 10)
		}
		if keys[field.def.Number] == nil {
			keys[field.def.Number] = make(map[string]bool)
		}
		if keys[field.def.Number][identity] {
			return nil, ErrUnsupported
		}
		keys[field.def.Number][identity] = true
	}
	return m, nil
}

func scalarWire(kind string) protowire.Type {
	switch kind {
	case "double", "fixed64", "sfixed64":
		return protowire.Fixed64Type
	case "float", "fixed32", "sfixed32":
		return protowire.Fixed32Type
	case "string", "bytes":
		return protowire.BytesType
	}
	if pinned.Enums[kind] != nil || kind == "int32" || kind == "int64" || kind == "uint32" || kind == "uint64" || kind == "sint32" || kind == "sint64" || kind == "bool" {
		return protowire.VarintType
	}
	return protowire.BytesType // Embedded message.
}

func validateScalar(kind string, data []byte) (int, error) {
	wire := scalarWire(kind)
	n := protowire.ConsumeFieldValue(1, wire, data)
	if n < 0 {
		return 0, ErrMalformed
	}
	if wire == protowire.VarintType {
		value, _ := protowire.ConsumeVarint(data)
		if kind == "bool" && value > 1 || kind == "uint32" && value > 1<<32-1 {
			return 0, ErrMalformed
		}
		if values := pinned.Enums[kind]; values != nil && !slices.Contains(values, value) {
			return 0, ErrUnsupported
		}
	}
	return n, nil
}

func (m *InferenceMessage) collect(message *wireMessage, key *wireField) error {
	if message.name == inferenceContentParts {
		return m.collectTextParts(message, key)
	}
	for _, field := range message.fields {
		if field.def.MapKey != "" {
			entryKey := field.child.field(1)
			// String map keys are actual user data and supply key/value detector
			// context. Integer map keys remain numeric, not detector text.
			var context *wireField
			if entryKey.def.Type == "string" {
				context = entryKey
			}
			if err := m.collect(field.child, context); err != nil {
				return err
			}
		} else if field.def.Type == "string" {
			label := []byte(field.def.Name)
			if key != nil && field != key {
				label = key.payload
			}
			// Check JSON escaping and repeated map-key context before copying
			// strings or marshaling. A small protobuf must not create an
			// arbitrarily amplified scanner projection.
			size := int64(3) + jsonStringSize(label) + jsonStringSize(field.payload)
			if len(m.slots) != 0 {
				size++
			}
			if m.jsonBytes+size > m.maxBytes {
				return ErrLimit
			}
			m.jsonBytes += size
			slot := textSlot{name: string(label), targets: []*wireField{field}, writable: writableText(message.name, field.def.Name)}
			if key != nil && field != key {
				slot.key = key
			}
			m.slots = append(m.slots, slot)
		} else if field.child != nil {
			if err := m.collect(field.child, key); err != nil {
				return err
			}
		}
	}
	return nil
}

// Segmented text is scanned as one logical string so a secret cannot evade
// detection by crossing a part boundary. Rewrites collapse that text into the
// first populated text field; parts with provider options or non-text variants
// remain unsupported because their per-part semantics are not established.
func (m *InferenceMessage) collectTextParts(message *wireMessage, key *wireField) error {
	var targets []*wireField
	var text []byte
	for _, field := range message.fields {
		part := field.child
		if part == nil {
			return ErrUnsupported
		}
		selected := part.field(1)
		if selected == nil || selected.child == nil {
			return ErrUnsupported
		}
		textPart := selected.child
		if textPart.field(2) != nil {
			return ErrUnsupported
		}
		content := textPart.field(1)
		if content == nil {
			continue
		}
		if int64(len(text))+int64(len(content.payload)) > m.maxBytes {
			return ErrLimit
		}
		text = append(text, content.payload...)
		targets = append(targets, content)
	}
	if len(targets) == 0 {
		return nil
	}
	label := []byte("text")
	if key != nil {
		label = key.payload
	}
	size := int64(3) + jsonStringSize(label) + jsonStringSize(text)
	if len(m.slots) != 0 {
		size++
	}
	if m.jsonBytes+size > m.maxBytes {
		return ErrLimit
	}
	m.jsonBytes += size
	slot := textSlot{name: string(label), targets: targets, writable: true}
	if key != nil {
		slot.key = key
	}
	m.slots = append(m.slots, slot)
	return nil
}

// Count encoding/json's string quoting without allocating its escaped output.
func jsonStringSize(data []byte) int64 {
	size := int64(2)
	for len(data) != 0 {
		r, n := utf8.DecodeRune(data)
		data = data[n:]
		switch r {
		case '"', '\\', '\b', '\f', '\n', '\r', '\t':
			size += 2
		case '<', '>', '&', '\u2028', '\u2029':
			size += 6
		default:
			if r < 0x20 {
				size += 6
			} else {
				size += int64(n)
			}
		}
	}
	return size
}

// Rewrite maps a successful scanner rewrite back onto the original wire tree.
// It never forwards the JSON projection as protobuf, silently drops fields, or
// modifies identifiers. The result is decoded again to verify the write-back.
func (m *InferenceMessage) Rewrite(scanned []byte) ([]byte, error) {
	if err := m.ctx.Err(); err != nil {
		return nil, err
	}
	if int64(len(scanned)) > m.maxBytes {
		return nil, ErrLimit
	}
	pairs, err := readProjection(scanned)
	if err != nil || len(pairs) != len(m.slots) {
		return nil, ErrRewrite
	}
	changes := make(map[*wireField][]byte)
	set := func(field *wireField, text string, writable bool) error {
		if !utf8.ValidString(text) {
			return ErrRewrite
		}
		if previous, ok := changes[field]; ok && string(previous) != text {
			return ErrRewrite
		}
		if string(field.payload) != text && !writable {
			return ErrUnsupported
		}
		changes[field] = []byte(text)
		return nil
	}
	for i, pair := range pairs {
		slot := m.slots[i]
		if slot.key != nil {
			if err := set(slot.key, pair[0], true); err != nil {
				return nil, err
			}
		} else if pair[0] != slot.name {
			return nil, ErrRewrite
		}
		if pair[1] != slot.text() {
			for index, target := range slot.targets {
				value := pair[1]
				if index != 0 {
					value = ""
				}
				if err := set(target, value, slot.writable); err != nil {
					return nil, err
				}
			}
		}
	}
	body, err := m.root.encode(changes, m.maxBytes)
	if err != nil {
		return nil, err
	}
	verified, err := decodeMessage(m.messageType, body, policy.DecodeLimits{MaxBytes: m.maxBytes, Context: m.ctx})
	if err != nil {
		return nil, ErrRewrite
	}
	actual, err := readProjection(verified.projection)
	if err != nil || !slices.Equal(actual, pairs) {
		return nil, ErrRewrite
	}
	return bytes.Clone(body), nil
}

// Read the exact projection shape so duplicate/extra JSON keys cannot be
// silently accepted by encoding/json's ordinary object decoder.
func readProjection(body []byte) ([][2]string, error) {
	d := json.NewDecoder(bytes.NewReader(body))
	expect := func(want any) bool {
		token, err := d.Token()
		return err == nil && token == want
	}
	if !expect(json.Delim('{')) || !expect("fields") || !expect(json.Delim('[')) {
		return nil, ErrRewrite
	}
	var result [][2]string
	for d.More() {
		if len(result) >= maxFields || !expect(json.Delim('{')) {
			return nil, ErrRewrite
		}
		token, err := d.Token()
		key, ok := token.(string)
		if err != nil || !ok {
			return nil, ErrRewrite
		}
		token, err = d.Token()
		value, ok := token.(string)
		if err != nil || !ok || !expect(json.Delim('}')) {
			return nil, ErrRewrite
		}
		result = append(result, [2]string{key, value})
	}
	if !expect(json.Delim(']')) || !expect(json.Delim('}')) {
		return nil, ErrRewrite
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, ErrRewrite
	}
	return result, nil
}
