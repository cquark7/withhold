package cursor

import (
	"bytes"
	"compress/gzip"
	"io"

	"github.com/klauspost/compress/zstd"
	"google.golang.org/protobuf/encoding/protowire"
)

func (d *decoder) expand(message *wireMessage, depth int) error {
	encoding, size, data := message.field(1), message.field(2), message.field(3)
	if encoding == nil || size == nil || data == nil {
		return ErrMalformed
	}
	remaining := d.maxBytes - d.decoded
	if int64(size.uint()) > remaining {
		return ErrLimit
	}
	var reader io.Reader
	var closeReader func()
	switch encoding.uint() {
	case 1:
		z, err := zstd.NewReader(bytes.NewReader(data.payload), zstd.WithDecoderConcurrency(1), zstd.WithDecoderMaxMemory(uint64(d.maxBytes)+1024*1024))
		if err != nil {
			return ErrMalformed
		}
		reader, closeReader = z, z.Close
	case 2:
		z, err := gzip.NewReader(bytes.NewReader(data.payload))
		if err != nil {
			return ErrMalformed
		}
		reader, closeReader = z, func() { _ = z.Close() }
	default:
		return ErrUnsupported
	}
	defer closeReader()
	// The advertised size is also a hard expansion bound. Reserve it before
	// allocating; a lying small size cannot force a full-cap expansion.
	if d.reserve != nil {
		if err := d.reserve(int(size.uint()) + 1); err != nil {
			return err
		}
	}
	decoded, err := io.ReadAll(io.LimitReader(reader, int64(size.uint())+1))
	if uint64(len(decoded)) > size.uint() {
		return ErrLimit
	}
	if err != nil || uint64(len(decoded)) != size.uint() {
		return ErrMalformed
	}
	d.decoded += int64(len(decoded))
	data.child, err = d.message(inferenceRequest, decoded, depth+1)
	message.compression = encoding.uint()
	return err
}

type limitedBuffer struct {
	bytes.Buffer
	max int64
}

func (b *limitedBuffer) Write(data []byte) (int, error) {
	if int64(b.Len())+int64(len(data)) > b.max {
		return 0, ErrLimit
	}
	return b.Buffer.Write(data)
}

func compress(data []byte, encoding uint64, maxBytes int64) ([]byte, error) {
	buffer := &limitedBuffer{max: maxBytes}
	var writer io.WriteCloser
	if encoding == 2 {
		writer = gzip.NewWriter(buffer)
	} else {
		z, err := zstd.NewWriter(buffer, zstd.WithEncoderConcurrency(1))
		if err != nil {
			return nil, ErrRewrite
		}
		writer = z
	}
	if _, err := writer.Write(data); err != nil {
		_ = writer.Close()
		return nil, ErrLimit
	}
	if err := writer.Close(); err != nil {
		return nil, ErrLimit
	}
	return buffer.Bytes(), nil
}

func (m *wireMessage) encode(changes map[*wireField][]byte, maxBytes int64) ([]byte, error) {
	if m.ctx != nil {
		if err := m.ctx.Err(); err != nil {
			return nil, err
		}
	}
	values := make(map[*wireField][]byte)
	for _, field := range m.fields {
		if text, ok := changes[field]; ok && !bytes.Equal(text, field.payload) {
			values[field] = protowire.AppendBytes(nil, text)
		}
		if field.child == nil {
			continue
		}
		child, err := field.child.encode(changes, maxBytes)
		if err != nil {
			return nil, err
		}
		if bytes.Equal(child, field.child.raw) {
			continue
		}
		if m.compression != 0 && field.def.Number == 3 {
			values[m.field(2)] = protowire.AppendVarint(nil, uint64(len(child)))
			child, err = compress(child, m.compression, maxBytes)
			if err != nil {
				return nil, err
			}
		}
		values[field] = protowire.AppendBytes(nil, child)
	}
	if len(values) == 0 {
		return m.raw, nil
	}
	// Check the complete output size before allocating/copying the rewritten
	// message; unchanged fields keep their original tags, lengths, and bytes.
	size := int64(len(m.raw))
	for field, value := range values {
		size += int64(field.tagSize + len(value) - len(field.raw))
	}
	if size > maxBytes {
		return nil, ErrLimit
	}
	result := make([]byte, 0, int(size))
	for _, field := range m.fields {
		if value, ok := values[field]; ok {
			result = append(result, field.raw[:field.tagSize]...)
			result = append(result, value...)
		} else {
			result = append(result, field.raw...)
		}
	}
	return result, nil
}
