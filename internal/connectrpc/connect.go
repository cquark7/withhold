// Package connectrpc implements bounded Connect request envelopes and header
// validation. It knows nothing about applications, protobuf schemas, or policy.
package connectrpc

import (
	"encoding/binary"
	"errors"
	"io"
	"mime"
	"net/http"
	"strings"
)

var (
	ErrMalformed   = errors.New("malformed Connect request")
	ErrUnsupported = errors.New("unsupported Connect request")
	ErrLimit       = errors.New("Connect request limit exceeded")
)

// Request describes transport only. Compression applies independently to each
// envelope, never to a continuing compression context.
type Request struct {
	Streaming   bool
	Compression string
}

func Parse(r *http.Request, streaming, duplex bool) (Request, error) {
	result := Request{Streaming: streaming}
	// Connect GET carries content in its URL. Reject all query-bearing RPCs,
	// including POST variants, instead of treating them as bodyless metadata.
	if r.Method != http.MethodPost || r.URL.RawQuery != "" || r.URL.ForceQuery ||
		len(r.Trailer) != 0 || r.Header.Get("Trailer") != "" {
		return result, ErrUnsupported
	}
	if duplex && (!streaming || r.ProtoMajor != 2) {
		return result, ErrUnsupported
	}
	if len(r.Header.Values("Content-Type")) != 1 {
		return result, ErrMalformed
	}
	media, params, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	want := "application/proto"
	if streaming {
		want = "application/connect+proto"
	}
	if err != nil || media != want || len(params) != 0 {
		return result, ErrUnsupported
	}
	if version := r.Header.Values("Connect-Protocol-Version"); len(version) > 1 ||
		len(version) == 1 && version[0] != "1" {
		return result, ErrUnsupported
	}
	if streaming {
		// HTTP compression would span envelope boundaries and defeat bounded
		// message admission. Streaming uses Connect message compression only.
		if len(r.Header.Values("Content-Encoding")) > 1 {
			return result, ErrUnsupported
		}
		if encoding := strings.TrimSpace(r.Header.Get("Content-Encoding")); encoding != "" && encoding != "identity" {
			return result, ErrUnsupported
		}
		encodings := r.Header.Values("Connect-Content-Encoding")
		if len(encodings) > 1 {
			return result, ErrUnsupported
		}
		result.Compression = strings.ToLower(strings.TrimSpace(r.Header.Get("Connect-Content-Encoding")))
		switch result.Compression {
		case "", "identity", "gzip", "br", "zstd", "deflate":
		default:
			return result, ErrUnsupported
		}
	}
	return result, nil
}

type Frame struct {
	Flags byte
	Data  []byte
}

// ReadFrame validates length/flags and reserves aggregate capacity before
// allocating a payload. EOF is clean only between complete envelopes.
func ReadFrame(r io.Reader, maxBytes int64, reserve func(int) error) (Frame, error) {
	var header [5]byte
	n, err := io.ReadFull(r, header[:])
	if n == 0 && err == io.EOF {
		return Frame{}, io.EOF
	}
	if err != nil {
		return Frame{}, ErrMalformed
	}
	if header[0]&^byte(1) != 0 {
		// EndStreamResponse and reserved flags are never request messages.
		return Frame{}, ErrUnsupported
	}
	size := int64(binary.BigEndian.Uint32(header[1:]))
	if maxBytes < 5 || size > maxBytes-5 {
		return Frame{}, ErrLimit
	}
	if reserve != nil {
		if err := reserve(int(size) + 5); err != nil {
			return Frame{}, err
		}
	}
	frame := Frame{Flags: header[0], Data: make([]byte, int(size))}
	if _, err := io.ReadFull(r, frame.Data); err != nil {
		return Frame{}, ErrMalformed
	}
	return frame, nil
}

func Envelope(flags byte, payload []byte, maxBytes int64) ([]byte, error) {
	if int64(len(payload))+5 > maxBytes || uint64(len(payload)) > 1<<32-1 {
		return nil, ErrLimit
	}
	result := make([]byte, 5+len(payload))
	result[0] = flags
	binary.BigEndian.PutUint32(result[1:5], uint32(len(payload)))
	copy(result[5:], payload)
	return result, nil
}
