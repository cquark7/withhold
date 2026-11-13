package cursor

import (
	"bytes"
	"compress/gzip"
	"errors"
	"io"
	"testing"

	"github.com/klauspost/compress/zstd"
	"google.golang.org/protobuf/encoding/protowire"
)

func fixtureReader(t *testing.T, data []byte, encoding uint64) (io.Reader, func()) {
	t.Helper()
	if encoding == 2 {
		z, err := gzip.NewReader(bytes.NewReader(data))
		if err != nil {
			t.Fatal(err)
		}
		return z, func() { _ = z.Close() }
	}
	z, err := zstd.NewReader(bytes.NewReader(data), zstd.WithDecoderConcurrency(1))
	if err != nil {
		t.Fatal(err)
	}
	return z, z.Close
}

func uintValue(t *testing.T, body []byte, number protowire.Number) uint64 {
	t.Helper()
	for len(body) > 0 {
		n, wire, tag := protowire.ConsumeTag(body)
		if tag < 0 {
			t.Fatal("invalid output tag")
		}
		size := protowire.ConsumeFieldValue(n, wire, body[tag:])
		if size < 0 {
			t.Fatal("invalid output value")
		}
		if n == number && wire == protowire.VarintType {
			value, _ := protowire.ConsumeVarint(body[tag:])
			return value
		}
		body = body[tag+size:]
	}
	t.Fatal("output field missing")
	return 0
}

func TestInferenceCompressionFailures(t *testing.T) {
	request := textRequest("Explain this function.")
	for _, encoding := range []uint64{1, 2} {
		data, err := compress(request, encoding, testCap)
		if err != nil {
			t.Fatal(err)
		}
		for _, test := range []struct {
			name string
			data []byte
			size uint64
			want error
		}{
			{"truncated", data[:len(data)-1], uint64(len(request)), ErrMalformed},
			{"wrong-size", data, uint64(len(request) + 1), ErrMalformed},
			{"advertised-over-cap", data, testCap + 1, ErrLimit},
			{"invalid-compression", []byte{0xff}, uint64(len(request)), ErrMalformed},
		} {
			t.Run(test.name+"/"+string(rune('0'+encoding)), func(t *testing.T) {
				wire := invocation(byteField(7, concat(uintField(1, encoding), uintField(2, test.size), byteField(3, test.data))))
				if message, err := DecodeRunInference(wire, testCap); message != nil || !errors.Is(err, test.want) {
					t.Fatalf("got %v, want %v", err, test.want)
				}
			})
		}
		large := bytes.Repeat([]byte("a"), 2*testCap)
		encoded, err := compress(large, encoding, testCap)
		if err != nil {
			t.Fatal(err)
		}
		// A lying decoded_size must not turn decompression into an unbounded read.
		wire := invocation(byteField(7, concat(uintField(1, encoding), uintField(2, 1), byteField(3, encoded))))
		if _, err := DecodeRunInference(wire, testCap); err == nil {
			t.Fatal("decompression overflow accepted")
		}
	}
	for _, request := range [][]byte{
		concat(uintField(1, 0), uintField(2, 0), byteField(3, nil)),
		concat(uintField(1, 99), uintField(2, 0), byteField(3, nil)),
	} {
		if _, err := DecodeRunInference(invocation(byteField(7, request)), testCap); !errors.Is(err, ErrUnsupported) {
			t.Fatalf("unsupported encoding accepted: %v", err)
		}
	}
	if _, err := compress(request, 2, 1); !errors.Is(err, ErrLimit) {
		t.Fatalf("compressed output cap not enforced: %v", err)
	}
}
