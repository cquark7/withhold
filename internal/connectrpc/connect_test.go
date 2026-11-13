package connectrpc

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRequestTransportValidation(t *testing.T) {
	for _, test := range []struct {
		name, method, path, media, compression string
		stream, duplex, bad                    bool
	}{
		{"unary", "POST", "/service/Method", "application/proto", "", false, false, false},
		{"stream", "POST", "/service/Method", "application/connect+proto", "gzip", true, true, false},
		{"get-payload", "GET", "/service/Method?message=secret", "application/proto", "", false, false, true},
		{"post-query", "POST", "/service/Method?message=secret", "application/proto", "", false, false, true},
		{"empty-query", "POST", "/service/Method?", "application/proto", "", false, false, true},
		{"json", "POST", "/service/Method", "application/connect+json", "", true, false, true},
		{"grpc", "POST", "/service/Method", "application/grpc", "", true, false, true},
		{"charset", "POST", "/service/Method", "application/proto; charset=utf-8", "", false, false, true},
		{"unknown-compression", "POST", "/service/Method", "application/connect+proto", "new", true, false, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			r := httptest.NewRequest(test.method, test.path, nil)
			r.ProtoMajor = 2
			r.Header.Set("Content-Type", test.media)
			r.Header.Set("Connect-Content-Encoding", test.compression)
			got, err := Parse(r, test.stream, test.duplex)
			if (err != nil) != test.bad {
				t.Fatalf("error %v", err)
			}
			if err == nil && got.Streaming != test.stream {
				t.Fatal("wrong framing")
			}
		})
	}
	for _, mutate := range []func(*http.Request){
		func(r *http.Request) { r.Header.Add("Content-Type", "application/connect+proto") },
		func(r *http.Request) { r.Header.Add("Connect-Protocol-Version", "2") },
		func(r *http.Request) { r.Header.Set("Content-Encoding", "gzip") },
		func(r *http.Request) {
			r.Header.Add("Connect-Content-Encoding", "gzip")
			r.Header.Add("Connect-Content-Encoding", "gzip")
		},
		func(r *http.Request) { r.Trailer = http.Header{"Digest": nil} },
		func(r *http.Request) { r.ProtoMajor = 1 },
	} {
		r := httptest.NewRequest("POST", "/service/Method", nil)
		r.ProtoMajor = 2
		r.Header.Set("Content-Type", "application/connect+proto")
		mutate(r)
		if _, err := Parse(r, true, true); err == nil {
			t.Fatal("unsupported headers accepted")
		}
	}
}

func TestEnvelopeBoundsAndReservation(t *testing.T) {
	wire, err := Envelope(1, []byte("payload"), 12)
	if err != nil {
		t.Fatal(err)
	}
	reserved := 0
	frame, err := ReadFrame(bytes.NewReader(wire), 12, func(n int) error { reserved += n; return nil })
	if err != nil || frame.Flags != 1 || string(frame.Data) != "payload" || reserved != 12 {
		t.Fatalf("bad round trip: %v", err)
	}
	capacity := errors.New("capacity")
	if _, err := ReadFrame(bytes.NewReader(wire), 12, func(int) error { return capacity }); !errors.Is(err, capacity) {
		t.Fatal("reservation error was lost")
	}
	for _, data := range [][]byte{wire[:1], wire[:4], wire[:len(wire)-1]} {
		if _, err := ReadFrame(bytes.NewReader(data), 100, nil); !errors.Is(err, ErrMalformed) {
			t.Fatal("truncated envelope accepted")
		}
	}
	for _, flags := range []byte{2, 3, 4, 128, 255} {
		bad := bytes.Clone(wire)
		bad[0] = flags
		if _, err := ReadFrame(bytes.NewReader(bad), 100, nil); !errors.Is(err, ErrUnsupported) {
			t.Fatal("request flags accepted")
		}
	}
	if _, err := ReadFrame(bytes.NewReader(nil), 0, nil); err != io.EOF {
		t.Fatal("boundary EOF failed")
	}
	if _, err := ReadFrame(bytes.NewReader(wire), 11, nil); !errors.Is(err, ErrLimit) {
		t.Fatal("length cap failed")
	}
	if _, err := Envelope(0, []byte("payload"), 11); !errors.Is(err, ErrLimit) {
		t.Fatal("output cap failed")
	}
}

func FuzzReadFrame(f *testing.F) {
	f.Add([]byte{0, 0, 0, 0, 0})
	f.Add([]byte{1, 0, 0, 0, 3, 'a', 'b', 'c'})
	f.Fuzz(func(t *testing.T, data []byte) {
		frame, err := ReadFrame(bytes.NewReader(data), 4096, nil)
		if err != nil {
			return
		}
		wire, err := Envelope(frame.Flags, frame.Data, 4096)
		if err != nil || !bytes.Equal(wire, data[:len(wire)]) {
			t.Fatal("envelope changed")
		}
	})
}
