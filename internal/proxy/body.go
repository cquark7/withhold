package proxy

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"errors"
	"io"
	"mime"
	"net/http"
	"strings"
	"sync"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
	"golang.org/x/net/html/charset"
)

var errCap = errors.New("body exceeds limit")
var errCapacity = errors.New("inspection capacity exceeded")

type budget struct {
	mu    sync.Mutex
	jobs  int
	bytes int64
}
type ticket struct {
	b    *budget
	used int64
	once sync.Once
}

func (b *budget) acquire() (*ticket, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.jobs >= 6 {
		return nil, errCapacity
	}
	b.jobs++
	return &ticket{b: b}, nil
}
func (t *ticket) add(n int) error {
	t.b.mu.Lock()
	defer t.b.mu.Unlock()
	if t.b.bytes+int64(n) > 64*1024*1024 {
		return errCapacity
	}
	t.b.bytes += int64(n)
	t.used += int64(n)
	return nil
}
func (t *ticket) release() {
	t.once.Do(func() {
		t.b.mu.Lock()
		t.b.jobs--
		t.b.bytes -= t.used
		t.b.mu.Unlock()
	})
}

// The transport closes an upload after sending it, independently of how long
// its response streams. Drop its buffered bytes and admission together.
type inspectedBody struct {
	mu     sync.Mutex
	reader io.ReadCloser
	ticket *ticket
}

func (b *inspectedBody) Read(data []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.reader == nil {
		return 0, io.EOF
	}
	return b.reader.Read(data)
}

func (b *inspectedBody) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.reader != nil {
		_ = b.reader.Close()
		b.reader = nil
	}
	b.ticket.release()
	return nil
}

func readBounded(r io.Reader, cap int64, t *ticket) ([]byte, error) {
	var out bytes.Buffer
	buf := make([]byte, 32*1024)
	for {
		n, err := r.Read(buf[:min(int64(len(buf)), cap+1-int64(out.Len()))])
		if n > 0 {
			if int64(out.Len())+int64(n) > cap {
				return nil, errCap
			}
			if t != nil {
				if e := t.add(n); e != nil {
					return nil, e
				}
			}
			_, _ = out.Write(buf[:n])
		}
		if err == io.EOF {
			return out.Bytes(), nil
		}
		if err != nil {
			return nil, err
		}
	}
}

func decodeBody(raw []byte, h http.Header, cap int64, t *ticket) ([]byte, error) {
	data := raw
	encodings := strings.Split(strings.ToLower(strings.Join(h.Values("Content-Encoding"), ",")), ",")
	for i := len(encodings) - 1; i >= 0; i-- {
		var reader io.Reader
		var closeReader func()
		var err error
		switch strings.TrimSpace(encodings[i]) {
		case "", "identity":
			continue
		case "gzip":
			var z *gzip.Reader
			z, err = gzip.NewReader(bytes.NewReader(data))
			if err == nil {
				reader = z
				closeReader = func() { _ = z.Close() }
			}
		case "deflate":
			var z io.ReadCloser
			z, err = zlib.NewReader(bytes.NewReader(data))
			if err != nil {
				z = flate.NewReader(bytes.NewReader(data))
				err = nil
			}
			reader = z
			closeReader = func() { _ = z.Close() }
		case "br":
			reader = brotli.NewReader(bytes.NewReader(data))
		case "zstd":
			var z *zstd.Decoder
			z, err = zstd.NewReader(bytes.NewReader(data), zstd.WithDecoderConcurrency(1), zstd.WithDecoderMaxMemory(uint64(cap)+1024*1024))
			if err == nil {
				reader = z
				closeReader = z.Close
			}
		default:
			return nil, errors.New("unsupported content encoding")
		}
		if err != nil {
			return nil, errors.New("invalid compressed body")
		}
		data, err = readBounded(reader, cap, t)
		if closeReader != nil {
			closeReader()
		}
		if err != nil {
			return nil, err
		}
	}
	_, params, err := mime.ParseMediaType(h.Get("Content-Type"))
	if err != nil && h.Get("Content-Type") != "" {
		return nil, errors.New("invalid content type")
	}
	label := strings.ToLower(params["charset"])
	if label != "" && label != "utf-8" && label != "utf8" {
		reader, err := charset.NewReaderLabel(label, bytes.NewReader(data))
		if err != nil {
			return nil, errors.New("unsupported body charset")
		}
		decoded, err := readBounded(reader, cap, t)
		// UTF-16 decoders can preserve the byte-order mark as U+FEFF. It is an
		// encoding signature rather than part of the JSON document.
		return bytes.TrimPrefix(decoded, []byte{0xef, 0xbb, 0xbf}), err
	}
	return data, nil
}

func bodyless(r *http.Request) bool {
	if len(r.TransferEncoding) > 0 || r.ContentLength > 0 || r.ContentLength < 0 {
		return false
	}
	for _, v := range r.Header.Values("Content-Length") {
		for _, s := range strings.Split(v, ",") {
			s = strings.TrimSpace(s)
			if s != "" && strings.Trim(s, "0") != "" {
				return false
			}
		}
	}
	return r.Header.Get("Transfer-Encoding") == ""
}
