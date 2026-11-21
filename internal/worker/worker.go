// Package worker scans request bodies over private stdin/stdout pipes.
package worker

import (
	"bufio"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"os"

	"github.com/cquark7/withhold/internal/detector"
	"github.com/cquark7/withhold/internal/pii"
	"github.com/cquark7/withhold/internal/scanner"
)

const (
	schema   = 1
	maxFrame = 128 * 1024 * 1024
)

type response struct {
	Schema  int            `json:"schema"`
	Engine  string         `json:"engine,omitempty"`
	Version string         `json:"version,omitempty"`
	PII     *pii.Metadata  `json:"pii,omitempty"`
	Report  scanner.Report `json:"report,omitempty"`
}

func readFrame(r io.Reader) ([]byte, error) {
	var header [4]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(header[:])
	if n > maxFrame {
		return nil, errors.New("scan input exceeds limit")
	}
	data := make([]byte, int(n))
	_, err := io.ReadFull(r, data)
	if errors.Is(err, io.EOF) {
		err = io.ErrUnexpectedEOF
	}
	return data, err
}

func writeFrame(w io.Writer, value any) error {
	data, err := json.Marshal(value)
	if err != nil {
		return errors.New("cannot encode scan report")
	}
	if len(data) > maxFrame {
		return errors.New("scan report exceeds limit")
	}
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(data)))
	if _, err = w.Write(header[:]); err != nil {
		return err
	}
	_, err = w.Write(data)
	return err
}

func serve(r io.Reader, w io.Writer, mode string) error {
	if mode == "--text" {
		return serveText(r, w)
	}
	d, err := detector.New(os.Getenv("WITHHOLD_PII"))
	if err != nil {
		return err
	}
	s := scanner.NewWithDebug(d, placeholderKey, os.Getenv("WITHHOLD_INTERNAL_DEBUG_FINDINGS") == "1")
	if err := writeFrame(w, response{Schema: schema, Engine: "withhold-scanner", Version: detector.Version, PII: d.PII()}); err != nil {
		return err
	}
	input := bufio.NewReader(r)
	for {
		data, err := readFrame(input)
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return errors.New("invalid scan frame")
		}
		if len(data) < 8 {
			return errors.New("invalid body frame")
		}
		maxBytes := int64(binary.BigEndian.Uint64(data[:8]))
		if err := writeFrame(w, response{Schema: schema, Report: s.Scan(data[8:], maxBytes)}); err != nil {
			return err
		}
	}
}

// Run serves one private worker mode inside the distributable executable.
func Run(mode string) error { return serve(os.Stdin, os.Stdout, mode) }

func ReadFrame(r io.Reader) ([]byte, error) { return readFrame(r) }
