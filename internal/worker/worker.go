// Package worker scans request bodies over private stdin/stdout pipes.
package worker

import (
	"bufio"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"unicode/utf8"

	"github.com/cquark7/withhold/internal/detector"
	"github.com/cquark7/withhold/internal/pii"
	"github.com/cquark7/withhold/internal/scanner"
)

const (
	schema   = 1
	maxFrame = 128 * 1024 * 1024
)

type response struct {
	Schema   int                 `json:"schema"`
	Engine   string              `json:"engine,omitempty"`
	Version  string              `json:"version,omitempty"`
	PII      *pii.Metadata       `json:"pii,omitempty"`
	Findings *[]detector.Finding `json:"findings,omitempty"`
	Report   scanner.Report      `json:"report,omitempty"`
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
	if mode == "--jsonl" {
		return serveJSONL(r, w, s)
	}
	engine := "betterleaks"
	if mode == "--body" {
		engine = "withhold-scanner"
	}
	if err := writeFrame(w, response{Schema: schema, Engine: engine, Version: detector.Version, PII: d.PII()}); err != nil {
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
		if mode == "--body" {
			if len(data) < 8 {
				return errors.New("invalid body frame")
			}
			maxBytes := int64(binary.BigEndian.Uint64(data[:8]))
			if err := writeFrame(w, response{Schema: schema, Report: s.Scan(data[8:], maxBytes)}); err != nil {
				return err
			}
			continue
		}
		if !utf8.Valid(data) {
			return errors.New("scan input is not UTF-8")
		}
		findings, err := d.Scan(string(data))
		if err != nil {
			return err
		}
		if err := writeFrame(w, response{Schema: schema, Findings: &findings}); err != nil {
			return err
		}
	}
}

func serveJSONL(r io.Reader, w io.Writer, s *scanner.Scanner) error {
	input := bufio.NewScanner(r)
	input.Buffer(make([]byte, 64*1024), maxFrame)
	output := json.NewEncoder(w)
	for input.Scan() {
		var request struct {
			Body     string `json:"body_base64"`
			MaxBytes *int64 `json:"max_bytes"`
		}
		if json.Unmarshal(input.Bytes(), &request) != nil {
			return errors.New("invalid scanner request")
		}
		body, err := base64.StdEncoding.DecodeString(request.Body)
		if err != nil {
			return errors.New("invalid scanner request")
		}
		maxBytes := int64(scanner.DefaultMaxBytes)
		if request.MaxBytes != nil {
			maxBytes = *request.MaxBytes
		}
		if err := output.Encode(s.Scan(body, maxBytes)); err != nil {
			return err
		}
	}
	return input.Err()
}

func Main() {
	defer func() {
		if recover() != nil {
			fmt.Fprintln(os.Stderr, "withhold-scanner: detector failed")
			os.Exit(1)
		}
	}()
	mode := ""
	if len(os.Args) == 2 {
		mode = os.Args[1]
	}
	if len(os.Args) > 2 || (mode != "" && mode != "--body" && mode != "--jsonl" && mode != "--text") {
		fmt.Fprintln(os.Stderr, "usage: withhold-scanner [--body|--jsonl|--text] (private stdin/stdout)")
		os.Exit(2)
	}
	if err := serve(os.Stdin, os.Stdout, mode); err != nil {
		fmt.Fprintln(os.Stderr, "withhold-scanner: scan failed")
		os.Exit(1)
	}
}

// Run serves one private worker mode inside the distributable executable.
func Run(mode string) error { return serve(os.Stdin, os.Stdout, mode) }

func ReadFrame(r io.Reader) ([]byte, error) { return readFrame(r) }
