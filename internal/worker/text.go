package worker

import (
	"bufio"
	"context"
	"errors"
	"io"
	"os"
	"unicode/utf8"

	"github.com/cquark7/withhold/internal/detector"
	"github.com/cquark7/withhold/internal/pii"
)

type TextGreeting struct {
	Schema        int           `json:"schema"`
	Engine        string        `json:"engine"`
	Secrets       bool          `json:"secrets"`
	SecretVersion string        `json:"secret_version,omitempty"`
	PII           *pii.Metadata `json:"pii,omitempty"`
}

type TextResponse struct {
	Schema   int                    `json:"schema"`
	Findings []detector.TextFinding `json:"findings"`
	Error    string                 `json:"error,omitempty"`
}

func serveText(r io.Reader, w io.Writer) error {
	setting := os.Getenv("WITHHOLD_INTERNAL_SCAN_SECRETS")
	if setting != "0" && setting != "1" {
		return errors.New("invalid text worker selection")
	}
	secrets := setting == "1"
	d, err := detector.NewInspection(secrets, os.Getenv("WITHHOLD_PII"))
	if err != nil || !secrets && d.PII() == nil {
		return errors.New("cannot initialize text scanner")
	}
	hello := TextGreeting{Schema: 1, Engine: "withhold-text-scanner", Secrets: secrets, PII: d.PII()}
	if secrets {
		hello.SecretVersion = detector.Version
	}
	if err := writeFrame(w, hello); err != nil {
		return err
	}
	input := bufio.NewReader(r)
	for {
		data, err := readFrame(input)
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil || !utf8.Valid(data) {
			return errors.New("invalid text scan frame")
		}
		findings, err := d.Inspect(context.Background(), string(data))
		reply := TextResponse{Schema: 1, Findings: findings}
		if err != nil {
			reply.Error = "detector-error"
			if errors.Is(err, detector.ErrFindingLimit) {
				reply.Error = "finding-limit"
			}
		}
		if err := writeFrame(w, reply); err != nil {
			return err
		}
	}
}
