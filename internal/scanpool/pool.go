// Package scanpool bounds and isolates scanning from the native proxy.
package scanpool

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/cquark7/withhold/internal/pii"
	"github.com/cquark7/withhold/internal/scanner"
	"github.com/cquark7/withhold/internal/worker"
)

var errScan = errors.New("native scanner failed")

type child struct {
	mu            sync.Mutex
	cmd           *exec.Cmd
	in            io.WriteCloser
	out           io.ReadCloser
	generation    uint64
	closed, ready bool
	idle          *time.Timer
}

type Pool struct {
	binary      string
	args        []string
	available   chan struct{}
	idle        []*child
	children    []*child
	mu          sync.Mutex
	bytes       int64
	jobs        int
	closed      bool
	environment []string
	pii         *pii.Metadata
	configErr   error
	debug       bool
	done        chan struct{}
	idleTimeout time.Duration
}

func New(binary string, args ...string) *Pool {
	return NewWithEnvironment(binary, os.Environ(), args...)
}

func NewWithEnvironment(binary string, environment []string, args ...string) *Pool {
	p := &Pool{binary: binary, args: args, available: make(chan struct{}, 3), done: make(chan struct{}), idleTimeout: 60 * time.Second}
	p.environment = append([]string{}, environment...)
	selection := ""
	debug := false
	for _, entry := range p.environment {
		key, value, _ := strings.Cut(entry, "=")
		if strings.EqualFold(key, "WITHHOLD_PII") {
			selection = value
		}
		if strings.EqualFold(key, "WITHHOLD_INTERNAL_DEBUG_FINDINGS") && value == "1" {
			debug = true
		}
	}
	p.debug = debug
	p.pii, p.configErr = pii.ConfigurationFor(selection)
	for range 3 {
		c := &child{}
		p.children = append(p.children, c)
		p.idle = append(p.idle, c)
		p.available <- struct{}{}
	}
	return p
}

// discard is called with c.mu held. Exactly one caller waits on each child.
func (c *child) discard() {
	if c.cmd == nil {
		return
	}
	_ = c.cmd.Process.Kill()
	_ = c.cmd.Wait()
	_ = c.in.Close()
	_ = c.out.Close()
	c.cmd = nil
	c.ready = false
}

func (p *Pool) Close() {
	p.mu.Lock()
	if !p.closed {
		p.closed = true
		close(p.done)
	}
	p.mu.Unlock()
	for _, c := range p.children {
		c.mu.Lock()
		c.closed = true
		if c.idle != nil {
			c.idle.Stop()
		}
		c.discard()
		c.mu.Unlock()
	}
}

func (p *Pool) Scan(ctx context.Context, body []byte, maxBytes int64) (scanner.Report, error) {
	if p.configErr != nil {
		return nil, p.configErr
	}
	size := int64(len(body)) + 8
	p.mu.Lock()
	if p.closed || p.jobs >= 6 || size > 128*1024*1024 || p.bytes+size > 64*1024*1024 {
		p.mu.Unlock()
		return nil, errors.New("native scanner capacity exceeded")
	}
	p.jobs++
	p.bytes += size
	p.mu.Unlock()
	defer func() { p.mu.Lock(); p.jobs--; p.bytes -= size; p.mu.Unlock() }()
	select {
	case <-p.available:
	case <-ctx.Done():
		return nil, errScan
	case <-p.done:
		return nil, errScan
	}
	// Reuse the most recently returned child. Sequential traffic should pay
	// for one detector process; additional children start only under overlap.
	p.mu.Lock()
	last := len(p.idle) - 1
	c := p.idle[last]
	p.idle = p.idle[:last]
	p.mu.Unlock()
	defer func() {
		p.mu.Lock()
		p.idle = append(p.idle, c)
		p.available <- struct{}{}
		p.mu.Unlock()
	}()
	c.mu.Lock()
	c.generation++
	generation := c.generation
	if c.idle != nil {
		c.idle.Stop()
	}
	if c.closed || ctx.Err() != nil {
		c.mu.Unlock()
		return nil, errScan
	}
	if c.cmd == nil {
		cmd := exec.Command(p.binary, p.args...)
		cmd.Env = p.environment
		in, err := cmd.StdinPipe()
		if err != nil {
			c.mu.Unlock()
			return nil, errScan
		}
		out, err := cmd.StdoutPipe()
		if err != nil {
			_ = in.Close()
			c.mu.Unlock()
			return nil, errScan
		}
		if err = cmd.Start(); err != nil {
			_ = in.Close()
			_ = out.Close()
			c.mu.Unlock()
			return nil, errScan
		}
		c.cmd, c.in, c.out = cmd, in, out
	}
	cmd, in, out, first := c.cmd, c.in, c.out, !c.ready
	c.mu.Unlock()

	done := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { _ = cmd.Process.Kill(); close(done) })
	var report scanner.Report
	var scanErr error
	func() {
		if first {
			data, err := worker.ReadFrame(out)
			if err != nil {
				scanErr = err
				return
			}
			var hello struct {
				Schema          int
				Engine, Version string
				PII             *pii.Metadata
			}
			if json.Unmarshal(data, &hello) != nil || hello.Schema != 1 || hello.Engine != "withhold-scanner" || hello.Version != "1.10.0" || !reflect.DeepEqual(hello.PII, p.pii) {
				scanErr = errScan
				return
			}
			c.mu.Lock()
			c.ready = true
			c.mu.Unlock()
		}
		var prefix [12]byte
		binary.BigEndian.PutUint32(prefix[:4], uint32(size))
		binary.BigEndian.PutUint64(prefix[4:], uint64(maxBytes))
		if _, err := in.Write(prefix[:]); err != nil {
			scanErr = err
			return
		}
		if _, err := in.Write(body); err != nil {
			scanErr = err
			return
		}
		data, err := worker.ReadFrame(out)
		if err != nil {
			scanErr = err
			return
		}
		var response struct {
			Schema int
			Report scanner.Report
		}
		if json.Unmarshal(data, &response) != nil || response.Schema != 1 || !validReportWithDebug(response.Report, p.debug) {
			scanErr = errScan
			return
		}
		report = response.Report
	}()
	if !stop() {
		<-done
		scanErr = errScan
	}
	c.mu.Lock()
	if scanErr != nil || c.closed || ctx.Err() != nil {
		c.discard()
		scanErr = errScan
	} else {
		c.idle = time.AfterFunc(p.idleTimeout, func() {
			c.mu.Lock()
			defer c.mu.Unlock()
			if c.generation == generation {
				c.discard()
			}
		})
	}
	c.mu.Unlock()
	p.mu.Lock()
	closed := p.closed
	p.mu.Unlock()
	if scanErr != nil || closed {
		return nil, errScan
	}
	return report, nil
}

// Never let an incompatible worker reply become permission to forward a body.
func validReport(r scanner.Report) bool {
	return validReportWithDebug(r, false)
}

func validReportWithDebug(r scanner.Report, debug bool) bool {
	if r == nil {
		return false
	}
	count := func(v any) bool {
		n, ok := v.(float64)
		return ok && n >= 0 && n <= float64(1<<53) && n == float64(int64(n))
	}
	allowed := map[string]bool{}
	for _, key := range []string{"status", "units", "stats", "reason", "size", "max_bytes", "body_base64", "rule_ids", "findings", "placeholders", "debug_findings"} {
		allowed[key] = true
	}
	for key := range r {
		if !allowed[key] {
			return false
		}
	}
	if stats, exists := r["stats"]; exists {
		m, ok := stats.(map[string]any)
		if !ok || len(m) != len(statKeys) {
			return false
		}
		for _, key := range statKeys {
			if !count(m[key]) {
				return false
			}
		}
	}
	if rules, exists := r["rule_ids"]; exists {
		list, ok := rules.([]any)
		if !ok {
			return false
		}
		for _, rule := range list {
			if _, ok := rule.(string); !ok {
				return false
			}
		}
	}
	status, _ := r["status"].(string)
	debugValue, hasDebug := r["debug_findings"]
	if hasDebug && !debug || hasDebug && status != "redacted" {
		return false
	}
	switch status {
	case "clean", "redacted":
		if !count(r["units"]) {
			return false
		}
		stats, ok := r["stats"].(map[string]any)
		if !ok {
			return false
		}
		for _, v := range stats {
			if !count(v) {
				return false
			}
		}
		if stats["units"] != r["units"] {
			return false
		}
		if status == "redacted" {
			body, ok := r["body_base64"].(string)
			if !ok {
				return false
			}
			if _, err := base64.StdEncoding.Strict().DecodeString(body); err != nil {
				return false
			}
			if !count(r["findings"]) || !count(r["placeholders"]) || r["findings"] == 0.0 || r["placeholders"] == 0.0 {
				return false
			}
			rules, ok := r["rule_ids"].([]any)
			if !ok {
				return false
			}
			for _, v := range rules {
				if _, ok := v.(string); !ok {
					return false
				}
			}
			if debug {
				rows, ok := debugValue.([]any)
				if !hasDebug || !ok || len(rows) == 0 {
					return false
				}
				for _, row := range rows {
					finding, ok := row.(map[string]any)
					if !ok || len(finding) != 3 {
						return false
					}
					detected, detectedOK := finding["detected_masked"].(string)
					placeholder, placeholderOK := finding["placeholder"].(string)
					ids, idsOK := finding["rule_ids"].([]any)
					if !detectedOK || !scanner.ValidDebugMask(detected) || !placeholderOK || !strings.HasPrefix(placeholder, "<WITHHELD_") || !idsOK || len(ids) == 0 {
						return false
					}
					for _, id := range ids {
						if _, ok := id.(string); !ok {
							return false
						}
					}
				}
			} else if hasDebug {
				return false
			}
		}
	case "over-cap", "over-cap-decoded":
		if !count(r["size"]) || !count(r["max_bytes"]) {
			return false
		}
	case "skipped-not-json", "scanner-error", "finding-without-secret":
		reason, ok := r["reason"].(string)
		if !ok || !safeReasons[reason] {
			return false
		}
	default:
		return false
	}
	if status != "redacted" {
		if _, ok := r["body_base64"]; ok {
			return false
		}
		if hasDebug {
			return false
		}
	}
	return true
}

var statKeys = []string{"units", "sweep_unrewritable", "skipped_data_media", "skipped_base64_blobs", "skipped_tools", "skipped_short", "chunked_large", "carved_attachments", "path_collisions", "b64_roundtrip"}
var safeReasons = map[string]bool{
	"body is not utf-8 text": true, "body is not JSON": true, "JSON too deeply nested": true,
	"top-level JSON is not an object": true, "body contains invalid Unicode": true,
	"duplicate JSON object key":                                         true,
	"duplicate JSON path across leaves - write-back would be ambiguous": true,
	"scanner input exceeds limit":                                       true, "detector failed": true, "scanner finding lacks both Secret and Match": true,
	"key rename would collide": true, "key write-back miss": true, "base64 write-back on malformed data URL": true,
	"base64 write-back decode failed": true, "redaction verification failed: secret fragment survived": true,
	"redaction verification failed: secret bytes survived in body": true, "secret survives decoded inside base64/data: leaf": true,
}
