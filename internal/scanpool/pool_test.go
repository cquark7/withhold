package scanpool

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"io"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/cquark7/withhold/internal/scanner"
	"github.com/cquark7/withhold/internal/worker"
)

// The test executable substitutes deterministic pipe peers for failure tests.
func TestPipePeer(t *testing.T) {
	mode := os.Getenv("WITHHOLD_TEST_POOL_PEER")
	if mode == "" {
		return
	}
	send := func(v any) {
		data, _ := json.Marshal(v)
		_ = binary.Write(os.Stdout, binary.BigEndian, uint32(len(data)))
		_, _ = os.Stdout.Write(data)
	}
	if mode == "no-greeting" {
		time.Sleep(time.Hour)
		os.Exit(0)
	}
	send(map[string]any{"schema": 1, "engine": "withhold-scanner", "version": "1.10.1"})
	for {
		body, err := worker.ReadFrame(os.Stdin)
		if err == io.EOF {
			os.Exit(0)
		}
		if err != nil {
			os.Exit(1)
		}
		if mode == "hang" {
			time.Sleep(time.Hour)
		}
		if mode == "crash" {
			os.Exit(1)
		}
		if mode == "slow-clean" {
			time.Sleep(100 * time.Millisecond)
		}
		if mode == "bad-report" {
			send(map[string]any{"schema": 1, "report": map[string]any{"status": "clean"}})
			continue
		}
		if len(body) < 8 {
			os.Exit(1)
		}
		stats := map[string]int{}
		for _, key := range statKeys {
			stats[key] = 0
		}
		send(map[string]any{"schema": 1, "report": map[string]any{"status": "clean", "units": 0, "stats": stats}})
	}
}

func testPool(t *testing.T, mode string) *Pool {
	t.Helper()
	t.Setenv("WITHHOLD_TEST_POOL_PEER", mode)
	p := New(os.Args[0], "-test.run=^TestPipePeer$")
	t.Cleanup(p.Close)
	return p
}

func TestTimeoutKillsPeerDuringGreetingAndScan(t *testing.T) {
	for _, mode := range []string{"no-greeting", "hang", "crash", "bad-report"} {
		t.Run(mode, func(t *testing.T) {
			p := testPool(t, mode)
			ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
			defer cancel()
			if _, err := p.Scan(ctx, []byte(`{}`), 1024); err == nil {
				t.Fatal("unsafe peer accepted")
			}
			for _, c := range p.children {
				c.mu.Lock()
				live := c.cmd != nil
				c.mu.Unlock()
				if live {
					t.Fatal("failed peer was not reaped")
				}
			}
		})
	}
}

func TestPIIConfigurationCannotUseAnOlderSecretOnlyPeer(t *testing.T) {
	t.Setenv("WITHHOLD_PII", "aadhaar")
	p := testPool(t, "clean")
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := p.Scan(ctx, []byte(`{}`), 1024); err == nil {
		t.Fatal("PII-enabled pool accepted a secret-only greeting")
	}
}

func TestIdleReapRestartsGreetingAndClosedPoolRefusesScans(t *testing.T) {
	p := testPool(t, "clean")
	p.idleTimeout = 20 * time.Millisecond
	for range 4 {
		if _, err := p.Scan(context.Background(), []byte(`{}`), 1024); err != nil {
			t.Fatal(err)
		}
		time.Sleep(40 * time.Millisecond)
	}
	p.Close()
	if _, err := p.Scan(context.Background(), []byte(`{}`), 1024); err == nil {
		t.Fatal("closed pool succeeded")
	}
}

func TestSequentialScansReuseOneWorker(t *testing.T) {
	p := testPool(t, "clean")
	for range 6 {
		if _, err := p.Scan(context.Background(), []byte(`{}`), 1024); err != nil {
			t.Fatal(err)
		}
	}
	live := 0
	for _, c := range p.children {
		c.mu.Lock()
		if c.cmd != nil {
			live++
		}
		c.mu.Unlock()
	}
	if live != 1 {
		t.Fatalf("sequential scans started %d workers; want one reused worker", live)
	}
}

func TestOverlappingScansStartAdditionalWorkers(t *testing.T) {
	p := testPool(t, "slow-clean")
	var wg sync.WaitGroup
	for range 3 {
		wg.Go(func() {
			if _, err := p.Scan(context.Background(), []byte(`{}`), 1024); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	for _, c := range p.children {
		c.mu.Lock()
		live := c.cmd != nil
		c.mu.Unlock()
		if !live {
			t.Fatal("overlapping scans did not start all three workers")
		}
	}
}

func TestCloseCancelsRunningAndQueuedScans(t *testing.T) {
	p := testPool(t, "hang")
	var wg sync.WaitGroup
	for range 6 {
		wg.Go(func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if _, err := p.Scan(ctx, []byte(`{}`), 1024); err == nil {
				t.Error("shutdown returned success")
			}
		})
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		p.mu.Lock()
		jobs := p.jobs
		p.mu.Unlock()
		if jobs == 6 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("scans were not admitted")
		}
		time.Sleep(time.Millisecond)
	}
	if _, err := p.Scan(context.Background(), []byte(`{}`), 1024); err == nil {
		t.Fatal("capacity not enforced")
	}
	p.Close()
	wg.Wait()
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.jobs != 0 || p.bytes != 0 {
		t.Fatal("reservation leaked")
	}
}

func TestMalformedSuccessReportsFailClosed(t *testing.T) {
	for _, r := range []scanner.Report{{"status": "clean"}, {"status": "unknown"}, {"status": "clean", "units": -1.0, "stats": map[string]any{}}, {"status": "redacted", "units": 0.0, "stats": map[string]any{}, "body_base64": "%%%"}} {
		if validReport(r) {
			t.Fatalf("accepted incompatible %v", r)
		}
	}
}

func TestDuplicateKeyFailureReportIsAccepted(t *testing.T) {
	if !validReport(scanner.Report{"status": "scanner-error", "reason": "duplicate JSON object key"}) {
		t.Fatal("duplicate-key failure rejected as an incompatible worker report")
	}
}

func TestDebugReportIsAcceptedOnlyForAnEnabledPool(t *testing.T) {
	stats := map[string]any{}
	for _, key := range statKeys {
		stats[key] = 0.0
	}
	stats["units"] = 1.0
	report := scanner.Report{
		"status": "redacted", "units": 1.0, "stats": stats,
		"body_base64": "e30=", "rule_ids": []any{"generic-api-key"},
		"findings": 1.0, "placeholders": 1.0,
		"debug_findings": []any{map[string]any{
			"detected_masked": "syn…", "placeholder": "<WITHHELD_0123456789abcdef>",
			"rule_ids": []any{"generic-api-key"},
		}},
	}
	if validReport(report) {
		t.Fatal("accepted raw finding data when debugging is disabled")
	}
	if !validReportWithDebug(report, true) {
		t.Fatal("rejected valid opt-in debug findings")
	}
	report["debug_findings"] = []any{map[string]any{
		"detected_masked": "synthetic-key", "placeholder": "<WITHHELD_0123456789abcdef>",
		"rule_ids": []any{"generic-api-key"},
	}}
	if validReportWithDebug(report, true) {
		t.Fatal("accepted unmasked finding data from an enabled worker")
	}
	if validReportWithDebug(scanner.Report{"status": "redacted", "units": 1.0, "stats": stats, "body_base64": "e30=", "rule_ids": []any{"generic-api-key"}, "findings": 1.0, "placeholders": 1.0}, true) {
		t.Fatal("accepted missing debug findings from an enabled worker")
	}
}
