package session

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/cquark7/withhold/internal/certstore"
	"github.com/cquark7/withhold/internal/control"
	"github.com/cquark7/withhold/internal/detector"
	"github.com/cquark7/withhold/internal/integration"
	"github.com/cquark7/withhold/internal/pii"
	"github.com/cquark7/withhold/internal/scanpool"
)

type check struct {
	ID     string `json:"id"`
	Status string `json:"status"`
	Detail string `json:"detail"`
	Fix    string `json:"fix"`
}

func exists(path string) bool { _, err := os.Stat(path); return err == nil }
func status(o Options, e integration.Target, r Record, recordErr error) int {
	state, h := ownership(o.Port, r)
	var pid any
	if h != nil {
		pid = h.PID
	}
	settings := map[string]any{"path": e.Resource, "http_proxy": nil, "clean": true, "error": nil}
	if recordErr == nil {
		e.Resource = r.Resource
		settings["path"] = e.Resource
	}
	appState, err := o.Application.Read(e)
	if err != nil {
		settings["error"] = err.Error()
	} else if appState.Proxy != nil {
		settings["http_proxy"] = appState.Proxy
		settings["clean"] = false
	}
	debugPath := filepath.Join(o.Dir, "debug-findings.log")
	debugEnabled := false
	var live *control.DebugStatus
	if state == "ours" {
		live = h.Debug
		debugEnabled = live.Enabled
	}
	debug := map[string]any{"enabled": debugEnabled, "path": debugPath, "healthy": nil, "summaries_written": nil, "write_failures": nil}
	coverage := map[string]any{"state": coverageState(live), "observe": nil, "integration": nil}
	if live != nil {
		debug["healthy"], debug["summaries_written"], debug["write_failures"] = live.Healthy, live.EventsWritten, live.WriteFailures
		coverage["observe"], coverage["integration"] = r.Configuration.Protection.Observe, r.Integration
	}
	payload := map[string]any{"schema": 4, "verb": "status", "ok": true, "port": o.Port, "runtime": "native", "proxy": map[string]any{"state": state, "pid": pid, "authenticated": state == "ours", "record": filepath.Join(o.Dir, StateName)}, "settings": settings, "backup": map[string]any{"path": appState.BackupPath, "present": appState.BackupPresent}, "ca": map[string]any{"dir": o.Dir, "files_present": exists(filepath.Join(o.Dir, "ca.crt")) && exists(filepath.Join(o.Dir, "ca.key")), "trust_state": exists(filepath.Join(o.Dir, "trust-state.json"))}, "debug": debug, "coverage": coverage, "traffic": trafficReport(live)}
	if recordErr != nil && !os.IsNotExist(recordErr) {
		payload["record_error"] = recordErr.Error()
	}
	if o.JSON {
		_ = json.NewEncoder(os.Stdout).Encode(payload)
	} else {
		switch state {
		case "ours":
			fmt.Printf("withhold is running on 127.0.0.1:%d (authenticated pid %d).\n", o.Port, h.PID)
		case "foreign":
			fmt.Printf("No authenticated withhold session; port %d is held by an unverified listener.\n", o.Port)
		default:
			fmt.Printf("withhold is off; no listener on 127.0.0.1:%d.\n", o.Port)
		}
		fmt.Printf("settings: %s\nbackup: %v\n", e.Resource, appState.BackupPresent)
		fmt.Printf("coverage: %s\n", coverageState(live))
		if live != nil {
			fmt.Printf("traffic: connects=%d received=%d scan_attempts=%d inspected=%d passthrough=%d detected=%d redacted=%d blocked=%d upstream_written=%d responses=%d upstream_errors=%d\n", live.Connections, live.Received, live.Scanned, live.Inspected, live.Passthrough, live.Detected, live.Redacted, live.Blocked, live.Written, live.Responses, live.UpstreamErrors)
			if live.Received == 0 {
				fmt.Println("No HTTP requests or WebSocket messages observed this session. Check application routing/trust; CONNECT alone does not prove body inspection.")
			} else if live.Inspected == 0 {
				fmt.Println("Traffic observed, but no supported body has completed inspection. Scan attempts and passthrough are not successful inspections.")
			} else {
				fmt.Println("Supported bodies inspected this session; this does not establish coverage of all application traffic.")
			}
			printObserveWarning(r.Configuration.Protection.Observe)
			fmt.Println("Limits: headers, URL queries, responses, and opaque attachments are not inspected. Integration-specific passthrough is not protected; review its guide.")
		}
		if debugEnabled {
			fmt.Println("debug: on —", debugPath)
			if runtime.GOOS == "windows" {
				fmt.Printf("Follow findings: Get-Content -Wait -LiteralPath '%s'\n", strings.ReplaceAll(debugPath, "'", "''"))
			} else {
				fmt.Printf("Follow findings: tail -F '%s'\n", strings.ReplaceAll(debugPath, "'", "'\\''"))
			}
			fmt.Printf("debug log: healthy=%v summaries_written=%d lost_summaries=%d\n", live.Healthy, live.EventsWritten, live.WriteFailures)
			if !live.Healthy {
				fmt.Println("WARNING: debug log writes are failing; check permissions and disk space.")
			}
			if live.WriteFailures > 0 {
				fmt.Println("WARNING: some finding summaries were lost; the findings log is incomplete.")
			}
		} else {
			fmt.Println("debug: off — enable with withhold off, then withhold on --debug")
		}
		if err != nil {
			fmt.Fprintln(os.Stdout, "settings error:", err)
		}
		switch state {
		case "ours":
			fmt.Fprintf(os.Stdout, "Next: follow the %s integration guide to verify traffic is routed and inspected.\n", o.Application.Name())
		case "foreign":
			fmt.Fprintln(os.Stdout, "Next: release this port or choose another with withhold on --port PORT.")
		default:
			fmt.Fprintln(os.Stdout, "Next: withhold doctor checks setup; withhold on starts a session.")
		}
	}
	return 0
}
func doctor(o Options, e integration.Target, r Record, recordErr error) int {
	rows := []check{{"native-runtime", "PASS", "standalone native executable", ""}}
	binary, err := os.Executable()
	if err == nil {
		environment := os.Environ()
		if o.Configuration != nil {
			environment = o.Configuration.WorkerEnvironment(environment)
		}
		pool := scanpool.NewWithEnvironment(binary, environment, "_scanner", "--body")
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		_, err = pool.Scan(ctx, []byte(`{}`), 32*1024*1024)
		cancel()
		pool.Close()
	}
	row := check{"scanner", "PASS", "offline betterleaks " + detector.Version + "; detector canaries verified", ""}
	selection := os.Getenv("WITHHOLD_PII")
	if o.Configuration != nil {
		selection = strings.Join(o.Configuration.Protection.PII, ",")
	}
	if meta, e := pii.ConfigurationFor(selection); e == nil && meta != nil {
		row.Detail += "; PII Alcatraz " + meta.Version + ": " + strings.Join(meta.Categories, ",")
	}
	if err != nil {
		row.Status = "FAIL"
		row.Detail = "native scanner self-test failed"
		row.Fix = "reinstall the matching native executable"
	}
	rows = append(rows, row)
	_, err = certstore.Load(o.Dir)
	row = check{"ca-files", "PASS", "valid private P-256 CA", ""}
	if err != nil {
		row.Status = "FAIL"
		row.Detail = err.Error()
		row.Fix = "withhold setup"
	}
	rows = append(rows, row)
	s, err := readTrust(o.Dir)
	row = check{"ca-trust", "PASS", "OS trust verified", ""}
	if err == nil {
		data, e := os.ReadFile(filepath.Join(o.Dir, "ca.crt"))
		if e != nil || certFingerprint(data) != s.Fingerprint {
			err = fmt.Errorf("CA and trust metadata differ")
		} else {
			err = SystemTrust().Check(s, filepath.Join(o.Dir, "ca.crt"))
		}
	}
	if err != nil {
		row.Status = "FAIL"
		row.Detail = "CA trust verification failed"
		row.Fix = "withhold setup"
	} else if s.Mode == "manual" {
		row.Status = "WARN"
		row.Detail = "manual trust; import ca.crt into the application trust store"
	}
	rows = append(rows, row)
	if launcher, ok := o.Application.(integration.Launcher); ok {
		row = check{"application-cli", "PASS", e.Binary, ""}
		if _, err := exec.LookPath(e.Binary); err != nil {
			row.Status = "WARN"
			row.Detail = "optional application launcher is unavailable: " + e.Binary
			row.Fix = launcher.MissingCLI()
		}
		rows = append(rows, row)
	}
	rows = append(rows, check{"application-restart", "WARN", "follow the integration guide for application trust and restart requirements", ""})
	if recordErr == nil {
		e.Resource = r.Resource
	}
	row = check{"backup", "WARN", "created by withhold on", ""}
	appState, settingsErr := o.Application.Read(e)
	if appState.BackupPresent {
		row.Status = "PASS"
		row.Detail = appState.BackupPath
	}
	rows = append(rows, row)
	row = check{"settings", "PASS", e.Resource, ""}
	if e.Resource == "" {
		row = check{"settings", "FAIL", "application settings could not be resolved", "correct integration/application configuration"}
	} else if settingsErr != nil {
		row.Status = "FAIL"
		row.Detail = err.Error()
		row.Fix = "repair application settings before continuing"
	}
	rows = append(rows, row)
	row = check{"request-cap", "PASS", "validated native cap; 6 jobs / 64 MiB intake and scan admission", ""}
	if o.ConfigError != "" {
		row.Status = "FAIL"
		row.Detail = o.ConfigError
		row.Fix = "correct TOML configuration, WITHHOLD_* overrides, or startup flags"
	}
	rows = append(rows, row)
	state, _ := ownership(o.Port, r)
	row = check{"port", "PASS", fmt.Sprintf("%d %s", o.Port, state), ""}
	if state == "foreign" {
		row.Status = "FAIL"
		row.Fix = "release this port or choose --port"
	}
	rows = append(rows, row)
	if recordErr != nil && !os.IsNotExist(recordErr) {
		rows = append(rows, check{"ownership-record", "FAIL", recordErr.Error(), "repair the private runtime record; no process will be signalled"})
	}
	ok := true
	for _, row := range rows {
		if row.Status == "FAIL" {
			ok = false
		}
	}
	if o.JSON {
		_ = json.NewEncoder(os.Stdout).Encode(map[string]any{"schema": 2, "verb": "doctor", "runtime": "native", "ok": ok, "checks": rows})
	} else {
		counts := map[string]int{}
		for _, row := range rows {
			counts[row.Status]++
			if o.Preflight && row.Status != "FAIL" {
				continue
			}
			stream := os.Stdout
			if o.Preflight {
				stream = os.Stderr
			}
			fmt.Fprintf(stream, "[%s] %s — %s\n", row.Status, row.ID, row.Detail)
			if row.Fix != "" {
				fmt.Fprintf(stream, "       Fix: %s\n", row.Fix)
			}
		}
		if !o.Preflight {
			fmt.Fprintf(os.Stdout, "\n%d passed, %d warnings, %d failed.\n", counts["PASS"], counts["WARN"], counts["FAIL"])
		}
	}
	if !ok {
		if o.Preflight {
			return 2
		}
		return 1
	}
	return 0
}
