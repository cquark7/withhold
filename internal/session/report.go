package session

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
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

func printTraffic(t *Traffic) {
	fmt.Printf("Inspected: %d supported bodies/messages\n", t.Inspected)
	fmt.Printf("Redacted:  %d decisions\n", t.Redacted)
	fmt.Printf("Blocked:   %d decisions\n", t.Blocked)
	if t.Blocked != 0 {
		for _, row := range []struct {
			label string
			count uint64
		}{
			{"findings", t.BlockReasons.Findings},
			{"unsupported or unscannable", t.BlockReasons.Unsupported},
			{"intake, read, or size limits", t.BlockReasons.Intake},
			{"suspicious unscoped hosts", t.BlockReasons.Suspicious},
			{"inspection failures", t.BlockReasons.Inspection},
			{"other", t.BlockReasons.Other},
		} {
			if row.count != 0 {
				fmt.Printf("  %s: %d\n", row.label, row.count)
			}
		}
	}
	if t.UpstreamErrors != 0 {
		fmt.Printf("Upstream failures: %d\n", t.UpstreamErrors)
		for _, row := range []struct {
			label string
			count uint64
		}{
			{"canceled", t.UpstreamReasons.Canceled},
			{"timeout", t.UpstreamReasons.Timeout},
			{"TLS verification", t.UpstreamReasons.TLS},
			{"DNS", t.UpstreamReasons.DNS},
			{"other or unknown", t.UpstreamReasons.Other},
		} {
			if row.count != 0 {
				fmt.Printf("  %s: %d\n", row.label, row.count)
			}
		}
	}
}

func printTrafficDetails(t *Traffic) {
	fmt.Printf("Traffic: connections=%d received=%d scan_attempts=%d passthrough=%d detected=%d upstream_written=%d responses=%d\n",
		t.Connections, t.Received, t.ScanAttempts, t.Passthrough, t.Detected, t.Written, t.Responses)
	fmt.Println("Counters are session-wide, not attribution to individual agents. Passthrough includes bodyless requests.")
}

func status(o Options, apps []application, r Record, recordErr error) int {
	state, h := ownership(o.Port, r)
	var pid any
	if h != nil {
		pid = h.PID
	}
	applicationReports := []map[string]any{}
	settingsError := false
	for _, app := range apps {
		settings := map[string]any{"path": app.Target.Resource, "http_proxy": nil, "clean": true, "error": nil}
		appState, err := app.adapter.Read(app.Target)
		if err != nil {
			settings["error"] = err.Error()
			settingsError = true
		} else if appState.Proxy != nil {
			settings["http_proxy"], settings["clean"] = appState.Proxy, false
		}
		applicationReports = append(applicationReports, map[string]any{"agent": app.Agent, "settings": settings, "backup": map[string]any{"path": appState.BackupPath, "present": appState.BackupPresent}})
	}
	debugPath := filepath.Join(o.Dir, "debug-findings.log")
	debugEnabled := false
	var live *control.DebugStatus
	if state == "ours" {
		live = h.Debug
		debugEnabled = live.Enabled
	}
	debug := map[string]any{"enabled": debugEnabled, "path": debugPath, "healthy": nil, "summaries_written": nil, "write_failures": nil}
	coverage := map[string]any{"state": coverageState(live), "observe": nil, "agents": []string{}}
	if live != nil {
		debug["healthy"], debug["summaries_written"], debug["write_failures"] = live.Healthy, live.EventsWritten, live.WriteFailures
		coverage["observe"], coverage["agents"] = r.Configuration.Protection.Observe, r.Configuration.Agents
	}
	active := []string{}
	if state == "ours" {
		active = r.Configuration.Agents
	}
	brokenRecord := recordErr != nil && !os.IsNotExist(recordErr)
	recoveryNeeded := recordErr == nil && state != "ours"
	trust, trustErr := readTrust(o.Dir)
	var trustMode any
	if trustErr == nil {
		switch trust.Mode {
		case "manual":
			trustMode = "manual"
		case "", "system":
			trustMode = "system"
		default:
			trustErr = fmt.Errorf("invalid trust metadata")
		}
	}
	var last *LastSession
	var summaryErr error
	if os.IsNotExist(recordErr) {
		last, summaryErr = loadSummary(o.Dir)
	}
	badSummary := summaryErr != nil && !os.IsNotExist(summaryErr)
	badTrust := live != nil && trustErr != nil
	ok := !brokenRecord && !recoveryNeeded && state != "foreign" && o.ConfigError == "" && !settingsError && !badSummary && !badTrust
	ca := map[string]any{"dir": o.Dir, "files_present": exists(filepath.Join(o.Dir, "ca.crt")) && exists(filepath.Join(o.Dir, "ca.key")), "trust_state": exists(filepath.Join(o.Dir, "trust-state.json")), "trust_mode": trustMode}
	if badTrust {
		ca["trust_error"] = "trust metadata unavailable"
	}
	payload := map[string]any{"schema": 6, "verb": "status", "ok": ok, "port": o.Port, "runtime": "native", "agents": o.Agents, "saved_agents": o.SavedAgents, "active_agents": active, "applications": applicationReports, "proxy": map[string]any{"state": state, "pid": pid, "authenticated": state == "ours", "record": filepath.Join(o.Dir, StateName)}, "recovery_needed": recoveryNeeded || brokenRecord, "ca": ca, "debug": debug, "coverage": coverage, "traffic": trafficReport(live), "last_session": last}
	if brokenRecord {
		payload["record_error"] = recordErr.Error()
	}
	if badSummary {
		payload["summary_error"] = "last-session summary is unreadable"
	}
	if o.ConfigError != "" {
		payload["config_error"] = o.ConfigError
		payload["saved_agents"] = nil
	}
	if o.JSON {
		_ = json.NewEncoder(os.Stdout).Encode(payload)
	} else {
		switch {
		case brokenRecord:
			fmt.Printf("withhold: cannot read the recovery record: %s\n", recordErr)
			fmt.Println("Keep the state and backups. Run 'withhold doctor'; no process will be stopped automatically.")
		case recoveryNeeded:
			fmt.Println("withhold is not running or cannot be authenticated.")
			fmt.Println("Recovery needed: recorded application settings may still point to the proxy.")
			if state == "foreign" {
				fmt.Printf("Port %d has an unverified listener; it will not be stopped.\n", o.Port)
			}
			fmt.Println("Next: run 'withhold off' to attempt to restore the recorded settings.")
		case state == "foreign":
			fmt.Printf("withhold is off; port %d is held by an unverified listener.\n", o.Port)
			fmt.Println("Next: release the port or choose another with 'withhold on --port PORT'.")
		case live != nil:
			fmt.Println("withhold is running.")
			fmt.Printf("Agents: %s\n", strings.Join(active, ", "))
			if !slices.Equal(o.SavedAgents, active) && o.ConfigError == "" {
				fmt.Printf("Saved agents: %s\n", strings.Join(o.SavedAgents, ", "))
			}
			pii := "off"
			if len(r.Configuration.Protection.PII) != 0 {
				pii = strings.Join(r.Configuration.Protection.PII, ", ")
			}
			if r.Configuration.Protection.Observe {
				fmt.Println("Mode: observe (sensitive content can be forwarded unchanged)")
			} else {
				fmt.Println("Mode: enforce")
			}
			if trustMode == "manual" {
				fmt.Println("CA trust: manual (not verified)")
			} else if trustErr != nil {
				fmt.Println("CA trust: metadata unavailable; run 'withhold doctor'.")
			}
			fmt.Printf("Policy: chat %s; inline %s; PII %s\n\n", r.Configuration.Protection.Chat, r.Configuration.Protection.Inline, pii)
			printTraffic(trafficReport(live))
			if live.Received == 0 {
				fmt.Println("\nNo HTTP requests or WebSocket messages observed this session.")
				fmt.Println("Next: restart the agent if needed, send a non-sensitive request, then check 'withhold status'.")
			} else if live.Inspected == 0 {
				fmt.Println("\nTraffic arrived, but no supported body or message completed inspection.")
				fmt.Println("Next: check application routing and trust with 'withhold doctor' and the agent guide.")
			}
			printObserveWarning(r.Configuration.Protection.Observe)
			fmt.Println("\nOnly supported routed bodies/messages are inspected; headers, URL queries, responses, opaque attachments, and passthrough are not.")
		default:
			fmt.Println("withhold is off.")
			if o.ConfigError == "" && len(o.SavedAgents) != 0 {
				fmt.Printf("Saved agents: %s\nStart: withhold on\n", strings.Join(o.SavedAgents, ", "))
			} else if o.ConfigError == "" {
				fmt.Println("Next: run 'withhold agents' and choose agents with 'withhold setup AGENT...'.")
			}
		}
		if o.ConfigError != "" {
			fmt.Printf("Saved agents unavailable: %s\n", o.ConfigError)
			fmt.Println("Next: correct the configuration; 'withhold off' can still restore recorded settings.")
		}
		if badSummary {
			fmt.Println("Last session: summary is unreadable; keep the state file for diagnosis.")
		}
		for _, app := range applicationReports {
			settings := app["settings"].(map[string]any)
			backup := app["backup"].(map[string]any)
			if o.Details {
				fmt.Printf("%s settings: %q\n  backup present: %v\n", app["agent"], settings["path"], backup["present"])
			}
			if settings["error"] != nil {
				fmt.Printf("WARNING: %s settings could not be read: %v\n", app["agent"], settings["error"])
			}
		}
		if live != nil && o.Details {
			fmt.Printf("\nProxy: 127.0.0.1:%d (authenticated pid %d)\n", o.Port, h.PID)
			printTrafficDetails(trafficReport(live))
		}
		if debugEnabled && o.Details {
			fmt.Println("Debug findings:", debugPath)
			if runtime.GOOS == "windows" {
				fmt.Printf("Follow findings: Get-Content -Wait -LiteralPath '%s'\n", strings.ReplaceAll(debugPath, "'", "''"))
			} else {
				fmt.Printf("Follow findings: tail -F '%s'\n", strings.ReplaceAll(debugPath, "'", "'\\''"))
			}
			fmt.Printf("Debug log: healthy=%v summaries_written=%d lost_summaries=%d\n", live.Healthy, live.EventsWritten, live.WriteFailures)
		}
		if debugEnabled && !live.Healthy {
			fmt.Println("WARNING: debug log writes are failing; check permissions and disk space.")
		}
		if debugEnabled && live.WriteFailures > 0 {
			fmt.Println("WARNING: some finding summaries were lost; the findings log is incomplete.")
		}
		if o.Details && live == nil && !recoveryNeeded && !brokenRecord && !badSummary {
			switch {
			case last == nil:
				fmt.Println("\nLast session: no summary available.")
			case !last.Available:
				fmt.Println("\nLast session: summary unavailable; the session may have stopped unexpectedly.")
			default:
				fmt.Printf("\nLast session: %s (snapshot before shutdown; late events may be omitted)\n", last.CapturedAt)
				fmt.Printf("Agents: %s\n", strings.Join(last.Agents, ", "))
				if last.Observe {
					fmt.Println("OBSERVE mode: sensitive content could be forwarded unchanged.")
				}
				printTraffic(last.Traffic)
				printTrafficDetails(last.Traffic)
			}
		}
	}
	if !ok {
		return 1
	}
	return 0
}
func doctor(o Options, apps []application, r Record, recordErr error) int {
	rows := []check{{"native-runtime", "PASS", "standalone native executable", ""}}
	if o.MissingAgents {
		rows = append([]check{{"agents", "FAIL", "no agents selected", "run 'withhold agents', then 'withhold setup AGENT...'"}}, rows...)
	}
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
	if o.MissingAgents {
		rows = append(rows, check{"setup", "WARN", "CA and trust not checked until an agent is selected", ""})
	} else {
		_, err = certstore.Load(o.Dir)
		row = check{"ca-files", "PASS", "valid private P-256 CA", ""}
		if err != nil {
			row.Status = "FAIL"
			row.Detail = err.Error()
			row.Fix = "withhold setup " + strings.Join(o.Agents, " ")
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
			row.Fix = "withhold setup " + strings.Join(o.Agents, " ")
		} else if s.Mode == "manual" {
			row.Status = "WARN"
			row.Detail = "manual trust is not verified; import ca.crt into the application trust store"
		}
		rows = append(rows, row)
	}
	for _, app := range apps {
		e := app.Target
		if launcher, ok := app.adapter.(integration.Launcher); ok {
			row = check{"application-cli", "PASS", e.Binary, ""}
			if _, err := exec.LookPath(e.Binary); err != nil {
				row.Status = "WARN"
				row.Detail = "optional application launcher is unavailable: " + e.Binary
				row.Fix = launcher.MissingCLI()
			}
			row.ID = app.Agent + "/" + row.ID
			rows = append(rows, row)
		}
		rows = append(rows, check{"application-restart", "WARN", "follow the agent guide for application trust and restart requirements", ""})
		row = check{"backup", "WARN", "created by withhold on", ""}
		appState, settingsErr := app.adapter.Read(e)
		if appState.BackupPresent {
			row.Status = "PASS"
			row.Detail = appState.BackupPath
		}
		row.ID = app.Agent + "/" + row.ID
		rows = append(rows, row)
		row = check{"settings", "PASS", e.Resource, ""}
		if app.resolveError != nil {
			row = check{"settings", "FAIL", app.resolveError.Error(), "correct namespaced application settings"}
		} else if settingsErr != nil {
			row.Status = "FAIL"
			row.Detail = settingsErr.Error()
			row.Fix = "repair application settings before continuing"
		}
		row.ID = app.Agent + "/" + row.ID
		rows = append(rows, row)
	}
	if len(o.Agents) == 0 && !o.MissingAgents && o.ConfigError == "" {
		rows = append(rows, check{"agents", "FAIL", "no agents selected", "run 'withhold setup AGENT...' to save a default set; use 'withhold agents' to list choices"})
	}
	row = check{"request-cap", "PASS", "validated native cap; 6 jobs / 64 MiB intake and scan admission", ""}
	if o.ConfigError != "" && !o.MissingAgents {
		row = check{"configuration", "FAIL", o.ConfigError, "correct TOML configuration, WITHHOLD_* overrides, or startup flags"}
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
		rows = append(rows, check{"ownership-record", "FAIL", recordErr.Error(), "keep state and backups; consult the recovery guide; no process will be signalled"})
	}
	if _, err := loadSummary(o.Dir); err != nil && !os.IsNotExist(err) {
		rows = append(rows, check{"last-session", "FAIL", "last-session summary is unreadable or unsafe",
			fmt.Sprintf("inspect %q; the existing file is preserved", filepath.Join(o.Dir, summaryName))})
	}
	ok := true
	for _, row := range rows {
		if row.Status == "FAIL" {
			ok = false
		}
	}
	if o.JSON {
		_ = json.NewEncoder(os.Stdout).Encode(map[string]any{"schema": 4, "verb": "doctor", "runtime": "native", "agents": o.Agents, "ok": ok, "checks": rows})
	} else {
		counts := map[string]int{}
		display := slices.Clone(rows)
		if !ok {
			slices.SortStableFunc(display, func(a, b check) int {
				if a.Status == "FAIL" && b.Status != "FAIL" {
					return -1
				}
				if a.Status != "FAIL" && b.Status == "FAIL" {
					return 1
				}
				return 0
			})
		}
		for _, row := range display {
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
