package proxy

import (
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/cquark7/withhold/internal/localstate"
	"github.com/cquark7/withhold/internal/policy"
	"github.com/cquark7/withhold/internal/scanner"
)

type audit struct {
	mu         sync.Mutex
	path, hint string
	seen       map[string]bool
}

// Field order is part of the audit interface. Worker bodies and reasons never
// enter this record; diagnostics contain only fixed rules and numeric counters.
type record struct {
	TS           string `json:"ts"`
	Host         string `json:"host"`
	API          string `json:"api"`
	Surface      string `json:"surface"`
	Provisional  bool   `json:"surface_provisional"`
	Mode         string `json:"mode"`
	Action       string `json:"action"`
	Rules        any    `json:"rule_ids"`
	Findings     any    `json:"findings"`
	Placeholders any    `json:"placeholders"`
	Units        any    `json:"units"`
	Stats        any    `json:"stats"`
	Method       string `json:"method"`
	Path         string `json:"path"`
}

func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) > n {
		r = r[:n]
	}
	return string(r)
}
func (a *audit) emit(r *http.Request, route policy.Route, mode, action string, report scanner.Report, observe, redacted bool) {
	if observe {
		if redacted {
			action = "would-redact"
		} else {
			action = "would-block"
		}
	}
	get := func(k string, fallback any) any {
		if v, ok := report[k]; ok {
			return v
		}
		return fallback
	}
	method, path := "", ""
	if r != nil {
		method = truncate(strings.ToUpper(r.Method), 16)
		path = truncate(strings.SplitN(strings.SplitN(r.URL.RequestURI(), "?", 2)[0], "#", 2)[0], 200)
	}
	row := record{time.Now().UTC().Format("2006-01-02T15:04:05.000000+00:00"), route.Host, route.API, route.Surface, route.Provisional, mode, action, get("rule_ids", []string{}), get("findings", 0), get("placeholders", 0), get("units", 0), get("stats", map[string]int{}), method, path}
	data, err := json.Marshal(row)
	if err != nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	appendFile(a.path, append(data, '\n'))
	prefix := ""
	if observe {
		prefix = "OBSERVE "
	}
	level := "BLOCK"
	if mode == "redact" {
		level = "WARN"
	}
	if action == "passthrough" {
		level = "NOTE"
	}
	warning := ""
	if redacted && residue(report) > 0 {
		warning = " - WARNING: unscannable leaves forwarded unscanned"
	}
	appendFile(a.hint, []byte(prefix+"["+row.TS+"] "+level+" "+route.Surface+" "+action+" on "+route.Host+warning+"\n"))
}

func appendFile(path string, data []byte) error {
	if localstate.Regular(path) != nil || localstate.Regular(path+".1") != nil {
		return errors.New("log destinations must be regular files")
	}
	if info, err := os.Stat(path); err == nil && info.Size()+int64(len(data)) > 10*1024*1024 {
		if err := os.Rename(path, path+".1"); err != nil {
			return err
		}
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	if err = localstate.Protect(path); err != nil {
		_ = f.Close()
		return err
	}
	_, err = f.Write(data)
	closeErr := f.Close()
	if err != nil {
		return err
	}
	return closeErr
}

func prepareAudit(paths ...string) error {
	for _, path := range paths {
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			return errors.New("cannot create audit directory")
		}
		if localstate.Regular(path) != nil || localstate.Regular(path+".1") != nil {
			return errors.New("audit destinations must be regular files")
		}
		if _, err := os.Stat(path + ".1"); err == nil {
			if err = localstate.Protect(path + ".1"); err != nil {
				return errors.New("cannot protect audit rotation backup")
			}
		}
		f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
		if err != nil {
			return errors.New("audit destination is not writable")
		}
		err = localstate.Protect(path)
		closeErr := f.Close()
		if err != nil || closeErr != nil {
			return errors.New("cannot protect audit destination")
		}
	}
	return nil
}

func logPathsCollide(debug string, paths ...string) bool {
	debugPaths := []string{filepath.Clean(debug), filepath.Clean(debug + ".1")}
	for _, path := range paths {
		if path == "" {
			continue
		}
		for _, auditPath := range []string{filepath.Clean(path), filepath.Clean(path + ".1")} {
			for _, debugPath := range debugPaths {
				if debugPath == auditPath {
					return true
				}
				debugInfo, debugErr := os.Stat(debugPath)
				auditInfo, auditErr := os.Stat(auditPath)
				if debugErr == nil && auditErr == nil && os.SameFile(debugInfo, auditInfo) {
					return true
				}
			}
		}
	}
	return false
}

func (a *audit) foreign(route policy.Route) {
	a.mu.Lock()
	if a.seen[route.Host] {
		a.mu.Unlock()
		return
	}
	if len(a.seen) >= 4096 {
		clear(a.seen)
	}
	a.seen[route.Host] = true
	a.mu.Unlock()
	route.API = "unscoped"
	route.Surface = "out-of-scope"
	a.emit(nil, route, "audit", "passthrough", scanner.Report{"rule_ids": []string{"out-of-scope-host"}}, false, false)
}
