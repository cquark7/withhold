// Package session manages authenticated proxy lifecycles and reversible
// application setup without depending on a particular coding harness.
package session

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/cquark7/withhold/internal/certstore"
	"github.com/cquark7/withhold/internal/config"
	"github.com/cquark7/withhold/internal/control"
	"github.com/cquark7/withhold/internal/integration"
	"github.com/cquark7/withhold/internal/localstate"
)

const StateName = "session.json"

type ManagedApplication struct {
	Agent  string             `json:"agent"`
	Target integration.Target `json:"target"`
}

type Record struct {
	Schema        int                  `json:"schema"`
	Identity      control.Identity     `json:"identity"`
	PID           int                  `json:"pid"`
	Port          int                  `json:"port"`
	Build         string               `json:"build"`
	Applications  []ManagedApplication `json:"applications"`
	Debug         bool                 `json:"debug"`
	Environment   string               `json:"environment"`
	Configuration *config.Config       `json:"configuration"`
}

func LoadRecord(path string) (Record, error) {
	var r Record
	data, err := localstate.ReadPrivate(path)
	if err != nil {
		return r, err
	}
	if json.Unmarshal(data, &r) != nil || r.Schema != 2 || !control.Valid(r.Identity) || r.PID < 0 || r.Port < 1 || r.Port > 65535 || r.Configuration == nil || len(r.Applications) == 0 {
		return Record{}, errors.New("invalid session record")
	}
	agents := slices.Clone(r.Configuration.Agents)
	if r.Configuration.Validate() != nil || !slices.Equal(agents, r.Configuration.Agents) || len(agents) != len(r.Applications) || r.Configuration.Proxy.Port != r.Port {
		return Record{}, errors.New("session configuration differs from its ownership record")
	}
	resources := map[string]bool{}
	for i, app := range r.Applications {
		if app.Agent != agents[i] || !filepath.IsAbs(app.Target.Resource) || resources[app.Target.Resource] {
			return Record{}, errors.New("invalid session application resources")
		}
		resources[app.Target.Resource] = true
	}
	return r, nil
}

func saveRecord(path string, r Record) error {
	data, err := json.Marshal(r)
	if err != nil {
		return err
	}
	if len(data) > 1024*1024 {
		return errors.New("runtime record exceeds recovery read limit")
	}
	return localstate.Write(path, data, false)
}

func BuildID(binary string) (string, error) {
	data, err := os.ReadFile(binary)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

type Options struct {
	ConfigError                                            string
	Verb, Dir, TrustMode, BinDir                           string
	Port                                                   int
	PortSet, TargetsSet, JSON, Preflight, KeepFiles, Debug bool
	ApplicationArgs                                        []string
	StartupTimeout                                         time.Duration
	Agents                                                 []string
	SavedAgents                                            []string
	EnvironmentID                                          string
	Applications                                           map[string]integration.Application
	LookupApplication                                      func(string) (integration.Application, error)
	SaveSelection                                          func() error
	Configuration                                          *config.Config
}

type application struct {
	ManagedApplication
	adapter      integration.Application
	resolveError error
}

func listening(port int) bool {
	c, err := net.DialTimeout("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), 100*time.Millisecond)
	if err != nil {
		return false
	}
	_ = c.Close()
	return true
}
func ownership(port int, r Record) (string, *control.Health) {
	if h, err := control.Probe(port, r.Identity); err == nil {
		if h.PID == r.PID && h.Build == r.Build {
			return "ours", &h
		}
	}
	if listening(port) {
		return "foreign", nil
	}
	return "none", nil
}
func fail(code int, err error) int { fmt.Fprintln(os.Stderr, "withhold:", err); return code }

func resolveApplications(o Options, recorded []ManagedApplication) ([]application, error) {
	var apps []application
	seen := map[string]bool{}
	for i, id := range o.Agents {
		adapter := o.Applications[id]
		var err error
		if recorded != nil || adapter == nil {
			if o.LookupApplication == nil {
				return nil, errors.New("recorded agent adapter is unavailable")
			}
			adapter, err = o.LookupApplication(id)
			if err != nil {
				return nil, err
			}
		}
		var target integration.Target
		if recorded != nil {
			target = recorded[i].Target
		} else {
			target, err = adapter.Resolve()
			if err != nil {
				if o.Verb != "doctor" {
					return nil, err
				}
			}
		}
		if !filepath.IsAbs(target.Resource) || seen[target.Resource] {
			err = errors.New("agents must manage distinct absolute application resources")
		}
		if err != nil && o.Verb != "doctor" {
			return nil, err
		}
		seen[target.Resource] = true
		apps = append(apps, application{ManagedApplication: ManagedApplication{Agent: id, Target: target}, adapter: adapter, resolveError: err})
	}
	return apps, nil
}

func Run(o Options) int {
	dir, err := filepath.Abs(o.Dir)
	if err != nil {
		return fail(2, err)
	}
	o.Dir = dir
	if o.Verb == "install" {
		return install(o)
	}
	readOnly := o.Verb == "status" || o.Verb == "doctor" || o.Verb == "launch"
	if !readOnly {
		if err = os.MkdirAll(o.Dir, 0700); err != nil {
			return fail(1, err)
		}
		unlock, err := localstate.Lock(filepath.Join(o.Dir, "command.lock"))
		if err != nil {
			return fail(1, err)
		}
		defer unlock()
	}
	statePath := filepath.Join(o.Dir, StateName)
	r, recordErr := LoadRecord(statePath)
	recovery := o.Verb == "off" || o.Verb == "uninstall" || o.Verb == "status" || o.Verb == "doctor" && !o.TargetsSet
	var recorded []ManagedApplication
	if recordErr == nil && recovery {
		o.Agents = r.Configuration.Agents
		if o.Verb != "doctor" {
			o.Configuration = r.Configuration
		}
		recorded = r.Applications
	}
	if !o.PortSet && recordErr == nil && (recovery || o.Verb == "doctor" || o.Verb == "launch") {
		o.Port = r.Port
	}
	// Without an ownership record cleanup has no resources to guess at.
	if recordErr != nil && (o.Verb == "off" || o.Verb == "uninstall") {
		o.Agents = nil
	}
	apps, err := resolveApplications(o, recorded)
	if err != nil {
		return fail(2, err)
	}
	switch o.Verb {
	case "status":
		return status(o, apps, r, recordErr)
	case "doctor":
		return doctor(o, apps, r, recordErr)
	case "launch":
		return launch(o, apps, r, recordErr)
	case "setup":
		for _, app := range apps {
			if _, err = app.adapter.Read(app.Target); err != nil {
				return fail(2, err)
			}
		}
		if _, err = certstore.Load(o.Dir); err != nil {
			if err = certstore.Init(o.Dir); err != nil {
				return fail(1, err)
			}
		}
		if err = SystemTrust().Install(o.Dir, o.TrustMode == "manual"); err != nil {
			return fail(1, err)
		}
		if o.SaveSelection != nil {
			if err = o.SaveSelection(); err != nil {
				return fail(1, fmt.Errorf("CA ready, but agent selection was not saved: %w", err))
			}
		}
		fmt.Printf("Local CA ready. Saved agents: %s.\nRun 'withhold on'. Follow each agent's integration guide for trust and restart requirements.\n", strings.Join(o.Agents, ", "))
		if o.TrustMode == "manual" {
			fmt.Printf("CA trust is manual; import %s into the application's trust store before use.\n", filepath.Join(o.Dir, "ca.crt"))
		}
		return 0
	case "on":
		return on(o, apps, r, recordErr)
	case "off":
		return off(o, apps, r, recordErr)
	case "uninstall":
		rc := off(o, apps, r, recordErr)
		s, e := readTrust(o.Dir)
		if e == nil && s.Mode == "manual" && o.KeepFiles {
			fmt.Printf("Manual trust: remove CA %s from every trust store. Local CA files retained.\n", s.Fingerprint)
			return rc
		}
		if err = SystemTrust().Remove(o.Dir); err != nil {
			return fail(1, err)
		}
		if !o.KeepFiles {
			for _, name := range []string{"ca.key", "ca.crt"} {
				if err = os.Remove(filepath.Join(o.Dir, name)); err != nil && !os.IsNotExist(err) {
					return fail(1, err)
				}
			}
		}
		fmt.Println("CA trust removal verified.")
		return rc
	}
	return fail(2, errors.New("unknown session command"))
}

func settingsLock(path string) (func(), error) {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}
	return localstate.Lock(path + ".withhold-lock")
}

func on(o Options, apps []application, r Record, recordErr error) int {
	if recordErr != nil && !os.IsNotExist(recordErr) {
		return fail(2, recordErr)
	}
	setupHint := fmt.Errorf("run 'withhold setup %s' before 'withhold on'", strings.Join(o.Agents, " "))
	if _, err := certstore.Load(o.Dir); err != nil {
		return fail(2, setupHint)
	}
	s, err := readTrust(o.Dir)
	if err != nil {
		return fail(2, setupHint)
	}
	data, err := os.ReadFile(filepath.Join(o.Dir, "ca.crt"))
	if err != nil || certFingerprint(data) != s.Fingerprint {
		return fail(2, errors.New("CA does not match trust metadata"))
	}
	if err = SystemTrust().Check(s, filepath.Join(o.Dir, "ca.crt")); err != nil {
		return fail(2, err)
	}
	managed := make([]ManagedApplication, 0, len(apps))
	for _, app := range apps {
		if _, err = app.adapter.Read(app.Target); err != nil {
			return fail(2, err)
		}
		managed = append(managed, app.ManagedApplication)
	}
	binary, err := os.Executable()
	if err != nil {
		return fail(1, err)
	}
	build, err := BuildID(binary)
	if err != nil {
		return fail(1, err)
	}
	if recordErr == nil {
		if !slices.Equal(r.Applications, managed) {
			return fail(2, fmt.Errorf("session targets are %s; run 'withhold off' before changing agents or application settings", strings.Join(r.Configuration.Agents, ", ")))
		}
		state, h := ownership(r.Port, r)
		if state != "none" {
			if state != "ours" || o.Port != r.Port {
				return fail(2, errors.New("existing session or foreign listener must be stopped before starting"))
			}
			if h.Build != build || r.Build != build || r.Environment != o.EnvironmentID || r.Debug != o.Debug {
				return fail(2, errors.New("runtime or configuration changed; run 'withhold off' before 'withhold on'"))
			}
			fmt.Printf("withhold already running on 127.0.0.1:%d (authenticated pid %d). Agents: %s.\n", r.Port, h.PID, strings.Join(o.Agents, ", "))
			printObserveWarning(r.Configuration.Protection.Observe)
			return 0
		}
	}
	if listening(o.Port) {
		return fail(2, errors.New("requested port is held by a foreign listener"))
	}
	// Lock resources in path order across state directories to avoid deadlocks.
	ordered := slices.Clone(apps)
	slices.SortFunc(ordered, func(a, b application) int { return strings.Compare(a.Target.Resource, b.Target.Resource) })
	for _, app := range ordered {
		unlock, err := settingsLock(app.Target.Resource)
		if err != nil {
			return fail(1, err)
		}
		defer unlock()
		marker := app.Target.Resource + ".withhold-session"
		if owner, err := os.ReadFile(marker); err == nil && string(owner) != o.Dir {
			return fail(2, errors.New("another withhold state directory manages these settings"))
		} else if err != nil && !os.IsNotExist(err) {
			return fail(1, err)
		}
	}
	r = Record{Schema: 2, Identity: control.Identity{Instance: control.Random(), Token: control.Random()}, Port: o.Port, Build: build, Applications: managed, Debug: o.Debug, Environment: o.EnvironmentID, Configuration: o.Configuration}
	statePath := filepath.Join(o.Dir, StateName)
	if err = saveRecord(statePath, r); err != nil {
		return fail(1, err)
	}
	rollback := func() {
		if restoreApplications(o, apps) == nil {
			_ = os.Remove(statePath)
		}
	}
	for _, app := range apps {
		if err = localstate.Write(app.Target.Resource+".withhold-session", []byte(o.Dir), false); err == nil {
			err = app.adapter.Apply(app.Target, integration.SetupOptions{Port: o.Port, CADir: o.Dir})
		}
		if err != nil {
			rollback()
			return fail(1, err)
		}
	}
	log, err := os.OpenFile(filepath.Join(o.Dir, "proxy.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		rollback()
		return fail(1, err)
	}
	cmd := exec.Command(binary, "_session-serve", "--state", statePath)
	cmd.Stdout, cmd.Stderr = log, log
	detach(cmd)
	err = startSession(cmd, statePath, &r)
	_ = log.Close()
	if err != nil {
		rollback()
		return fail(1, err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	deadline := time.Now().Add(o.StartupTimeout)
	for time.Now().Before(deadline) {
		if h, e := control.Probe(o.Port, r.Identity); e == nil && h.Build == build && h.PID == r.PID {
			fmt.Printf("withhold is running on 127.0.0.1:%d (authenticated pid %d). Agents: %s; routing configured.\nFollow each integration guide for trust and restart requirements; startup does not prove traffic is inspected.\n", o.Port, h.PID, strings.Join(o.Agents, ", "))
			if h.Debug != nil && h.Debug.Enabled {
				fmt.Printf("Debug findings: %s\nUse 'withhold status' for live traffic/redaction counters.\n", filepath.Join(o.Dir, "debug-findings.log"))
			}
			printObserveWarning(r.Configuration.Protection.Observe)
			return 0
		}
		select {
		case <-done:
			rollback()
			return fail(1, errors.New("proxy exited during startup; see proxy.log"))
		case <-time.After(30 * time.Millisecond):
		}
	}
	_ = cmd.Process.Kill()
	<-done
	rollback()
	return fail(1, errors.New("proxy startup timed out; see recovery state in 'withhold status'"))
}

// Continue restoring other applications after a failure. Successful restores
// are idempotent; the record remains until every resource can be recovered.
func restoreApplications(o Options, apps []application) error {
	var failures []error
	for _, app := range slices.Backward(apps) {
		marker := app.Target.Resource + ".withhold-session"
		owner, err := os.ReadFile(marker)
		if err == nil && string(owner) != o.Dir {
			err = errors.New("settings belong to another state directory")
		} else if os.IsNotExist(err) {
			err = nil
		}
		if err == nil {
			err = app.adapter.Restore(app.Target)
		}
		if err == nil {
			err = os.Remove(marker)
			if os.IsNotExist(err) {
				err = nil
			}
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "withhold: %s settings restore failed: %v\n", app.Agent, err)
			failures = append(failures, err)
		}
	}
	return errors.Join(failures...)
}

func off(o Options, apps []application, r Record, recordErr error) int {
	rc := 0
	if recordErr != nil && !os.IsNotExist(recordErr) {
		return fail(1, recordErr)
	}
	if recordErr == nil {
		if o.PortSet && o.Port != r.Port {
			fmt.Fprintln(os.Stderr, "withhold: requested port differs from the recorded session; restoring the recorded session")
			rc = 1
		}
		o.Port = r.Port
		state, _ := ownership(o.Port, r)
		if state == "ours" {
			if err := control.Shutdown(o.Port, r.Identity); err != nil {
				fmt.Fprintln(os.Stderr, "withhold: authenticated shutdown failed")
				rc = 1
			}
		}
		deadline := time.Now().Add(5 * time.Second)
		for state == "ours" && listening(o.Port) && time.Now().Before(deadline) {
			time.Sleep(25 * time.Millisecond)
		}
	}
	ordered := slices.Clone(apps)
	slices.SortFunc(ordered, func(a, b application) int { return strings.Compare(a.Target.Resource, b.Target.Resource) })
	for _, app := range ordered {
		unlock, err := settingsLock(app.Target.Resource)
		if err != nil {
			return fail(1, err)
		}
		defer unlock()
	}
	// Restore even when authentication or shutdown fails.
	if restoreApplications(o, apps) != nil {
		rc = 1
	}
	if listening(o.Port) {
		fmt.Fprintln(os.Stderr, "withhold: port remains held; no foreign process was signalled")
		rc = 1
	}
	if rc == 0 {
		if err := os.Remove(filepath.Join(o.Dir, StateName)); err != nil && !os.IsNotExist(err) {
			return fail(1, err)
		}
		fmt.Println("withhold is off; managed settings restored.")
		if len(apps) > 0 {
			fmt.Printf("Restart %s if connections or launch-time proxy settings are cached; follow each integration guide.\n", strings.Join(o.Agents, ", "))
		}
	}
	return rc
}

func printObserveWarning(observe bool) {
	if observe {
		fmt.Fprintln(os.Stderr, "withhold: OBSERVE mode is active; secrets can be forwarded unchanged.")
	}
}
