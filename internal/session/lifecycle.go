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
	"strconv"
	"time"

	"github.com/cquark7/withhold/internal/certstore"
	"github.com/cquark7/withhold/internal/config"
	"github.com/cquark7/withhold/internal/control"
	"github.com/cquark7/withhold/internal/integration"
	"github.com/cquark7/withhold/internal/localstate"
)

const StateName = "session.json"

type Record struct {
	Schema        int              `json:"schema"`
	Identity      control.Identity `json:"identity"`
	PID           int              `json:"pid"`
	Port          int              `json:"port"`
	Build         string           `json:"build"`
	Resource      string           `json:"resource"`
	Debug         bool             `json:"debug"`
	Environment   string           `json:"environment"`
	Integration   string           `json:"integration"`
	Configuration *config.Config   `json:"configuration"`
}

func LoadRecord(path string) (Record, error) {
	var r Record
	data, err := localstate.ReadPrivate(path)
	if err != nil {
		return r, err
	}
	if json.Unmarshal(data, &r) != nil || r.Schema != 1 || !control.Valid(r.Identity) || r.PID < 0 || r.Port < 1 || r.Port > 65535 || !filepath.IsAbs(r.Resource) || r.Integration == "" || r.Configuration == nil {
		return Record{}, errors.New("invalid session record")
	}
	if r.Configuration.Validate() != nil || r.Configuration.Integration != r.Integration || r.Configuration.Proxy.Port != r.Port {
		return Record{}, errors.New("session configuration differs from its ownership record")
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
	ConfigError                                string
	Verb, Dir, TrustMode, BinDir               string
	Port                                       int
	PortSet, JSON, Preflight, KeepFiles, Debug bool
	ApplicationArgs                            []string
	StartupTimeout                             time.Duration
	Integration, EnvironmentID                 string
	Application                                integration.Application
	LookupApplication                          func(string) (integration.Application, error)
	Configuration                              *config.Config
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
func Run(o Options) int {
	dir, err := filepath.Abs(o.Dir)
	if err != nil {
		return fail(2, err)
	}
	o.Dir = dir
	if o.Verb == "install" {
		return install(o)
	}
	statePath := filepath.Join(o.Dir, StateName)
	r, recordErr := LoadRecord(statePath)
	if recordErr == nil && (o.Verb == "off" || o.Verb == "uninstall" || o.Verb == "status" || o.Verb == "doctor") {
		if o.LookupApplication == nil {
			return fail(2, errors.New("recorded integration is unavailable"))
		}
		o.Application, err = o.LookupApplication(r.Integration)
		if err != nil {
			return fail(2, err)
		}
	}
	if o.Application == nil {
		return fail(2, errors.New("application integration is required"))
	}
	target, err := o.Application.Resolve()
	if err != nil {
		if o.Verb == "doctor" {
			o.ConfigError = err.Error()
			if recordErr == nil {
				target = integration.Target{Resource: r.Resource}
			}
		} else if recordErr == nil && (o.Verb == "off" || o.Verb == "uninstall" || o.Verb == "status") {
			target = integration.Target{Resource: r.Resource}
		} else {
			return fail(2, err)
		}
	}
	if !o.PortSet && recordErr == nil && (o.Verb == "off" || o.Verb == "uninstall" || o.Verb == "status" || o.Verb == "doctor" || o.Verb == "launch") {
		o.Port = r.Port
	}
	if o.Verb == "status" {
		return status(o, target, r, recordErr)
	}
	if o.Verb == "doctor" {
		return doctor(o, target, r, recordErr)
	}
	if o.Verb == "launch" {
		return launch(o, target, r, recordErr)
	}
	if err = os.MkdirAll(o.Dir, 0700); err != nil {
		return fail(1, err)
	}
	unlock, err := localstate.Lock(filepath.Join(o.Dir, "command.lock"))
	if err != nil {
		return fail(1, err)
	}
	defer unlock()
	// Reload after taking the command lock so another command cannot replace our session.
	r, recordErr = LoadRecord(statePath)
	if recordErr == nil && (o.Verb == "off" || o.Verb == "uninstall") {
		if o.LookupApplication == nil {
			return fail(2, errors.New("recorded integration is unavailable"))
		}
		o.Application, err = o.LookupApplication(r.Integration)
		if err != nil {
			return fail(2, err)
		}
		target.Resource = r.Resource
	}
	switch o.Verb {
	case "setup":
		if _, err = certstore.Load(o.Dir); err != nil {
			if err = certstore.Init(o.Dir); err != nil {
				return fail(1, err)
			}
		}
		if err = SystemTrust().Install(o.Dir, o.TrustMode == "manual"); err != nil {
			return fail(1, err)
		}
		fmt.Printf("Local CA ready. Run 'withhold doctor', then 'withhold on'. Follow the %s integration guide for trust and restart requirements.\n", o.Application.Name())
		if o.TrustMode == "manual" {
			fmt.Printf("CA trust is manual; import %s into the application's trust store before use.\n", filepath.Join(o.Dir, "ca.crt"))
		}
		return 0
	case "on":
		return on(o, target, r, recordErr)
	case "off":
		return off(o, target, r, recordErr)
	case "uninstall":
		rc := off(o, target, r, recordErr)
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
func on(o Options, e integration.Target, r Record, recordErr error) int {
	if recordErr != nil && !os.IsNotExist(recordErr) {
		return fail(2, recordErr)
	}
	if _, err := certstore.Load(o.Dir); err != nil {
		return fail(2, err)
	}
	s, err := readTrust(o.Dir)
	if err != nil {
		return fail(2, errors.New("run 'withhold setup' before 'withhold on'"))
	}
	data, err := os.ReadFile(filepath.Join(o.Dir, "ca.crt"))
	if err != nil || certFingerprint(data) != s.Fingerprint {
		return fail(2, errors.New("CA does not match trust metadata"))
	}
	if err = SystemTrust().Check(s, filepath.Join(o.Dir, "ca.crt")); err != nil {
		return fail(2, err)
	}
	if _, err = o.Application.Read(e); err != nil {
		return fail(2, err)
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
		state, h := ownership(r.Port, r)
		if state != "none" {
			if state != "ours" || o.Port != r.Port || r.Resource != e.Resource {
				return fail(2, errors.New("existing session or foreign listener must be stopped before starting"))
			}
			if h.Build != build || r.Build != build || r.Integration != o.Integration || r.Environment != o.EnvironmentID || r.Debug != o.Debug {
				return fail(2, errors.New("runtime or configuration changed; run 'withhold off' before 'withhold on'"))
			}
			fmt.Printf("withhold already running on 127.0.0.1:%d (authenticated pid %d).\n", r.Port, h.PID)
			printObserveWarning(r.Configuration.Protection.Observe)
			return 0
		}
		if r.Resource != e.Resource || r.Integration != o.Integration {
			return fail(2, errors.New("restore the previous application session with 'withhold off' first"))
		}
	}
	if listening(o.Port) {
		return fail(2, errors.New("requested port is held by a foreign listener"))
	}
	unlock, err := settingsLock(e.Resource)
	if err != nil {
		return fail(1, err)
	}
	defer unlock()
	marker := e.Resource + ".withhold-session"
	if owner, err := os.ReadFile(marker); err == nil && string(owner) != o.Dir {
		return fail(2, errors.New("another withhold state directory manages these settings"))
	} else if err != nil && !os.IsNotExist(err) {
		return fail(1, err)
	}
	r = Record{Schema: 1, Identity: control.Identity{Instance: control.Random(), Token: control.Random()}, Port: o.Port, Build: build, Resource: e.Resource, Debug: o.Debug, Environment: o.EnvironmentID, Integration: o.Integration, Configuration: o.Configuration}
	statePath := filepath.Join(o.Dir, StateName)
	if err = saveRecord(statePath, r); err != nil {
		return fail(1, err)
	}
	if err = localstate.Write(marker, []byte(o.Dir), false); err != nil {
		return fail(1, err)
	}
	rollback := func() {
		if e := o.Application.Restore(e); e != nil {
			fmt.Fprintln(os.Stderr, "withhold: settings restore failed:", e)
			return
		}
		_ = os.Remove(marker)
		_ = os.Remove(statePath)
	}
	if err = o.Application.Apply(e, integration.SetupOptions{Port: o.Port, CADir: o.Dir}); err != nil {
		rollback()
		return fail(1, err)
	}
	log, err := os.OpenFile(filepath.Join(o.Dir, "proxy.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		rollback()
		return fail(1, err)
	}
	cmd := exec.Command(binary, "_session-serve", "--state", statePath)
	cmd.Stdout = log
	cmd.Stderr = log
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
			fmt.Printf("withhold is running on 127.0.0.1:%d (authenticated pid %d). %s routing configured.\nFollow the integration guide for trust and restart requirements; startup does not prove traffic is inspected.\n", o.Port, h.PID, o.Application.Name())
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
	return fail(1, errors.New("proxy startup timed out; settings rolled back"))
}
func off(o Options, e integration.Target, r Record, recordErr error) int {
	rc := 0
	if recordErr != nil && !os.IsNotExist(recordErr) {
		fmt.Fprintln(os.Stderr, "withhold:", recordErr)
		rc = 1
	}
	if recordErr == nil {
		if o.PortSet && o.Port != r.Port {
			fmt.Fprintln(os.Stderr, "withhold: requested port differs from the recorded session; restoring the recorded session")
			rc = 1
		}
		e.Resource = r.Resource
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
	// Restore even when ownership cannot be established or shutdown fails.
	unlock, err := settingsLock(e.Resource)
	if err != nil {
		fmt.Fprintln(os.Stderr, "withhold: settings lock failed:", err)
		rc = 1
	} else {
		defer unlock()
		marker := e.Resource + ".withhold-session"
		owner, readErr := os.ReadFile(marker)
		if readErr == nil && string(owner) != o.Dir {
			fmt.Fprintln(os.Stderr, "withhold: settings belong to another state directory")
			rc = 1
		} else if readErr != nil && !os.IsNotExist(readErr) {
			fmt.Fprintln(os.Stderr, "withhold: cannot read settings owner")
			rc = 1
		} else if err = o.Application.Restore(e); err != nil {
			fmt.Fprintln(os.Stderr, "withhold: settings restore failed:", err)
			rc = 1
		} else {
			_ = os.Remove(marker)
		}
	}
	if listening(o.Port) {
		fmt.Fprintln(os.Stderr, "withhold: port remains held; no foreign process was signalled")
		rc = 1
	}
	if rc == 0 {
		_ = os.Remove(filepath.Join(o.Dir, StateName))
		fmt.Println("withhold is off; managed settings restored.")
		fmt.Printf("Restart %s if it caches connections or launch-time proxy settings; follow its integration guide.\n", o.Application.Name())
	}
	return rc
}

func printObserveWarning(observe bool) {
	if observe {
		fmt.Fprintln(os.Stderr, "withhold: OBSERVE mode is active; secrets can be forwarded unchanged.")
	}
}
