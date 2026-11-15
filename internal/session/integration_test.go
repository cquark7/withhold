package session

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cquark7/withhold/internal/certstore"
	"github.com/cquark7/withhold/internal/config"
	"github.com/cquark7/withhold/internal/control"
	"github.com/cquark7/withhold/internal/integration"
	"github.com/cquark7/withhold/internal/localstate"
	"github.com/cquark7/withhold/internal/testintegration"
)

// The test executable is a deliberately failing child, never a second test
// runner or a real proxy. Process acceptance separately runs the native binary.
func TestMain(m *testing.M) {
	if len(os.Args) > 1 && os.Args[1] == "_session-serve" {
		if _, err := LoadStartupRecord(os.Args[3], os.Stdin); err == nil {
			fmt.Println("session record committed before child read")
		}
		os.Exit(1)
	}
	os.Exit(m.Run())
}

func TestSessionStartupCommitsOwnershipBeforeChildReads(t *testing.T) {
	o, _ := fixtureOptions(t)
	if Run(o) != 1 {
		t.Fatal("deliberately failing child unexpectedly started a session")
	}
	log, err := os.ReadFile(filepath.Join(o.Dir, "proxy.log"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(log), "session record committed before child read") {
		t.Fatalf("child was not released after PID publication: %s", log)
	}
}

func unusedPort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	_, port, _ := net.SplitHostPort(l.Addr().String())
	n, _ := strconv.Atoi(port)
	return n
}

func fixtureOptions(t *testing.T) (Options, *testintegration.Application) {
	t.Helper()
	dir := t.TempDir()
	if err := certstore.Init(dir); err != nil {
		t.Fatal(err)
	}
	crt, _ := os.ReadFile(filepath.Join(dir, "ca.crt"))
	if err := writeTrust(dir, TrustState{Fingerprint: certFingerprint(crt), Mode: "manual"}); err != nil {
		t.Fatal(err)
	}
	app := &testintegration.Application{Path: filepath.Join(dir, "client.ini")}
	if err := os.WriteFile(app.Path, []byte("endpoint=original\nkeep=original\n"), 0600); err != nil {
		t.Fatal(err)
	}
	o := Options{Verb: "on", Dir: dir, Port: unusedPort(t), StartupTimeout: time.Second, Agents: []string{"fixture"}, Applications: map[string]integration.Application{"fixture": app}}
	c := config.Defaults("linux")
	c.Agents = o.Agents
	c.Proxy.Port = o.Port
	o.Configuration = &c
	o.LookupApplication = func(id string) (integration.Application, error) {
		if id != "fixture" {
			return nil, errors.New("unknown fixture")
		}
		return app, nil
	}
	return o, app
}

func TestIndependentApplicationRollsBackApplyAndChildFailures(t *testing.T) {
	for _, failure := range []string{"apply", "child", "restore"} {
		t.Run(failure, func(t *testing.T) {
			o, app := fixtureOptions(t)
			if failure == "apply" {
				app.ApplyError = errors.New("partial apply failed")
			}
			if failure == "restore" {
				app.RestoreError = errors.New("restore must be retried")
			}
			if Run(o) != 1 || app.Applied != 1 || app.Restored != 1 {
				t.Fatal("startup did not use adapter rollback")
			}
			if app.Setup.Port != o.Port || app.Setup.CADir != o.Dir {
				t.Fatal("application setup did not receive connection and CA options")
			}
			_, stateErr := os.Stat(filepath.Join(o.Dir, StateName))
			if failure == "restore" {
				if stateErr != nil {
					t.Fatal("recovery record discarded after restore failure")
				}
				app.RestoreError = nil
				o.Verb = "off"
				if Run(o) != 0 {
					t.Fatal("retry failed")
				}
			} else if !os.IsNotExist(stateErr) {
				t.Fatal("successful rollback retained stale record")
			}
			got, _ := os.ReadFile(app.Path)
			if !strings.Contains(string(got), "endpoint=original") || strings.Contains(string(got), "endpoint=guard") {
				t.Fatal("original application configuration not restored")
			}
		})
	}
}

func TestAgentSetPreflightRollbackAndRecordedRecovery(t *testing.T) {
	for _, failure := range []string{"preflight", "shared resource", "apply", "restore"} {
		t.Run(failure, func(t *testing.T) {
			o, first := fixtureOptions(t)
			second := &testintegration.Application{Path: filepath.Join(o.Dir, "second.ini")}
			secondPath := second.Path
			if err := os.WriteFile(second.Path, []byte("endpoint=second-original\n"), 0600); err != nil {
				t.Fatal(err)
			}
			o.Agents = []string{"fixture", "second"}
			o.Configuration.Agents = o.Agents
			o.Applications["second"] = second
			o.LookupApplication = func(id string) (integration.Application, error) {
				if id == "fixture" {
					return first, nil
				}
				if id == "second" {
					return second, nil
				}
				return nil, errors.New("unknown agent")
			}
			wantCode := 1
			if failure == "preflight" || failure == "shared resource" {
				if failure == "shared resource" {
					second.Path = first.Path
				} else {
					second.ResolveError = errors.New("cannot resolve second application")
				}
				wantCode = 2
			} else {
				second.ApplyError = errors.New("second application partially applied")
				if failure == "restore" {
					first.RestoreError = errors.New("first restore temporarily unavailable")
				}
			}
			if Run(o) != wantCode {
				t.Fatal("unexpected activation result")
			}
			if wantCode == 2 && (first.Applied != 0 || second.Applied != 0) {
				t.Fatal("preflight failure changed an application")
			}
			if failure == "restore" {
				if _, err := LoadRecord(filepath.Join(o.Dir, StateName)); err != nil {
					t.Fatal("partial recovery lost the complete resource record:", err)
				}
				first.RestoreError = nil
				first.ResolveError = errors.New("discovery must not be required")
				second.ResolveError = first.ResolveError
				o.Verb, o.Agents, o.Applications = "off", []string{"unrelated"}, nil
				if Run(o) != 0 {
					t.Fatal("retry did not recover both recorded applications")
				}
			}
			for path, endpoint := range map[string]string{first.Path: "endpoint=original", secondPath: "endpoint=second-original"} {
				data, _ := os.ReadFile(path)
				if !strings.Contains(string(data), endpoint) || strings.Contains(string(data), "endpoint=guard") {
					t.Fatalf("application not restored: %s", data)
				}
			}
			if _, err := os.Stat(filepath.Join(o.Dir, StateName)); !os.IsNotExist(err) {
				t.Fatal("completed recovery left a stale record")
			}
		})
	}
}

func TestRecoveryUsesRecordedIntegrationAndResourceDespiteBrokenDiscovery(t *testing.T) {
	o, app := fixtureOptions(t)
	target, _ := app.Resolve()
	if err := app.Apply(target, integration.SetupOptions{Port: o.Port, CADir: o.Dir}); err != nil {
		t.Fatal(err)
	}
	current, _ := os.ReadFile(app.Path)
	_ = os.WriteFile(app.Path, append(current, []byte("mid-session=preserved\n")...), 0600)
	r := Record{Schema: 2, Identity: control.Identity{Instance: control.Random(), Token: control.Random()}, Port: o.Port, Applications: []ManagedApplication{{Agent: "fixture", Target: target}}, Configuration: o.Configuration}
	if err := saveRecord(filepath.Join(o.Dir, StateName), r); err != nil {
		t.Fatal(err)
	}
	app.ResolveError = errors.New("current discovery is broken")
	o.Applications = map[string]integration.Application{"invalid": &testintegration.Application{Path: filepath.Join(o.Dir, "wrong-client.ini")}}
	o.Agents = []string{"invalid-current-selection"}
	o.Verb = "off"
	if Run(o) != 0 || app.Restored != 1 {
		t.Fatal("recorded integration was not used for recovery")
	}
	got, _ := os.ReadFile(app.Path)
	if !strings.Contains(string(got), "mid-session=preserved") || !strings.Contains(string(got), "endpoint=original") {
		t.Fatal("recovery lost unrelated edits")
	}
}

func TestOffRestoresOtherApplicationsWhenSettingsLockFails(t *testing.T) {
	o, first := fixtureOptions(t)
	second := &testintegration.Application{Path: filepath.Join(o.Dir, "second.ini")}
	if err := os.WriteFile(second.Path, []byte("endpoint=second-original\n"), 0600); err != nil {
		t.Fatal(err)
	}
	o.Agents = []string{"fixture", "second"}
	o.Configuration.Agents = o.Agents
	o.LookupApplication = func(id string) (integration.Application, error) {
		switch id {
		case "fixture":
			return first, nil
		case "second":
			return second, nil
		default:
			return nil, errors.New("unknown agent")
		}
	}
	var managed []ManagedApplication
	for i, app := range []*testintegration.Application{first, second} {
		target, err := app.Resolve()
		if err != nil {
			t.Fatal(err)
		}
		if err := app.Apply(target, integration.SetupOptions{Port: o.Port, CADir: o.Dir}); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(target.Resource+".withhold-session", []byte(o.Dir), 0600); err != nil {
			t.Fatal(err)
		}
		managed = append(managed, ManagedApplication{Agent: o.Agents[i], Target: target})
	}
	record := Record{Schema: 2, Identity: control.Identity{Instance: control.Random(), Token: control.Random()}, Port: o.Port, Applications: managed, Configuration: o.Configuration}
	if err := saveRecord(filepath.Join(o.Dir, StateName), record); err != nil {
		t.Fatal(err)
	}
	unlock, err := localstate.Lock(first.Path + ".withhold-lock")
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	o.Verb = "off"
	if Run(o) != 1 {
		t.Fatal("off must report the lock failure")
	}
	if first.Restored != 0 || second.Restored != 1 {
		t.Fatalf("restore counts: locked=%d, available=%d", first.Restored, second.Restored)
	}
	if got, err := os.ReadFile(second.Path); err != nil || !strings.Contains(string(got), "endpoint=second-original") {
		t.Fatalf("available application not restored: %s, %v", got, err)
	}
	if _, err := LoadRecord(filepath.Join(o.Dir, StateName)); err != nil {
		t.Fatal("lock failure lost the recovery record:", err)
	}
	unlock()
	if Run(o) != 0 {
		t.Fatal("retry did not complete recovery")
	}
	if got, err := os.ReadFile(first.Path); err != nil || !strings.Contains(string(got), "endpoint=original") {
		t.Fatalf("locked application not restored on retry: %s, %v", got, err)
	}
	if _, err := os.Stat(filepath.Join(o.Dir, StateName)); !os.IsNotExist(err) {
		t.Fatal("completed recovery left a stale record")
	}
}

func TestApplicationWithoutLauncherCanRecoverButCannotLaunch(t *testing.T) {
	o, app := fixtureOptions(t)
	if _, ok := any(app).(integration.Launcher); ok {
		t.Fatal("fixture must exercise an application with no launch capability")
	}
	o.Verb = "launch"
	if Run(o) != 2 {
		t.Fatal("unsupported launch was not a usage error")
	}
	o.Verb = "off"
	if Run(o) != 0 {
		t.Fatal("recovery required an optional launcher")
	}
}

func TestOversizedRecoveryRecordIsRefusedBeforePublication(t *testing.T) {
	path := filepath.Join(t.TempDir(), StateName)
	if saveRecord(path, Record{Environment: strings.Repeat("x", 1024*1024)}) == nil {
		t.Fatal("unreadable recovery record published")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("oversized recovery record left state behind")
	}
}

func TestSessionRecordRequiresCompleteConsistentFrozenConfiguration(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, StateName)
	for _, test := range []struct {
		name   string
		change func(*Record)
		valid  bool
	}{
		{name: "current", valid: true},
		{name: "missing agent", change: func(r *Record) { r.Applications[0].Agent = "" }},
		{name: "missing configuration", change: func(r *Record) { r.Configuration = nil }},
		{name: "missing resource", change: func(r *Record) { r.Applications[0].Target.Resource = "" }},
		{name: "different agent", change: func(r *Record) { r.Configuration.Agents = []string{"other"} }},
		{name: "missing application", change: func(r *Record) { r.Applications = nil }},
		{name: "different port", change: func(r *Record) { r.Configuration.Proxy.Port++ }},
		{name: "invalid policy", change: func(r *Record) { r.Configuration.Protection.Chat = "warn" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			c := config.Defaults("linux")
			c.Agents = []string{"fixture"}
			r := Record{Schema: 2, Identity: control.Identity{Instance: control.Random(), Token: control.Random()}, Port: c.Proxy.Port, Applications: []ManagedApplication{{Agent: "fixture", Target: integration.Target{Resource: filepath.Join(dir, "client.ini")}}}, Configuration: &c}
			if test.change != nil {
				test.change(&r)
			}
			if err := saveRecord(path, r); err != nil {
				t.Fatal(err)
			}
			before, _ := os.ReadFile(path)
			if _, err := LoadRecord(path); (err == nil) != test.valid {
				t.Fatalf("record validity: %v", err)
			}
			after, _ := os.ReadFile(path)
			if !bytes.Equal(before, after) {
				t.Fatal("record read changed recovery state")
			}
			if test.valid {
				var data map[string]any
				if json.Unmarshal(after, &data) != nil || data["applications"] == nil || data["resource"] != nil {
					t.Fatal("record does not use the resource contract")
				}
			}
		})
	}
}
