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
	o := Options{Verb: "on", Dir: dir, Port: unusedPort(t), StartupTimeout: time.Second, Integration: "fixture", Application: app}
	c := config.Defaults("fixture", "linux")
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

func TestRecoveryUsesRecordedIntegrationAndResourceDespiteBrokenDiscovery(t *testing.T) {
	o, app := fixtureOptions(t)
	target, _ := app.Resolve()
	if err := app.Apply(target, integration.SetupOptions{Port: o.Port, CADir: o.Dir}); err != nil {
		t.Fatal(err)
	}
	current, _ := os.ReadFile(app.Path)
	_ = os.WriteFile(app.Path, append(current, []byte("mid-session=preserved\n")...), 0600)
	r := Record{Schema: 1, Identity: control.Identity{Instance: control.Random(), Token: control.Random()}, Port: o.Port, Resource: app.Path, Integration: "fixture", Configuration: o.Configuration}
	if err := saveRecord(filepath.Join(o.Dir, StateName), r); err != nil {
		t.Fatal(err)
	}
	app.ResolveError = errors.New("current discovery is broken")
	o.Application = &testintegration.Application{Path: filepath.Join(o.Dir, "wrong-client.ini")}
	o.Integration = "invalid-current-selection"
	o.Verb = "off"
	if Run(o) != 0 || app.Restored != 1 {
		t.Fatal("recorded integration was not used for recovery")
	}
	got, _ := os.ReadFile(app.Path)
	if !strings.Contains(string(got), "mid-session=preserved") || !strings.Contains(string(got), "endpoint=original") {
		t.Fatal("recovery lost unrelated edits")
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
	if saveRecord(path, Record{Resource: strings.Repeat("x", 1024*1024)}) == nil {
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
		{name: "missing integration", change: func(r *Record) { r.Integration = "" }},
		{name: "missing configuration", change: func(r *Record) { r.Configuration = nil }},
		{name: "missing resource", change: func(r *Record) { r.Resource = "" }},
		{name: "different integration", change: func(r *Record) { r.Configuration.Integration = "other" }},
		{name: "different port", change: func(r *Record) { r.Configuration.Proxy.Port++ }},
		{name: "invalid policy", change: func(r *Record) { r.Configuration.Protection.Chat = "warn" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			c := config.Defaults("fixture", "linux")
			r := Record{Schema: 1, Identity: control.Identity{Instance: control.Random(), Token: control.Random()}, Port: c.Proxy.Port, Resource: filepath.Join(dir, "client.ini"), Integration: c.Integration, Configuration: &c}
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
				if json.Unmarshal(after, &data) != nil || data["resource"] != r.Resource || data["settings"] != nil {
					t.Fatal("record does not use the resource contract")
				}
			}
		})
	}
}
