// Package testintegration is imported only by tests. It deliberately uses a
// different request path, error protocol, and settings format from the built-in.
// It is not registered or selectable in the distributable executable.
package testintegration

import (
	"net/http"
	"os"
	"strings"

	"github.com/cquark7/withhold/internal/integration"
	"github.com/cquark7/withhold/internal/policy"
)

type Profile struct{ Host, Mode, Surface string }

func (p Profile) Classify(authority, path string) policy.Route {
	surface := p.Surface
	if surface == "" {
		surface = "fixture-content"
	}
	return policy.Route{Host: policy.Host(authority), Surface: surface, API: "fixture", Scoped: policy.Host(authority) == p.Host, Unknown: path != "/submit", Mode: p.Mode}
}
func (Profile) WantsStream([]byte) bool { return false }
func (Profile) Block(reason string, _ bool) policy.Response {
	return policy.Response{Status: http.StatusTeapot, Header: http.Header{"Content-Type": {"text/plain"}, "X-Fixture-Block": {"yes"}}, Body: []byte("fixture denied: " + reason)}
}

type Application struct {
	Path                                   string
	ResolveError, ApplyError, RestoreError error
	Applied, Restored                      int
	Setup                                  integration.SetupOptions
}

func (*Application) Name() string { return "Fixture Client" }
func (a *Application) Resolve() (integration.Target, error) {
	return integration.Target{Resource: a.Path, Binary: "fixture-client"}, a.ResolveError
}
func (*Application) Read(target integration.Target) (integration.State, error) {
	state := integration.State{BackupPath: target.Resource + ".original"}
	_, err := os.Stat(state.BackupPath)
	state.BackupPresent = err == nil
	data, err := os.ReadFile(target.Resource)
	if os.IsNotExist(err) {
		return state, nil
	}
	for _, line := range strings.Split(string(data), "\n") {
		if value, ok := strings.CutPrefix(line, "endpoint="); ok {
			state.Proxy = value
		}
	}
	return state, err
}
func (a *Application) Apply(target integration.Target, options integration.SetupOptions) error {
	a.Setup = options
	before, err := os.ReadFile(target.Resource)
	if err != nil {
		return err
	}
	if err = os.WriteFile(target.Resource+".original", before, 0600); err != nil {
		return err
	}
	if err = os.WriteFile(target.Resource, []byte("endpoint=guard\nkeep=original\n"), 0600); err != nil {
		return err
	}
	a.Applied++
	return a.ApplyError
}
func (a *Application) Restore(target integration.Target) error {
	a.Restored++
	if a.RestoreError != nil {
		return a.RestoreError
	}
	before, err := os.ReadFile(target.Resource + ".original")
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	current, err := os.ReadFile(target.Resource)
	if err != nil {
		return err
	}
	var kept []string
	for _, line := range strings.Split(string(current), "\n") {
		if line != "" && !strings.HasPrefix(line, "endpoint=") {
			kept = append(kept, line)
		}
	}
	for _, line := range strings.Split(string(before), "\n") {
		if strings.HasPrefix(line, "endpoint=") {
			kept = append(kept, line)
		}
	}
	if err = os.WriteFile(target.Resource, []byte(strings.Join(kept, "\n")+"\n"), 0600); err != nil {
		return err
	}
	return os.Remove(target.Resource + ".original")
}
