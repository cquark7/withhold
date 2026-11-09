// Package integration defines built-in application adapters. Implementations
// depend on these contracts; the runtime does not import their implementations.
package integration

import (
	"encoding/json"
	"os/exec"
)

type Target struct{ Resource, Binary string }

type State struct {
	Proxy         any
	BackupPath    string
	BackupPresent bool
}

type ApplicationOptions struct {
	Home, Platform, ConfigRoot, AppData string
	Settings                            json.RawMessage
}

type LaunchOptions struct {
	Port              int
	CADir             string
	Args, Environment []string
}

// SetupOptions supplies the local connection and CA location to adapters that
// configure proxy URLs, provider base URLs, or application-specific CA settings.
type SetupOptions struct {
	Port  int
	CADir string
}

// Apply/Restore must preserve unrelated user edits. The session manager records
// Resource before Apply, and can restore it without resolving current settings.
// Apply configures the current user's application independently of its launcher;
// Resource is an absolute recovery anchor: a settings file or an adapter-owned
// manifest for multiple artifacts. Recovery must not rediscover current settings.
type Application interface {
	Name() string
	Resolve() (Target, error)
	Read(Target) (State, error)
	Apply(Target, SetupOptions) error
	Restore(Target) error
}

// Launcher is optional convenience, never a prerequisite for protection.
// Applications without a launcher need not implement dummy commands.
type Launcher interface {
	Command(Target, LaunchOptions) (*exec.Cmd, error)
	MissingCLI() string
}
