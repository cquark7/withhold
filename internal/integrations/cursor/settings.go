package cursor

import (
	"os/exec"

	"github.com/cquark7/withhold/internal/editorsettings"
	"github.com/cquark7/withhold/internal/integration"
)

// Application is testable independently of product registration. It shares
// JSONC backup/recovery with the other editor adapter, not its traffic policy.
type Application struct {
	Options integration.ApplicationOptions
}

func (Application) Name() string { return "Cursor" }
func (Application) MissingCLI() string {
	return "install the Cursor 'cursor' command in PATH or set WITHHOLD_EDITOR_BIN to its executable"
}

func (a Application) editor() (editorsettings.Application, error) {
	s, err := settings(a.Options.Settings, nil)
	return editorsettings.Application{Options: a.Options, SettingsDir: s.SettingsDir,
		Binary: s.Binary, Label: a.Name(), Missing: a.MissingCLI(), Additional: cursorNetwork(),
		WindowsExecutables: map[string]string{"cursor": "Cursor.exe"}}, err
}

func cursorNetwork() map[string]any {
	// Tab and other services require HTTP/2. Do not force HTTP/1 as a workaround
	// for unsupported protobuf content or bidirectional transport.
	return map[string]any{"cursor.general.disableHttp2": false}
}

func (a Application) Resolve() (integration.Target, error) {
	editor, err := a.editor()
	if err != nil {
		return integration.Target{}, err
	}
	return editor.Resolve()
}
func (Application) Read(target integration.Target) (integration.State, error) {
	return (editorsettings.Application{}).Read(target)
}
func (Application) Apply(target integration.Target, options integration.SetupOptions) error {
	return (editorsettings.Application{Additional: cursorNetwork()}).Apply(target, options)
}
func (Application) Restore(target integration.Target) error {
	// Recovery uses the recorded anchor, never current discovery/configuration.
	return (editorsettings.Application{Additional: cursorNetwork()}).Restore(target)
}
func (a Application) Command(target integration.Target, options integration.LaunchOptions) (*exec.Cmd, error) {
	editor, err := a.editor()
	if err != nil {
		return nil, err
	}
	return editor.Command(target, options)
}
