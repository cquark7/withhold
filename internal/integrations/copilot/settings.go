package copilot

import (
	"github.com/cquark7/withhold/internal/editorsettings"
	"github.com/cquark7/withhold/internal/integration"
)

type Application struct {
	Options integration.ApplicationOptions
}

func (Application) Name() string { return "VS Code" }
func (Application) MissingCLI() string {
	return "install the VS Code 'code' command in PATH or set WITHHOLD_EDITOR_BIN to its executable"
}

func (a Application) editor() (editorsettings.Application, error) {
	settings, err := settings(a.Options.Settings, nil)
	return editorsettings.Application{Options: a.Options, SettingsDir: settings.SettingsDir,
		Binary: settings.Binary, Label: a.Name(), Missing: a.MissingCLI(),
		WindowsExecutables: map[string]string{"code": "Code.exe", "code-insiders": "Code - Insiders.exe", "cursor": "Cursor.exe", "windsurf": "Windsurf.exe"}}, err
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
	return (editorsettings.Application{}).Apply(target, options)
}
func (Application) Restore(target integration.Target) error {
	return (editorsettings.Application{}).Restore(target)
}
