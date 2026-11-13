package copilot

import (
	"os/exec"

	"github.com/cquark7/withhold/internal/integration"
)

func (a Application) Command(target integration.Target, options integration.LaunchOptions) (*exec.Cmd, error) {
	editor, err := a.editor()
	if err != nil {
		return nil, err
	}
	return editor.Command(target, options)
}
