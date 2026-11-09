package copilot

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/cquark7/withhold/internal/integration"
)

func (a Application) Command(target integration.Target, o integration.LaunchOptions) (*exec.Cmd, error) {
	binary, err := exec.LookPath(target.Binary)
	if err != nil {
		return nil, fmt.Errorf("cannot find editor %q; %s", target.Binary, a.MissingCLI())
	}
	binary, prefix, err := editorInvocation(binary, a.Options.Platform)
	if err != nil {
		return nil, err
	}
	cmd := exec.Command(binary, append(prefix, o.Args...)...)
	// Supply proxy and CA environment for application runtimes that do not
	// use the application-level settings managed by Apply.
	proxy := fmt.Sprintf("http://127.0.0.1:%d", o.Port)
	values := map[string]string{"HTTP_PROXY": proxy, "HTTPS_PROXY": proxy, "http_proxy": proxy, "https_proxy": proxy, "NO_PROXY": "localhost,127.0.0.1,::1", "no_proxy": "localhost,127.0.0.1,::1", "NODE_EXTRA_CA_CERTS": filepath.Join(o.CADir, "ca.crt")}
	if len(prefix) != 0 {
		values["ELECTRON_RUN_AS_NODE"] = "1"
		values["VSCODE_DEV"] = ""
	}
	cmd.Env = withEnv(o.Environment, values)
	return cmd, nil
}

func withEnv(base []string, values map[string]string) []string {
	result := make([]string, 0, len(base)+len(values))
	for _, entry := range base {
		key, _, _ := strings.Cut(entry, "=")
		replace := false
		for wanted := range values {
			if strings.EqualFold(key, wanted) {
				replace = true
				break
			}
		}
		if !replace {
			result = append(result, entry)
		}
	}
	for k, v := range values {
		result = append(result, k+"="+v)
	}
	return result
}

// Resolve standard Windows editor shims without invoking a shell.
func editorInvocation(binary, platform string) (string, []string, error) {
	if platform != "windows" || (!strings.EqualFold(filepath.Ext(binary), ".cmd") && !strings.EqualFold(filepath.Ext(binary), ".bat")) {
		return binary, nil, nil
	}
	root := filepath.Dir(filepath.Dir(binary))
	name := strings.ToLower(strings.TrimSuffix(filepath.Base(binary), filepath.Ext(binary)))
	names := map[string]string{"code": "Code.exe", "code-insiders": "Code - Insiders.exe", "cursor": "Cursor.exe", "windsurf": "Windsurf.exe"}
	exe, ok := names[name]
	if !ok {
		return "", nil, errors.New("unrecognized editor shim; set WITHHOLD_EDITOR_BIN to its .exe executable")
	}
	target := filepath.Join(root, exe)
	cli := filepath.Join(root, "resources", "app", "out", "cli.js")
	for _, file := range []string{target, cli} {
		info, err := os.Stat(file)
		if err != nil || !info.Mode().IsRegular() {
			return "", nil, errors.New("editor installation is incomplete; reinstall the editor or set WITHHOLD_EDITOR_BIN to its .exe executable")
		}
	}
	return target, []string{cli}, nil
}
