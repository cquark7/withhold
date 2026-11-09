package session

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"

	"github.com/cquark7/withhold/internal/certstore"
	"github.com/cquark7/withhold/internal/integration"
	"github.com/cquark7/withhold/internal/localstate"
)

func install(o Options) int {
	source, err := os.Executable()
	if err != nil {
		return fail(1, err)
	}
	dir := o.BinDir
	if dir == "" {
		home, e := os.UserHomeDir()
		if e != nil {
			return fail(1, e)
		}
		dir = filepath.Join(home, ".local", "bin")
		if runtime.GOOS == "windows" {
			dir = filepath.Join(os.Getenv("LOCALAPPDATA"), "withhold", "bin")
			if !filepath.IsAbs(dir) {
				dir = filepath.Join(home, "AppData", "Local", "withhold", "bin")
			}
		}
	}
	dir, err = filepath.Abs(dir)
	if err != nil {
		return fail(1, err)
	}
	name := "withhold"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	target := filepath.Join(dir, name)
	if filepath.Clean(source) == target {
		fmt.Println("Native executable is already installed at", target)
		return 0
	}
	// Running session upgrades require an explicit off; installation never kills processes.
	if r, e := LoadRecord(filepath.Join(o.Dir, StateName)); e == nil {
		if state, _ := ownership(r.Port, r); state == "ours" {
			return fail(1, errors.New("run 'withhold off' before upgrading the executable"))
		}
	} else if !os.IsNotExist(e) {
		return fail(1, e)
	}
	data, err := os.ReadFile(source)
	if err != nil {
		return fail(1, err)
	}
	if err = localstate.Write(target, data, false); err != nil {
		return fail(1, err)
	}
	if runtime.GOOS != "windows" {
		if err = os.Chmod(target, 0755); err != nil {
			return fail(1, err)
		}
	}
	fmt.Printf("Installed %s. Add %s to PATH.\n", target, dir)
	return 0
}
func launch(o Options, e integration.Target, r Record, recordErr error) int {
	launcher, ok := o.Application.(integration.Launcher)
	if !ok {
		return fail(2, errors.New("selected integration does not support launch; follow its integration guide"))
	}
	if recordErr != nil {
		return fail(1, errors.New("run 'withhold on' before launching the application"))
	}
	if state, _ := ownership(o.Port, r); state != "ours" {
		return fail(1, errors.New("application launch requires an authenticated guard listener"))
	}
	if e.Resource != r.Resource || o.Integration != r.Integration {
		return fail(1, errors.New("application settings differ from the running session; run 'withhold off' before changing integrations or settings"))
	}
	if _, err := certstore.Load(o.Dir); err != nil {
		return fail(1, err)
	}
	cmd, err := launcher.Command(e, integration.LaunchOptions{Port: o.Port, CADir: o.Dir, Args: o.ApplicationArgs, Environment: os.Environ()})
	if err != nil {
		return fail(1, err)
	}
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err = cmd.Run(); err != nil {
		if exit, ok := err.(*exec.ExitError); ok {
			return exit.ExitCode()
		}
		return fail(1, err)
	}
	return 0
}
