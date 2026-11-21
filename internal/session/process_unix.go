//go:build !windows

package session

import (
	"errors"
	"os/exec"
	"syscall"
)

func detach(cmd *exec.Cmd) { cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true} }

func processExited(pid int) bool {
	return pid == 0 || errors.Is(syscall.Kill(pid, 0), syscall.ESRCH)
}
