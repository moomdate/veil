//go:build unix

package runner

import (
	"os/exec"
	"syscall"
)

// setProcessGroup runs the command in its own process group so a timeout
// stops the command and everything it started.
func setProcessGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
}
