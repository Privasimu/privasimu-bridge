//go:build !linux && !windows

package packages

import (
	"os/exec"
	"syscall"
)

// startLowPriority starts cmd and then lowers its CPU priority to nice 19 (other Unix
// systems; I/O priority is not adjustable portably).
func startLowPriority(cmd *exec.Cmd) error {
	if err := cmd.Start(); err != nil {
		return err
	}
	_ = syscall.Setpriority(syscall.PRIO_PROCESS, cmd.Process.Pid, 19)
	return nil
}
