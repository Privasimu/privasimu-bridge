//go:build windows

package packages

import (
	"os/exec"
	"syscall"
)

// idlePriorityClass is IDLE_PRIORITY_CLASS: the process runs only when the system is idle,
// and its I/O gets the matching low priority.
const idlePriorityClass = 0x00000040

// startLowPriority starts cmd in the idle priority class.
func startLowPriority(cmd *exec.Cmd) error {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.CreationFlags |= idlePriorityClass
	return cmd.Start()
}
