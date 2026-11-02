//go:build linux

package packages

import (
	"os/exec"
	"runtime"

	"golang.org/x/sys/unix"
)

// ioprioClassIdle is IOPRIO_CLASS_IDLE shifted into place (linux/ioprio.h).
const ioprioClassIdle = 3 << 13

// startLowPriority starts cmd at the lowest CPU priority (nice 19) and the idle I/O class.
// On Linux both are attributes of the thread that forks, so the child is started from a
// locked thread that lowers its own priority first. The goroutine ends without unlocking,
// so the runtime discards that thread and the bridge itself keeps its normal priority.
func startLowPriority(cmd *exec.Cmd) error {
	done := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		// Failures only mean the child runs at normal priority.
		_ = unix.Setpriority(unix.PRIO_PROCESS, 0, 19)
		_, _, _ = unix.Syscall(unix.SYS_IOPRIO_SET, 1 /* IOPRIO_WHO_PROCESS */, 0, ioprioClassIdle)
		done <- cmd.Start()
	}()
	return <-done
}
