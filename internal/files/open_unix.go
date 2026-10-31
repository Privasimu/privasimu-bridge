//go:build !windows

package files

import (
	"os"
	"syscall"
)

// openFlags opens without blocking, so a file swapped for a named pipe between listing
// and opening cannot stall the scan; the opened file is then checked to be regular.
const openFlags = os.O_RDONLY | syscall.O_NONBLOCK
