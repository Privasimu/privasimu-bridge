//go:build windows

package files

import "os"

// openFlags opens files read-only; os.Root refuses reparse points that leave the root.
const openFlags = os.O_RDONLY
