//go:build !windows

// Package fsutil keeps file ownership consistent when an administrator runs a command
// as root on files the bridge service (running as its own user) must read and write.
package fsutil

import (
	"os"
	"path/filepath"
	"syscall"
)

// InheritOwner gives path the owner of the file it replaces (previous) or, when there is
// none, the owner of its directory. It only has an effect when running as root (for
// example "sudo privasimu-bridge secret set" after "service install"); otherwise a file
// already belongs to the current user and nothing changes. Errors are ignored.
func InheritOwner(path, previous string) {
	if os.Geteuid() != 0 {
		return
	}
	ref := previous
	if ref == "" {
		ref = filepath.Dir(path)
	}
	st, err := os.Stat(ref)
	if err != nil {
		if ref == previous {
			st, err = os.Stat(filepath.Dir(path))
		}
		if err != nil {
			return
		}
	}
	if sys, ok := st.Sys().(*syscall.Stat_t); ok {
		_ = os.Chown(path, int(sys.Uid), int(sys.Gid))
	}
}
