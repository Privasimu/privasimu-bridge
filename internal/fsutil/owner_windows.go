//go:build windows

// Package fsutil keeps file ownership consistent across administrative commands. On
// Windows new files inherit the folder's ACL, which already grants the service account
// its access, so nothing needs to be done.
package fsutil

// InheritOwner is a no-op on Windows.
func InheritOwner(string, string) {}
