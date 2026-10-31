// Package service installs the bridge as a Windows service or a systemd unit, and runs
// it under the Windows service control manager.
package service

import (
	"errors"
	"fmt"
	"strings"
)

// Spec describes the service to install.
type Spec struct {
	// Name is the service (Windows) or unit (systemd) name.
	Name string
	// Mode is "serve" (mode A) or "agent" (mode B).
	Mode string
	// Executable is the absolute path of the bridge binary.
	Executable string
	// ConfigPath is the absolute path of bridge.yaml.
	ConfigPath string
	// Account runs the service: a Windows account ("NT AUTHORITY\LocalService", a gMSA
	// "DOMAIN\name$") or a Unix user.
	Account string
	// ReadWritePaths are directories the service writes (state, logs).
	ReadWritePaths []string
	// ReadOnlyPaths are directories it only reads (configuration, file roots).
	ReadOnlyPaths []string
	// BindPrivileged is true when the server listens on a port below 1024.
	BindPrivileged bool
}

// DefaultName returns the default service name of a mode.
func DefaultName(mode string) string {
	if mode == "agent" {
		return "privasimu-bridge-agent"
	}
	return "privasimu-bridge"
}

// Validate checks the spec.
func (s Spec) Validate() error {
	if s.Mode != "serve" && s.Mode != "agent" {
		return errors.New("mode must be serve or agent")
	}
	if s.Name == "" || strings.ContainsAny(s.Name, " /\\:*?\"<>|") {
		return errors.New("the service name may not contain spaces or path characters")
	}
	if s.Executable == "" || s.ConfigPath == "" {
		return errors.New("executable and configuration paths are required")
	}
	return nil
}

// Description is shown by the service manager.
func (s Spec) Description() string {
	if s.Mode == "agent" {
		return "Privasimu Bridge agent (mode B): scans local data sources and reports findings to Privasimu."
	}
	return "Privasimu Bridge (mode A): answers Privasimu Data Discovery with column names and findings."
}

// ErrUnsupported means the platform has no supported service manager.
var ErrUnsupported = errors.New("service installation is supported on Windows and on Linux with systemd")

// quoteArg quotes an argument for a command line shown to the operator.
func quoteArg(a string) string {
	if a == "" || strings.ContainsAny(a, " \t\"") {
		return fmt.Sprintf("%q", a)
	}
	return a
}
