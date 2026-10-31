package config

import (
	"os"
	"path/filepath"
	"runtime"
)

// DefaultDir is the directory init writes the configuration, secrets and state to when no
// directory is given: %ProgramData%\PrivasimuBridge on Windows, /etc/privasimu-bridge
// elsewhere.
func DefaultDir() string {
	if runtime.GOOS == "windows" {
		base := os.Getenv("ProgramData")
		if base == "" {
			base = `C:\ProgramData`
		}
		return filepath.Join(base, "PrivasimuBridge")
	}
	return "/etc/privasimu-bridge"
}

// DefaultPath is the configuration file used when --config is not given: the
// PRIVASIMU_BRIDGE_CONFIG environment variable, else bridge.yaml in DefaultDir.
func DefaultPath() string {
	if p := os.Getenv("PRIVASIMU_BRIDGE_CONFIG"); p != "" {
		return p
	}
	return filepath.Join(DefaultDir(), "bridge.yaml")
}

// DefaultStateDir is where reports and the agent status are kept on Linux when init is
// run with the system layout; elsewhere state lives under the configuration directory.
func DefaultStateDir(dir string) string {
	if runtime.GOOS != "windows" && dir == "/etc/privasimu-bridge" {
		return "/var/lib/privasimu-bridge"
	}
	return filepath.Join(dir, "state")
}

// DefaultLogDir is where the audit log is written.
func DefaultLogDir(dir string) string {
	if runtime.GOOS != "windows" && dir == "/etc/privasimu-bridge" {
		return "/var/log/privasimu-bridge"
	}
	return filepath.Join(dir, "logs")
}
