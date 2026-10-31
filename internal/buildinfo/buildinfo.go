// Package buildinfo holds the version of the bridge and the protocol versions it speaks.
package buildinfo

import (
	"runtime"
	"runtime/debug"
)

// Version, Commit and Date are set at build time with -ldflags "-X ...".
var (
	Version = "0.1.0-dev"
	Commit  = ""
	Date    = ""
)

const (
	// ContractVersion is the platform-calls-bridge contract (mode A) this build implements.
	// The platform sends it in the X-Contract-Version header.
	ContractVersion = "1"
	// AgentProtocol is the outbound agent protocol (mode B) this build implements.
	AgentProtocol = 1
	// ProductName is the name used in the User-Agent header and in service descriptions.
	ProductName = "privasimu-bridge"
)

// UserAgent is sent on every request the bridge makes to the platform.
func UserAgent() string { return ProductName + "/" + Version }

// Revision returns the commit the binary was built from, when known.
func Revision() string {
	if Commit != "" {
		return Commit
	}
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, s := range info.Settings {
			if s.Key == "vcs.revision" {
				if len(s.Value) > 12 {
					return s.Value[:12]
				}
				return s.Value
			}
		}
	}
	return "unknown"
}

// Platform returns GOOS/GOARCH of the running binary.
func Platform() string { return runtime.GOOS + "/" + runtime.GOARCH }
