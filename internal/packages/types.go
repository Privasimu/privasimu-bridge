// Package packages inventories the software of allow-listed targets (an installed host, a
// directory or a local container image archive) with Syft, and matches it against
// vulnerability data with Grype or Trivy. It backs the agent job scan_packages (agent
// protocol 1, revision 3).
//
// The scanners are external programs that the operator installs; the bridge never
// downloads them. Each one is pinned by path and SHA-256 in the configuration and its
// checksum is verified before every run. They run as child processes without a shell, with
// fixed argument lists, an emptied environment, a timeout, capped output and the lowest
// CPU and I/O priority, and they write only below the bridge's state directory. The
// bridge never scans a network: it reads local files only, and only package names,
// versions, licences and vulnerability ids leave the client network (never a path, a file
// or the SBOM itself).
package packages

import (
	"errors"
	"fmt"
	"time"
)

// Item is one package in a part of kind "packages" (docs/AGENT-PROTOCOL.md section 6.7).
// Keys are in protocol order.
type Item struct {
	Name             string   `json:"name"`
	Version          string   `json:"version"`
	Ecosystem        string   `json:"ecosystem"`
	EcosystemRelease string   `json:"ecosystem_release,omitempty"`
	PURL             string   `json:"purl,omitempty"`
	Type             string   `json:"type"`
	Layer            string   `json:"layer"`
	Dependency       string   `json:"dependency"`
	Licenses         []string `json:"licenses"`
	Matches          []Match  `json:"matches"`
}

// Match is one vulnerability a matcher reported for a package.
type Match struct {
	ID          string   `json:"id"`
	Aliases     []string `json:"aliases"`
	Severity    string   `json:"severity"`
	CVSS        []CVSS   `json:"cvss"`
	FixVersions []string `json:"fix_versions"`
	Matcher     string   `json:"matcher"`
}

// CVSS is one CVSS rating. The score is sent in tenths as an integer (no floats on the
// wire): 9.1 is 91.
type CVSS struct {
	Version     string `json:"version"`
	Vector      string `json:"vector"`
	ScoreTenths int    `json:"score_tenths"`
}

// OSInfo names the operating system of a host or an image.
type OSInfo struct {
	ID      string `json:"id"`
	Version string `json:"version"`
}

// Result is the result of a scan_packages job (complete.result). Keys are in protocol
// order; null values are pointers without omitempty.
type Result struct {
	TargetKind           string  `json:"target_kind"`
	TargetLabel          string  `json:"target_label"`
	OS                   *OSInfo `json:"os"`
	InventoryTool        string  `json:"inventory_tool"`
	InventoryToolVersion string  `json:"inventory_tool_version"`
	Matcher              string  `json:"matcher"`
	MatcherVersion       *string `json:"matcher_version"`
	MatcherDBBuiltAt     *string `json:"matcher_db_built_at"`
	PackagesTotal        int     `json:"packages_total"`
	MatchesTotal         int     `json:"matches_total"`
	Truncated            bool    `json:"truncated"`
	DurationMS           int64   `json:"duration_ms"`
	BridgeVersion        string  `json:"bridge_version"`
	SBOMSHA256           string  `json:"sbom_sha256"`
}

// Report is the outcome of one scan, kept in the state directory so that a job can be
// answered from a recent scan (like file roots).
type Report struct {
	TargetID   string    `json:"target_id"`
	FinishedAt time.Time `json:"finished_at"`
	// Matched means the configured matcher ran (or none is configured), so the report can
	// answer a job that asks for matching.
	Matched bool   `json:"matched"`
	Result  Result `json:"result"`
	Items   []Item `json:"items"`
}

// WithoutMatches returns a copy of the report for a job that asked for the inventory
// only (option match: false).
func (r *Report) WithoutMatches() *Report {
	out := *r
	out.Result.Matcher, out.Result.MatcherVersion, out.Result.MatcherDBBuiltAt = "none", nil, nil
	out.Result.MatchesTotal = 0
	out.Items = make([]Item, len(r.Items))
	for i, it := range r.Items {
		it.Matches = []Match{}
		out.Items[i] = it
	}
	return &out
}

// Failure codes of package scans. The agent reports them as fail.error_code (protocol
// section 6.6); the platforms store the Indonesian text of each.
const (
	CodeToolMissing      = "tool_missing"
	CodeToolChecksum     = "tool_checksum_mismatch"
	CodeToolFailed       = "tool_failed"
	CodeToolTimeout      = "tool_timeout"
	CodeMatcherDB        = "matcher_db_unavailable"
	CodeTargetUnreadable = "target_unreadable"
)

// Error is a scan failure with a protocol failure code. Stage says where it happened
// (target, tool, inventory, matching). The wrapped error stays local (logs only).
type Error struct {
	Code  string
	Stage string
	Tool  string
	Err   error
}

func (e *Error) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s (%s %s): %v", e.Code, e.Stage, e.Tool, e.Err)
	}
	return fmt.Sprintf("%s (%s %s)", e.Code, e.Stage, e.Tool)
}

func (e *Error) Unwrap() error { return e.Err }

func scanError(code, stage, tool string, err error) *Error {
	return &Error{Code: code, Stage: stage, Tool: tool, Err: err}
}

// CodeOf returns the failure code of err ("" when err is not a scan failure).
func CodeOf(err error) string {
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	return ""
}

// ErrUnknownTarget means the id names no packages target of the configuration.
var ErrUnknownTarget = errors.New("unknown packages target")

// Closed lists of the protocol (contract section 2.1 and 7.4).
var (
	// Ecosystems are OSV ecosystem names plus "other".
	Ecosystems = []string{"npm", "Packagist", "Go", "Maven", "PyPI", "NuGet", "RubyGems", "crates.io", "Debian", "Ubuntu",
		"Alpine", "Red Hat", "Rocky Linux", "AlmaLinux", "other"}
	// Types are the component types.
	Types = []string{"library", "os_package", "application", "framework", "container", "firmware", "other"}
	// Layers are the component layers.
	Layers = []string{"os", "runtime", "application"}
	// Severities are the qualitative severities of a match.
	Severities = []string{"critical", "high", "medium", "low", "negligible", "unknown"}
)

// osEcosystems are the ecosystems of operating-system packages (matched by the agent's
// matcher, never by the platform in phase 1).
var osEcosystems = map[string]bool{"Debian": true, "Ubuntu": true, "Alpine": true, "Red Hat": true, "Rocky Linux": true, "AlmaLinux": true}

// Limits of items (protocol section 6.7).
const (
	maxNameChars      = 255
	maxVersionChars   = 128
	maxPURLChars      = 512
	maxReleaseChars   = 32
	maxLicenses       = 10
	maxLicenseChars   = 64
	maxMatches        = 200
	maxAliases        = 20
	maxFixVersions    = 10
	maxFixChars       = 128
	maxCVSS           = 8
	maxVectorChars    = 200
	maxToolVersionLen = 40
)
