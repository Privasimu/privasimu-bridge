package config

import (
	"fmt"
	"net/url"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"
)

// JobScanPackages is the opt-in job that inventories the software of a packages target
// (Syft) and matches it against vulnerability data (Grype or Trivy). It is never in the
// default allowed_jobs.
const JobScanPackages = "scan_packages"

// Kinds of a packages target.
const (
	// PackageHost scans an installed system rooted at path (normally "/").
	PackageHost = "host"
	// PackageDirectory scans one directory (an application, a deployment folder).
	PackageDirectory = "directory"
	// PackageImageArchive scans a container image saved as a local OCI or docker archive
	// file. There is no Docker socket and no registry pull in phase 1.
	PackageImageArchive = "image_archive"
)

// Vulnerability matchers of package scans.
const (
	MatcherGrype = "grype"
	MatcherTrivy = "trivy"
	MatcherNone  = "none"
)

// Bounds of package scans.
const (
	// MaxPackagesLimit is the most packages one scan_packages job may report (the platform
	// stores at most 20 000 items per job).
	MaxPackagesLimit = 20000
	// maxPackageTimeout bounds the configured timeout of one scan.
	maxPackageTimeout = 6 * time.Hour
	// minPackageRefresh bounds background rescans: package scans read a whole system.
	minPackageRefresh = time.Hour
	maxExcludes       = 64
)

// PackagesConfig configures software inventory and vulnerability matching (job
// scan_packages). Targets are allow-listed like file roots: the platform names a target by
// its id and can never send a path.
type PackagesConfig struct {
	Targets     []PackageTarget `yaml:"targets"`
	Tools       PackageTools    `yaml:"tools"`
	Timeout     Duration        `yaml:"timeout"`
	MaxPackages int             `yaml:"max_packages"`
}

// PackageTarget is one system, directory or image archive whose packages may be listed.
type PackageTarget struct {
	ID          string   `yaml:"id"`
	Label       string   `yaml:"label"`
	Description string   `yaml:"description"`
	Kind        string   `yaml:"kind"`
	Path        string   `yaml:"path"`
	Exclude     []string `yaml:"exclude"`
	// RefreshInterval rescans the target in the background when its report is older
	// (0 = only on request).
	RefreshInterval Duration `yaml:"refresh_interval"`
}

// PackageTools pins the external scanners by path and SHA-256. The bridge verifies the
// checksum before every run and never downloads a tool.
type PackageTools struct {
	Syft    ToolConfig  `yaml:"syft"`
	Matcher string      `yaml:"matcher"`
	Grype   GrypeConfig `yaml:"grype"`
	Trivy   TrivyConfig `yaml:"trivy"`
}

// ToolConfig is an executable and its expected SHA-256 (lower-case hex).
type ToolConfig struct {
	Path   string `yaml:"path"`
	SHA256 string `yaml:"sha256"`
}

// IsSet reports whether a path was configured.
func (t ToolConfig) IsSet() bool { return strings.TrimSpace(t.Path) != "" }

// GrypeConfig configures the Grype matcher and its local vulnerability database.
type GrypeConfig struct {
	Path         string   `yaml:"path"`
	SHA256       string   `yaml:"sha256"`
	DBDir        string   `yaml:"db_dir"`
	DBUpdateURL  string   `yaml:"db_update_url"`
	DBAutoUpdate bool     `yaml:"db_auto_update"`
	DBMaxAge     Duration `yaml:"db_max_age"`
}

// Tool returns the executable settings.
func (g GrypeConfig) Tool() ToolConfig { return ToolConfig{Path: g.Path, SHA256: g.SHA256} }

// TrivyConfig configures the Trivy matcher and its local cache.
type TrivyConfig struct {
	Path         string `yaml:"path"`
	SHA256       string `yaml:"sha256"`
	CacheDir     string `yaml:"cache_dir"`
	DBRepository string `yaml:"db_repository"`
	SkipDBUpdate *bool  `yaml:"skip_db_update"`
}

// Tool returns the executable settings.
func (t TrivyConfig) Tool() ToolConfig { return ToolConfig{Path: t.Path, SHA256: t.SHA256} }

// SkipUpdate reports whether Trivy must use its local database only (default true).
func (t TrivyConfig) SkipUpdate() bool { return t.SkipDBUpdate == nil || *t.SkipDBUpdate }

var (
	sha256Pattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
	// repoPattern is an OCI repository reference such as ghcr.io/aquasecurity/trivy-db:2.
	repoPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/@-]{0,254}$`)
)

func (c *Config) applyPackageDefaults() {
	p := &c.Packages
	for i := range p.Targets {
		t := &p.Targets[i]
		if strings.TrimSpace(t.Label) == "" {
			t.Label = t.ID
		}
		t.Kind = strings.ToLower(strings.TrimSpace(t.Kind))
	}
	if p.Timeout <= 0 {
		p.Timeout = Duration(30 * time.Minute)
	}
	if p.MaxPackages <= 0 {
		p.MaxPackages = MaxPackagesLimit
	}
	tl := &p.Tools
	tl.Matcher = strings.ToLower(strings.TrimSpace(tl.Matcher))
	if tl.Matcher == "" {
		switch {
		case strings.TrimSpace(tl.Grype.Path) != "":
			tl.Matcher = MatcherGrype
		case strings.TrimSpace(tl.Trivy.Path) != "":
			tl.Matcher = MatcherTrivy
		default:
			tl.Matcher = MatcherNone
		}
	}
	if tl.Grype.DBDir == "" {
		tl.Grype.DBDir = filepath.Join(c.StateDir, "grype-db")
	}
	if tl.Grype.DBMaxAge <= 0 {
		tl.Grype.DBMaxAge = Duration(120 * time.Hour)
	}
	if tl.Trivy.CacheDir == "" {
		tl.Trivy.CacheDir = filepath.Join(c.StateDir, "trivy")
	}
	tl.Syft.SHA256 = strings.ToLower(strings.TrimSpace(tl.Syft.SHA256))
	tl.Grype.SHA256 = strings.ToLower(strings.TrimSpace(tl.Grype.SHA256))
	tl.Trivy.SHA256 = strings.ToLower(strings.TrimSpace(tl.Trivy.SHA256))
}

// PackageTarget returns the packages target with the given id.
func (c *Config) PackageTarget(id string) (*PackageTarget, bool) {
	for i := range c.Packages.Targets {
		if c.Packages.Targets[i].ID == id {
			return &c.Packages.Targets[i], true
		}
	}
	return nil, false
}

// isFilesystemRoot reports whether p is "/" or a Windows drive root such as "C:\".
func isFilesystemRoot(p string) bool {
	clean := filepath.Clean(p)
	return filepath.Dir(clean) == clean
}

// withinDir reports whether p is base or below it (both absolute and cleaned).
func withinDir(p, base string) bool {
	rel, err := filepath.Rel(base, p)
	if err != nil {
		return false
	}
	if runtime.GOOS == "windows" && !strings.EqualFold(filepath.VolumeName(p), filepath.VolumeName(base)) {
		return false
	}
	return rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)))
}

func (c *Config) validatePackages(p *problems, seen func(where, id string)) {
	pk := &c.Packages
	for i := range pk.Targets {
		t := &pk.Targets[i]
		at := fmt.Sprintf("packages.targets[%d]", i)
		if !idPattern.MatchString(t.ID) {
			p.add("config.id", at+".id")
		} else {
			seen(at, t.ID)
		}
		if !validText(t.Label, 1, 128) || !validText(t.Description, 0, 512) {
			p.add("config.text", at)
		}
		switch t.Kind {
		case PackageHost, PackageDirectory, PackageImageArchive:
		default:
			p.add("config.pkg_kind", at+".kind")
		}
		if t.Path == "" || !filepath.IsAbs(t.Path) || hasControl(t.Path) {
			p.add("config.pkg_path", at+".path")
		} else if t.Kind != PackageHost && isFilesystemRoot(t.Path) {
			// Only a host scan may start at the filesystem root; the ban on system
			// directories of file roots does not apply to package targets.
			p.add("config.pkg_root_host_only", at+".path")
		}
		if len(t.Exclude) > maxExcludes {
			p.add("config.pkg_exclude", at+".exclude")
		}
		for j, e := range t.Exclude {
			if e == "" || hasControl(e) || len(e) > 512 || (!filepath.IsAbs(e) && !strings.HasPrefix(e, "./")) {
				p.add("config.pkg_exclude", fmt.Sprintf("%s.exclude[%d]", at, j))
			}
		}
		if iv := t.RefreshInterval.D(); iv < 0 || (iv > 0 && iv < minPackageRefresh) {
			p.add("config.pkg_refresh", at+".refresh_interval")
		}
	}
	if pk.Timeout.D() < time.Minute || pk.Timeout.D() > maxPackageTimeout {
		p.add("config.pkg_timeout", "packages.timeout")
	}
	if pk.MaxPackages < 1 || pk.MaxPackages > MaxPackagesLimit {
		p.add("config.pkg_max", "packages.max_packages", MaxPackagesLimit)
	}
	tl := &pk.Tools
	switch tl.Matcher {
	case MatcherGrype, MatcherTrivy, MatcherNone:
	default:
		p.add("config.matcher", "packages.tools.matcher")
	}
	// The tools are only required once there is something to scan.
	needed := len(pk.Targets) > 0
	validateTool(p, "packages.tools.syft", tl.Syft, needed)
	validateTool(p, "packages.tools.grype", tl.Grype.Tool(), needed && tl.Matcher == MatcherGrype)
	validateTool(p, "packages.tools.trivy", tl.Trivy.Tool(), needed && tl.Matcher == MatcherTrivy)
	state := filepath.Clean(c.Resolve(c.StateDir))
	// The matchers write their databases; the agent never writes outside its state dir.
	for where, dir := range map[string]string{"packages.tools.grype.db_dir": tl.Grype.DBDir, "packages.tools.trivy.cache_dir": tl.Trivy.CacheDir} {
		if hasControl(dir) || !withinDir(filepath.Clean(c.Resolve(dir)), state) {
			p.add("config.pkg_state_dir", where)
		}
	}
	if tl.Grype.DBUpdateURL != "" {
		if u, err := url.Parse(tl.Grype.DBUpdateURL); err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
			p.add("config.https_url", "packages.tools.grype.db_update_url")
		}
	}
	if tl.Grype.DBMaxAge.D() < time.Hour {
		p.add("config.pkg_db_age", "packages.tools.grype.db_max_age")
	}
	if tl.Trivy.DBRepository != "" && !repoPattern.MatchString(tl.Trivy.DBRepository) {
		p.add("config.pkg_repository", "packages.tools.trivy.db_repository")
	}
}

// validateTool checks a tool's path and checksum format. The file itself (present,
// regular, matching checksum) is checked by "check" and before every run.
func validateTool(p *problems, where string, t ToolConfig, required bool) {
	if !t.IsSet() && !required && t.SHA256 == "" {
		return
	}
	if t.Path == "" || !filepath.IsAbs(t.Path) || hasControl(t.Path) {
		p.add("config.tool_path", where+".path")
	}
	if !sha256Pattern.MatchString(t.SHA256) {
		p.add("config.tool_sha256", where+".sha256")
	}
}
