package config

import (
	"fmt"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

var zeroSum = strings.Repeat("0", 64)

// fsRoot is the filesystem root ("/" or a drive root).
func fsRoot() string {
	if runtime.GOOS == "windows" {
		return `C:\`
	}
	return "/"
}

func packagesYAML(extra string) string {
	return fmt.Sprintf(`
state_dir: %s
packages:
  targets:
    - {id: web-01, kind: host, path: %s}
    - {id: app, label: App, kind: directory, path: %s, exclude: [%s, "./**/*.log"], refresh_interval: 24h}
    - {id: image, kind: image_archive, path: %s}
  tools:
    syft: {path: %s, sha256: %s}
    grype: {path: %s, sha256: %s}
%s`, strconv.Quote(abs("state")), strconv.Quote(fsRoot()), strconv.Quote(abs("app")), strconv.Quote(abs("app/cache")),
		strconv.Quote(abs("image.tar")), strconv.Quote(abs("tools/syft")), zeroSum, strconv.Quote(abs("tools/grype")), zeroSum, extra)
}

func TestPackagesDefaults(t *testing.T) {
	c, err := Parse([]byte(packagesYAML("")))
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	p := c.Packages
	if p.Tools.Matcher != MatcherGrype || p.Timeout.D() != 30*time.Minute || p.MaxPackages != MaxPackagesLimit ||
		p.Tools.Grype.DBMaxAge.D() != 120*time.Hour || !p.Tools.Trivy.SkipUpdate() || p.Targets[0].Label != "web-01" ||
		p.Tools.Grype.DBDir != filepath.Join(abs("state"), "grype-db") || p.Tools.Trivy.CacheDir != filepath.Join(abs("state"), "trivy") {
		t.Fatalf("%+v", p)
	}
	// scan_packages is never a default job, but may be allowed.
	if c.Agent.JobAllowed(JobScanPackages) {
		t.Fatal("scan_packages must be opt-in")
	}
	c.Agent.PlatformURL = "https://app.example"
	c.Agent.AllowedJobs = []string{JobScanPackages}
	if err := c.ValidateAgent(); err != nil {
		t.Fatal(err)
	}
	if tgt, ok := c.PackageTarget("image"); !ok || tgt.Kind != PackageImageArchive {
		t.Fatal("PackageTarget")
	}
	// Without a matcher tool the matcher defaults to none; with only Trivy to trivy.
	c2, _ := Parse([]byte("packages:\n  tools:\n    trivy: {path: /opt/t, sha256: " + zeroSum + "}\n"))
	c3, _ := Parse([]byte("packages: {}\n"))
	if c2.Packages.Tools.Matcher != MatcherTrivy || c3.Packages.Tools.Matcher != MatcherNone {
		t.Fatal("matcher defaults")
	}
}

func TestPackagesValidation(t *testing.T) {
	bad := fmt.Sprintf(`
state_dir: %s
sources:
  - {id: web-01, engine: postgresql, host: h, database: d, username: u, password: "env:X"}
packages:
  targets:
    - {id: web-01, kind: host, path: %s}
    - {id: dir, kind: directory, path: %s}
    - {id: rel, kind: vm, path: relative/path, exclude: ["", "relative-glob"], refresh_interval: 10m}
  tools:
    syft: {path: syft, sha256: "ABC"}
    matcher: clair
    grype: {db_dir: %s, db_update_url: "http://mirror.example", db_max_age: 10m}
    trivy: {db_repository: "not a repo!"}
  timeout: 10s
  max_packages: 30000
`, strconv.Quote(abs("state")), strconv.Quote(fsRoot()), strconv.Quote(fsRoot()), strconv.Quote(abs("elsewhere")))
	c, err := Parse([]byte(bad))
	if err != nil {
		t.Fatal(err)
	}
	ve, ok := c.Validate().(*ValidationError)
	if !ok {
		t.Fatal("expected validation errors")
	}
	joined := strings.Join(ve.Problems, "\n")
	for _, want := range []string{`"web-01"`, "packages.targets[1].path", "packages.targets[2].kind", "packages.targets[2].path",
		"packages.targets[2].exclude[0]", "packages.targets[2].exclude[1]", "packages.targets[2].refresh_interval",
		"packages.timeout", "packages.max_packages", "packages.tools.matcher", "packages.tools.syft.path", "packages.tools.syft.sha256",
		"packages.tools.grype.db_dir", "packages.tools.grype.db_update_url", "packages.tools.grype.db_max_age",
		"packages.tools.trivy.db_repository"} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing problem about %s in:\n%s", want, joined)
		}
	}
	// The matcher's tool is required with the matcher.
	c, _ = Parse([]byte(packagesYAML("    matcher: trivy\n")))
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "packages.tools.trivy.path") {
		t.Fatalf("%v", err)
	}
	// Packages targets count towards the inventory limit.
	var b strings.Builder
	b.WriteString(packagesYAML(""))
	b.WriteString("sources:\n")
	for i := 0; i < MaxInventory-2; i++ {
		fmt.Fprintf(&b, "  - {id: s%d, engine: postgresql, host: h, database: d, username: u, password: \"env:X\"}\n", i)
	}
	c, _ = Parse([]byte(b.String()))
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "201") {
		t.Fatalf("%v", err)
	}
}
