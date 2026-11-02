package agent

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/privasimu/bridge/internal/config"
	"github.com/privasimu/bridge/internal/packages"
	"github.com/privasimu/bridge/internal/testutil/faketools"
)

// TestMain lets the test binary act as Syft, Grype and Trivy (see faketools); no real
// scanner is downloaded or run.
func TestMain(m *testing.M) {
	if faketools.Main() {
		return
	}
	protocolErrors = loadProtocolErrors()
	os.Exit(m.Run())
}

var (
	exeOnce      sync.Once
	exePath, exe string
)

// testTool returns the test executable and its SHA-256 (it stands in for every tool).
func testTool(t *testing.T) (string, string) {
	t.Helper()
	exeOnce.Do(func() {
		p, err := os.Executable()
		if err != nil {
			return
		}
		f, err := os.Open(p)
		if err != nil {
			return
		}
		defer f.Close()
		h := sha256.New()
		_, _ = io.Copy(h, f)
		exePath, exe = p, hex.EncodeToString(h.Sum(nil))
	})
	if exePath == "" {
		t.Fatal("cannot hash the test executable")
	}
	return exePath, exe
}

// packagesYAML is envYAML with a packages target and scan_packages allowed.
const packagesYAML = `
agent:
  platform_url: {{url}}
  poll_min: 5s
  poll_max: 10s
  allowed_jobs: [test_source, scan_database, scan_files, scan_packages]
files:
  roots:
    - id: hr-share
      label: HR share
      path: {{share}}
packages:
  targets:
    - id: web-01
      label: Web 01
      kind: host
      path: {{host}}
  tools:
    syft: {path: {{exe}}, sha256: {{sum}}}
    matcher: grype
    grype: {path: {{exe}}, sha256: {{sum}}}
`

type pkgEnv struct {
	*env
	host string
	home string
}

func newPackagesEnv(t *testing.T, yamlTemplate string, mutate func(*config.Config)) *pkgEnv {
	t.Helper()
	exe, sum := testTool(t)
	host := t.TempDir()
	if err := os.MkdirAll(filepath.Join(host, "etc"), 0o755); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(host, "etc", "os-release"), []byte("ID=ubuntu\nVERSION_ID=\"24.04\"\n"), 0o644)
	y := strings.NewReplacer("{{host}}", strconv.Quote(host), "{{exe}}", strconv.Quote(exe), "{{sum}}", sum).Replace(yamlTemplate)
	e := newEnvYAML(t, y, mutate)
	state := e.cfg.Resolve(e.cfg.StateDir)
	dbFile := filepath.Join(state, "grype-db", "6", "vulnerability.db") // the default db_dir
	if err := os.MkdirAll(filepath.Dir(dbFile), 0o700); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(dbFile, []byte("db"), 0o600)
	pe := &pkgEnv{env: e, host: host, home: filepath.Join(state, "packages", "home")}
	fixture := func(name string) string {
		p, _ := filepath.Abs(filepath.Join("..", "packages", "testdata", name))
		return p
	}
	if err := faketools.Write(pe.home, faketools.Control{"syft": {StdoutFile: fixture("syft-host.cdx.json")},
		"grype": {StdoutFile: fixture("grype.json")}}); err != nil {
		t.Fatal(err)
	}
	return pe
}

func (e *env) sourcesSent() *SourcesRequest {
	e.fp.mu.Lock()
	defer e.fp.mu.Unlock()
	return e.fp.sources
}

func hasPackagesSource(s *SourcesRequest) bool {
	if s == nil {
		return false
	}
	for _, src := range s.Sources {
		if src.Kind == "packages" {
			return true
		}
	}
	return false
}

// TestOldPlatformGetsNoPackagesSources: a platform without platform_features refuses an
// inventory with kind packages as a whole, so the agent never sends one to it (the fake
// platform fails the test on any 400). The capability job:scan_packages is still sent,
// because scan_packages is allowed locally.
func TestOldPlatformGetsNoPackagesSources(t *testing.T) {
	e := newPackagesEnv(t, packagesYAML, nil)
	e.enroll()
	a := e.agent()
	if !e.run(a, 5*time.Second, func() bool { e.fp.mu.Lock(); defer e.fp.mu.Unlock(); return e.fp.sources != nil && e.fp.polls >= 2 }) {
		t.Fatal("no inventory")
	}
	if s := e.sourcesSent(); hasPackagesSource(s) || len(s.Sources) != 1 {
		t.Fatalf("%+v", s)
	}
	if !bytes.Contains(e.fp.allBodies(), []byte(`"job:scan_packages"`)) {
		t.Fatal("the capability job:scan_packages must be sent when scan_packages is allowed")
	}
}

// TestPackagesInventoryFollowsPlatformFeatures: once a poll answer lists
// source_kind:packages the inventory gains the packages targets (with a new digest), and
// loses them again when the platform stops listing it.
func TestPackagesInventoryFollowsPlatformFeatures(t *testing.T) {
	e := newPackagesEnv(t, packagesYAML, nil)
	e.enroll()
	a := e.agent()
	stage := 0
	var oldDigest string
	if !e.run(a, 10*time.Second, func() bool {
		s := e.sourcesSent()
		switch {
		case stage == 0 && s != nil:
			oldDigest = s.SourcesDigest
			e.fp.mu.Lock()
			e.fp.features = []string{FeatureSourceKindPackages, FeatureJobScanPackages}
			e.fp.mu.Unlock()
			stage = 1
		case stage == 1 && hasPackagesSource(s):
			stage = 2
			e.fp.mu.Lock()
			e.fp.features = []string{}
			e.fp.mu.Unlock()
		case stage == 2 && s != nil && !hasPackagesSource(s):
			return true
		}
		if stage == 2 && s != nil {
			for _, src := range s.Sources {
				if src.Kind == "packages" && (src.ID != "web-01" || src.Engine != "host" || src.Label != "Web 01" ||
					!slices.Equal(src.Capabilities, []string{"matcher:grype", "os:ubuntu"}) || s.SourcesDigest == oldDigest) {
					t.Errorf("%+v (digest %s)", src, s.SourcesDigest)
				}
			}
		}
		return false
	}) {
		t.Fatalf("stage %d", stage)
	}
}

func (e *pkgEnv) runJob(job Job, timeout time.Duration) *fakeJob {
	e.t.Helper()
	e.enroll()
	e.fp.enqueue(job)
	a := e.agent()
	if !e.run(a, timeout, e.finished(job.JobID)) {
		e.t.Fatal("the job did not finish")
	}
	return e.fp.job(job.JobID)
}

func TestScanPackagesJob(t *testing.T) {
	e := newPackagesEnv(t, packagesYAML, nil)
	e.fp.features = []string{FeatureSourceKindPackages, FeatureJobScanPackages}
	j := e.runJob(Job{JobID: "job-pkg", Type: JobScanPackages, SourceID: "web-01", Options: JobOptions{Refresh: true}}, 20*time.Second)
	if j.completed == nil {
		t.Fatalf("failed: %+v", j.failed)
	}
	raw, _ := json.Marshal(j.completed.Result)
	var res packages.Result
	_ = json.Unmarshal(raw, &res)
	if res.TargetKind != "host" || res.Matcher != "grype" || res.PackagesTotal != 9 || res.MatchesTotal != 3 || res.OS == nil ||
		res.OS.ID != "ubuntu" || len(res.SBOMSHA256) != 64 {
		t.Fatalf("%s", raw)
	}
	items := e.fp.items("job-pkg")
	if len(items) != 9 || j.completed.Parts != 1 {
		t.Fatalf("items %d, parts %d", len(items), j.completed.Parts)
	}
	var first packages.Item
	_ = json.Unmarshal(items[0], &first)
	if first.Name != "org.apache.logging.log4j:log4j-core" || first.Matches[0].CVSS[0].ScoreTenths != 100 {
		t.Fatalf("%+v", first)
	}
	// score_tenths is an integer on the wire.
	if !bytes.Contains(items[0], []byte(`"score_tenths":100`)) {
		t.Fatalf("%s", items[0])
	}
	body := e.fp.allBodies()
	for _, leak := range []string{"/srv/placeholder", "/var/lib/dpkg", "secret.env", e.host, filepath.ToSlash(e.host), e.home} {
		if bytes.Contains(body, []byte(leak)) {
			t.Fatalf("a request carries %q", leak)
		}
	}
	for _, p := range j.progress {
		if !reWord.MatchString(p.Stage) {
			t.Fatalf("progress stage %q", p.Stage)
		}
	}
}

func TestScanPackagesWithoutMatching(t *testing.T) {
	e := newPackagesEnv(t, packagesYAML, nil)
	no := false
	j := e.runJob(Job{JobID: "job-inv", Type: JobScanPackages, SourceID: "web-01", Options: JobOptions{Refresh: true, Match: &no}}, 20*time.Second)
	if j.completed == nil {
		t.Fatalf("failed: %+v", j.failed)
	}
	// The agent sends the result keys in protocol order (the fake platform keeps the raw body).
	if !bytes.Contains(e.fp.allBodies(), []byte(`"matcher":"none","matcher_version":null,"matcher_db_built_at":null,"packages_total":9,"matches_total":0,"truncated":true,`)) {
		t.Fatalf("%s", e.fp.allBodies())
	}
	for _, it := range e.fp.items("job-inv") {
		if !bytes.Contains(it, []byte(`"matches":[]`)) {
			t.Fatalf("%s", it)
		}
	}
	for _, c := range faketools.Calls(e.home) {
		if c.Tool == "grype" {
			t.Fatal("match: false must not run the matcher")
		}
	}
}

// TestScanPackagesIsOptIn: without scan_packages in allowed_jobs (the default) the job is
// refused and the capability is not announced.
func TestScanPackagesIsOptIn(t *testing.T) {
	y := strings.Replace(packagesYAML, "  allowed_jobs: [test_source, scan_database, scan_files, scan_packages]\n", "", 1)
	e := newPackagesEnv(t, y, nil)
	j := e.runJob(Job{JobID: "job-off", Type: JobScanPackages, SourceID: "web-01"}, 10*time.Second)
	if j.failed == nil || j.failed.ErrorCode != FailJobNotAllowed || j.failed.Retryable {
		t.Fatalf("%+v", j.failed)
	}
	if bytes.Contains(e.fp.allBodies(), []byte("job:scan_packages")) {
		t.Fatal("job:scan_packages announced although it is not allowed")
	}
	if len(faketools.Calls(e.home)) != 0 {
		t.Fatal("no tool may run for a refused job")
	}
}

func TestScanPackagesFailures(t *testing.T) {
	cases := []struct {
		name      string
		job       Job
		mutate    func(*config.Config)
		code      string
		kind      string
		retryable bool
	}{
		{"unknown target", Job{JobID: "j1", Type: JobScanPackages, SourceID: "hr-share"}, nil, FailSourceNotFound, "config", false},
		{"checksum", Job{JobID: "j2", Type: JobScanPackages, SourceID: "web-01", Options: JobOptions{Refresh: true}},
			func(c *config.Config) { c.Packages.Tools.Syft.SHA256 = strings.Repeat("a", 64) }, FailToolChecksum, "config", false},
		{"missing tool", Job{JobID: "j3", Type: JobScanPackages, SourceID: "web-01", Options: JobOptions{Refresh: true}},
			func(c *config.Config) { c.Packages.Tools.Grype.Path = filepath.Join(os.TempDir(), "no-such-grype") }, FailToolMissing, "config", false},
		{"no database", Job{JobID: "j4", Type: JobScanPackages, SourceID: "web-01", Options: JobOptions{Refresh: true}},
			func(c *config.Config) { c.Packages.Tools.Grype.DBDir = filepath.Join(c.StateDir, "empty-db") }, FailMatcherDB, "config", false},
		{"unreadable target", Job{JobID: "j5", Type: JobScanPackages, SourceID: "web-01", Options: JobOptions{Refresh: true}},
			func(c *config.Config) { c.Packages.Targets[0].Path = filepath.Join(os.TempDir(), "no-such-target-dir") }, FailTargetUnreadable, "permission", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := newPackagesEnv(t, packagesYAML, c.mutate)
			j := e.runJob(c.job, 10*time.Second)
			if j.failed == nil || j.failed.ErrorCode != c.code || j.failed.ErrorKind != c.kind || j.failed.Retryable != c.retryable {
				t.Fatalf("%+v", j.failed)
			}
		})
	}
	// A tool that fails or times out may be retried.
	e := newPackagesEnv(t, packagesYAML, nil)
	_ = faketools.Write(e.home, faketools.Control{"syft": {SleepMS: 5000}})
	j := e.runJob(Job{JobID: "j6", Type: JobScanPackages, SourceID: "web-01", Options: JobOptions{Refresh: true, DeadlineSeconds: 1}}, 15*time.Second)
	if j.failed == nil || j.failed.ErrorCode != FailToolTimeout || j.failed.ErrorKind != "timeout" || !j.failed.Retryable {
		t.Fatalf("%+v", j.failed)
	}
}

// TestPartsFit: items beyond 500 parts are left out (the result then says truncated).
func TestPartsFit(t *testing.T) {
	big := strings.Repeat("x", 200<<10) // two such items fill a part
	items := make([]any, 0, 1200)
	for i := 0; i < 1200; i++ {
		items = append(items, map[string]string{"name": big})
	}
	n, err := partsFit(items)
	if err != nil || n != 1000 {
		t.Fatalf("%d %v", n, err)
	}
	small := make([]any, 20000)
	for i := range small {
		small[i] = map[string]int{"n": i}
	}
	if n, _ := partsFit(small); n != 20000 {
		t.Fatalf("%d", n)
	}
	if _, err := partsFit([]any{map[string]string{"x": strings.Repeat("y", 600<<10)}}); err == nil {
		t.Fatal("an item larger than a part")
	}
}
