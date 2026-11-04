package packages

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/privasimu/bridge/internal/config"
	"github.com/privasimu/bridge/internal/testutil/faketools"
)

// TestMain lets the test binary act as Syft, Grype and Trivy (see faketools); no real
// scanner is downloaded or run.
func TestMain(m *testing.M) {
	if faketools.Main() {
		return
	}
	os.Exit(m.Run())
}

var (
	selfOnce sync.Once
	selfPath string
	selfSum  string
)

// self returns the test executable and its SHA-256: it stands in for every tool.
func self(t *testing.T) (string, string) {
	t.Helper()
	selfOnce.Do(func() {
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
		if _, err := io.Copy(h, f); err != nil {
			return
		}
		selfPath, selfSum = p, hex.EncodeToString(h.Sum(nil))
	})
	if selfPath == "" {
		t.Fatal("cannot hash the test executable")
	}
	return selfPath, selfSum
}

func testdata(name string) string {
	p, _ := filepath.Abs(filepath.Join("testdata", name))
	return p
}

type fixture struct {
	t     *testing.T
	cfg   *config.Config
	svc   *Service
	host  string
	home  string
	state string
}

// newFixture builds a configuration with a host target (a directory with os-release), a
// directory target and an image archive target, the fake tools, and a Grype database.
func newFixture(t *testing.T, matcher string, mutate func(*config.Config)) *fixture {
	t.Helper()
	exe, sum := self(t)
	dir := t.TempDir()
	host := filepath.Join(dir, "host")
	if err := os.MkdirAll(filepath.Join(host, "etc"), 0o755); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(host, "etc", "os-release"), []byte("NAME=\"Ubuntu\"\nID=ubuntu\nVERSION_ID=\"24.04\"\n"), 0o644)
	app := filepath.Join(dir, "app")
	_ = os.MkdirAll(app, 0o755)
	archive := filepath.Join(dir, "image.tar")
	writeTar(t, archive, []string{"manifest.json", "abc/layer.tar"}, false)
	yaml := fmt.Sprintf(`state_dir: %s
packages:
  targets:
    - {id: web-01, label: Web 01, kind: host, path: %s, exclude: [%s]}
    - {id: app, label: App, kind: directory, path: %s}
    - {id: image, label: Image, kind: image_archive, path: %s}
  tools:
    syft: {path: %s, sha256: %s}
    matcher: %s
    grype: {path: %s, sha256: %s}
    trivy: {path: %s, sha256: %s}
`, quote(filepath.Join(dir, "state")), quote(host), quote(filepath.Join(host, "tmp")), quote(app), quote(archive),
		quote(exe), sum, matcher, quote(exe), sum, quote(exe), sum)
	cfg, err := config.Parse([]byte(yaml))
	if err != nil {
		t.Fatal(err)
	}
	cfg.SetPath(filepath.Join(dir, "bridge.yaml"))
	if mutate != nil {
		mutate(cfg)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	state := cfg.Resolve(cfg.StateDir)
	writeFile(t, filepath.Join(cfg.Resolve(cfg.Packages.Tools.Grype.DBDir), "6", "vulnerability.db"), "db")
	writeFile(t, filepath.Join(cfg.Resolve(cfg.Packages.Tools.Trivy.CacheDir), "db", "trivy.db"), "db")
	svc, err := NewService(cfg, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	f := &fixture{t: t, cfg: cfg, svc: svc, host: host, home: filepath.Join(state, "packages", "home"), state: state}
	f.control(faketools.Control{
		"syft":          {StdoutFile: testdata("syft-host.cdx.json")},
		"grype":         {StdoutFile: testdata("grype.json")},
		"trivy":         {StdoutFile: testdata("trivy.json")},
		"trivy-version": {StdoutFile: testdata("trivy-version.json")},
	})
	return f
}

func quote(s string) string {
	raw, _ := json.Marshal(s)
	return string(raw)
}

func writeFile(t *testing.T, p, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func writeTar(t *testing.T, p string, names []string, gz bool) {
	t.Helper()
	var buf bytes.Buffer
	var w io.Writer = &buf
	var zw *gzip.Writer
	if gz {
		zw = gzip.NewWriter(&buf)
		w = zw
	}
	tw := tar.NewWriter(w)
	for _, n := range names {
		_ = tw.WriteHeader(&tar.Header{Name: n, Mode: 0o644, Size: 2, Typeflag: tar.TypeReg})
		_, _ = tw.Write([]byte("{}"))
	}
	_ = tw.Close()
	if zw != nil {
		_ = zw.Close()
	}
	if err := os.WriteFile(p, buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
}

func (f *fixture) control(c faketools.Control) {
	f.t.Helper()
	if err := faketools.Write(f.home, c); err != nil {
		f.t.Fatal(err)
	}
}

func (f *fixture) calls(tool string) []faketools.Call {
	var out []faketools.Call
	for _, c := range faketools.Calls(f.home) {
		if c.Tool == tool {
			out = append(out, c)
		}
	}
	return out
}

func (f *fixture) run(id string, o ScanOptions) (*Report, error) {
	f.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	return f.svc.Run(ctx, id, o, nil)
}

func itemByName(rep *Report, name string) *Item {
	for i := range rep.Items {
		if rep.Items[i].Name == name {
			return &rep.Items[i]
		}
	}
	return nil
}

func TestScanWithGrype(t *testing.T) {
	t.Setenv("PRIVASIMU_BRIDGE_SECRETS_KEY", "placeholder-store-key-never-inherited")
	f := newFixture(t, config.MatcherGrype, nil)
	rep, err := f.run("web-01", ScanOptions{Refresh: true, Match: true})
	if err != nil {
		t.Fatal(err)
	}
	r := rep.Result
	if r.TargetKind != "host" || r.TargetLabel != "Web 01" || r.OS == nil || r.OS.ID != "ubuntu" || r.OS.Version != "24.04" ||
		r.InventoryTool != "syft" || r.InventoryToolVersion != "1.55.0" || r.Matcher != "grype" ||
		r.MatcherVersion == nil || *r.MatcherVersion != "0.121.0" || r.MatcherDBBuiltAt == nil || *r.MatcherDBBuiltAt != "2026-11-01T04:12:30Z" {
		t.Fatalf("%+v", r)
	}
	raw, _ := os.ReadFile(testdata("syft-host.cdx.json"))
	sum := sha256.Sum256(raw)
	if r.SBOMSHA256 != hex.EncodeToString(sum[:]) {
		t.Fatal("sbom_sha256 must be the SHA-256 of Syft's output")
	}
	// 10 package components: one has a name with a control character and is skipped; the
	// duplicate lodash is merged. One match names a package outside the SBOM and one has an
	// invalid id: what cannot be sent marks the result truncated.
	if r.PackagesTotal != 9 || len(rep.Items) != 9 || !r.Truncated || r.MatchesTotal != 3 {
		t.Fatalf("total %d, items %d, truncated %t, matches %d", r.PackagesTotal, len(rep.Items), r.Truncated, r.MatchesTotal)
	}
	if got := []string{rep.Items[0].Name, rep.Items[1].Name, rep.Items[2].Name}; !slices.Equal(got,
		[]string{"org.apache.logging.log4j:log4j-core", "openssl", "lodash"}) {
		t.Fatalf("packages with matches come first, by ecosystem: %v", got)
	}
	ssl := itemByName(rep, "openssl")
	if ssl.Ecosystem != "Ubuntu" || ssl.EcosystemRelease != "24.04" || ssl.Type != "os_package" || ssl.Layer != "os" ||
		!slices.Equal(ssl.Licenses, []string{"Apache-2.0"}) || len(ssl.Matches) != 1 {
		t.Fatalf("%+v", ssl)
	}
	m := ssl.Matches[0]
	if m.ID != "CVE-2024-5535" || m.Severity != "medium" || len(m.Aliases) != 0 || m.Matcher != "grype" ||
		len(m.CVSS) != 1 || m.CVSS[0].ScoreTenths != 91 || m.CVSS[0].Version != "3.1" || !slices.Equal(m.FixVersions, []string{"3.0.13-0ubuntu3.5"}) {
		t.Fatalf("%+v", m)
	}
	lodash := itemByName(rep, "lodash")
	if lodash.Ecosystem != "npm" || lodash.Layer != "application" || len(lodash.Matches) != 1 ||
		!slices.Equal(lodash.Matches[0].Aliases, []string{"CVE-2021-23337"}) || len(lodash.Matches[0].CVSS) != 1 || lodash.Matches[0].CVSS[0].ScoreTenths != 72 {
		t.Fatalf("the two lodash copies must be one item with one match: %+v", lodash)
	}
	log4j := itemByName(rep, "org.apache.logging.log4j:log4j-core")
	if log4j.Ecosystem != "Maven" || log4j.Matches[0].Severity != "critical" || log4j.Matches[0].CVSS[0].ScoreTenths != 100 ||
		!slices.Equal(log4j.Matches[0].Aliases, []string{"CVE-2021-44228"}) {
		t.Fatalf("%+v", log4j)
	}
	for name, want := range map[string][3]string{
		"org.apache.logging.log4j:log4j-api": {"Maven", "library", "application"},
		"Django":                             {"PyPI", "library", "application"},
		"laravel/framework":                  {"Packagist", "library", "application"},
		"golang.org/x/net":                   {"Go", "library", "application"},
		"@babel/core":                        {"npm", "library", "application"},
		"node":                               {"other", "application", "runtime"},
	} {
		it := itemByName(rep, name)
		if it == nil || it.Ecosystem != want[0] || it.Type != want[1] || it.Layer != want[2] || it.Dependency != "unknown" ||
			it.Matches == nil || it.Licenses == nil {
			t.Errorf("%s: %+v", name, it)
		}
	}
	if l := itemByName(rep, "@babel/core").Licenses; !slices.Equal(l, []string{"MIT OR Apache-2.0"}) {
		t.Errorf("licence expression: %v", l)
	}
	// Nothing local leaves: no path, no file name, not the SBOM.
	out, _ := json.Marshal(rep.Items)
	res, _ := json.Marshal(rep.Result)
	for _, leak := range []string{"/srv/placeholder", "/var/lib/dpkg", "secret.env", "package-id", f.host, filepath.ToSlash(f.host)} {
		if bytes.Contains(out, []byte(leak)) || bytes.Contains(res, []byte(leak)) {
			t.Errorf("the report carries %q", leak)
		}
	}
	// Fixed argument lists, no inherited environment.
	syft := f.calls("syft")
	if len(syft) != 1 {
		t.Fatalf("syft calls: %d", len(syft))
	}
	args := syft[0].Args
	if args[0] != "scan" || args[1] != "dir:"+f.host || args[2] != "-o" || args[3] != "cyclonedx-json" ||
		!slices.Contains(args, "./tmp/**") {
		t.Fatalf("syft args: %v", args)
	}
	grype := f.calls("grype")
	if len(grype) != 1 || !strings.HasPrefix(grype[0].Args[0], "sbom:") || !slices.Equal(grype[0].Args[1:], []string{"-o", "json"}) {
		t.Fatalf("grype calls: %+v", grype)
	}
	for _, c := range append(syft, grype...) {
		for _, kv := range c.Env {
			if strings.Contains(kv, "PRIVASIMU_BRIDGE") || strings.Contains(kv, "placeholder-store-key") {
				t.Fatalf("%s inherited %q", c.Tool, kv)
			}
		}
		if !slices.Contains(c.Env, "HOME="+f.home) {
			t.Fatalf("%s: HOME must be the private home: %v", c.Tool, c.Env)
		}
	}
	if !slices.Contains(grype[0].Env, "GRYPE_DB_AUTO_UPDATE=false") || !slices.Contains(grype[0].Env, "GRYPE_CHECK_FOR_APP_UPDATE=false") ||
		!slices.Contains(syft[0].Env, "SYFT_CHECK_FOR_APP_UPDATE=false") {
		t.Fatal("update checks and database downloads must be off")
	}
	// The report is kept, and the work directory is gone.
	if latest, err := f.svc.Latest("web-01"); err != nil || len(latest.Items) != 9 || !latest.Matched {
		t.Fatalf("stored report: %v", err)
	}
	if entries, _ := os.ReadDir(filepath.Join(f.state, "packages", "work")); len(entries) != 0 {
		t.Fatalf("work directories left: %d", len(entries))
	}
	if d := f.svc.Describe(); len(d) != 3 || d[0].OS != "ubuntu" || d[0].Matcher != "grype" || d[1].Kind != "directory" {
		t.Fatalf("%+v", d)
	}
}

func TestScanWithTrivy(t *testing.T) {
	f := newFixture(t, config.MatcherTrivy, nil)
	rep, err := f.run("app", ScanOptions{Refresh: true, Match: true})
	if err != nil {
		t.Fatal(err)
	}
	r := rep.Result
	if r.Matcher != "trivy" || *r.MatcherVersion != "0.67.2" || *r.MatcherDBBuiltAt != "2026-11-01T06:12:00Z" || r.MatchesTotal != 2 || r.TargetKind != "directory" {
		t.Fatalf("%+v", r)
	}
	m := itemByName(rep, "openssl").Matches[0]
	if m.ID != "CVE-2024-5535" || !slices.Equal(m.Aliases, []string{"USN-6937-1"}) || m.Matcher != "trivy" ||
		len(m.CVSS) != 2 || m.CVSS[0].ScoreTenths != 91 || m.CVSS[1].ScoreTenths != 37 ||
		!slices.Equal(m.FixVersions, []string{"3.0.13-0ubuntu3.5", "3.1.0"}) {
		t.Fatalf("NVD first, fixed versions split: %+v", m)
	}
	calls := f.calls("trivy")
	if len(calls) != 1 || !slices.Equal(calls[0].Args[2:], []string{"--format", "json", "--skip-db-update"}) {
		t.Fatalf("%+v", calls)
	}
	if len(f.calls("syft")) != 1 || len(f.calls("trivy-version")) != 1 {
		t.Fatal("one inventory and one version query")
	}
}

func TestStoredReportsAndOptions(t *testing.T) {
	f := newFixture(t, config.MatcherGrype, nil)
	now := time.Now()
	f.svc.now = func() time.Time { return now }
	if _, err := f.run("web-01", ScanOptions{Refresh: true, Match: true}); err != nil {
		t.Fatal(err)
	}
	// A recent report answers without a scan.
	if _, err := f.run("web-01", ScanOptions{Match: true}); err != nil || len(f.calls("syft")) != 1 {
		t.Fatalf("calls %d, %v", len(f.calls("syft")), err)
	}
	// match: false is answered from the same report, without matches.
	rep, err := f.run("web-01", ScanOptions{Match: false})
	if err != nil || len(f.calls("syft")) != 1 || rep.Result.Matcher != "none" || rep.Result.MatcherVersion != nil ||
		rep.Result.MatchesTotal != 0 || len(rep.Items[0].Matches) != 0 {
		t.Fatalf("%+v %v", rep.Result, err)
	}
	// Older than max age: scanned again.
	now = now.Add(2 * time.Hour)
	if _, err := f.run("web-01", ScanOptions{Match: true, MaxAge: time.Hour}); err != nil || len(f.calls("syft")) != 2 {
		t.Fatalf("calls %d, %v", len(f.calls("syft")), err)
	}
	// A refresh without matching runs only Syft and does not replace the stored report.
	rep, err = f.run("web-01", ScanOptions{Refresh: true, Match: false})
	if err != nil || len(f.calls("syft")) != 3 || len(f.calls("grype")) != 2 || rep.Result.Matcher != "none" {
		t.Fatalf("%v", err)
	}
	if latest, _ := f.svc.Latest("web-01"); !latest.Matched || latest.Result.MatchesTotal != 3 {
		t.Fatal("an inventory without matching must not replace the stored report")
	}
	if _, err := f.run("nope", ScanOptions{}); err != ErrUnknownTarget {
		t.Fatalf("%v", err)
	}
}

func TestToolChecksumsAreVerifiedBeforeEveryRun(t *testing.T) {
	f := newFixture(t, config.MatcherGrype, func(c *config.Config) { c.Packages.Tools.Grype.SHA256 = strings.Repeat("0", 64) })
	_, err := f.run("web-01", ScanOptions{Refresh: true, Match: true})
	if CodeOf(err) != CodeToolChecksum || len(faketools.Calls(f.home)) != 0 {
		t.Fatalf("%v (calls %d): a mismatching matcher is refused before anything runs", err, len(faketools.Calls(f.home)))
	}
	f.cfg.Packages.Tools.Syft.Path = filepath.Join(t.TempDir(), "syft")
	if _, err := f.run("web-01", ScanOptions{Refresh: true, Match: true}); CodeOf(err) != CodeToolMissing {
		t.Fatalf("%v", err)
	}
	f.cfg.Packages.Tools.Syft.Path = t.TempDir() // a directory is not a tool
	if _, err := f.run("web-01", ScanOptions{Refresh: true, Match: true}); CodeOf(err) != CodeToolMissing {
		t.Fatalf("%v", err)
	}
	// Replacing the binary while the bridge runs is caught on the next run.
	exe, _ := self(t)
	copyPath := filepath.Join(t.TempDir(), "syft-copy")
	if runtime.GOOS == "windows" {
		copyPath += ".exe"
	}
	raw, _ := os.ReadFile(exe)
	_ = os.WriteFile(copyPath, raw, 0o755)
	f.cfg.Packages.Tools.Syft.Path = copyPath
	f.cfg.Packages.Tools.Grype.SHA256 = f.cfg.Packages.Tools.Syft.SHA256
	if _, err := f.run("web-01", ScanOptions{Refresh: true, Match: true}); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(copyPath, append(raw, 0), 0o755)
	if _, err := f.run("web-01", ScanOptions{Refresh: true, Match: true}); CodeOf(err) != CodeToolChecksum {
		t.Fatalf("%v", err)
	}
}

func TestMatcherDatabaseProblems(t *testing.T) {
	f := newFixture(t, config.MatcherGrype, nil)
	_ = os.RemoveAll(f.cfg.Resolve(f.cfg.Packages.Tools.Grype.DBDir))
	if _, err := f.run("web-01", ScanOptions{Refresh: true, Match: true}); CodeOf(err) != CodeMatcherDB || len(faketools.Calls(f.home)) != 0 {
		t.Fatalf("no database and no auto update: %v", err)
	}
	if MatcherDatabaseReady(f.cfg) {
		t.Fatal("MatcherDatabaseReady")
	}
	writeFile(t, filepath.Join(f.cfg.Resolve(f.cfg.Packages.Tools.Grype.DBDir), "6", "vulnerability.db"), "db")
	f.control(faketools.Control{"syft": {StdoutFile: testdata("syft-host.cdx.json")},
		"grype": {Exit: 1, Stderr: "failed to load vulnerability db: the vulnerability database was built 9 days ago (max allowed age is 5 days)"}})
	if _, err := f.run("web-01", ScanOptions{Refresh: true, Match: true}); CodeOf(err) != CodeMatcherDB {
		t.Fatalf("stale database: %v", err)
	}
	f.control(faketools.Control{"syft": {StdoutFile: testdata("syft-host.cdx.json")}, "grype": {Exit: 2, Stderr: "panic: unexpected"}})
	if _, err := f.run("web-01", ScanOptions{Refresh: true, Match: true}); CodeOf(err) != CodeToolFailed {
		t.Fatalf("other failure: %v", err)
	}
	f.control(faketools.Control{"syft": {Exit: 1, Stderr: "could not determine source"}})
	if _, err := f.run("web-01", ScanOptions{Refresh: true, Match: true}); CodeOf(err) != CodeToolFailed {
		t.Fatalf("inventory failure: %v", err)
	}
	f.control(faketools.Control{"syft": {StdoutFile: testdata("grype.json")}})
	if _, err := f.run("web-01", ScanOptions{Refresh: true, Match: false}); CodeOf(err) != CodeToolFailed {
		t.Fatalf("not a CycloneDX document: %v", err)
	}
	// Trivy without a database while updates are skipped.
	f.cfg.Packages.Tools.Matcher = config.MatcherTrivy
	_ = os.RemoveAll(f.cfg.Resolve(f.cfg.Packages.Tools.Trivy.CacheDir))
	if _, err := f.run("web-01", ScanOptions{Refresh: true, Match: true}); CodeOf(err) != CodeMatcherDB {
		t.Fatalf("trivy: %v", err)
	}
}

func TestTimeoutAndOutputLimit(t *testing.T) {
	f := newFixture(t, config.MatcherNone, nil)
	f.control(faketools.Control{"syft": {SleepMS: 5000, StdoutFile: testdata("syft-host.cdx.json")}})
	started := time.Now()
	_, err := f.run("app", ScanOptions{Refresh: true, Match: true, Timeout: 300 * time.Millisecond})
	if CodeOf(err) != CodeToolTimeout || time.Since(started) > 4*time.Second {
		t.Fatalf("%v after %s", err, time.Since(started))
	}
	old := maxStdout
	maxStdout = 1 << 20
	t.Cleanup(func() { maxStdout = old })
	f.control(faketools.Control{"syft": {StdoutBytes: 4 << 20}})
	_, err = f.run("app", ScanOptions{Refresh: true, Match: true})
	var se *Error
	if CodeOf(err) != CodeToolFailed || !errorsAs(err, &se) || se.Stage != "output" {
		t.Fatalf("%v", err)
	}
	// A cancelled job is not a tool failure.
	f.control(faketools.Control{"syft": {SleepMS: 5000}})
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(200*time.Millisecond, cancel)
	if _, err := f.svc.Run(ctx, "app", ScanOptions{Refresh: true}, nil); err != context.Canceled {
		t.Fatalf("%v", err)
	}
}

// TestDeadlineBeforeTheToolStartsIsATimeout: on a busy host the deadline can pass before
// the tool has started; that is a timeout, retried like one, not a broken tool. A job
// cancelled by then stays a cancellation.
func TestDeadlineBeforeTheToolStartsIsATimeout(t *testing.T) {
	exe, sum := self(t)
	tool := run{tool: config.ToolConfig{Path: exe, SHA256: sum}, name: "syft", timeout: time.Minute}
	expired, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	tool.stdout = filepath.Join(t.TempDir(), "expired.out")
	if _, err := execute(expired, tool); CodeOf(err) != CodeToolTimeout {
		t.Fatalf("a deadline passed before the start: %v", err)
	}
	cancelled, cancelNow := context.WithCancel(context.Background())
	cancelNow()
	tool.stdout = filepath.Join(t.TempDir(), "cancelled.out")
	if _, err := execute(cancelled, tool); err != context.Canceled {
		t.Fatalf("a cancelled job: %v", err)
	}
}

func errorsAs(err error, target **Error) bool {
	e, ok := err.(*Error)
	if ok {
		*target = e
	}
	return ok
}

func TestTargets(t *testing.T) {
	f := newFixture(t, config.MatcherNone, nil)
	// Image archives: docker save, OCI layout, gzip; the Syft source follows the format.
	dir := t.TempDir()
	cases := map[string]struct {
		names []string
		gz    bool
		want  string
	}{
		"docker.tar":    {[]string{"manifest.json", "repositories"}, false, "docker-archive"},
		"oci.tar":       {[]string{"oci-layout", "index.json", "blobs/sha256/aa"}, false, "oci-archive"},
		"docker.tar.gz": {[]string{"./manifest.json"}, true, "docker-archive"},
	}
	for name, c := range cases {
		p := filepath.Join(dir, name)
		writeTar(t, p, c.names, c.gz)
		if got, err := archiveScheme(p); err != nil || got != c.want {
			t.Errorf("%s: %q %v", name, got, err)
		}
	}
	notImage := filepath.Join(dir, "notes.txt")
	writeFile(t, notImage, "plain text, not a tar")
	plainTar := filepath.Join(dir, "plain.tar")
	writeTar(t, plainTar, []string{"a.txt"}, false)
	for _, p := range []string{notImage, plainTar, filepath.Join(dir, "missing.tar"), dir} {
		f.cfg.Packages.Targets[2].Path = p
		if _, err := f.run("image", ScanOptions{Refresh: true}); CodeOf(err) != CodeTargetUnreadable {
			t.Errorf("%s: %v", p, err)
		}
	}
	f.cfg.Packages.Targets[2].Path = filepath.Join(dir, "oci.tar")
	if _, err := f.run("image", ScanOptions{Refresh: true}); err != nil {
		t.Fatal(err)
	}
	calls := f.calls("syft")
	if args := calls[len(calls)-1].Args; args[1] != "oci-archive:"+filepath.Join(dir, "oci.tar") || slices.Contains(args, "--exclude") {
		t.Fatalf("%v", args)
	}
	f.cfg.Packages.Targets[1].Path = filepath.Join(dir, "missing-dir")
	if _, err := f.run("app", ScanOptions{Refresh: true}); CodeOf(err) != CodeTargetUnreadable {
		t.Fatalf("%v", err)
	}
}

func TestExcludeGlobs(t *testing.T) {
	root := t.TempDir()
	tgt := &config.PackageTarget{Kind: config.PackageDirectory, Path: root,
		Exclude: []string{filepath.Join(root, "cache"), "./**/*.log", filepath.Join(filepath.Dir(root), "elsewhere"), root}}
	got := excludeGlobs(tgt, []string{filepath.Join(root, "state")})
	want := []string{"./cache", "./cache/**", "./**/*.log", "./state", "./state/**"}
	if !slices.Equal(got, want) {
		t.Fatalf("%v", got)
	}
	if runtime.GOOS != "windows" {
		host := &config.PackageTarget{Kind: config.PackageHost, Path: "/"}
		if got := excludeGlobs(host, nil); !slices.Contains(got, "./proc/**") || !slices.Contains(got, "./sys/**") {
			t.Fatalf("%v", got)
		}
		// A host mounted below another root keeps its virtual filesystems excluded.
		mounted := &config.PackageTarget{Kind: config.PackageHost, Path: "/host", Exclude: []string{"/proc"}}
		if got := excludeGlobs(mounted, nil); !slices.Contains(got, "./proc/**") || !slices.Contains(got, "./run/**") || len(got) != 8 {
			t.Fatalf("%v", got)
		}
	}
}

func TestEcosystemMapping(t *testing.T) {
	ubuntu := &OSInfo{ID: "ubuntu", Version: "24.04"}
	cases := []struct {
		rec           record
		sys           *OSInfo
		eco, release  string
		typ, layer    string
		composedName  string
		composedGroup string
	}{
		{record{name: "bash", version: "5", syftType: "deb", purl: "pkg:deb/debian/bash@5?distro=debian-12"}, nil, "Debian", "12", "os_package", "os", "", ""},
		{record{name: "bash", version: "5", syftType: "deb"}, ubuntu, "Ubuntu", "24.04", "os_package", "os", "", ""},
		{record{name: "bash", version: "5", syftType: "deb", purl: "pkg:deb/linuxmint/bash@5?distro=linuxmint-21"}, nil, "other", "", "os_package", "os", "", ""},
		{record{name: "musl", version: "1", syftType: "apk", purl: "pkg:apk/alpine/musl@1?distro=alpine-3.20.3"}, nil, "Alpine", "3.20.3", "os_package", "os", "", ""},
		{record{name: "glibc", version: "2", syftType: "rpm", purl: "pkg:rpm/redhat/glibc@2?distro=rhel-9.4"}, nil, "Red Hat", "9.4", "os_package", "os", "", ""},
		{record{name: "glibc", version: "2", syftType: "rpm", purl: "pkg:rpm/rocky/glibc@2?distro=rocky-9.4"}, nil, "Rocky Linux", "9.4", "os_package", "os", "", ""},
		{record{name: "glibc", version: "2", syftType: "rpm", purl: "pkg:rpm/almalinux/glibc@2?distro=almalinux-9.4"}, nil, "AlmaLinux", "9.4", "os_package", "os", "", ""},
		{record{name: "glibc", version: "2", syftType: "rpm", purl: "pkg:rpm/centos/glibc@2?distro=centos-7"}, nil, "other", "", "os_package", "os", "", ""},
		{record{name: "core", group: "babel", version: "7", cdxType: "library", purl: "pkg:npm/%40babel/core@7"}, nil, "npm", "", "library", "application", "@babel/core", ""},
		{record{name: "log", group: "monolog", version: "3", cdxType: "library", syftType: "php-composer"}, nil, "Packagist", "", "library", "application", "monolog/log", ""},
		{record{name: "spring-core", group: "org.springframework", version: "6", cdxType: "framework", syftType: "java-archive"}, nil, "Maven", "", "framework", "runtime", "org.springframework:spring-core", ""},
		{record{name: "jenkins-x", version: "1", cdxType: "library", syftType: "java-archive", purl: "pkg:jenkins/jenkins-x@1"}, nil, "other", "", "library", "application", "", ""},
		{record{name: "requests", version: "2", cdxType: "library", purl: "pkg:pypi/requests@2"}, nil, "PyPI", "", "library", "application", "", ""},
		{record{name: "rails", version: "7", cdxType: "library", syftType: "gem"}, nil, "RubyGems", "", "library", "application", "", ""},
		{record{name: "serde", version: "1", cdxType: "library", syftType: "rust-crate"}, nil, "crates.io", "", "library", "application", "", ""},
		{record{name: "Newtonsoft.Json", version: "13", cdxType: "library", syftType: "dotnet"}, nil, "NuGet", "", "library", "application", "", ""},
		{record{name: "golang.org/x/text", version: "v0.3.0", cdxType: "library", syftType: "go-module"}, nil, "Go", "", "library", "application", "", ""},
		{record{name: "python", version: "3.12", cdxType: "application", syftType: "binary"}, nil, "other", "", "application", "runtime", "", ""},
		{record{name: "thing", version: "1", cdxType: "device"}, nil, "other", "", "other", "application", "", ""},
	}
	for _, c := range cases {
		p := parsePURL(c.rec.purl)
		eco, release := ecosystemOf(c.rec, p, c.sys)
		typ, layer := typeAndLayer(c.rec, eco)
		name := packageName(c.rec, eco)
		wantName := c.composedName
		if wantName == "" {
			wantName = c.rec.name
		}
		if eco != c.eco || release != c.release || typ != c.typ || layer != c.layer || name != wantName {
			t.Errorf("%+v: got %s %q %s %s %q", c.rec, eco, release, typ, layer, name)
		}
		if !slices.Contains(Ecosystems, eco) || !slices.Contains(Types, typ) || !slices.Contains(Layers, layer) {
			t.Errorf("%+v: outside the closed lists", c.rec)
		}
	}
}

func TestItemBoundsAndTruncation(t *testing.T) {
	doc := &sbom{}
	for i := 0; i < 5; i++ {
		doc.records = append(doc.records, record{name: "pkg" + string(rune('a'+i)), version: "1.0", cdxType: "library", syftType: "npm"})
	}
	doc.records = append(doc.records, record{name: strings.Repeat("n", 256), version: "1", syftType: "npm"},
		record{name: "v", version: strings.Repeat("9", 129), syftType: "npm"})
	doc.total = len(doc.records) + 3 // three more beyond the records kept
	mr := &matcherReport{}
	for i := 0; i < 250; i++ {
		mr.matches = append(mr.matches, found{name: "pkge", version: "1.0", match: Match{ID: "CVE-2026-" + strings.Repeat("1", 4) + string(rune('0'+i%10)) + string(rune('a'+i/10)),
			Severity: []string{"low", "critical"}[i%2], Matcher: "grype",
			Aliases:     []string{"GHSA-xxxx-yyyy-zzzz", "bad alias with spaces", strings.Repeat("A", 65)},
			CVSS:        []CVSS{{Version: "3.1", Vector: "CVSS:3.1/AV:N", ScoreTenths: 98}, {Version: "3.1", Vector: "x y", ScoreTenths: 50}, {Version: "3.1", Vector: "CVSS:3.1/AV:L", ScoreTenths: 101}},
			FixVersions: []string{"1.1", strings.Repeat("1", 129)}}})
	}
	inv := buildItems(doc, mr, 3)
	if len(inv.items) != 3 || inv.items[0].Name != "pkge" || inv.total != 8 || inv.dropped == 0 {
		t.Fatalf("items %d, first %s, total %d, dropped %d", len(inv.items), inv.items[0].Name, inv.total, inv.dropped)
	}
	m := inv.items[0].Matches
	if len(m) != maxMatches || m[0].Severity != "critical" || m[len(m)-1].Severity != "low" {
		t.Fatalf("matches %d, most severe first", len(m))
	}
	if !slices.Equal(m[0].Aliases, []string{"GHSA-xxxx-yyyy-zzzz"}) || len(m[0].CVSS) != 1 || m[0].CVSS[0].ScoreTenths != 98 ||
		!slices.Equal(m[0].FixVersions, []string{"1.1"}) {
		t.Fatalf("%+v", m[0])
	}
	if tenths(9.05) != 91 && tenths(9.05) != 90 || tenths(-1) != -1 || tenths(10.01) != -1 {
		t.Fatal("tenths")
	}
}

func TestHostOSAndToolVersion(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "usr", "lib", "os-release"), "ID='rocky'\nVERSION_ID=\"9.4\"\n")
	if o := hostOS(root); o == nil || o.ID != "rocky" || o.Version != "9.4" {
		t.Fatalf("%+v", o)
	}
	if hostOS(t.TempDir()) != nil {
		t.Fatal("no os-release")
	}
	if toolVersion("v1.55.0\n") != "1.55.0" || toolVersion(strings.Repeat("x", 50)) != strings.Repeat("x", 40) {
		t.Fatal("toolVersion")
	}
}

func TestScheduleRefreshesStaleTargets(t *testing.T) {
	f := newFixture(t, config.MatcherGrype, func(c *config.Config) {
		c.Packages.Targets[0].RefreshInterval = config.Duration(time.Hour)
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { f.svc.RunSchedule(ctx); close(done) }()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if rep, err := f.svc.Latest("web-01"); err == nil && rep.Matched {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	cancel()
	<-done
	if _, err := f.svc.Latest("web-01"); err != nil {
		t.Fatal("the schedule did not scan the stale target")
	}
	if _, err := f.svc.Latest("app"); err == nil {
		t.Fatal("a target without refresh_interval is scanned on request only")
	}
}
