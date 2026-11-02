package packages

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/privasimu/bridge/internal/audit"
	"github.com/privasimu/bridge/internal/buildinfo"
	"github.com/privasimu/bridge/internal/config"
	"github.com/privasimu/bridge/internal/secrets"
)

// Service owns the configured packages targets, runs at most one package scan at a time
// (a scan reads a whole system), keeps the latest report of each target and rescans
// targets on their refresh interval.
type Service struct {
	cfg   *config.Config
	state string // <state_dir>/packages
	own   []string
	log   *slog.Logger
	audit *audit.Logger
	// slot admits one scan at a time.
	slot chan struct{}

	mu  sync.Mutex
	os  map[string]*OSInfo
	now func() time.Time
}

// ScanOptions tune one request for a report.
type ScanOptions struct {
	// Refresh scans now even when a recent report exists.
	Refresh bool
	// MaxAge is how old a stored report may be (default 24 hours).
	MaxAge time.Duration
	// Match runs the configured matcher (the protocol option "match", default true).
	Match bool
	// Timeout lowers the configured timeout of a scan.
	Timeout time.Duration
}

// Stage names reported as job progress.
const (
	StageWaiting   = "waiting"
	StageInventory = "inventory"
	StageMatching  = "matching"
)

// NewService prepares the state directory of package scans. Targets are not opened here:
// an image archive may be replaced between scans, so a missing target is reported by the
// job that needs it (target_unreadable) and by "check".
func NewService(cfg *config.Config, log *slog.Logger, auditLog *audit.Logger) (*Service, error) {
	stateDir := cfg.Resolve(cfg.StateDir)
	s := &Service{cfg: cfg, state: filepath.Join(stateDir, "packages"), log: log, audit: auditLog,
		slot: make(chan struct{}, 1), os: map[string]*OSInfo{}, now: time.Now}
	if s.log == nil {
		s.log = slog.New(slog.DiscardHandler)
	}
	if s.audit == nil {
		s.audit = audit.Discard()
	}
	s.own = []string{cfg.Dir(), stateDir, filepath.Dir(cfg.Resolve(cfg.Secrets.File)), filepath.Dir(cfg.Resolve(cfg.Audit.File))}
	if len(cfg.Packages.Targets) == 0 {
		return s, nil
	}
	for _, d := range []string{s.state, s.dir("reports"), s.dir("work"), s.dir("home")} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return nil, err
		}
	}
	// Work directories of scans that did not finish (a crash, a restart) are removed.
	if entries, err := os.ReadDir(s.dir("work")); err == nil {
		for _, e := range entries {
			_ = os.RemoveAll(filepath.Join(s.dir("work"), e.Name()))
		}
	}
	for i := range cfg.Packages.Targets {
		t := &cfg.Packages.Targets[i]
		if rep, err := s.Latest(t.ID); err == nil && rep.Result.OS != nil {
			s.os[t.ID] = rep.Result.OS
		} else if t.Kind == config.PackageHost {
			s.os[t.ID] = hostOS(t.Path)
		}
	}
	return s, nil
}

func (s *Service) dir(name string) string { return filepath.Join(s.state, name) }

// TargetInfo describes a target for the agent inventory.
type TargetInfo struct {
	ID, Label, Description, Kind, Matcher string
	// OS is the operating system id when known (os-release of a host, or the last scan).
	OS string
}

// Describe lists the targets in configuration order.
func (s *Service) Describe() []TargetInfo {
	out := make([]TargetInfo, 0, len(s.cfg.Packages.Targets))
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, t := range s.cfg.Packages.Targets {
		info := TargetInfo{ID: t.ID, Label: t.Label, Description: t.Description, Kind: t.Kind, Matcher: s.cfg.Packages.Tools.Matcher}
		if o := s.os[t.ID]; o != nil && osIDPattern.MatchString(o.ID) {
			info.OS = o.ID
		}
		out = append(out, info)
	}
	return out
}

var reportName = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,62}$`)

func (s *Service) reportPath(id string) string { return filepath.Join(s.dir("reports"), id+".json") }

// Latest returns the stored report of a target.
func (s *Service) Latest(id string) (*Report, error) {
	if _, ok := s.cfg.PackageTarget(id); !ok || !reportName.MatchString(id) {
		return nil, ErrUnknownTarget
	}
	data, err := os.ReadFile(s.reportPath(id))
	if err != nil {
		return nil, err
	}
	var rep Report
	if err := json.Unmarshal(data, &rep); err != nil {
		return nil, err
	}
	return &rep, nil
}

func (s *Service) save(rep *Report) {
	data, err := json.Marshal(rep)
	if err == nil {
		err = secrets.WriteFileAtomic(s.reportPath(rep.TargetID), data, 0o600)
	}
	if err != nil {
		s.log.Error("package report could not be saved", "target", rep.TargetID, "error", err.Error())
	}
}

// usable reports whether a stored report answers a request.
func (s *Service) usable(rep *Report, o ScanOptions, notBefore time.Time) bool {
	if rep == nil || (o.Match && !rep.Matched) || (!notBefore.IsZero() && !rep.FinishedAt.After(notBefore)) {
		return false
	}
	maxAge := o.MaxAge
	if maxAge <= 0 {
		maxAge = 24 * time.Hour
	}
	return s.now().Sub(rep.FinishedAt) <= maxAge
}

// Run answers a request for a target's report: a stored report when it is recent enough
// (unless Refresh), else a new scan. Scans run one at a time; a request that waited for
// another scan of the same target uses that scan's report.
func (s *Service) Run(ctx context.Context, id string, o ScanOptions, stage func(string)) (*Report, error) {
	t, ok := s.cfg.PackageTarget(id)
	if !ok {
		return nil, ErrUnknownTarget
	}
	if stage == nil {
		stage = func(string) {}
	}
	requested := s.now()
	if !o.Refresh {
		if rep, err := s.Latest(id); err == nil && s.usable(rep, o, time.Time{}) {
			return view(rep, o.Match), nil
		}
	}
	stage(StageWaiting)
	select {
	case s.slot <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	defer func() { <-s.slot }()
	// A scan of this target may have finished while this request waited.
	notBefore := time.Time{}
	if o.Refresh {
		notBefore = requested
	}
	if rep, err := s.Latest(id); err == nil && s.usable(rep, o, notBefore) {
		return view(rep, o.Match), nil
	}
	rep, err := s.scan(ctx, t, o, stage)
	if err != nil {
		return nil, err
	}
	return rep, nil
}

func view(rep *Report, match bool) *Report {
	if match {
		return rep
	}
	return rep.WithoutMatches()
}

// RunSchedule rescans targets whose report is older than their refresh interval, until
// ctx ends. A target whose scan failed is tried again after an hour at the earliest (or its
// interval, when shorter), not on every tick.
func (s *Service) RunSchedule(ctx context.Context) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	tried := map[string]time.Time{}
	for {
		for i := range s.cfg.Packages.Targets {
			target := &s.cfg.Packages.Targets[i]
			iv := target.RefreshInterval.D()
			if iv <= 0 {
				continue
			}
			if rep, err := s.Latest(target.ID); err == nil && rep.Matched && s.now().Sub(rep.FinishedAt) < iv {
				continue
			}
			if last, ok := tried[target.ID]; ok && s.now().Sub(last) < min(iv, time.Hour) {
				continue
			}
			select {
			case s.slot <- struct{}{}:
			default:
				continue // a scan is running; try again on the next tick
			}
			tried[target.ID] = s.now()
			s.log.Info("scheduled package scan started", "target", target.ID)
			if _, err := s.scan(ctx, target, ScanOptions{Match: true}, nil); err != nil && ctx.Err() == nil {
				s.log.Error("scheduled package scan failed", "target", target.ID, "code", CodeOf(err), "error", err.Error())
			}
			<-s.slot
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// scan runs Syft, then the matcher, and stores the report when it is complete (the
// matcher ran as configured). The caller holds the scan slot.
func (s *Service) scan(ctx context.Context, t *config.PackageTarget, o ScanOptions, stage func(string)) (rep *Report, err error) {
	if stage == nil {
		stage = func(string) {}
	}
	started := s.now()
	ev := audit.Event{Event: "package_scan", SourceID: t.ID, Engine: t.Kind}
	defer func() {
		ev.DurationMS = time.Since(started).Milliseconds()
		if err != nil {
			ev.Outcome, ev.Code = audit.Error, CodeOf(err)
			if ev.Code == "" {
				ev.Code = "scan_failed"
			}
		} else {
			ev.Outcome = audit.OK
			ev.Counts = map[string]int{"packages": len(rep.Items), "matches": rep.Result.MatchesTotal}
		}
		s.audit.Log(ev)
	}()
	pk := &s.cfg.Packages
	timeout := pk.Timeout.D()
	if o.Timeout > 0 && o.Timeout < timeout {
		timeout = o.Timeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	matcher := pk.Tools.Matcher
	if !o.Match {
		matcher = config.MatcherNone
	}
	// Every refusal that needs no tool run comes first: target, tools, matcher database.
	scheme, err := checkTarget(t)
	if err != nil {
		s.log.Warn("package target is not readable", "target", t.ID, "error", err.Error())
		return nil, scanError(CodeTargetUnreadable, "target", "", err)
	}
	if err := VerifyTool(pk.Tools.Syft); err != nil {
		return nil, toolFailure("syft", err)
	}
	switch matcher {
	case config.MatcherGrype:
		if err := VerifyTool(pk.Tools.Grype.Tool()); err != nil {
			return nil, toolFailure("grype", err)
		}
		if !pk.Tools.Grype.DBAutoUpdate && !hasFile(s.cfg.Resolve(pk.Tools.Grype.DBDir), "vulnerability.db", 2) {
			return nil, scanError(CodeMatcherDB, "matching", "grype", errors.New("no Grype database in db_dir and db_auto_update is off"))
		}
	case config.MatcherTrivy:
		if err := VerifyTool(pk.Tools.Trivy.Tool()); err != nil {
			return nil, toolFailure("trivy", err)
		}
		if pk.Tools.Trivy.SkipUpdate() && !hasFile(filepath.Join(s.cfg.Resolve(pk.Tools.Trivy.CacheDir), "db"), "trivy.db", 0) {
			return nil, scanError(CodeMatcherDB, "matching", "trivy", errors.New("no Trivy database in cache_dir and skip_db_update is on"))
		}
	}
	work, err := s.workDir()
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(work)
	home := s.dir("home")

	stage(StageInventory)
	sbomPath := filepath.Join(work, "sbom.cdx.json")
	syftOut, err := execute(ctx, run{tool: pk.Tools.Syft, name: "syft", args: s.syftArgs(t, scheme), dir: work,
		env: childEnv(home, work, syftEnv...), stdout: sbomPath, timeout: timeout})
	if err != nil {
		return nil, s.classify(err, "inventory", "syft")
	}
	doc, err := readSBOMFile(sbomPath)
	if err != nil {
		return nil, scanError(CodeToolFailed, "inventory", "syft", err)
	}

	var mr *matcherReport
	if matcher != config.MatcherNone {
		stage(StageMatching)
		if mr, err = s.match(ctx, matcher, sbomPath, work, home, timeout); err != nil {
			return nil, err
		}
	}

	inv := buildItems(doc, mr, pk.MaxPackages)
	res := Result{TargetKind: t.Kind, TargetLabel: t.Label, OS: doc.os, InventoryTool: "syft",
		InventoryToolVersion: firstNonEmpty(toolVersion(doc.toolVersion), "unknown"), Matcher: matcher,
		PackagesTotal: inv.total, Truncated: inv.total > len(inv.items) || inv.dropped > 0,
		BridgeVersion: buildinfo.Version, SBOMSHA256: syftOut.sha256}
	if mr != nil {
		v := firstNonEmpty(toolVersion(mr.version), "unknown")
		res.MatcherVersion = &v
		if mr.dbBuiltAt != nil {
			b := mr.dbBuiltAt.UTC().Format("2006-01-02T15:04:05Z")
			res.MatcherDBBuiltAt = &b
		}
	}
	if res.OS != nil && (!osIDPattern.MatchString(res.OS.ID) || !validText(res.OS.Version, 0, 40)) {
		res.OS = nil
	}
	for _, it := range inv.items {
		res.MatchesTotal += len(it.Matches)
	}
	res.DurationMS = time.Since(started).Milliseconds()
	rep = &Report{TargetID: t.ID, FinishedAt: s.now().UTC(), Matched: o.Match, Result: res, Items: inv.items}
	if o.Match {
		s.save(rep)
	}
	if res.OS != nil {
		s.mu.Lock()
		s.os[t.ID] = res.OS
		s.mu.Unlock()
	}
	return rep, nil
}

// syftEnv turns off everything in Syft that would reach the network: the update check
// and the remote lookups of some catalogers (all off by default; set explicitly).
var syftEnv = []string{"SYFT_CHECK_FOR_APP_UPDATE=false", "SYFT_JAVA_USE_NETWORK=false",
	"SYFT_GOLANG_SEARCH_REMOTE_LICENSES=false", "SYFT_JAVASCRIPT_SEARCH_REMOTE_LICENSES=false"}

// syftArgs is the fixed argument list of an inventory. The SBOM goes to standard output
// (captured and capped by the bridge).
func (s *Service) syftArgs(t *config.PackageTarget, scheme string) []string {
	if t.Kind == config.PackageImageArchive {
		return []string{"scan", scheme + ":" + t.Path, "-o", "cyclonedx-json"}
	}
	args := []string{"scan", "dir:" + t.Path, "-o", "cyclonedx-json"}
	for _, g := range excludeGlobs(t, s.own) {
		args = append(args, "--exclude", g)
	}
	return args
}

// match runs the configured matcher on the SBOM.
func (s *Service) match(ctx context.Context, matcher, sbomPath, work, home string, timeout time.Duration) (*matcherReport, error) {
	pk := &s.cfg.Packages
	out := filepath.Join(work, matcher+".json")
	if matcher == config.MatcherGrype {
		g := pk.Tools.Grype
		env := []string{"GRYPE_CHECK_FOR_APP_UPDATE=false", "GRYPE_DB_CACHE_DIR=" + s.cfg.Resolve(g.DBDir),
			"GRYPE_DB_AUTO_UPDATE=" + boolText(g.DBAutoUpdate), "GRYPE_DB_MAX_ALLOWED_BUILT_AGE=" + g.DBMaxAge.D().String(),
			"GRYPE_DB_VALIDATE_AGE=true"}
		if g.DBUpdateURL != "" {
			env = append(env, "GRYPE_DB_UPDATE_URL="+g.DBUpdateURL)
		}
		if _, err := execute(ctx, run{tool: g.Tool(), name: "grype", args: []string{"sbom:" + sbomPath, "-o", "json"}, dir: work,
			env: childEnv(home, work, env...), stdout: out, timeout: timeout}); err != nil {
			return nil, s.classify(err, "matching", "grype")
		}
		mr, err := readReportFile(out, readGrype)
		if err != nil {
			return nil, scanError(CodeToolFailed, "matching", "grype", err)
		}
		return mr, nil
	}
	tv := pk.Tools.Trivy
	env := []string{"TRIVY_CACHE_DIR=" + s.cfg.Resolve(tv.CacheDir), "TRIVY_SKIP_VERSION_CHECK=true", "TRIVY_DISABLE_TELEMETRY=true"}
	if tv.DBRepository != "" {
		env = append(env, "TRIVY_DB_REPOSITORY="+tv.DBRepository)
	}
	args := []string{"sbom", sbomPath, "--format", "json"}
	if tv.SkipUpdate() {
		args = append(args, "--skip-db-update")
	}
	if _, err := execute(ctx, run{tool: tv.Tool(), name: "trivy", args: args, dir: work, env: childEnv(home, work, env...),
		stdout: out, timeout: timeout}); err != nil {
		return nil, s.classify(err, "matching", "trivy")
	}
	mr, err := readReportFile(out, readTrivy)
	if err != nil {
		return nil, scanError(CodeToolFailed, "matching", "trivy", err)
	}
	// Trivy's report names neither its version nor its database date; "trivy version"
	// does (best effort: a failure leaves them unknown).
	versionOut := filepath.Join(work, "trivy-version.json")
	if _, err := execute(ctx, run{tool: tv.Tool(), name: "trivy", args: []string{"version", "--format", "json"}, dir: work,
		env: childEnv(home, work, env...), stdout: versionOut, timeout: time.Minute}); err == nil {
		if f, err := os.Open(versionOut); err == nil { // #nosec G304 -- inside the private work directory
			mr.version, mr.dbBuiltAt = readTrivyVersion(f)
			f.Close()
		}
	}
	return mr, nil
}

// dbProblem recognises a matcher that refused to run for want of a usable vulnerability
// database (missing, too old, not downloadable while updates are off).
var dbProblem = regexp.MustCompile(`(?i)(vulnerability (db|database)|\bdb\b|database).{0,80}(not found|does not exist|missing|stale|too old|built|invalid|expired|not available|unavailable|no such file|cannot|failed)|first run cannot skip|skip-db-update cannot`)

// classify maps a failed tool run to a scan failure. The tool's standard error is only
// matched against patterns; it is never sent or logged (it can name local paths).
func (s *Service) classify(err error, stage, tool string) error {
	var ef *exitFailure
	if !errors.As(err, &ef) {
		return err // a scan failure already, or the job's context ended
	}
	if stage == "matching" && dbProblem.Match(ef.stderr) {
		return scanError(CodeMatcherDB, stage, tool, err)
	}
	s.log.Warn("package scanner failed", "tool", tool, "stage", stage, "error", ef.err.Error())
	return scanError(CodeToolFailed, stage, tool, err)
}

func (s *Service) workDir() (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	d := filepath.Join(s.dir("work"), hex.EncodeToString(b))
	return d, os.MkdirAll(d, 0o700)
}

func readSBOMFile(p string) (*sbom, error) {
	f, err := os.Open(p) // #nosec G304 -- inside the private work directory
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return readCycloneDX(f)
}

func readReportFile(p string, read func(io.Reader) (*matcherReport, error)) (*matcherReport, error) {
	f, err := os.Open(p) // #nosec G304 -- inside the private work directory
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return read(f)
}

// hasFile reports whether name exists as a regular file in dir or up to depth levels
// below it (Grype keeps its database in <db_dir>/<schema>/vulnerability.db).
func hasFile(dir, name string, depth int) bool {
	if fi, err := os.Stat(filepath.Join(dir, name)); err == nil && fi.Mode().IsRegular() {
		return true
	}
	if depth == 0 {
		return false
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return false
	}
	for _, e := range entries {
		if e.IsDir() && !strings.HasPrefix(e.Name(), ".") && hasFile(filepath.Join(dir, e.Name()), name, depth-1) {
			return true
		}
	}
	return false
}

func boolText(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

// CheckTarget reports whether a target can be read now (for "check").
func CheckTarget(t *config.PackageTarget) error {
	_, err := checkTarget(t)
	return err
}

// MatcherDatabaseReady reports whether the configured matcher may run: it has a local
// vulnerability database, or it is allowed to download one.
func MatcherDatabaseReady(cfg *config.Config) bool {
	tl := cfg.Packages.Tools
	switch tl.Matcher {
	case config.MatcherGrype:
		return tl.Grype.DBAutoUpdate || hasFile(cfg.Resolve(tl.Grype.DBDir), "vulnerability.db", 2)
	case config.MatcherTrivy:
		return !tl.Trivy.SkipUpdate() || hasFile(filepath.Join(cfg.Resolve(tl.Trivy.CacheDir), "db"), "trivy.db", 0)
	}
	return true
}

// Tools lists the tools the configuration needs, by name: Syft, and the matcher unless
// it is none.
func Tools(cfg *config.Config) map[string]config.ToolConfig {
	tl := cfg.Packages.Tools
	out := map[string]config.ToolConfig{"syft": tl.Syft}
	switch tl.Matcher {
	case config.MatcherGrype:
		out["grype"] = tl.Grype.Tool()
	case config.MatcherTrivy:
		out["trivy"] = tl.Trivy.Tool()
	}
	return out
}

// ToolProblem explains a VerifyTool error in a word the CLI translates: "missing" or
// "checksum".
func ToolProblem(err error) string {
	if errors.Is(err, errToolChecksum) {
		return "checksum"
	}
	return "missing"
}

// WritableByOthers reports whether a Unix file can be changed by its group or by anyone
// (a pinned tool should be owned by root and writable only by root).
func WritableByOthers(path string) bool {
	if runtime.GOOS == "windows" {
		return false
	}
	fi, err := os.Stat(path)
	return err == nil && fi.Mode().Perm()&0o022 != 0
}
