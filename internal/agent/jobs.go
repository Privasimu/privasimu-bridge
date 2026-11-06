package agent

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/privasimu/bridge/internal/audit"
	"github.com/privasimu/bridge/internal/buildinfo"
	"github.com/privasimu/bridge/internal/config"
	"github.com/privasimu/bridge/internal/dbsource"
	"github.com/privasimu/bridge/internal/detect"
	"github.com/privasimu/bridge/internal/files"
	"github.com/privasimu/bridge/internal/packages"
	"github.com/privasimu/bridge/internal/scan"
)

// Limits of mode B jobs. The platform stores at most 500 tables and 1000 columns per
// table; job options can only lower these.
const (
	defaultMaxTables  = 500
	defaultMaxColumns = 1000
	dbDeadline        = 30 * time.Minute
	filesDeadline     = 6 * time.Hour
	// testDeadline bounds a test_source job (connect and list the tables, or open a root).
	testDeadline   = 10 * time.Minute
	partMaxItems   = 200
	partMaxBytes   = 512 << 10
	uploadAttempts = 5
	// maxParts is the most parts the platform accepts for one job (seq 0 to 499).
	maxParts = 500
	// packagesDeadline is the most a platform may give a package scan (deadline_seconds).
	packagesDeadline = time.Hour
	// watchdogGrace is how long the work of a job may still run after its deadline (or after
	// it was cancelled) before the watchdog abandons it: the job is reported and its slot
	// freed, whatever the work still does.
	watchdogGrace = 60 * time.Second
)

// Stages a job reports besides those of the scan package and the package service.
const (
	stageStarting = "starting"
	stageConnect  = "connect"
	stageUpload   = "upload"
)

// jobError is a failure reported to the platform with codes only. table names the table a
// database scan stopped at (schema.table), never a value.
type jobError struct {
	kind, code string
	retryable  bool
	stage      string
	table      string
}

func (e *jobError) Error() string { return e.code }

func failure(kind, code, stage string, retryable bool) *jobError {
	return &jobError{kind: kind, code: code, stage: stage, retryable: retryable}
}

// progressState is what a running job has achieved, shared between the job and its lease
// renewal (B-6). Its values change only when the job advances: a new stage, a finished
// table, file or part. A renewal that finds nothing new sends the same values again, which
// is a heartbeat and never progress, and the percentage never goes back within a run.
type progressState struct {
	mu          sync.Mutex
	stage       string
	done, total int
	// pct is the highest percentage reported in this run.
	pct int
	// scan follows a database scan while one runs: its stage, its counts and the table it
	// is working on.
	scan *scan.Tracker
}

func newProgress() *progressState { return &progressState{stage: stageStarting} }

// set records a stage and its counts; it ends following a database scan.
func (p *progressState) set(stage string, done, total int) {
	p.mu.Lock()
	p.stage, p.done, p.total, p.scan = stage, done, total, nil
	p.mu.Unlock()
}

// follow takes the stage and the counts from a database scan until the next set.
func (p *progressState) follow(t *scan.Tracker) {
	p.mu.Lock()
	p.scan = t
	p.mu.Unlock()
}

func (p *progressState) request() ProgressRequest {
	p.mu.Lock()
	defer p.mu.Unlock()
	stage, done, total := p.stage, p.done, p.total
	if p.scan != nil {
		if w := p.scan.Where(); w.Stage != "" {
			stage, done, total = w.Stage, w.Done, w.Total
		}
	}
	if total > 0 {
		p.pct = max(p.pct, min(99, done*100/total))
	}
	return ProgressRequest{Progress: p.pct, Stage: stage, Done: done, Total: total}
}

// stoppedAt names where the work stopped, for a failure and the local log: the stage, and
// in a database scan the table (schema.table) and the column it was examining. Names only.
func (p *progressState) stoppedAt() (stage, table, column string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	stage = p.stage
	if p.scan != nil {
		w := p.scan.Where()
		if w.Stage != "" {
			stage = w.Stage
		}
		if w.Table != "" {
			stage, table, column = w.Step, w.Table, w.Column
		}
	}
	return stage, table, column
}

// runningJob is a job the agent is working on, under one lease.
type runningJob struct {
	lease  string
	cancel context.CancelFunc
	// superseded means the platform leased the job again: the run stops and reports
	// nothing, and the job starts again under the new lease.
	superseded atomic.Bool
}

// start runs a job in the background. A poll can return a job that is still running here
// under an older lease: the platform expired that lease (no renewal reached it for the
// lease time, for example during an outage) and leased the job again, with its parts
// dropped. The old run then stops, and the job starts again under the new lease once the
// old run has ended.
func (a *Agent) start(parent context.Context, job Job) {
	if job.JobID == "" {
		return
	}
	a.mu.Lock()
	if cur, dup := a.running[job.JobID]; dup {
		if cur.lease != job.LeaseToken {
			cur.superseded.Store(true)
			cur.cancel()
			a.releases[job.JobID] = job
		}
		a.mu.Unlock()
		return
	}
	ctx, cancel := context.WithCancel(parent)
	run := &runningJob{lease: job.LeaseToken, cancel: cancel}
	a.running[job.JobID] = run
	a.mu.Unlock()
	a.jobs.Add(1)
	go func() {
		defer a.jobs.Done()
		defer func() {
			a.mu.Lock()
			delete(a.running, job.JobID)
			next, again := a.releases[job.JobID]
			delete(a.releases, job.JobID)
			a.mu.Unlock()
			cancel()
			if again && parent.Err() == nil {
				a.start(parent, next)
			}
		}()
		a.runJob(ctx, job, run)
	}()
}

// leaseState records why a job's lease renewal stopped the job.
type leaseState struct {
	// lost: the platform withdrew the lease or refused the agent; nothing is reported.
	lost atomic.Bool
	// canceled: the platform asked to stop (an admin cancelled the job).
	canceled atomic.Bool
}

// work is what the work of a job produced.
type work struct {
	result any
	items  []any
	kind   string
	err    error
	ev     audit.Event
}

// Watchdog states of a job's work: it runs until it either finishes or is abandoned.
const (
	workRunning int32 = iota
	workFinished
	workAbandoned
)

// runJob executes a job, keeps its lease alive and reports the outcome. The work runs in
// its own goroutine under the job's deadline (B-2): when the deadline passes or the job is
// cancelled, the work has watchdogGrace to return. Work that still runs after that is
// abandoned: the job is reported failed (with the stage and the table it stopped at), its
// slot is freed for other jobs, and the goroutine is left to end on its own.
func (a *Agent) runJob(ctx context.Context, job Job, run *runningJob) {
	started := time.Now()
	ev := audit.Event{Event: "job", Mode: "agent", AgentID: a.agentID, JobID: job.JobID, JobType: job.Type, SourceID: job.SourceID}
	prog := newProgress()
	jobCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	var lease leaseState
	var leaseWG sync.WaitGroup
	leaseWG.Add(1)
	go func() {
		defer leaseWG.Done()
		a.keepLease(jobCtx, job, prog, cancel, &lease)
	}()

	workCtx, workCancel := context.WithTimeout(jobCtx, a.jobDeadline(job))
	defer workCancel()
	var state atomic.Int32
	out := make(chan work, 1)
	go func() {
		w := work{ev: ev}
		w.result, w.items, w.kind, w.err = a.execute(workCtx, job, prog, &w.ev)
		if !state.CompareAndSwap(workRunning, workFinished) {
			n := a.abandoned.Add(-1)
			a.log.Warn("abandoned job work has ended", "job_id", job.JobID, "still_abandoned", n)
		}
		out <- w
	}()
	w, finished := a.await(workCtx, out, &state)
	expired := errors.Is(workCtx.Err(), context.DeadlineExceeded)
	workCancel()
	parts := 0
	if finished {
		ev = w.ev
		if w.err == nil && len(w.items) > 0 {
			parts, w.err = a.upload(jobCtx, job, w.kind, w.items, prog)
		}
	}
	cancel()
	leaseWG.Wait()

	if run.superseded.Load() {
		ev.Outcome, ev.Code = audit.Error, "lease_replaced"
		ev.DurationMS = time.Since(started).Milliseconds()
		a.audit.Log(ev)
		a.log.Warn("job restarts: the platform leased it again after its lease expired", "job_id", job.JobID)
		return
	}
	if lease.lost.Load() {
		ev.Outcome, ev.Code = audit.Error, "lease_lost"
		ev.DurationMS = time.Since(started).Milliseconds()
		a.audit.Log(ev)
		a.log.Warn("job abandoned: the platform withdrew its lease", "job_id", job.JobID)
		return
	}
	// The job context is over; finishing gets its own short deadline, even at shutdown.
	fctx, fcancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer fcancel()
	if finished && w.err == nil {
		err := a.retry(fctx, func(c context.Context) error {
			return a.client.Complete(c, job, CompleteRequest{Parts: parts, Result: w.result})
		})
		ev.Outcome = audit.OK
		if err != nil {
			ev.Outcome, ev.Code = audit.Error, "complete_failed"
			a.log.Error("job result could not be delivered", "job_id", job.JobID, "error", err.Error())
		}
		ev.DurationMS = time.Since(started).Milliseconds()
		a.audit.Log(ev)
		return
	}
	stage, table, column := prog.stoppedAt()
	var je *jobError
	switch {
	case !finished:
		je = a.abandonedFailure(ctx, &lease, stage, table)
		ev.Code = "watchdog"
		a.log.Error("job abandoned: its work did not stop within the grace period after its deadline or cancellation; "+
			"it may keep using CPU until the service restarts", "job_id", job.JobID, "type", job.Type, "source", job.SourceID,
			"stage", stage, "table", table, "column", column, "abandoned", a.abandoned.Load())
	default:
		je = jobFailure(ctx, &lease, expired, w.err, stage, table)
		ev.Code = je.code
	}
	ev.Outcome = audit.Error
	if ferr := a.retry(fctx, func(c context.Context) error {
		return a.client.Fail(c, job, FailRequest{ErrorKind: je.kind, ErrorCode: je.code, Retryable: je.retryable, Stage: je.stage, Table: je.table})
	}); ferr != nil {
		a.log.Error("job failure could not be delivered", "job_id", job.JobID, "error", ferr.Error())
	}
	a.log.Warn("job failed", "job_id", job.JobID, "type", job.Type, "source", job.SourceID, "code", je.code,
		"stage", je.stage, "table", je.table, "column", column)
	ev.DurationMS = time.Since(started).Milliseconds()
	a.audit.Log(ev)
}

// await waits for the work of a job. Once the work's context has ended (its deadline, a
// cancellation, a lost lease, a shutdown) the work gets a.grace to return; after that it is
// abandoned and await reports false. The work's own state decides a race at the last
// moment: work that has just finished is never abandoned.
func (a *Agent) await(ctx context.Context, out <-chan work, state *atomic.Int32) (work, bool) {
	select {
	case w := <-out:
		return w, true
	case <-ctx.Done():
	}
	grace := time.NewTimer(a.grace)
	defer grace.Stop()
	select {
	case w := <-out:
		return w, true
	case <-grace.C:
	}
	a.abandoned.Add(1) // before the swap, so the work's own decrement always comes after
	if !state.CompareAndSwap(workRunning, workAbandoned) {
		a.abandoned.Add(-1)
		return <-out, true // it finished just now
	}
	return work{}, false
}

// jobDeadline is how long the work of a job may run: the limit of its type, lowered by the
// platform's deadline_seconds. The watchdog allows a.grace on top.
func (a *Agent) jobDeadline(job Job) time.Duration {
	d := testDeadline
	switch job.Type {
	case JobScanDatabase:
		d = dbDeadline
	case JobScanFiles:
		d = filesDeadline
	case JobScanPackages:
		// deadline_seconds lowers the scan's own timeout (the tool runs); the job may first
		// wait for another package scan to finish, since one runs at a time.
		scanTimeout := a.cfg.Packages.Timeout.D()
		if s := job.Options.DeadlineSeconds; s > 0 {
			scanTimeout = min(scanTimeout, time.Duration(s)*time.Second, packagesDeadline)
		}
		return 2*scanTimeout + time.Minute
	}
	if s := job.Options.DeadlineSeconds; s > 0 {
		d = min(d, time.Duration(s)*time.Second)
	}
	return d
}

// jobFailure turns the error of finished work (or of its upload) into the codes reported
// to the platform. How the work's context ended decides first: a cancellation by the
// platform, a stopping agent, or the job's deadline (expired), which names the stage and, in
// a database scan, the table where the work stopped. Otherwise the work's own error counts.
func jobFailure(ctx context.Context, lease *leaseState, expired bool, err error, stage, table string) *jobError {
	var je *jobError
	switch {
	case lease.canceled.Load():
		return &jobError{kind: "canceled", code: FailCanceled, stage: stage, table: table}
	case ctx.Err() != nil:
		return failure("canceled", FailCanceled, "run", true) // the agent is stopping
	case expired:
		return &jobError{kind: dbsource.KindTimeout, code: FailTimeout, retryable: true, stage: stage, table: table}
	case errors.As(err, &je):
		return je
	case codeOf(err) == ErrPayloadTooLarge:
		return failure("limit", FailResultTooLarge, stageUpload, false)
	}
	return failure("internal", FailInternal, "run", true)
}

// abandonedFailure is the failure of work the watchdog abandoned. It is not retryable: work
// that ignored its deadline would most likely hang again and hold another slot.
func (a *Agent) abandonedFailure(ctx context.Context, lease *leaseState, stage, table string) *jobError {
	switch {
	case lease.canceled.Load():
		return &jobError{kind: "canceled", code: FailCanceled, stage: stage, table: table}
	case ctx.Err() != nil:
		return failure("canceled", FailCanceled, "run", true) // the agent is stopping
	}
	return &jobError{kind: dbsource.KindTimeout, code: FailTimeout, stage: stage, table: table}
}

// keepLease renews the lease until the job ends; it cancels the job when the platform
// withdraws the lease or asks to stop. Each renewal carries the job's progress as it is: a
// renewal while nothing advanced repeats the last values (a heartbeat, never progress).
func (a *Agent) keepLease(ctx context.Context, job Job, prog *progressState, cancel context.CancelFunc, lease *leaseState) {
	every := max(time.Duration(job.LeaseSeconds)*time.Second/3, a.minRenew)
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		pctx, pcancel := context.WithTimeout(ctx, 20*time.Second)
		resp, err := a.client.Progress(pctx, job, prog.request())
		pcancel()
		if err != nil {
			// The job is over for the platform: its lease is gone, the organisation is
			// refused, or the agent's token no longer works. Revocation fails the agent's jobs
			// on the platform (agent_revoked), so finishing the scan would only waste the
			// source's time.
			switch codeOf(err) {
			case ErrLeaseExpired, ErrJobNotFound, ErrForbidden, ErrAgentRevoked, ErrUnauthenticated:
				lease.lost.Store(true)
				cancel()
				return
			}
			continue // a transient failure: the next renewal may succeed before the lease ends
		}
		if resp.CancelRequested {
			lease.canceled.Store(true)
			cancel()
			return
		}
		if resp.LeaseSeconds > 0 {
			t.Reset(max(time.Duration(resp.LeaseSeconds)*time.Second/3, a.minRenew))
		}
	}
}

// retry sends a request again on network errors, 429 and 5xx.
func (a *Agent) retry(ctx context.Context, fn func(context.Context) error) error {
	wait := time.Second
	var err error
	for attempt := 0; attempt < uploadAttempts; attempt++ {
		cctx, cancel := context.WithTimeout(ctx, requestTimeout)
		err = fn(cctx)
		cancel()
		if err == nil {
			return nil
		}
		var ae *APIError
		if errors.As(err, &ae) && !ae.Retryable() {
			return err
		}
		if errors.As(err, &ae) && ae.RetryAfter > 0 {
			wait = ae.RetryAfter
		}
		if !a.sleep(ctx, wait) {
			return err
		}
		wait = min(wait*2, 30*time.Second)
	}
	return err
}

// partsFit returns how many of the items fit into maxParts parts, split the way upload
// splits them (at most partMaxItems items and partMaxBytes bytes per part).
func partsFit(items []any) (int, error) {
	parts, count, size := 0, 0, 0
	for i, it := range items {
		raw, err := json.Marshal(it)
		if err != nil {
			return i, err
		}
		if len(raw) > partMaxBytes {
			return i, failure("limit", FailResultTooLarge, "upload", false)
		}
		if count == 0 || count >= partMaxItems || size+len(raw) > partMaxBytes {
			if parts == maxParts {
				return i, nil
			}
			parts, count, size = parts+1, 0, 0
		}
		count++
		size += len(raw)
	}
	return len(items), nil
}

// upload sends the items in numbered parts of bounded size and returns how many parts
// were sent. Its progress is the stage upload with the parts sent of the parts to send.
func (a *Agent) upload(ctx context.Context, job Job, kind string, items []any, prog *progressState) (int, error) {
	var parts [][]any
	var batch []any
	size := 0
	for _, it := range items {
		raw, err := json.Marshal(it)
		if err != nil {
			return 0, err
		}
		if len(raw) > partMaxBytes {
			return 0, failure("limit", FailResultTooLarge, stageUpload, false)
		}
		if len(batch) > 0 && (len(batch) >= partMaxItems || size+len(raw) > partMaxBytes) {
			parts, batch, size = append(parts, batch), nil, 0
		}
		batch = append(batch, json.RawMessage(raw))
		size += len(raw)
	}
	if len(batch) > 0 {
		parts = append(parts, batch)
	}
	for seq, p := range parts {
		prog.set(stageUpload, seq, len(parts))
		req := PartRequest{Seq: seq, Kind: kind, Items: p}
		if err := a.retry(ctx, func(c context.Context) error { return a.client.Part(c, job, req) }); err != nil {
			return seq, err
		}
	}
	prog.set(stageUpload, len(parts), len(parts))
	return len(parts), nil
}

// execute runs the work of a job and returns the result, the part items and their kind.
func (a *Agent) execute(ctx context.Context, job Job, prog *progressState, ev *audit.Event) (any, []any, string, error) {
	if !a.cfg.Agent.JobAllowed(job.Type) {
		if job.Type != JobTestSource && job.Type != JobScanDatabase && job.Type != JobScanFiles && job.Type != JobScanPackages {
			return nil, nil, "", failure("config", FailUnsupportedJob, "accept", false)
		}
		return nil, nil, "", failure("config", FailJobNotAllowed, "accept", false)
	}
	src, isDB := a.cfg.Source(job.SourceID)
	_, isRoot := a.cfg.Root(job.SourceID)
	_, isTarget := a.cfg.PackageTarget(job.SourceID)
	switch {
	case job.Type == JobScanDatabase && !isDB, job.Type == JobScanFiles && !isRoot, job.Type == JobTestSource && !isDB && !isRoot,
		job.Type == JobScanPackages && !isTarget:
		return nil, nil, "", failure("config", FailSourceNotFound, "accept", false)
	}
	switch job.Type {
	case JobTestSource:
		if isDB {
			r, err := a.testDatabase(ctx, src, prog, ev)
			return r, nil, "", err
		}
		r, err := a.testRoot(job.SourceID)
		return r, nil, "", err
	case JobScanDatabase:
		return a.scanDatabase(ctx, job, src, prog, ev)
	case JobScanPackages:
		return a.scanPackages(ctx, job, prog, ev)
	default:
		return a.scanFiles(ctx, job, prog, ev)
	}
}

// scanPackages answers a scan_packages job: a stored report of the target when it is recent
// enough (unless the job asks to refresh), else a new scan; then the items are cut to what
// fits in the parts the platform accepts.
func (a *Agent) scanPackages(ctx context.Context, job Job, prog *progressState, ev *audit.Event) (any, []any, string, error) {
	if a.packages == nil {
		return nil, nil, "", failure("config", FailSourceNotFound, "accept", false)
	}
	o := job.Options
	opts := packages.ScanOptions{Refresh: o.Refresh, Match: o.Match == nil || *o.Match}
	if o.MaxAgeSeconds > 0 {
		opts.MaxAge = time.Duration(o.MaxAgeSeconds) * time.Second
	}
	if o.DeadlineSeconds > 0 {
		opts.Timeout = min(time.Duration(o.DeadlineSeconds)*time.Second, packagesDeadline)
	}
	target, _ := a.cfg.PackageTarget(job.SourceID)
	ev.Engine = target.Kind
	rep, err := a.packages.Run(ctx, job.SourceID, opts, func(stage string) { prog.set(stage, 0, 0) })
	if err != nil {
		if ctx.Err() != nil {
			return nil, nil, "", ctx.Err()
		}
		return nil, nil, "", packageFailure(err)
	}
	result := rep.Result
	result.BridgeVersion = buildinfo.Version
	items := make([]any, 0, len(rep.Items))
	for _, it := range rep.Items {
		items = append(items, it)
	}
	fit, err := partsFit(items)
	if err != nil {
		return nil, nil, "", err
	}
	if fit < len(items) {
		for _, it := range rep.Items[fit:] {
			result.MatchesTotal -= len(it.Matches)
		}
		items, result.Truncated = items[:fit], true
	}
	ev.Counts = map[string]int{"packages": len(items), "matches": result.MatchesTotal}
	return result, items, PartPackages, nil
}

// packageFailure reports a package scan failure with the codes of revision 3.
func packageFailure(err error) *jobError {
	var pe *packages.Error
	if !errors.As(err, &pe) {
		if errors.Is(err, packages.ErrUnknownTarget) {
			return failure("config", FailSourceNotFound, "accept", false)
		}
		return failure("internal", FailInternal, "run", true)
	}
	stage := pe.Stage // target, tool, output, run, inventory or matching
	switch pe.Code {
	case packages.CodeToolMissing:
		return failure("config", FailToolMissing, stage, false)
	case packages.CodeToolChecksum:
		return failure("config", FailToolChecksum, stage, false)
	case packages.CodeToolTimeout:
		return failure("timeout", FailToolTimeout, stage, true)
	case packages.CodeMatcherDB:
		return failure("config", FailMatcherDB, stage, false)
	case packages.CodeTargetUnreadable:
		return failure("permission", FailTargetUnreadable, stage, false)
	}
	return failure("internal", FailToolFailed, stage, true)
}

func (a *Agent) target(src *config.SourceConfig) (dbsource.Target, error) {
	t, err := dbsource.FromSource(src, a.resolver.Resolve)
	if err != nil {
		return t, failure("config", FailSecretMissing, "connect", false)
	}
	return t, nil
}

// dbFailure reports a database error as error_kind = the dbsource kind and error_code =
// "database_" + kind ("database_auth", "database_unreachable", ...), or "database_error"
// for an unclassified error.
func dbFailure(stage string, err error) *jobError {
	kind := dbsource.KindOf(err)
	retryable := kind == dbsource.KindUnreachable || kind == dbsource.KindTimeout
	code := FailDatabasePrefix + kind
	if kind == dbsource.KindDatabase {
		code = FailDatabase
	}
	return failure(kind, code, stage, retryable)
}

func (a *Agent) testDatabase(ctx context.Context, src *config.SourceConfig, prog *progressState, ev *audit.Event) (TestResult, error) {
	ev.Engine = src.Engine
	t, err := a.target(src)
	if err != nil {
		return TestResult{}, err
	}
	started := time.Now()
	prog.set(stageConnect, 0, 0)
	conn, err := a.open(ctx, t)
	if err != nil {
		if ctx.Err() != nil {
			return TestResult{}, ctx.Err()
		}
		a.log.Warn("database connection failed", "source", src.ID, "error", errMessage(err))
		return TestResult{}, dbFailure("connect", err)
	}
	defer conn.Close()
	prog.set(scan.StageListTables, 0, 0)
	tables, err := conn.ListTables(ctx, "")
	if err != nil && ctx.Err() != nil {
		return TestResult{}, ctx.Err()
	}
	if err != nil {
		return TestResult{}, dbFailure("list_tables", err)
	}
	n := len(tables)
	version := conn.ServerVersion(ctx)
	r := TestResult{Success: true, LatencyMS: time.Since(started).Milliseconds(), TablesFound: &n, SSLEnabled: conn.TLSInUse()}
	if version != "" {
		if len(version) > 30 {
			version = version[:30] // the platform stores at most 30 characters
		}
		r.ServerVersion = &version
	}
	ev.Tables = n
	return r, nil
}

func (a *Agent) testRoot(id string) (TestResult, error) {
	if a.files == nil {
		return TestResult{}, failure("config", FailFilesRootMissing, "accept", false)
	}
	root, ok := a.files.Root(id)
	if !ok {
		return TestResult{}, failure("config", FailFilesRootMissing, "accept", false)
	}
	started := time.Now()
	dir, err := os.Open(root.Path)
	if err != nil {
		return TestResult{}, failure("files", FailFileRoot, "open", false)
	}
	_, err = dir.ReadDir(1)
	_ = dir.Close()
	if err != nil && !errors.Is(err, io.EOF) {
		return TestResult{}, failure("files", FailFileRoot, "read", false)
	}
	return TestResult{Success: true, LatencyMS: time.Since(started).Milliseconds()}, nil
}

func (a *Agent) scanDatabase(ctx context.Context, job Job, src *config.SourceConfig, prog *progressState, ev *audit.Event) (any, []any, string, error) {
	ev.Engine = src.Engine
	o := job.Options
	if o.Schema != "" && len(src.Schemas) > 0 {
		allowed := false
		for _, s := range src.Schemas {
			allowed = allowed || strings.EqualFold(s, o.Schema)
		}
		if !allowed {
			return nil, nil, "", failure("config", FailInvalidOptions, "accept", false)
		}
	}
	// The deadline is the job's (runJob): the scan honours it at every stage, and the
	// watchdog ends the job even when a stage does not.
	sampling := a.cfg.SamplingFor(src)
	opts := scan.DBOptions{
		Schema:     o.Schema,
		Sampling:   sampling.On() && (o.Sampling == nil || *o.Sampling),
		Rows:       sampling.Rows,
		Thresholds: detect.Thresholds{MinMatches: sampling.MinMatches, Ratio: sampling.Ratio},
		MaxTables:  lower(defaultMaxTables, o.MaxTables),
		MaxColumns: lower(defaultMaxColumns, o.MaxColumns),
	}
	if src.AccessInventory && a.platformHas(FeatureTableAccess) {
		opts.Access, opts.RoleNames = true, a.roleNames
	}
	if a.entities != nil {
		opts.Entities, opts.EntityMinChars, opts.EntityMaxBytes = a.entities, a.cfg.Detection.NLP.MinChars, int(a.cfg.Detection.NLP.MaxBytes)
	}
	t, err := a.target(src)
	if err != nil {
		return nil, nil, "", err
	}
	prog.set(stageConnect, 0, 0)
	conn, err := a.open(ctx, t)
	if err != nil {
		if ctx.Err() != nil {
			return nil, nil, "", ctx.Err()
		}
		a.log.Warn("database connection failed", "source", src.ID, "error", errMessage(err))
		return nil, nil, "", dbFailure("connect", err)
	}
	defer conn.Close()
	opts.Track = &scan.Tracker{}
	prog.follow(opts.Track)
	res, err := scan.Database(ctx, conn, opts, nil)
	if err != nil {
		if ctx.Err() != nil {
			return nil, nil, "", ctx.Err()
		}
		return nil, nil, "", dbFailure("list_tables", err)
	}
	items := make([]any, 0, len(res.Tables))
	for _, tbl := range res.Tables {
		items = append(items, tableItem(tbl))
		pii, _ := tbl.PIIColumns()
		ev.Columns += len(tbl.Columns)
		ev.PIIColumns += pii
	}
	failed := make([]TableFailure, 0, len(res.Failed))
	for _, f := range res.Failed {
		failed = append(failed, TableFailure{Name: f.Name, ErrorKind: f.Kind})
	}
	ev.Tables, ev.Sampled = len(res.Tables), res.Sampling
	result := DatabaseResult{Engine: res.Engine, ServerVersion: res.ServerVersion, SSLEnabled: res.TLS, TablesTotal: res.TablesTotal,
		TablesFailed: failed, Truncated: res.Truncated, Sampling: res.Sampling, DurationMS: res.Duration.Milliseconds(),
		BridgeVersion: buildinfo.Version}
	return result, items, PartTables, nil
}

func lower(def, requested int) int {
	if requested > 0 && requested < def {
		return requested
	}
	return def
}

func tableItem(t scan.TableAnalysis) TableItem {
	item := TableItem{Name: t.Name, Schema: t.Schema, RowEstimate: t.RowEstimate, OmittedColumns: t.Omitted,
		Sampled: t.Sampled, SamplingError: t.SamplingError, Columns: make([]ColumnItem, 0, len(t.Columns))}
	if a := t.Access; a != nil {
		roles := a.Roles
		if roles == nil {
			roles = []string{}
		}
		item.Access = &TableAccess{Readers: a.Readers, Roles: roles, RolesTotal: a.RolesTotal, Admins: a.Admins, Public: a.Public,
			Complete: a.Complete}
	}
	for _, c := range t.Columns {
		f := c.Finding
		ci := ColumnItem{Name: c.Name, DataType: c.DataType, Nullable: c.Nullable, PII: f.IsPII, Category: string(f.Category),
			PDPCategory: f.PDP, Confidence: f.Confidence, Detection: f.Source, Shadow: f.Shadow}
		if f.Content != nil {
			ci.ProtectionState = f.Content.Protection
			ci.Content = &ContentCount{Sampled: f.Content.NonEmpty}
			if f.Content.Category != "" {
				ci.Content.Matching = f.Content.Matches[f.Content.Category]
			}
			if len(f.Content.Matches) > 0 {
				ci.Content.Matches = map[string]int{}
				for k, v := range f.Content.Matches {
					ci.Content.Matches[string(k)] = v
				}
			}
		}
		item.Columns = append(item.Columns, ci)
	}
	return item
}

func (a *Agent) scanFiles(ctx context.Context, job Job, prog *progressState, ev *audit.Event) (any, []any, string, error) {
	if a.files == nil {
		return nil, nil, "", failure("config", FailFilesRootMissing, "accept", false)
	}
	if _, ok := a.files.Root(job.SourceID); !ok {
		return nil, nil, "", failure("config", FailFilesRootMissing, "accept", false)
	}
	var rep *files.Report
	maxAge := 24 * time.Hour
	if s := job.Options.MaxAgeSeconds; s > 0 {
		maxAge = time.Duration(s) * time.Second
	}
	latest, err := a.files.Latest(job.SourceID)
	if err == nil && !job.Options.Refresh && time.Since(latest.FinishedAt) <= maxAge {
		rep = latest
	}
	if rep == nil {
		// Progress counts the files seen so far against the files the root's previous scan
		// saw (0 = unknown, the percentage then stays at 0): a walk does not know its total in
		// advance, and seen/scanned would move back and forth without measuring advancement.
		expected := 0
		if err == nil {
			expected = latest.FilesSeen
		}
		prog.set("files", 0, expected)
		rep, err = a.files.ScanNow(ctx, job.SourceID, func(seen, _ int) {
			total := expected
			if total > 0 {
				total = max(total, seen)
			}
			prog.set("files", seen, total)
		})
		switch {
		case errors.Is(err, files.ErrRunning):
			return nil, nil, "", failure("files", FailScanAlreadyRuns, "scan", true)
		case err != nil && ctx.Err() != nil:
			return nil, nil, "", ctx.Err()
		case err != nil:
			return nil, nil, "", failure("files", FailFileRoot, "scan", false)
		}
	}
	view := rep.View()
	items := make([]any, 0, len(view.Files))
	for _, f := range view.Files {
		items = append(items, f)
	}
	ev.Files, ev.Counts = rep.FilesScanned, view.Summary.Totals
	return view.Summary, items, PartFiles, nil
}

func errMessage(err error) string {
	var e *dbsource.Error
	if errors.As(err, &e) {
		return e.Message()
	}
	return "error"
}
