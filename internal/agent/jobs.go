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
	"github.com/privasimu/bridge/internal/scan"
)

// Limits of mode B jobs. The platform stores at most 500 tables and 1000 columns per
// table; job options can only lower these.
const (
	defaultMaxTables  = 500
	defaultMaxColumns = 1000
	dbDeadline        = 30 * time.Minute
	filesDeadline     = 6 * time.Hour
	partMaxItems      = 200
	partMaxBytes      = 512 << 10
	uploadAttempts    = 5
)

// jobError is a failure reported to the platform with codes only.
type jobError struct {
	kind, code string
	retryable  bool
	stage      string
}

func (e *jobError) Error() string { return e.code }

func failure(kind, code, stage string, retryable bool) *jobError {
	return &jobError{kind: kind, code: code, stage: stage, retryable: retryable}
}

// progressState is shared between a running job and its lease renewal.
type progressState struct {
	done, total atomic.Int64
	stage       atomic.Value
}

func (p *progressState) set(stage string, done, total int) {
	p.stage.Store(stage)
	p.done.Store(int64(done))
	p.total.Store(int64(total))
}

func (p *progressState) request() ProgressRequest {
	stage, _ := p.stage.Load().(string)
	done, total := int(p.done.Load()), int(p.total.Load())
	pct := 0
	if total > 0 {
		pct = min(99, done*100/total)
	}
	return ProgressRequest{Progress: pct, Stage: stage, Done: done, Total: total}
}

// start runs a job in the background.
func (a *Agent) start(parent context.Context, job Job) {
	a.mu.Lock()
	if _, dup := a.running[job.JobID]; dup || job.JobID == "" {
		a.mu.Unlock()
		return
	}
	ctx, cancel := context.WithCancel(parent)
	a.running[job.JobID] = cancel
	a.mu.Unlock()
	a.jobs.Add(1)
	go func() {
		defer a.jobs.Done()
		defer func() {
			a.mu.Lock()
			delete(a.running, job.JobID)
			a.mu.Unlock()
			cancel()
		}()
		a.runJob(ctx, job)
	}()
}

// runJob executes a job, keeps its lease alive and reports the outcome.
func (a *Agent) runJob(ctx context.Context, job Job) {
	started := time.Now()
	ev := audit.Event{Event: "job", Mode: "agent", AgentID: a.agentID, JobID: job.JobID, JobType: job.Type, SourceID: job.SourceID}
	prog := &progressState{}
	prog.set("starting", 0, 0)
	jobCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	var lost atomic.Bool
	var leaseWG sync.WaitGroup
	leaseWG.Add(1)
	go func() {
		defer leaseWG.Done()
		a.keepLease(jobCtx, job, prog, cancel, &lost)
	}()

	result, items, kind, err := a.execute(jobCtx, job, prog, &ev)
	parts := 0
	if err == nil && len(items) > 0 {
		parts, err = a.upload(jobCtx, job, kind, items)
	}
	cancel()
	leaseWG.Wait()

	if lost.Load() {
		ev.Outcome, ev.Code = audit.Error, "lease_lost"
		ev.DurationMS = time.Since(started).Milliseconds()
		a.audit.Log(ev)
		a.log.Warn("job abandoned: the platform withdrew its lease", "job_id", job.JobID)
		return
	}
	// The job context is over; finishing gets its own short deadline, even at shutdown.
	fctx, fcancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer fcancel()
	if err == nil {
		err = a.retry(fctx, func(c context.Context) error {
			return a.client.Complete(c, job, CompleteRequest{Parts: parts, Result: result})
		})
		ev.Outcome = audit.OK
		if err != nil {
			ev.Outcome, ev.Code = audit.Error, "complete_failed"
			a.log.Error("job result could not be delivered", "job_id", job.JobID, "error", err.Error())
		}
	} else {
		je := asJobError(ctx, err)
		ev.Outcome, ev.Code = audit.Error, je.code
		if ferr := a.retry(fctx, func(c context.Context) error {
			return a.client.Fail(c, job, FailRequest{ErrorKind: je.kind, ErrorCode: je.code, Retryable: je.retryable, Stage: je.stage})
		}); ferr != nil {
			a.log.Error("job failure could not be delivered", "job_id", job.JobID, "error", ferr.Error())
		}
		a.log.Warn("job failed", "job_id", job.JobID, "type", job.Type, "source", job.SourceID, "code", je.code)
	}
	ev.DurationMS = time.Since(started).Milliseconds()
	a.audit.Log(ev)
}

func asJobError(ctx context.Context, err error) *jobError {
	var je *jobError
	switch {
	case errors.As(err, &je):
		return je
	case ctx.Err() != nil && errors.Is(ctx.Err(), context.Canceled):
		return failure("canceled", FailCanceled, "run", true)
	case errors.Is(err, context.DeadlineExceeded):
		return failure(dbsource.KindTimeout, FailTimeout, "run", true)
	case codeOf(err) == ErrPayloadTooLarge:
		return failure("limit", FailResultTooLarge, "upload", false)
	}
	return failure("internal", FailInternal, "run", true)
}

// keepLease renews the lease until the job ends; it cancels the job when the platform
// withdraws the lease or asks to stop.
func (a *Agent) keepLease(ctx context.Context, job Job, prog *progressState, cancel context.CancelFunc, lost *atomic.Bool) {
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
				lost.Store(true)
				cancel()
				return
			}
			continue // a transient failure: the next renewal may succeed before the lease ends
		}
		if resp.CancelRequested {
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

// upload sends the items in numbered parts of bounded size and returns how many parts
// were sent.
func (a *Agent) upload(ctx context.Context, job Job, kind string, items []any) (int, error) {
	seq := 0
	var batch []any
	size := 0
	flush := func() error {
		if len(batch) == 0 {
			return nil
		}
		req := PartRequest{Seq: seq, Kind: kind, Items: batch}
		err := a.retry(ctx, func(c context.Context) error { return a.client.Part(c, job, req) })
		if err != nil {
			return err
		}
		seq++
		batch, size = nil, 0
		return nil
	}
	for _, it := range items {
		raw, err := json.Marshal(it)
		if err != nil {
			return seq, err
		}
		if len(raw) > partMaxBytes {
			return seq, failure("limit", FailResultTooLarge, "upload", false)
		}
		if len(batch) >= partMaxItems || size+len(raw) > partMaxBytes {
			if err := flush(); err != nil {
				return seq, err
			}
		}
		batch = append(batch, json.RawMessage(raw))
		size += len(raw)
	}
	err := flush()
	return seq, err
}

// execute runs the work of a job and returns the result, the part items and their kind.
func (a *Agent) execute(ctx context.Context, job Job, prog *progressState, ev *audit.Event) (any, []any, string, error) {
	if !a.cfg.Agent.JobAllowed(job.Type) {
		if job.Type != JobTestSource && job.Type != JobScanDatabase && job.Type != JobScanFiles {
			return nil, nil, "", failure("config", FailUnsupportedJob, "accept", false)
		}
		return nil, nil, "", failure("config", FailJobNotAllowed, "accept", false)
	}
	src, isDB := a.cfg.Source(job.SourceID)
	_, isRoot := a.cfg.Root(job.SourceID)
	switch {
	case job.Type == JobScanDatabase && !isDB, job.Type == JobScanFiles && !isRoot, job.Type == JobTestSource && !isDB && !isRoot:
		return nil, nil, "", failure("config", FailSourceNotFound, "accept", false)
	}
	switch job.Type {
	case JobTestSource:
		if isDB {
			r, err := a.testDatabase(ctx, src, ev)
			return r, nil, "", err
		}
		r, err := a.testRoot(job.SourceID)
		return r, nil, "", err
	case JobScanDatabase:
		return a.scanDatabase(ctx, job, src, prog, ev)
	default:
		return a.scanFiles(ctx, job, prog, ev)
	}
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

func (a *Agent) testDatabase(ctx context.Context, src *config.SourceConfig, ev *audit.Event) (TestResult, error) {
	ev.Engine = src.Engine
	t, err := a.target(src)
	if err != nil {
		return TestResult{}, err
	}
	started := time.Now()
	conn, err := a.open(ctx, t)
	if err != nil {
		a.log.Warn("database connection failed", "source", src.ID, "error", errMessage(err))
		return TestResult{}, dbFailure("connect", err)
	}
	defer conn.Close()
	tables, err := conn.ListTables(ctx, "")
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
	dir.Close()
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
	deadline := dbDeadline
	if o.DeadlineSeconds > 0 {
		deadline = min(deadline, time.Duration(o.DeadlineSeconds)*time.Second)
	}
	ctx, cancel := context.WithTimeout(ctx, deadline)
	defer cancel()
	sampling := a.cfg.SamplingFor(src)
	opts := scan.DBOptions{
		Schema:     o.Schema,
		Sampling:   sampling.On() && (o.Sampling == nil || *o.Sampling),
		Rows:       sampling.Rows,
		Thresholds: detect.Thresholds{MinMatches: sampling.MinMatches, Ratio: sampling.Ratio},
		MaxTables:  lower(defaultMaxTables, o.MaxTables),
		MaxColumns: lower(defaultMaxColumns, o.MaxColumns),
	}
	t, err := a.target(src)
	if err != nil {
		return nil, nil, "", err
	}
	prog.set("connect", 0, 0)
	conn, err := a.open(ctx, t)
	if err != nil {
		a.log.Warn("database connection failed", "source", src.ID, "error", errMessage(err))
		return nil, nil, "", dbFailure("connect", err)
	}
	defer conn.Close()
	res, err := scan.Database(ctx, conn, opts, func(done, total int) { prog.set("tables", done, total) })
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
	prog.set("upload", len(res.Tables), len(res.Tables))
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
	deadline := filesDeadline
	if s := job.Options.DeadlineSeconds; s > 0 {
		deadline = min(deadline, time.Duration(s)*time.Second)
	}
	ctx, cancel := context.WithTimeout(ctx, deadline)
	defer cancel()
	var rep *files.Report
	maxAge := 24 * time.Hour
	if s := job.Options.MaxAgeSeconds; s > 0 {
		maxAge = time.Duration(s) * time.Second
	}
	if !job.Options.Refresh {
		if latest, err := a.files.Latest(job.SourceID); err == nil && time.Since(latest.FinishedAt) <= maxAge {
			rep = latest
		}
	}
	if rep == nil {
		prog.set("files", 0, 0)
		var err error
		rep, err = a.files.ScanNow(ctx, job.SourceID, func(seen, scanned int) { prog.set("files", scanned, seen) })
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
