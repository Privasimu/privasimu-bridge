package agent

// Items B-1, B-2 and B-6 of the 6 November 2026 staging report: a scan of free text that
// once looped for ever finishes; a job ends at its deadline and names the stage and the
// table it stopped at; a watchdog fails and frees the slot of work that never returns; and
// progress moves only when the job advances.

import (
	"bytes"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/privasimu/bridge/internal/dbsource"
	"github.com/privasimu/bridge/internal/testutil/fakedb"
)

// syncBuffer is a log destination shared by the agent's goroutines.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func TestScanFinishesOnFreeTextThatLoopedBefore(t *testing.T) {
	e := newEnv(t, nil)
	e.enroll()
	notes := fakedb.Table{Schema: "public", Name: "catatan_cabang", Columns: []dbsource.Column{fakedb.Text("catatan")}}
	for _, v := range []string{"2+2 = 4", "Lantai(2) gedung timur", "kirim ke budi+0812345678@example.co.id"} {
		notes.Rows = append(notes.Rows, map[string]string{"catatan": v})
	}
	e.db.Tables = []fakedb.Table{notes}
	e.fp.enqueue(Job{JobID: "j", Type: JobScanDatabase, SourceID: "core-banking"})
	a := e.agent()
	if !e.run(a, 20*time.Second, e.finished("j")) {
		t.Fatal("the scan of free text did not finish")
	}
	j := e.fp.job("j")
	if j.completed == nil {
		t.Fatalf("the scan failed: %+v", j.failed)
	}
	for _, v := range []string{"Lantai(2)", "budi+0812345678", "2+2 = 4"} {
		if bytes.Contains(e.fp.allBodies(), []byte(v)) {
			t.Fatalf("a sampled value reached the platform: %q", v)
		}
	}
}

// TestDeadlineFailureNamesTheStageAndTheTable: sampling never returns (a driver that ignores
// its context). The scan ends at the job's deadline by itself, before the watchdog, and the
// failure names the step and the table; the local log names the column too. No value leaves.
func TestDeadlineFailureNamesTheStageAndTheTable(t *testing.T) {
	e := newEnv(t, nil)
	e.enroll()
	stuck := make(chan struct{})
	t.Cleanup(func() { close(stuck) })
	e.db.Stuck = map[string]chan struct{}{"sample": stuck}
	e.fp.enqueue(Job{JobID: "j", Type: JobScanDatabase, SourceID: "core-banking", Options: JobOptions{DeadlineSeconds: 1}})
	a := e.agent()
	logs := &syncBuffer{}
	a.log = slog.New(slog.NewJSONHandler(logs, nil))
	a.grace = 10 * time.Second // the scan must end at its deadline, not through the watchdog
	if !e.run(a, 8*time.Second, e.finished("j")) {
		t.Fatal("the job did not end at its deadline")
	}
	f := e.fp.job("j").failed
	if f == nil || f.ErrorCode != FailTimeout || f.ErrorKind != dbsource.KindTimeout || !f.Retryable ||
		f.Stage != "sampling" || f.Table != "public.users" {
		t.Fatalf("failure = %+v", f)
	}
	if n := a.abandoned.Load(); n != 0 {
		t.Fatalf("abandoned = %d: the scan honours its deadline itself", n)
	}
	if !strings.Contains(logs.String(), `"table":"public.users"`) || !strings.Contains(logs.String(), `"stage":"sampling"`) {
		t.Fatalf("the log does not name where the job stopped:\n%s", logs.String())
	}
	for _, v := range sampleValues {
		if bytes.Contains(e.fp.allBodies(), []byte(v)) || strings.Contains(logs.String(), v) {
			t.Fatalf("a value left the agent or reached the log: %q", v)
		}
	}
}

// TestWatchdogFreesTheSlotOfWorkThatNeverReturns: the connection never returns and ignores
// its context. After the deadline and the grace period the job is reported failed (not
// retryable, stage connect), its slot runs the next job although max_parallel_jobs is 1,
// and the status counts the abandoned work until it ends.
func TestWatchdogFreesTheSlotOfWorkThatNeverReturns(t *testing.T) {
	e := newEnv(t, nil)
	e.enroll()
	stuck := make(chan struct{})
	released := false
	t.Cleanup(func() {
		if !released {
			close(stuck)
		}
	})
	e.db.Stuck = map[string]chan struct{}{"open": stuck}
	e.fp.enqueue(Job{JobID: "j1", Type: JobScanDatabase, SourceID: "core-banking", Options: JobOptions{DeadlineSeconds: 1}})
	e.fp.enqueue(Job{JobID: "j2", Type: JobTestSource, SourceID: "hr-share"})
	a := e.agent()
	a.grace = 200 * time.Millisecond
	if e.cfg.Agent.MaxParallelJobs != 1 {
		t.Fatalf("max_parallel_jobs = %d, want the default 1", e.cfg.Agent.MaxParallelJobs)
	}
	if !e.run(a, 15*time.Second, func() bool { return e.finished("j1")() && e.finished("j2")() }) {
		t.Fatal("the stuck job was not failed, or its slot was not freed")
	}
	f := e.fp.job("j1").failed
	if f == nil || f.ErrorCode != FailTimeout || f.ErrorKind != dbsource.KindTimeout || f.Retryable || f.Stage != "connect" || f.Table != "" {
		t.Fatalf("failure = %+v", f)
	}
	if j2 := e.fp.job("j2"); j2.completed == nil {
		t.Fatalf("the freed slot did not run the next job: %+v", j2.failed)
	}
	if n := a.abandoned.Load(); n != 1 {
		t.Fatalf("abandoned = %d, want 1", n)
	}
	if st, err := LoadStatus(e.cfg.Resolve(e.cfg.StateDir)); err != nil || st.AbandonedJobs != 1 {
		t.Fatalf("status %+v, %v", st, err)
	}
	released = true
	close(stuck)
	for deadline := time.Now().Add(5 * time.Second); a.abandoned.Load() != 0 && time.Now().Before(deadline); {
		time.Sleep(10 * time.Millisecond)
	}
	if n := a.abandoned.Load(); n != 0 {
		t.Fatalf("abandoned = %d after the work returned", n)
	}
}

// TestCanceledJobReportsCanceled: when the platform asks to stop, the agent reports
// canceled (section 5.4), not an internal error.
func TestCanceledJobReportsCanceled(t *testing.T) {
	e := newEnv(t, nil)
	e.enroll()
	e.db.Delay = 100 * time.Millisecond // the scan takes seconds
	e.fp.cancelJobs = true
	e.fp.enqueue(Job{JobID: "j", Type: JobScanDatabase, SourceID: "core-banking", LeaseSeconds: 1})
	a := e.agent()
	a.minRenew = 50 * time.Millisecond
	if !e.run(a, 10*time.Second, e.finished("j")) {
		t.Fatal("the canceled job was not reported")
	}
	if f := e.fp.job("j").failed; f == nil || f.ErrorCode != FailCanceled || f.ErrorKind != "canceled" || f.Retryable {
		t.Fatalf("failure = %+v", f)
	}
}

// TestRenewalsReportOnlyRealAdvancement: the stages come in order, the percentage never
// goes back and the counts never go back within a stage.
func TestRenewalsReportOnlyRealAdvancement(t *testing.T) {
	e := newEnv(t, nil)
	e.enroll()
	e.db.Delay = 5 * time.Millisecond // about a second for 451 tables
	e.fp.enqueue(Job{JobID: "j", Type: JobScanDatabase, SourceID: "core-banking", LeaseSeconds: 1})
	a := e.agent()
	a.minRenew = 20 * time.Millisecond
	if !e.run(a, 30*time.Second, e.finished("j")) {
		t.Fatal("job did not finish")
	}
	j := e.fp.job("j")
	if j.completed == nil {
		t.Fatalf("failed: %+v", j.failed)
	}
	order := map[string]int{"starting": 0, "connect": 1, "list_tables": 2, "tables": 3, "upload": 4}
	last, pct, done := -1, 0, 0
	for _, p := range j.progress {
		o, known := order[p.Stage]
		switch {
		case !known:
			t.Fatalf("unknown stage %q", p.Stage)
		case o < last:
			t.Fatalf("the stage went back: %+v", j.progress)
		case p.Progress < pct:
			t.Fatalf("the percentage went back: %+v", j.progress)
		case o == last && p.Done < done:
			t.Fatalf("done went back within a stage: %+v", j.progress)
		case p.Stage == "tables" && p.Total != 451:
			t.Fatalf("tables total = %d, want 451", p.Total)
		}
		last, pct, done = o, p.Progress, p.Done
	}
}

func TestProgressStateRepeatsItselfUntilTheJobAdvances(t *testing.T) {
	p := newProgress()
	if r := p.request(); r.Stage != "starting" || r.Progress != 0 || r.Done != 0 || r.Total != 0 {
		t.Fatalf("%+v", r)
	}
	p.set("files", 50, 100)
	first, again := p.request(), p.request()
	if first != again || first.Progress != 50 {
		t.Fatalf("a renewal without advancement must repeat the values: %+v then %+v", first, again)
	}
	p.set("files", 60, 200) // more files than expected: the share stays, the counts move
	if r := p.request(); r.Progress != 50 || r.Done != 60 || r.Total != 200 {
		t.Fatalf("%+v", r)
	}
	p.set("upload", 0, 3)
	if r := p.request(); r.Progress != 50 || r.Stage != "upload" {
		t.Fatalf("%+v", r)
	}
	p.set("upload", 3, 3)
	if r := p.request(); r.Progress != 99 {
		t.Fatalf("progress stays below 100 until the result is accepted: %+v", r)
	}
	stage, table, column := p.stoppedAt()
	if stage != "upload" || table != "" || column != "" {
		t.Fatalf("stopped at %q %q %q", stage, table, column)
	}
}

func TestJobDeadlines(t *testing.T) {
	e := newEnv(t, nil)
	a := &Agent{cfg: e.cfg}
	cases := []struct {
		job  Job
		want time.Duration
	}{
		{Job{Type: JobTestSource}, 10 * time.Minute},
		{Job{Type: JobScanDatabase}, 30 * time.Minute},
		{Job{Type: JobScanDatabase, Options: JobOptions{DeadlineSeconds: 60}}, time.Minute},
		{Job{Type: JobScanDatabase, Options: JobOptions{DeadlineSeconds: 7200}}, 30 * time.Minute},
		{Job{Type: JobScanFiles}, 6 * time.Hour},
		{Job{Type: JobScanFiles, Options: JobOptions{DeadlineSeconds: 900}}, 15 * time.Minute},
		// A package scan may wait for another one first: twice its timeout, plus a minute.
		{Job{Type: JobScanPackages}, 61 * time.Minute},
		{Job{Type: JobScanPackages, Options: JobOptions{DeadlineSeconds: 600}}, 21 * time.Minute},
	}
	for _, c := range cases {
		if got := a.jobDeadline(c.job); got != c.want {
			t.Errorf("%s %+v: %s, want %s", c.job.Type, c.job.Options, got, c.want)
		}
	}
}
