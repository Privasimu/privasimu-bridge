package scan

import (
	"sync"
	"sync/atomic"
)

// Stages of a database scan. They are stage words of the agent protocol: a job's progress
// names the scan stage (list_tables, tables), and a failure names the step of the table it
// stopped at (columns, sampling, detection, entities, access).
const (
	StageListTables = "list_tables"
	StageTables     = "tables"
	StageColumns    = "columns"
	StageSampling   = "sampling"
	StageDetection  = "detection"
	StageEntities   = "entities"
	StageAccess     = "access"
)

// tableSteps are the steps of one table, in order; TableStep keeps an index into it.
var tableSteps = [...]string{StageColumns, StageSampling, StageDetection, StageEntities, StageAccess}

const (
	stepColumns int32 = iota
	stepSampling
	stepDetection
	stepEntities
	stepAccess
)

// Tracker follows a database scan: its stage, how many tables are finished, and the tables
// being analysed with the step each is in. A scan that stops (its deadline, a cancellation,
// a step that never returns) can then say where it stopped: a stage and a table name, never
// a value. It is safe for concurrent use; a nil Tracker records nothing.
type Tracker struct {
	mu          sync.Mutex
	stage       string
	done, total int
	started     int
	active      map[*TableStep]struct{}
}

// Where is where a scan is.
type Where struct {
	// Stage is the scan stage (list_tables, tables); Done and Total count tables.
	Stage       string
	Done, Total int
	// Table is the oldest table still being analysed (schema.table), "" when none: the table
	// a stuck scan stopped at. Step is that table's step, Column the column it examined
	// (for the local log; empty outside sampling).
	Table, Step, Column string
}

func (t *Tracker) setStage(stage string, done, total int) {
	if t == nil {
		return
	}
	t.mu.Lock()
	t.stage, t.done, t.total = stage, done, total
	t.mu.Unlock()
}

// Where returns the stage, the counts and the oldest table in progress.
func (t *Tracker) Where() Where {
	if t == nil {
		return Where{}
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	w := Where{Stage: t.stage, Done: t.done, Total: t.total}
	var oldest *TableStep
	for s := range t.active {
		if oldest == nil || s.order < oldest.order {
			oldest = s
		}
	}
	if oldest != nil {
		w.Table, w.Step = oldest.table, tableSteps[oldest.step.Load()]
		if c := oldest.column.Load(); c != nil {
			w.Column = *c
		}
	}
	return w
}

// begin records that a table is being analysed; end it with TableStep.end.
func (t *Tracker) begin(table string) *TableStep {
	if t == nil {
		return nil
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.active == nil {
		t.active = map[*TableStep]struct{}{}
	}
	t.started++
	s := &TableStep{tracker: t, table: table, order: t.started}
	t.active[s] = struct{}{}
	return s
}

// TableStep is one table being analysed. Its step and column are atomics: sampling sets
// them for every value, so they must cost no lock.
type TableStep struct {
	tracker *Tracker
	table   string
	order   int
	step    atomic.Int32
	column  atomic.Pointer[string]
}

func (s *TableStep) set(step int32) {
	if s != nil {
		s.step.Store(step)
		if step != stepSampling && step != stepDetection {
			s.column.Store(nil)
		}
	}
}

// examine records that a value of column is being classified (step detection).
func (s *TableStep) examine(column *string) {
	if s != nil {
		s.column.Store(column)
		s.step.Store(stepDetection)
	}
}

// end records that the table is finished. A table stopped by the end of the scan's context
// stays listed, so the scan can still name where it stopped after its workers returned.
func (s *TableStep) end(stopped bool) {
	if s == nil || stopped {
		return
	}
	s.tracker.mu.Lock()
	delete(s.tracker.active, s)
	s.tracker.mu.Unlock()
}

// qualified is the name a failure reports: schema.table, or the table alone when the
// engine has no schema, cut to 255 bytes on a character boundary (the protocol's name rule).
func qualified(schema, name string) string {
	q := name
	if schema != "" {
		q = schema + "." + name
	}
	if len(q) <= 255 {
		return q
	}
	cut := 255
	for cut > 0 && q[cut]&0xC0 == 0x80 {
		cut--
	}
	return q[:cut]
}
