// Package scan turns a database catalog into findings: it lists tables, reads column
// metadata, optionally samples values locally, and classifies each column. Results hold
// names, types, categories, counts and confidence; never a value.
package scan

import (
	"context"
	"errors"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/privasimu/bridge/internal/dbsource"
	"github.com/privasimu/bridge/internal/detect"
)

// DBOptions configure a database analysis.
type DBOptions struct {
	// Schema narrows the listing to one schema (the platform's schema_name).
	Schema     string
	Sampling   bool
	Rows       int
	Thresholds detect.Thresholds
	// MaxTables and MaxColumns bound the work; zero means 10000 and 5000.
	MaxTables  int
	MaxColumns int
	// Concurrency bounds tables analyzed at once by Database (default 4).
	Concurrency int
	// Entities, when set, also examines long sampled text values (at least
	// EntityMinChars characters, at most EntityMaxBytes per column) with a local
	// language-model service; only its counts are kept (detection.nlp).
	Entities       detect.EntityCounter
	EntityMinChars int
	EntityMaxBytes int
}

func (o DBOptions) maxTables() int {
	if o.MaxTables > 0 {
		return o.MaxTables
	}
	return 10000
}

func (o DBOptions) maxColumns() int {
	if o.MaxColumns > 0 {
		return o.MaxColumns
	}
	return 5000
}

// ColumnAnalysis is one classified column.
type ColumnAnalysis struct {
	Name     string         `json:"name"`
	DataType string         `json:"data_type,omitempty"`
	Nullable *bool          `json:"nullable,omitempty"`
	Finding  detect.Finding `json:"finding"`
}

// TableAnalysis is one classified table.
type TableAnalysis struct {
	Name        string           `json:"name"`
	Schema      string           `json:"schema,omitempty"`
	RowEstimate *int64           `json:"row_estimate,omitempty"`
	Columns     []ColumnAnalysis `json:"columns"`
	// Omitted counts columns left out: names the platform cannot store, or columns over
	// the limit.
	Omitted int `json:"omitted,omitempty"`
	// Sampled reports whether values were examined; SamplingError holds the error kind
	// when sampling was on but failed (the columns are then classified by name only).
	Sampled       bool   `json:"sampled"`
	SamplingError string `json:"sampling_error,omitempty"`
}

// PIIColumns counts the columns classified as personal data.
func (t TableAnalysis) PIIColumns() (pii, pdp int) {
	for _, c := range t.Columns {
		if c.Finding.IsPII {
			pii++
			if c.Finding.PDP != "" {
				pdp++
			}
		}
	}
	return pii, pdp
}

// ListTables returns at most MaxTables tables and the total number found. Tables whose
// reported name the platform cannot store are left out but counted in the total, so the
// platform marks the listing incomplete instead of rejecting it.
func ListTables(ctx context.Context, c dbsource.Conn, o DBOptions) ([]dbsource.Table, int, error) {
	listed, err := c.ListTables(ctx, o.Schema)
	if err != nil {
		return nil, 0, err
	}
	total := len(listed)
	tables := listed[:0:0]
	for _, t := range listed {
		if platformSafe(t.Ref) {
			tables = append(tables, t)
		}
	}
	if len(tables) > o.maxTables() {
		tables = tables[:o.maxTables()]
	}
	return tables, total, nil
}

// AnalyzeTable reads the columns of t and classifies them, sampling values when enabled.
// A sampling failure does not fail the table: the columns are classified by name and the
// error kind is reported.
func AnalyzeTable(ctx context.Context, c dbsource.Conn, t dbsource.Table, o DBOptions) (TableAnalysis, error) {
	cols, err := c.Columns(ctx, t)
	if err != nil {
		return TableAnalysis{}, err
	}
	res := TableAnalysis{Name: t.Ref, Schema: t.Schema, RowEstimate: t.RowEstimate}
	kept := cols[:0:0]
	for _, col := range cols {
		if !platformSafe(col.Name) {
			res.Omitted++
			continue
		}
		kept = append(kept, col)
	}
	if len(kept) > o.maxColumns() {
		res.Omitted += len(kept) - o.maxColumns()
		kept = kept[:o.maxColumns()]
	}
	var content []*detect.ContentResult
	if o.Sampling && o.Rows > 0 {
		samplers := make([]*detect.ColumnSampler, len(kept))
		for i, col := range kept {
			if col.Sampleable {
				samplers[i] = detect.NewColumnSampler(col.Name)
				if o.Entities != nil && o.EntityMinChars > 0 && o.EntityMaxBytes > 0 {
					samplers[i].KeepLongText(o.EntityMinChars, o.EntityMaxBytes)
				}
			}
		}
		err := c.Sample(ctx, t, kept, o.Rows, func(i int, value string, null bool) {
			if i >= 0 && i < len(samplers) && samplers[i] != nil {
				samplers[i].Add(value, null)
			}
		})
		if err != nil {
			if ctx.Err() != nil {
				return TableAnalysis{}, ctx.Err()
			}
			res.SamplingError = dbsource.KindOf(err)
		} else {
			res.Sampled = true
			addEntities(ctx, o.Entities, samplers)
			content = make([]*detect.ContentResult, len(kept))
			for i, s := range samplers {
				if s != nil {
					r := s.Result(o.Thresholds)
					content[i] = &r
				}
			}
		}
		for _, s := range samplers {
			if s != nil {
				s.DropLongText()
			}
		}
	}
	res.Columns = make([]ColumnAnalysis, 0, len(kept))
	for i, col := range kept {
		var cr *detect.ContentResult
		if content != nil {
			cr = content[i]
		}
		res.Columns = append(res.Columns, ColumnAnalysis{
			Name: col.Name, DataType: col.DataType, Nullable: col.Nullable, Finding: detect.Combine(col.Name, cr),
		})
	}
	return res, nil
}

// addEntities sends each column's kept long text to the language-model service, one request
// per column, and counts what it found. When the service fails, the columns keep what the
// patterns found.
func addEntities(ctx context.Context, ec detect.EntityCounter, samplers []*detect.ColumnSampler) {
	if ec == nil {
		return
	}
	for _, s := range samplers {
		if s == nil || len(s.LongText()) == 0 {
			continue
		}
		found, err := ec.Count(ctx, s.LongText())
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			continue
		}
		s.AddEntities(found)
	}
}

// platformSafe reports whether the platform accepts a name: 1 to 255 bytes of valid UTF-8
// without control characters. One bad column name would make the platform reject the whole
// table, so such columns are left out and counted.
func platformSafe(s string) bool {
	if s == "" || len(s) > 255 || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

// TableFailure records a table that could not be analyzed (error kind only).
type TableFailure struct {
	Name string `json:"name"`
	Kind string `json:"error_kind"`
}

// DatabaseResult is a whole-database scan.
type DatabaseResult struct {
	Engine        string          `json:"engine"`
	ServerVersion string          `json:"server_version,omitempty"`
	TLS           *bool           `json:"tls,omitempty"`
	TablesTotal   int             `json:"tables_total"`
	Tables        []TableAnalysis `json:"tables"`
	Failed        []TableFailure  `json:"tables_failed"`
	Truncated     bool            `json:"truncated"`
	Sampling      bool            `json:"sampling"`
	Duration      time.Duration   `json:"-"`
}

// Database scans every table with bounded concurrency. progress is called after each
// table. A cancelled or expired context stops the scan and returns its error.
func Database(ctx context.Context, c dbsource.Conn, o DBOptions, progress func(done, total int)) (DatabaseResult, error) {
	started := time.Now()
	res := DatabaseResult{Engine: c.Engine(), ServerVersion: c.ServerVersion(ctx), TLS: c.TLSInUse(), Sampling: o.Sampling,
		Failed: []TableFailure{}}
	tables, total, err := ListTables(ctx, c, o)
	if err != nil {
		return res, err
	}
	res.TablesTotal = total
	res.Truncated = total > len(tables)
	workers := o.Concurrency
	if workers <= 0 {
		workers = 4
	}
	results := make([]*TableAnalysis, len(tables))
	failures := make([]string, len(tables))
	var mu sync.Mutex
	done := 0
	sem := make(chan struct{}, workers)
	var wg sync.WaitGroup
	for i, t := range tables {
		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
		}
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		go func(i int, t dbsource.Table) {
			defer wg.Done()
			defer func() { <-sem }()
			a, err := AnalyzeTable(ctx, c, t, o)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				failures[i] = dbsource.KindOf(err)
			} else {
				results[i] = &a
			}
			done++
			if progress != nil {
				progress(done, len(tables))
			}
		}(i, t)
	}
	wg.Wait()
	if err := ctx.Err(); err != nil {
		return res, err
	}
	for i, t := range tables {
		switch {
		case results[i] != nil:
			res.Tables = append(res.Tables, *results[i])
		case failures[i] != "":
			res.Failed = append(res.Failed, TableFailure{Name: t.Ref, Kind: failures[i]})
		}
	}
	res.Duration = time.Since(started)
	return res, nil
}

// ErrNoTables is returned when a database has no table the account can see.
var ErrNoTables = errors.New("no tables")
