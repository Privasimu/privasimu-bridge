// Package fakedb is an in-memory dbsource.Conn for tests. Its tables hold synthetic
// values only.
package fakedb

import (
	"context"
	"errors"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/privasimu/bridge/internal/dbsource"
)

// Table is a fake table.
type Table struct {
	Schema  string
	Name    string
	Columns []dbsource.Column
	// Rows hold the values by column name.
	Rows []map[string]string
}

// DB is a fake database.
type DB struct {
	Engine        string
	Version       string
	DefaultSchema string
	Tables        []Table
	// Delay is added to every call (to test timeouts).
	Delay time.Duration
	// Fail makes the given operation ("list", "find", "columns", "sample") fail.
	Fail map[string]error

	mu      sync.Mutex
	Opened  []dbsource.Target // every target Open was called with
	Sampled int               // number of Sample calls
}

// Opener returns a function suitable for dbsource.Pool.Open.
func (d *DB) Opener() func(ctx context.Context, t dbsource.Target) (dbsource.Conn, error) {
	return func(ctx context.Context, t dbsource.Target) (dbsource.Conn, error) {
		d.mu.Lock()
		d.Opened = append(d.Opened, t)
		d.mu.Unlock()
		if err := d.Fail["open"]; err != nil {
			return nil, err
		}
		return &conn{db: d, target: t}, nil
	}
}

// LastTarget returns the target of the last Open call.
func (d *DB) LastTarget() dbsource.Target {
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.Opened) == 0 {
		return dbsource.Target{}
	}
	return d.Opened[len(d.Opened)-1]
}

type conn struct {
	db     *DB
	target dbsource.Target
}

func (c *conn) wait(ctx context.Context) error {
	if c.db.Delay <= 0 {
		return nil
	}
	select {
	case <-time.After(c.db.Delay):
		return nil
	case <-ctx.Done():
		return &dbsource.Error{Kind: dbsource.KindTimeout, Op: "fake", Cause: ctx.Err(), Safe: true}
	}
}

func (c *conn) Engine() string {
	if c.db.Engine != "" {
		return c.db.Engine
	}
	return c.target.Engine
}
func (c *conn) ServerVersion(context.Context) string { return c.db.Version }
func (c *conn) DefaultSchema() string {
	if c.db.DefaultSchema != "" {
		return c.db.DefaultSchema
	}
	return "public"
}
func (c *conn) TLSInUse() *bool { return nil }
func (c *conn) Close() error    { return nil }

func (c *conn) allowed(schema string) bool {
	if len(c.target.Schemas) == 0 {
		return true
	}
	for _, s := range c.target.Schemas {
		if strings.EqualFold(s, schema) {
			return true
		}
	}
	return false
}

func (c *conn) ListTables(ctx context.Context, schema string) ([]dbsource.Table, error) {
	if err := c.wait(ctx); err != nil {
		return nil, err
	}
	if err := c.db.Fail["list"]; err != nil {
		return nil, err
	}
	var out []dbsource.Table
	for _, t := range c.db.Tables {
		if schema != "" && !strings.EqualFold(t.Schema, schema) {
			continue
		}
		if schema == "" && !c.allowed(t.Schema) {
			continue
		}
		ref := t.Name
		if schema == "" && !strings.EqualFold(t.Schema, c.DefaultSchema()) {
			ref = t.Schema + "." + t.Name
		}
		n := int64(len(t.Rows))
		out = append(out, dbsource.Table{Schema: t.Schema, Name: t.Name, Ref: ref, RowEstimate: &n})
	}
	sort.SliceStable(out, func(i, j int) bool {
		di, dj := strings.EqualFold(out[i].Schema, c.DefaultSchema()), strings.EqualFold(out[j].Schema, c.DefaultSchema())
		if di != dj {
			return di
		}
		if out[i].Schema != out[j].Schema {
			return out[i].Schema < out[j].Schema
		}
		return out[i].Name < out[j].Name
	})
	return out, nil
}

func (c *conn) table(schema, name string) *Table {
	for i := range c.db.Tables {
		t := &c.db.Tables[i]
		if strings.EqualFold(t.Schema, schema) && t.Name == name && c.allowed(t.Schema) {
			return t
		}
	}
	return nil
}

func (c *conn) FindTable(ctx context.Context, ref, schema string) (dbsource.Table, bool, error) {
	if err := c.wait(ctx); err != nil {
		return dbsource.Table{}, false, err
	}
	if err := c.db.Fail["find"]; err != nil {
		return dbsource.Table{}, false, err
	}
	cands := [][2]string{{schema, ref}}
	if schema == "" {
		cands = [][2]string{{c.DefaultSchema(), ref}}
		if s, n, ok := strings.Cut(ref, "."); ok {
			cands = append(cands, [2]string{s, n})
		}
	}
	for _, cand := range cands {
		if t := c.table(cand[0], cand[1]); t != nil {
			n := int64(len(t.Rows))
			return dbsource.Table{Schema: t.Schema, Name: t.Name, Ref: ref, RowEstimate: &n}, true, nil
		}
	}
	return dbsource.Table{}, false, nil
}

func (c *conn) Columns(ctx context.Context, t dbsource.Table) ([]dbsource.Column, error) {
	if err := c.wait(ctx); err != nil {
		return nil, err
	}
	if err := c.db.Fail["columns"]; err != nil {
		return nil, err
	}
	ft := c.table(t.Schema, t.Name)
	if ft == nil {
		return nil, &dbsource.Error{Kind: dbsource.KindNotFound, Op: "columns", Safe: true}
	}
	return append([]dbsource.Column(nil), ft.Columns...), nil
}

func (c *conn) Sample(ctx context.Context, t dbsource.Table, cols []dbsource.Column, rows int, visit func(int, string, bool)) error {
	c.db.mu.Lock()
	c.db.Sampled++
	c.db.mu.Unlock()
	if err := c.wait(ctx); err != nil {
		return err
	}
	if err := c.db.Fail["sample"]; err != nil {
		return err
	}
	ft := c.table(t.Schema, t.Name)
	if ft == nil {
		return errors.New("no table")
	}
	for n, row := range ft.Rows {
		if n >= rows {
			break
		}
		for i, col := range cols {
			if !col.Sampleable {
				continue
			}
			v, ok := row[col.Name]
			visit(i, v, !ok)
		}
	}
	return nil
}

// Text returns a sampleable text column.
func Text(name string) dbsource.Column {
	yes := true
	return dbsource.Column{Name: name, DataType: "character varying(255)", Nullable: &yes, Sampleable: true}
}

// Int returns a non-sampleable integer column.
func Int(name string) dbsource.Column {
	no := false
	return dbsource.Column{Name: name, DataType: "integer", Nullable: &no}
}
