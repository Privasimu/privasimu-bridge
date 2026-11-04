package dbsource

import (
	"context"
	"database/sql"
	"sort"
	"strings"
	"time"
)

// dialect holds what differs between SQL engines.
type dialect interface {
	engine() string
	// placeholder returns the bind parameter marker for argument i (1-based).
	placeholder(i int) string
	quote(identifier string) string
	version(ctx context.Context, db *sql.DB) string
	defaultSchema(ctx context.Context, db *sql.DB, t Target) (string, error)
	// tablesQuery lists (schema, name, row estimate) for the given schemas; an empty list
	// means every non-system schema.
	tablesQuery(schemas []string) (string, []any)
	// tableQuery returns (schema, name, row estimate) of one table.
	tableQuery(schema, name string) (string, []any)
	// columnsQuery returns (name, data type, nullable "YES"/"NO" or "Y"/"N") in order.
	columnsQuery(schema, name string) (string, []any)
	sampleable(dataType string) bool
	// selectExpr reads a column as text.
	selectExpr(c Column) string
	// sampleQuery reads up to rows rows of the given expressions.
	sampleQuery(table string, exprs []string, rows int) (string, []any)
	// beginSample starts the transaction sampling runs in (read-only, non-blocking).
	beginSample(ctx context.Context, db *sql.DB) (*sql.Tx, error)
}

// sqlConn implements Conn for the database/sql engines.
type sqlConn struct {
	db      *sql.DB
	d       dialect
	t       Target
	schema  string
	tls     *bool
	version string
}

func newSQLConn(ctx context.Context, db *sql.DB, d dialect, t Target, tlsOn *bool) (*sqlConn, error) {
	db.SetMaxOpenConns(t.MaxOpen)
	db.SetMaxIdleConns(2)
	db.SetConnMaxIdleTime(60 * time.Second)
	db.SetConnMaxLifetime(10 * time.Minute)
	pctx, cancel := context.WithTimeout(ctx, t.Timeout)
	defer cancel()
	if err := db.PingContext(pctx); err != nil {
		_ = db.Close()
		return nil, wrap("connect", err, true)
	}
	schema, err := d.defaultSchema(pctx, db, t)
	if err != nil {
		_ = db.Close()
		return nil, wrap("default schema", err, true)
	}
	c := &sqlConn{db: db, d: d, t: t, schema: schema, tls: tlsOn}
	c.version = d.version(pctx, db)
	return c, nil
}

func (c *sqlConn) Engine() string                       { return c.d.engine() }
func (c *sqlConn) ServerVersion(context.Context) string { return c.version }
func (c *sqlConn) DefaultSchema() string                { return c.schema }
func (c *sqlConn) TLSInUse() *bool                      { return c.tls }
func (c *sqlConn) Close() error                         { return c.db.Close() }

func (c *sqlConn) ctx(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, c.t.Timeout)
}

// schemasFor returns the schemas a listing covers.
func (c *sqlConn) schemasFor(schema string) ([]string, error) {
	if schema != "" {
		if !c.t.schemaAllowed(schema) {
			return nil, &Error{Kind: KindPermission, Op: "list tables", Safe: true}
		}
		return []string{schema}, nil
	}
	return c.t.Schemas, nil
}

func (c *sqlConn) ref(schema, name, requested string) string {
	if requested != "" || strings.EqualFold(schema, c.schema) {
		return name
	}
	return schema + "." + name
}

func (c *sqlConn) ListTables(ctx context.Context, schema string) ([]Table, error) {
	schemas, err := c.schemasFor(schema)
	if err != nil {
		return nil, err
	}
	qctx, cancel := c.ctx(ctx)
	defer cancel()
	query, args := c.d.tablesQuery(schemas)
	rows, err := c.db.QueryContext(qctx, query, args...)
	if err != nil {
		return nil, wrap("list tables", err, true)
	}
	defer rows.Close()
	var out []Table
	for rows.Next() {
		var s, n string
		var est sql.NullFloat64
		if err := rows.Scan(&s, &n, &est); err != nil {
			return nil, wrap("list tables", err, true)
		}
		if !validName(s) || !validName(n) {
			continue
		}
		t := Table{Schema: s, Name: n, Ref: c.ref(s, n, schema)}
		if est.Valid && est.Float64 >= 0 {
			v := int64(est.Float64)
			t.RowEstimate = &v
		}
		out = append(out, t)
	}
	if err := rows.Err(); err != nil {
		return nil, wrap("list tables", err, true)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Schema != out[j].Schema {
			// Tables of the default schema first, then the others by name.
			if strings.EqualFold(out[i].Schema, c.schema) != strings.EqualFold(out[j].Schema, c.schema) {
				return strings.EqualFold(out[i].Schema, c.schema)
			}
			return out[i].Schema < out[j].Schema
		}
		return out[i].Name < out[j].Name
	})
	return out, nil
}

func (c *sqlConn) FindTable(ctx context.Context, ref, schema string) (Table, bool, error) {
	if !validName(ref) {
		return Table{}, false, nil
	}
	type candidate struct{ schema, name string }
	var cands []candidate
	switch {
	case schema != "":
		cands = []candidate{{schema, ref}}
	case strings.Contains(ref, "."):
		s, n, _ := strings.Cut(ref, ".")
		cands = []candidate{{c.schema, ref}, {s, n}}
	default:
		cands = []candidate{{c.schema, ref}}
	}
	qctx, cancel := c.ctx(ctx)
	defer cancel()
	for _, cand := range cands {
		if cand.schema == "" || cand.name == "" || !c.t.schemaAllowed(cand.schema) {
			continue
		}
		query, args := c.d.tableQuery(cand.schema, cand.name)
		var s, n string
		var est sql.NullFloat64
		err := c.db.QueryRowContext(qctx, query, args...).Scan(&s, &n, &est)
		if err == sql.ErrNoRows {
			continue
		}
		if err != nil {
			return Table{}, false, wrap("find table", err, true)
		}
		t := Table{Schema: s, Name: n, Ref: ref}
		if est.Valid && est.Float64 >= 0 {
			v := int64(est.Float64)
			t.RowEstimate = &v
		}
		return t, true, nil
	}
	return Table{}, false, nil
}

func (c *sqlConn) Columns(ctx context.Context, t Table) ([]Column, error) {
	qctx, cancel := c.ctx(ctx)
	defer cancel()
	query, args := c.d.columnsQuery(t.Schema, t.Name)
	rows, err := c.db.QueryContext(qctx, query, args...)
	if err != nil {
		return nil, wrap("columns", err, true)
	}
	defer rows.Close()
	var out []Column
	for rows.Next() {
		var name, typ, nullable sql.NullString
		if err := rows.Scan(&name, &typ, &nullable); err != nil {
			return nil, wrap("columns", err, true)
		}
		col := Column{Name: name.String, DataType: strings.ToLower(typ.String)}
		if nullable.Valid {
			n := strings.HasPrefix(strings.ToUpper(nullable.String), "Y")
			col.Nullable = &n
		}
		col.Sampleable = c.d.sampleable(col.DataType)
		out = append(out, col)
	}
	if err := rows.Err(); err != nil {
		return nil, wrap("columns", err, true)
	}
	return out, nil
}

// Sample reads values inside a read-only (or read-uncommitted) transaction. Errors are
// classified without their driver message: a conversion error can quote a value.
func (c *sqlConn) Sample(ctx context.Context, t Table, cols []Column, rows int, visit func(int, string, bool)) error {
	var idx []int
	var exprs []string
	for i, col := range cols {
		if col.Sampleable && validName(col.Name) {
			idx = append(idx, i)
			exprs = append(exprs, c.d.selectExpr(col))
		}
	}
	if len(idx) == 0 || rows <= 0 {
		return nil
	}
	qctx, cancel := c.ctx(ctx)
	defer cancel()
	tx, err := c.d.beginSample(qctx, c.db)
	if err != nil {
		return wrap("sample", err, false)
	}
	defer tx.Rollback() //nolint:errcheck // read-only transaction
	table := c.d.quote(t.Schema) + "." + c.d.quote(t.Name)
	query, args := c.d.sampleQuery(table, exprs, rows)
	r, err := tx.QueryContext(qctx, query, args...)
	if err != nil {
		return wrap("sample", err, false)
	}
	defer r.Close()
	vals := make([]sql.NullString, len(idx))
	ptrs := make([]any, len(idx))
	for i := range vals {
		ptrs[i] = &vals[i]
	}
	for n := 0; n < rows && r.Next(); n++ {
		if err := r.Scan(ptrs...); err != nil {
			return wrap("sample", err, false)
		}
		for i, v := range vals {
			visit(idx[i], v.String, !v.Valid)
			vals[i] = sql.NullString{}
		}
	}
	return wrap("sample", r.Err(), false)
}

// placeholders returns n bind markers starting at argument from.
func placeholders(d dialect, from, n int) string {
	parts := make([]string, n)
	for i := 0; i < n; i++ {
		parts[i] = d.placeholder(from + i)
	}
	return strings.Join(parts, ", ")
}

func toArgs(list []string) []any {
	out := make([]any, len(list))
	for i, s := range list {
		out[i] = s
	}
	return out
}

// typeHas reports whether a lower-case data type starts with or contains any of words.
func typeHas(dataType string, words ...string) bool {
	for _, w := range words {
		if strings.HasPrefix(dataType, w) || strings.Contains(dataType, " "+w) {
			return true
		}
	}
	return false
}
