package dbsource

import (
	"context"
	"database/sql"
	"net"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/stdlib"

	"github.com/privasimu/bridge/internal/config"
)

type pgDialect struct{}

func (pgDialect) engine() string           { return "postgresql" }
func (pgDialect) placeholder(i int) string { return "$" + strconv.Itoa(i) }
func (pgDialect) quote(id string) string   { return `"` + strings.ReplaceAll(id, `"`, `""`) + `"` }

func (pgDialect) version(ctx context.Context, db *sql.DB) string {
	var v string
	if err := db.QueryRowContext(ctx, "SHOW server_version").Scan(&v); err != nil {
		return ""
	}
	return "PostgreSQL " + v
}

func (pgDialect) defaultSchema(ctx context.Context, db *sql.DB, _ Target) (string, error) {
	var s sql.NullString
	if err := db.QueryRowContext(ctx, "SELECT current_schema()").Scan(&s); err != nil {
		return "", err
	}
	if !s.Valid || s.String == "" {
		return "public", nil
	}
	return s.String, nil
}

// pgTables lists ordinary and partitioned tables; partitions and inheritance children are
// left out because their parent already describes them.
const pgTables = `SELECT n.nspname, c.relname, c.reltuples::float8
FROM pg_catalog.pg_class c
JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
WHERE c.relkind IN ('r', 'p')
  AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_inherits i WHERE i.inhrelid = c.oid)`

func (pgDialect) tablesQuery(schemas []string) (string, []any) {
	if len(schemas) > 0 {
		return pgTables + " AND n.nspname = ANY($1) ORDER BY 1, 2", []any{schemas}
	}
	return pgTables + ` AND n.nspname NOT IN ('pg_catalog', 'information_schema')
  AND n.nspname NOT LIKE 'pg\_toast%' AND n.nspname NOT LIKE 'pg\_temp%' ORDER BY 1, 2`, nil
}

func (pgDialect) tableQuery(schema, name string) (string, []any) {
	return `SELECT n.nspname, c.relname, c.reltuples::float8
FROM pg_catalog.pg_class c
JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
WHERE c.relkind IN ('r', 'p') AND n.nspname = $1 AND c.relname = $2`, []any{schema, name}
}

func (pgDialect) columnsQuery(schema, name string) (string, []any) {
	return `SELECT a.attname, pg_catalog.format_type(a.atttypid, a.atttypmod),
       CASE WHEN a.attnotnull THEN 'NO' ELSE 'YES' END
FROM pg_catalog.pg_attribute a
JOIN pg_catalog.pg_class c ON c.oid = a.attrelid
JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
WHERE n.nspname = $1 AND c.relname = $2 AND a.attnum > 0 AND NOT a.attisdropped
ORDER BY a.attnum`, []any{schema, name}
}

func (pgDialect) sampleable(t string) bool {
	if strings.Contains(t, "[]") {
		return false
	}
	return typeHas(t, "character", "char", "varchar", "text", "citext", "json", "bigint", "numeric", "decimal")
}

func (d pgDialect) selectExpr(c Column) string { return d.quote(c.Name) + "::text" }

func (pgDialect) sampleQuery(table string, exprs []string, rows int) (string, []any) {
	return "SELECT " + strings.Join(exprs, ", ") + " FROM " + table + " LIMIT $1", []any{rows}
}

func (pgDialect) beginSample(ctx context.Context, db *sql.DB) (*sql.Tx, error) {
	return db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
}

func openPostgres(ctx context.Context, t Target) (Conn, error) {
	cfg, err := pgx.ParseConfig("sslmode=disable")
	if err != nil {
		return nil, wrap("config", err, true)
	}
	cfg.Host = t.Host
	cfg.Port = uint16(t.Port)
	cfg.Database = t.Database
	cfg.User = t.Username
	cfg.Password = t.Password.Reveal()
	cfg.ConnectTimeout = t.Timeout
	cfg.ValidateConnect = nil
	// Every transaction is read-only; a statement or a lock wait cannot run for long.
	cfg.RuntimeParams = map[string]string{
		"application_name":              "privasimu-bridge",
		"default_transaction_read_only": "on",
		"statement_timeout":             strconv.FormatInt(t.Timeout.Milliseconds(), 10),
		"lock_timeout":                  "5000",
	}
	tlsCfg, err := t.TLS.TLSConfig(t.Host)
	if err != nil {
		return nil, err
	}
	cfg.TLSConfig = tlsCfg
	cfg.Fallbacks = nil
	var tlsOn *bool
	switch t.TLS.Mode {
	case config.DBTLSPrefer:
		cfg.Fallbacks = []*pgconn.FallbackConfig{{Host: t.Host, Port: uint16(t.Port)}}
	case config.DBTLSDisable, "":
		off := false
		tlsOn = &off
	default:
		on := true
		tlsOn = &on
	}
	if t.Dial != nil {
		// The guarded dialer resolves and checks the host itself.
		cfg.LookupFunc = func(_ context.Context, host string) ([]string, error) { return []string{host}, nil }
		cfg.DialFunc = func(ctx context.Context, network, addr string) (net.Conn, error) { return t.Dial(ctx, network, addr) }
	}
	db := stdlib.OpenDB(*cfg)
	return newSQLConn(ctx, db, pgDialect{}, t, tlsOn)
}
