package dbsource

import (
	"context"
	"database/sql"
	"errors"
	"net"
	"regexp"
	"strconv"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/stdlib"

	"github.com/privasimu/bridge/internal/config"
)

// rsDialect reads Amazon Redshift (provisioned and Serverless) over the PostgreSQL
// protocol. Redshift's catalog is PostgreSQL 8.0's: no arrays (schema lists are IN lists),
// no partitioned tables or inheritance, and row counts in pg_class are not maintained, so
// row estimates are left out.
type rsDialect struct{}

func (rsDialect) engine() string           { return "redshift" }
func (rsDialect) placeholder(i int) string { return "$" + strconv.Itoa(i) }
func (rsDialect) quote(id string) string   { return pgDialect{}.quote(id) }

// redshiftVersion finds "Redshift 1.0.77467" in the long version() string.
var redshiftVersion = regexp.MustCompile(`Redshift [0-9][0-9.]*`)

func (rsDialect) version(ctx context.Context, db *sql.DB) string {
	var v string
	if err := db.QueryRowContext(ctx, "SELECT version()").Scan(&v); err != nil {
		return ""
	}
	if m := redshiftVersion.FindString(v); m != "" {
		return m
	}
	return "Redshift"
}

func (rsDialect) defaultSchema(ctx context.Context, db *sql.DB, t Target) (string, error) {
	return pgDialect{}.defaultSchema(ctx, db, t)
}

// rsSystemSchemas are left out of a listing without a schema allow-list.
const rsSystemSchemas = `('pg_catalog', 'information_schema', 'pg_internal', 'pg_automv', 'pg_auto_copy', 'pg_mv',
  'pg_s3', 'catalog_history')`

const rsTables = `SELECT n.nspname, c.relname, NULL::float8
FROM pg_catalog.pg_class c
JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
WHERE c.relkind = 'r'`

func (d rsDialect) tablesQuery(schemas []string) (string, []any) {
	if len(schemas) > 0 {
		return rsTables + " AND n.nspname IN (" + placeholders(d, 1, len(schemas)) + ") ORDER BY 1, 2", toArgs(schemas)
	}
	return rsTables + " AND n.nspname NOT IN " + rsSystemSchemas + ` AND n.nspname NOT LIKE 'pg\_temp%' ORDER BY 1, 2`, nil
}

func (rsDialect) tableQuery(schema, name string) (string, []any) {
	return rsTables + " AND n.nspname = $1 AND c.relname = $2", []any{schema, name}
}

func (rsDialect) columnsQuery(schema, name string) (string, []any) {
	return pgDialect{}.columnsQuery(schema, name)
}

func (rsDialect) sampleable(t string) bool {
	return typeHas(t, "character", "char", "varchar", "text", "bigint", "numeric", "decimal")
}

// selectExpr casts to the longest VARCHAR: TEXT is VARCHAR(256) in Redshift and would cut
// longer values.
func (d rsDialect) selectExpr(c Column) string {
	return "CAST(" + d.quote(c.Name) + " AS VARCHAR(65535))"
}

func (rsDialect) sampleQuery(table string, exprs []string, rows int) (string, []any) {
	return pgDialect{}.sampleQuery(table, exprs, rows)
}

func (rsDialect) beginSample(ctx context.Context, db *sql.DB) (*sql.Tx, error) {
	return db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
}

// openRedshift connects like PostgreSQL with Redshift's parameters: statement_timeout and
// application_name are Redshift configuration parameters; default_transaction_read_only and
// lock_timeout are not, so sampling runs in a READ ONLY transaction and the account should
// only hold USAGE and SELECT (install guide).
func openRedshift(ctx context.Context, t Target) (Conn, error) {
	if t.Port < 1 || t.Port > 65535 {
		return nil, &Error{Kind: KindConfig, Op: "config", Cause: errors.New("port out of range"), Safe: true}
	}
	cfg, err := pgx.ParseConfig("sslmode=disable")
	if err != nil {
		return nil, wrap("config", err, true)
	}
	cfg.Host = t.Host
	cfg.Port = uint16(t.Port) // #nosec G115 -- checked above
	cfg.Database = t.Database
	cfg.User = t.Username
	cfg.Password = t.Password.Reveal()
	cfg.ConnectTimeout = t.Timeout
	cfg.RuntimeParams = map[string]string{
		"application_name":  "privasimu-bridge",
		"statement_timeout": strconv.FormatInt(t.Timeout.Milliseconds(), 10),
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
		cfg.Fallbacks = []*pgconn.FallbackConfig{{Host: t.Host, Port: uint16(t.Port)}} // #nosec G115 -- checked above
	case config.DBTLSDisable, "":
		off := false
		tlsOn = &off
	default:
		on := true
		tlsOn = &on
	}
	if t.Dial != nil {
		cfg.LookupFunc = func(_ context.Context, host string) ([]string, error) { return []string{host}, nil }
		cfg.DialFunc = func(ctx context.Context, network, addr string) (net.Conn, error) { return t.Dial(ctx, network, addr) }
	}
	return newSQLConn(ctx, stdlib.OpenDB(*cfg), rsDialect{}, t, tlsOn)
}
