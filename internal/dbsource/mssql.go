package dbsource

import (
	"context"
	"database/sql"
	"net"
	"net/url"
	"strconv"
	"strings"

	mssql "github.com/microsoft/go-mssqldb"
	"github.com/microsoft/go-mssqldb/msdsn"

	"github.com/privasimu/bridge/internal/config"
)

type msDialect struct{}

func (msDialect) engine() string           { return "mssql" }
func (msDialect) placeholder(i int) string { return "@p" + strconv.Itoa(i) }
func (msDialect) quote(id string) string   { return "[" + strings.ReplaceAll(id, "]", "]]") + "]" }

func (msDialect) version(ctx context.Context, db *sql.DB) string {
	var v sql.NullString
	if err := db.QueryRowContext(ctx, "SELECT CAST(SERVERPROPERTY('ProductVersion') AS NVARCHAR(128))").Scan(&v); err != nil || !v.Valid {
		return ""
	}
	return "SQL Server " + v.String
}

func (msDialect) defaultSchema(ctx context.Context, db *sql.DB, _ Target) (string, error) {
	var s sql.NullString
	if err := db.QueryRowContext(ctx, "SELECT SCHEMA_NAME()").Scan(&s); err != nil {
		return "", err
	}
	if !s.Valid || s.String == "" {
		return "dbo", nil
	}
	return s.String, nil
}

const msTables = `SELECT s.name, t.name, CAST(SUM(p.rows) AS FLOAT)
FROM sys.tables t
JOIN sys.schemas s ON s.schema_id = t.schema_id
LEFT JOIN sys.partitions p ON p.object_id = t.object_id AND p.index_id IN (0, 1)
WHERE t.is_ms_shipped = 0`

func (d msDialect) tablesQuery(schemas []string) (string, []any) {
	if len(schemas) == 0 {
		return msTables + " GROUP BY s.name, t.name ORDER BY s.name, t.name", nil
	}
	return msTables + " AND s.name IN (" + placeholders(d, 1, len(schemas)) + ") GROUP BY s.name, t.name ORDER BY s.name, t.name", toArgs(schemas)
}

func (msDialect) tableQuery(schema, name string) (string, []any) {
	return msTables + " AND s.name = @p1 AND t.name = @p2 GROUP BY s.name, t.name", []any{schema, name}
}

func (msDialect) columnsQuery(schema, name string) (string, []any) {
	return `SELECT c.name, TYPE_NAME(c.user_type_id), CASE WHEN c.is_nullable = 1 THEN 'YES' ELSE 'NO' END
FROM sys.columns c
JOIN sys.tables t ON t.object_id = c.object_id
JOIN sys.schemas s ON s.schema_id = t.schema_id
WHERE s.name = @p1 AND t.name = @p2
ORDER BY c.column_id`, []any{schema, name}
}

func (msDialect) sampleable(t string) bool {
	return typeHas(t, "char", "varchar", "nchar", "nvarchar", "text", "ntext", "bigint", "decimal", "numeric")
}

func (d msDialect) selectExpr(c Column) string {
	return "CONVERT(NVARCHAR(4000), " + d.quote(c.Name) + ")"
}

func (msDialect) sampleQuery(table string, exprs []string, rows int) (string, []any) {
	return "SELECT TOP (@p1) " + strings.Join(exprs, ", ") + " FROM " + table, []any{rows}
}

// Sampling reads uncommitted data so that it never waits for, or blocks, the
// application's transactions.
func (msDialect) beginSample(ctx context.Context, db *sql.DB) (*sql.Tx, error) {
	return db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadUncommitted})
}

// ctxDialer adapts a DialFunc to the dialer interfaces of the SQL Server, Oracle and
// MongoDB drivers.
type ctxDialer struct{ dial DialFunc }

func (d ctxDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	return d.dial(ctx, network, addr)
}

func openMSSQL(ctx context.Context, t Target) (Conn, error) {
	q := url.Values{}
	if t.Database != "" {
		q.Set("database", t.Database)
	}
	q.Set("app name", "privasimu-bridge")
	// Routes to a readable secondary when the database is in an availability group.
	q.Set("ApplicationIntent", "ReadOnly")
	secs := strconv.Itoa(max(1, int(t.Timeout.Seconds())))
	q.Set("connection timeout", secs)
	q.Set("dial timeout", secs)
	verify := false
	var tlsOn *bool
	switch t.TLS.Mode {
	case config.DBTLSDisable, "":
		q.Set("encrypt", "false") // only the login packet is encrypted
		off := false
		tlsOn = &off
	case config.DBTLSPrefer, config.DBTLSRequire:
		q.Set("encrypt", "true")
		q.Set("TrustServerCertificate", "true")
		on := true
		tlsOn = &on
	default:
		q.Set("encrypt", "true")
		q.Set("TrustServerCertificate", "false")
		verify = true
		on := true
		tlsOn = &on
	}
	if t.TLS.TrustServerCertificate && !verify {
		q.Set("TrustServerCertificate", "true")
	}
	u := &url.URL{Scheme: "sqlserver", User: url.UserPassword(t.Username, t.Password.Reveal()), RawQuery: q.Encode()}
	if t.Instance != "" {
		// A named instance: the SQL Browser service resolves the port unless one is set.
		u.Host = t.Host
		if t.Port != 0 && t.Port != config.DefaultPort("mssql") {
			u.Host = net.JoinHostPort(t.Host, strconv.Itoa(t.Port))
		}
		u.Path = t.Instance
	} else {
		u.Host = net.JoinHostPort(t.Host, strconv.Itoa(t.Port))
	}
	parsed, err := msdsn.Parse(u.String())
	if err != nil {
		return nil, &Error{Kind: KindConfig, Op: "config", Cause: err, Safe: false}
	}
	if verify {
		tlsCfg, err := t.TLS.TLSConfig(t.Host)
		if err != nil {
			return nil, err
		}
		parsed.TLSConfig = tlsCfg
	}
	connector := mssql.NewConnectorConfig(parsed)
	if t.Dial != nil {
		connector.Dialer = ctxDialer{t.Dial}
	}
	return newSQLConn(ctx, sql.OpenDB(connector), msDialect{}, t, tlsOn)
}
