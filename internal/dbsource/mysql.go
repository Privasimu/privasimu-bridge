package dbsource

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/go-sql-driver/mysql"

	"github.com/privasimu/bridge/internal/config"
)

type myDialect struct{}

func (myDialect) engine() string         { return "mysql" }
func (myDialect) placeholder(int) string { return "?" }
func (myDialect) quote(id string) string { return "`" + strings.ReplaceAll(id, "`", "``") + "`" }

func (myDialect) version(ctx context.Context, db *sql.DB) string {
	var v string
	if err := db.QueryRowContext(ctx, "SELECT VERSION()").Scan(&v); err != nil {
		return ""
	}
	return mysqlVersionLabel(v)
}

// mysqlVersionLabel names the server and its version number without the build suffix:
// "10.6.12-MariaDB-0ubuntu0.22.04.1-log" is "MariaDB 10.6.12" and "8.0.36-0ubuntu0.22.04.1"
// is "MySQL 8.0.36". The platform keeps at most 30 characters of a server version.
func mysqlVersionLabel(v string) string {
	product := "MySQL"
	if strings.Contains(strings.ToLower(v), "mariadb") {
		product = "MariaDB"
	}
	number, _, _ := strings.Cut(strings.TrimSpace(v), "-")
	if number == "" {
		return product
	}
	return product + " " + number
}

// errUnknownVariable is the MySQL and MariaDB error for a system variable the server does
// not have (ER_UNKNOWN_SYSTEM_VARIABLE).
const errUnknownVariable = 1193

// mysqlSessionConnector prepares every new connection before the pool hands it out:
//
//   - SET SESSION TRANSACTION READ ONLY (MySQL 5.6.5+, MariaDB 10.0+) makes every later
//     transaction of the session read-only, autocommit statements included: the
//     counterpart of default_transaction_read_only on PostgreSQL.
//   - max_execution_time (MySQL 5.7.8+, milliseconds) or max_statement_time (MariaDB
//     10.1+, seconds) stops a statement on the server at the source's timeout, even when
//     the bridge has gone away; a server without the variable keeps the client-side
//     timeout only.
//   - lock_wait_timeout = 5 seconds: a query never waits long behind a metadata lock (an
//     ALTER TABLE), like lock_timeout on PostgreSQL.
type mysqlSessionConnector struct {
	driver.Connector
	timeout time.Duration
}

func (c mysqlSessionConnector) Connect(ctx context.Context) (driver.Conn, error) {
	conn, err := c.Connector.Connect(ctx)
	if err != nil {
		return nil, err
	}
	if err := prepareMySQLSession(ctx, conn, c.timeout); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return conn, nil
}

// prepareMySQLSession runs the session statements of mysqlSessionConnector on conn.
func prepareMySQLSession(ctx context.Context, conn driver.Conn, timeout time.Duration) error {
	exec, canExec := conn.(driver.ExecerContext)
	query, canQuery := conn.(driver.QueryerContext)
	if !canExec || !canQuery {
		return errors.New("mysql: the driver connection cannot run statements")
	}
	version, err := firstString(ctx, query, "SELECT VERSION()")
	if err != nil {
		return err
	}
	for _, stmt := range []string{"SET SESSION TRANSACTION READ ONLY", "SET SESSION lock_wait_timeout = 5"} {
		if _, err := exec.ExecContext(ctx, stmt, nil); err != nil {
			return err
		}
	}
	limit := "SET SESSION max_execution_time = " + strconv.FormatInt(max(timeout.Milliseconds(), 1), 10)
	if strings.Contains(strings.ToLower(version), "mariadb") {
		limit = "SET SESSION max_statement_time = " + strconv.FormatFloat(max(timeout.Seconds(), 0.001), 'f', 3, 64)
	}
	if _, err := exec.ExecContext(ctx, limit, nil); err != nil {
		var me *mysql.MySQLError
		if !errors.As(err, &me) || me.Number != errUnknownVariable {
			return err
		}
	}
	return nil
}

// firstString returns the first column of the first row of a query, as text.
func firstString(ctx context.Context, q driver.QueryerContext, query string) (string, error) {
	rows, err := q.QueryContext(ctx, query, nil)
	if err != nil {
		return "", err
	}
	defer rows.Close()
	dest := make([]driver.Value, len(rows.Columns()))
	if len(dest) == 0 {
		return "", errors.New("mysql: the query returned no column")
	}
	if err := rows.Next(dest); err != nil {
		if errors.Is(err, io.EOF) {
			return "", errors.New("mysql: the query returned no row")
		}
		return "", err
	}
	switch v := dest[0].(type) {
	case []byte:
		return string(v), nil
	case string:
		return v, nil
	}
	return "", nil
}

// In MySQL a schema is a database: the default schema is the configured database.
func (myDialect) defaultSchema(ctx context.Context, db *sql.DB, t Target) (string, error) {
	var s sql.NullString
	if err := db.QueryRowContext(ctx, "SELECT DATABASE()").Scan(&s); err != nil {
		return "", err
	}
	if s.Valid && s.String != "" {
		return s.String, nil
	}
	return t.Database, nil
}

const myTables = `SELECT table_schema, table_name, table_rows FROM information_schema.tables WHERE table_type = 'BASE TABLE'`

func (d myDialect) tablesQuery(schemas []string) (string, []any) {
	if len(schemas) == 0 {
		return myTables + " AND table_schema = DATABASE() ORDER BY 1, 2", nil
	}
	return myTables + " AND table_schema IN (" + placeholders(d, 1, len(schemas)) + ") ORDER BY 1, 2", toArgs(schemas)
}

func (myDialect) tableQuery(schema, name string) (string, []any) {
	return myTables + " AND table_schema = ? AND table_name = ?", []any{schema, name}
}

func (myDialect) columnsQuery(schema, name string) (string, []any) {
	return `SELECT column_name, column_type, is_nullable FROM information_schema.columns
WHERE table_schema = ? AND table_name = ? ORDER BY ordinal_position`, []any{schema, name}
}

func (myDialect) sampleable(t string) bool {
	return typeHas(t, "char", "varchar", "text", "tinytext", "mediumtext", "longtext", "json", "bigint", "decimal", "numeric")
}

func (d myDialect) selectExpr(c Column) string { return d.quote(c.Name) }

func (myDialect) sampleQuery(table string, exprs []string, rows int) (string, []any) {
	return "SELECT " + strings.Join(exprs, ", ") + " FROM " + table + " LIMIT ?", []any{rows}
}

func (myDialect) beginSample(ctx context.Context, db *sql.DB) (*sql.Tx, error) {
	return db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
}

func openMySQL(ctx context.Context, t Target) (Conn, error) {
	cfg := mysql.NewConfig()
	cfg.User = t.Username
	cfg.Passwd = t.Password.Reveal()
	cfg.Net = "tcp"
	cfg.Addr = net.JoinHostPort(t.Host, strconv.Itoa(t.Port))
	cfg.DBName = t.Database
	cfg.Timeout = t.Timeout
	cfg.ReadTimeout = t.Timeout + 5*time.Second
	cfg.WriteTimeout = t.Timeout
	// A server must never be able to read local files (LOAD DATA LOCAL INFILE), and
	// passwords are never sent in clear text.
	cfg.AllowAllFiles = false
	cfg.AllowCleartextPasswords = false
	cfg.MultiStatements = false
	cfg.InterpolateParams = false
	cfg.ParseTime = false
	cfg.ConnectionAttributes = "program_name:privasimu-bridge"
	tlsCfg, err := t.TLS.TLSConfig(t.Host)
	if err != nil {
		return nil, err
	}
	var tlsOn *bool
	switch t.TLS.Mode {
	case config.DBTLSDisable, "":
		off := false
		tlsOn = &off
	case config.DBTLSPrefer:
		cfg.TLS = tlsCfg
		cfg.AllowFallbackToPlaintext = true
	default:
		cfg.TLS = tlsCfg
		on := true
		tlsOn = &on
	}
	if t.Dial != nil {
		cfg.DialFunc = t.Dial
	}
	connector, err := mysql.NewConnector(cfg)
	if err != nil {
		return nil, wrap("config", err, true)
	}
	return newSQLConn(ctx, sql.OpenDB(mysqlSessionConnector{Connector: connector, timeout: t.Timeout}), myDialect{}, t, tlsOn)
}
