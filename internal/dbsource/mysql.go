package dbsource

import (
	"context"
	"database/sql"
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
	if strings.Contains(strings.ToLower(v), "mariadb") {
		return "MariaDB " + v
	}
	return "MySQL " + v
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
	return newSQLConn(ctx, sql.OpenDB(connector), myDialect{}, t, tlsOn)
}
