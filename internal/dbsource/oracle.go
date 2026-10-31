package dbsource

import (
	"context"
	"database/sql"
	"strconv"
	"strings"

	go_ora "github.com/sijms/go-ora/v2"

	"github.com/privasimu/bridge/internal/config"
)

type oraDialect struct{}

func (oraDialect) engine() string           { return "oracle" }
func (oraDialect) placeholder(i int) string { return ":" + strconv.Itoa(i) }
func (oraDialect) quote(id string) string   { return `"` + strings.ReplaceAll(id, `"`, `""`) + `"` }

func (oraDialect) version(ctx context.Context, db *sql.DB) string {
	var v sql.NullString
	if err := db.QueryRowContext(ctx, "SELECT version FROM product_component_version WHERE ROWNUM = 1").Scan(&v); err != nil || !v.Valid {
		return ""
	}
	return "Oracle " + v.String
}

// The default schema is the session's current schema (the user's own, upper case).
func (oraDialect) defaultSchema(ctx context.Context, db *sql.DB, _ Target) (string, error) {
	var s string
	if err := db.QueryRowContext(ctx, "SELECT SYS_CONTEXT('USERENV', 'CURRENT_SCHEMA') FROM DUAL").Scan(&s); err != nil {
		return "", err
	}
	return s, nil
}

// oraTables leaves out tables in the recycle bin, nested tables and secondary objects.
const oraTables = `SELECT owner, table_name, num_rows FROM all_tables
WHERE dropped = 'NO' AND nested = 'NO' AND secondary = 'N'`

func (d oraDialect) tablesQuery(schemas []string) (string, []any) {
	if len(schemas) == 0 {
		return oraTables + " AND owner = SYS_CONTEXT('USERENV', 'CURRENT_SCHEMA') ORDER BY 1, 2", nil
	}
	return oraTables + " AND owner IN (" + placeholders(d, 1, len(schemas)) + ") ORDER BY 1, 2", toArgs(schemas)
}

func (oraDialect) tableQuery(schema, name string) (string, []any) {
	return "SELECT owner, table_name, num_rows FROM all_tables WHERE owner = :1 AND table_name = :2", []any{schema, name}
}

func (oraDialect) columnsQuery(schema, name string) (string, []any) {
	return `SELECT column_name, data_type, nullable FROM all_tab_columns
WHERE owner = :1 AND table_name = :2 ORDER BY column_id`, []any{schema, name}
}

func (oraDialect) sampleable(t string) bool {
	return typeHas(t, "varchar2", "nvarchar2", "char", "nchar", "clob", "nclob", "number")
}

func (d oraDialect) selectExpr(c Column) string {
	if strings.Contains(c.DataType, "clob") {
		return "DBMS_LOB.SUBSTR(" + d.quote(c.Name) + ", 4000, 1)"
	}
	return "TO_CHAR(" + d.quote(c.Name) + ")"
}

func (oraDialect) sampleQuery(table string, exprs []string, rows int) (string, []any) {
	return "SELECT " + strings.Join(exprs, ", ") + " FROM " + table + " WHERE ROWNUM <= :1", []any{rows}
}

func (oraDialect) beginSample(ctx context.Context, db *sql.DB) (*sql.Tx, error) {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	if _, err := tx.ExecContext(ctx, "SET TRANSACTION READ ONLY"); err != nil {
		_ = tx.Rollback()
		return nil, err
	}
	return tx, nil
}

func openOracle(ctx context.Context, t Target) (Conn, error) {
	secs := strconv.Itoa(max(1, int(t.Timeout.Seconds())))
	opts := map[string]string{"CONNECTION TIMEOUT": secs, "TIMEOUT": secs}
	service := t.ServiceName
	if t.SID != "" && service == "" {
		opts["SID"] = t.SID
	} else if service == "" {
		service = t.Database
	}
	var tlsOn *bool
	switch t.TLS.Mode {
	case config.DBTLSDisable, "":
		off := false
		tlsOn = &off
	case config.DBTLSPrefer, config.DBTLSRequire:
		opts["SSL"] = "true"
		opts["SSL VERIFY"] = "false"
		on := true
		tlsOn = &on
	default:
		opts["SSL"] = "true"
		opts["SSL VERIFY"] = "true"
		on := true
		tlsOn = &on
	}
	dsn := go_ora.BuildUrl(t.Host, t.Port, service, t.Username, t.Password.Reveal(), opts)
	connector, ok := go_ora.NewConnector(dsn).(*go_ora.OracleConnector)
	if !ok {
		return nil, &Error{Kind: KindConfig, Op: "config", Safe: true}
	}
	if opts["SSL VERIFY"] == "true" {
		tlsCfg, err := t.TLS.TLSConfig(t.Host)
		if err != nil {
			return nil, err
		}
		connector.WithTLSConfig(tlsCfg)
	}
	if t.Dial != nil {
		connector.Dialer(ctxDialer{t.Dial})
	}
	return newSQLConn(ctx, sql.OpenDB(connector), oraDialect{}, t, tlsOn)
}
