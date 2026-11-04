package dbsource

import (
	"context"
	"database/sql/driver"
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/go-sql-driver/mysql"
)

// sessionConn is a driver connection that records the statements a session runs.
type sessionConn struct {
	version   string
	failLimit error
	stmts     []string
}

func (c *sessionConn) Prepare(string) (driver.Stmt, error) { return nil, errors.New("not used") }
func (c *sessionConn) Close() error                        { return nil }
func (c *sessionConn) Begin() (driver.Tx, error)           { return nil, errors.New("not used") }

func (c *sessionConn) ExecContext(_ context.Context, query string, _ []driver.NamedValue) (driver.Result, error) {
	c.stmts = append(c.stmts, query)
	if c.failLimit != nil && strings.HasPrefix(query, "SET SESSION max_") {
		return nil, c.failLimit
	}
	return driver.RowsAffected(0), nil
}

func (c *sessionConn) QueryContext(context.Context, string, []driver.NamedValue) (driver.Rows, error) {
	return &oneRow{value: c.version}, nil
}

type oneRow struct {
	value string
	done  bool
}

func (r *oneRow) Columns() []string { return []string{"VERSION()"} }
func (r *oneRow) Close() error      { return nil }
func (r *oneRow) Next(dest []driver.Value) error {
	if r.done {
		return io.EOF
	}
	r.done = true
	dest[0] = []byte(r.value)
	return nil
}

func TestMySQLSessionsAreReadOnlyAndBounded(t *testing.T) {
	cases := []struct {
		version string
		limit   string
	}{
		{"8.4.3", "SET SESSION max_execution_time = 20000"},
		{"8.0.36-0ubuntu0.22.04.1", "SET SESSION max_execution_time = 20000"},
		{"11.8.9-MariaDB", "SET SESSION max_statement_time = 20.000"},
		{"10.6.12-MariaDB-0ubuntu0.22.04.1-log", "SET SESSION max_statement_time = 20.000"},
	}
	for _, c := range cases {
		conn := &sessionConn{version: c.version}
		if err := prepareMySQLSession(context.Background(), conn, 20*time.Second); err != nil {
			t.Fatalf("%s: %v", c.version, err)
		}
		want := []string{"SET SESSION TRANSACTION READ ONLY", "SET SESSION lock_wait_timeout = 5", c.limit}
		if !reflect.DeepEqual(conn.stmts, want) {
			t.Errorf("%s: %q, want %q", c.version, conn.stmts, want)
		}
	}
}

func TestMySQLSessionWithoutAStatementLimit(t *testing.T) {
	// A server without the variable (before MySQL 5.7.8 or MariaDB 10.1) keeps the
	// client-side timeout; the read-only statement is never optional.
	old := &sessionConn{version: "5.6.51", failLimit: &mysql.MySQLError{Number: errUnknownVariable}}
	if err := prepareMySQLSession(context.Background(), old, time.Second); err != nil {
		t.Fatalf("an unknown variable must not fail the session: %v", err)
	}
	denied := &sessionConn{version: "8.4.3", failLimit: &mysql.MySQLError{Number: 1227}}
	if err := prepareMySQLSession(context.Background(), denied, time.Second); err == nil {
		t.Fatal("any other failure of the session statements fails the connection")
	}
}

func TestMySQLVersionLabel(t *testing.T) {
	for in, want := range map[string]string{
		"11.8.9-MariaDB":                       "MariaDB 11.8.9",
		"10.6.12-MariaDB-0ubuntu0.22.04.1-log": "MariaDB 10.6.12",
		"8.0.36-0ubuntu0.22.04.1":              "MySQL 8.0.36",
		"8.4.3":                                "MySQL 8.4.3",
		"":                                     "MySQL",
	} {
		if got := mysqlVersionLabel(in); got != want {
			t.Errorf("%q: %q, want %q", in, got, want)
		}
	}
}

// failingConnector stands in for the driver's connector.
type failingConnector struct{ conn *sessionConn }

func (f failingConnector) Connect(context.Context) (driver.Conn, error) { return f.conn, nil }
func (f failingConnector) Driver() driver.Driver                        { return nil }

func TestMySQLSessionConnectorClosesAConnectionItCannotPrepare(t *testing.T) {
	conn := &sessionConn{version: "8.4.3", failLimit: &mysql.MySQLError{Number: 1227}}
	c := mysqlSessionConnector{Connector: failingConnector{conn}, timeout: time.Second}
	if got, err := c.Connect(context.Background()); err == nil || got != nil {
		t.Fatalf("got %v, %v", got, err)
	}
}
