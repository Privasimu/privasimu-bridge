//go:build integration

package dbsource

// Session checks against real servers: the bridge's sessions are read-only and bounded on
// the server itself, whatever the account may do. Set BRIDGE_IT_<ENGINE>_WRITER_USER and
// _WRITER_PASSWORD to an account that may write to the fixture table to show that the
// session refuses the write anyway.

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/go-sql-driver/mysql"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/privasimu/bridge/internal/config"
	"github.com/privasimu/bridge/internal/secrets"
	"github.com/privasimu/bridge/internal/testutil/itenv"
)

// sessionTimeout is the statement timeout of the probe sessions.
const sessionTimeout = 2 * time.Second

func TestSessionsAreReadOnlyAndBounded(t *testing.T) {
	for _, engine := range []string{"postgresql", "mysql"} {
		t.Run(engine, func(t *testing.T) {
			s, ok := itenv.Lookup(engine)
			if !ok {
				t.Skipf("BRIDGE_IT_%s_HOST is not set", strings.ToUpper(engine))
			}
			user, password, writer := s.User, s.Password, s.WriterUser != ""
			if writer {
				user, password = s.WriterUser, s.WriterPassword
			}
			port := s.Port
			if port == 0 {
				port = config.DefaultPort(engine)
			}
			tlsMode := s.TLS
			if tlsMode == "" {
				tlsMode = config.DBTLSPrefer
			}
			conn, err := Open(context.Background(), Target{Engine: engine, Host: s.Host, Port: port, Database: s.Database,
				Username: user, Password: secrets.Value(password), Timeout: sessionTimeout,
				TLS: TLSSettings{Mode: tlsMode, CAFile: s.CAFile, ServerName: s.ServerName}})
			if err != nil {
				t.Fatalf("open: %v", err)
			}
			defer conn.Close()
			c, ok := conn.(*sqlConn)
			if !ok {
				t.Fatalf("unexpected connection type %T", conn)
			}
			if engine == "postgresql" {
				checkPostgresSession(t, c, writer)
			} else {
				checkMySQLSession(t, c, writer)
			}
		})
	}
}

func checkPostgresSession(t *testing.T, c *sqlConn, writer bool) {
	ctx := context.Background()
	for name, want := range map[string]string{"default_transaction_read_only": "on", "statement_timeout": "2s",
		"lock_timeout": "5s", "application_name": "privasimu-bridge"} {
		var got string
		if err := c.db.QueryRowContext(ctx, "SELECT current_setting($1)", name).Scan(&got); err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Errorf("%s = %q, want %q", name, got, want)
		}
	}
	// The session refuses a write as read-only (SQLSTATE 25006) before any privilege check:
	// even CREATE TEMP TABLE, which every account may run, is refused.
	stmt := "CREATE TEMP TABLE bridge_it_probe (x integer)"
	if writer {
		stmt = "INSERT INTO customers (id) VALUES (999999)"
	}
	_, err := c.db.ExecContext(ctx, stmt)
	var pg *pgconn.PgError
	if !errors.As(err, &pg) || pg.Code != "25006" {
		t.Fatalf("%s: %v, want a read-only refusal (25006)", stmt, err)
	}
	checkServerStops(t, c, "SELECT pg_sleep(5)")
}

func checkMySQLSession(t *testing.T, c *sqlConn, writer bool) {
	ctx := context.Background()
	var version string
	if err := c.db.QueryRowContext(ctx, "SELECT VERSION()").Scan(&version); err != nil {
		t.Fatal(err)
	}
	mariadb := strings.Contains(strings.ToLower(version), "mariadb")
	readOnly, limit, want := "@@session.transaction_read_only", "@@session.max_execution_time", "2000"
	if mariadb {
		readOnly, limit, want = "@@session.tx_read_only", "@@session.max_statement_time", "2.000000"
	}
	var ro, lockWait int
	var got string
	if err := c.db.QueryRowContext(ctx, "SELECT "+readOnly+", @@session.lock_wait_timeout, CAST("+limit+" AS CHAR)").Scan(&ro, &lockWait, &got); err != nil {
		t.Fatal(err)
	}
	if ro != 1 || lockWait != 5 || got != want {
		t.Fatalf("%s: read only %d, lock_wait_timeout %d, %s %q (want 1, 5, %q)", version, ro, lockWait, limit, got, want)
	}
	if writer {
		_, err := c.db.ExecContext(ctx, "INSERT INTO customers (id) VALUES (999999)")
		var me *mysql.MySQLError
		if !errors.As(err, &me) || me.Number != 1792 {
			t.Fatalf("a write in the bridge's session: %v, want a read-only refusal (1792)", err)
		}
	} else {
		t.Log("BRIDGE_IT_MYSQL_WRITER_USER is not set: the write refusal is not checked")
	}
	// SLEEP inside a derived table, so that an interrupted statement reports an error
	// instead of SLEEP returning 1.
	checkServerStops(t, c, "SELECT s FROM (SELECT SLEEP(5) AS s) AS probe")
}

// checkServerStops runs a statement that takes 5 seconds with a client deadline of 20
// seconds: the server's own statement limit (2 seconds) must stop it, as timeout.
func checkServerStops(t *testing.T, c *sqlConn, query string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	started := time.Now()
	var v sql.NullString
	err := c.db.QueryRowContext(ctx, query).Scan(&v)
	elapsed := time.Since(started)
	if elapsed >= 4*time.Second {
		t.Fatalf("the server did not stop the statement (%s)", elapsed)
	}
	if err == nil {
		t.Fatalf("an interrupted statement must fail, got %q after %s", v.String, elapsed)
	}
	if k := KindOf(wrap("probe", err, true)); k != KindTimeout {
		t.Fatalf("kind %s (%v), want timeout", k, err)
	}
	t.Logf("the server stopped the statement after %s", elapsed.Round(10*time.Millisecond))
}
