//go:build integration

package dbsource_test

// Integration tests against real databases. They run only with the build tag and only for
// the engines whose environment variables are set (internal/testutil/itenv lists them),
// for example:
//
//	BRIDGE_IT_POSTGRESQL_HOST=127.0.0.1 BRIDGE_IT_POSTGRESQL_DB=bridge_it \
//	BRIDGE_IT_POSTGRESQL_USER=bridge_ro BRIDGE_IT_POSTGRESQL_PASSWORD=... \
//	go test -tags integration ./internal/...
//
// Load testdata/integration/<engine>.sql (or mongodb.js) first: it creates a "customers"
// table with synthetic values, and the tests check that its NIK column is found by
// sampling and that no value reaches the platform.

import (
	"context"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/privasimu/bridge/internal/config"
	"github.com/privasimu/bridge/internal/dbsource"
	"github.com/privasimu/bridge/internal/detect"
	"github.com/privasimu/bridge/internal/scan"
	"github.com/privasimu/bridge/internal/secrets"
	"github.com/privasimu/bridge/internal/testutil/itenv"
)

func targetFromEnv(t *testing.T, engine string) dbsource.Target {
	t.Helper()
	s, ok := itenv.Lookup(engine)
	if !ok {
		t.Skipf("BRIDGE_IT_%s_HOST is not set", strings.ToUpper(engine))
	}
	return targetOf(t, s, s.User, s.Password)
}

func targetOf(t *testing.T, s itenv.Settings, user, password string) dbsource.Target {
	t.Helper()
	port := s.Port
	if port == 0 {
		port = config.DefaultPort(s.Engine)
	}
	tlsMode := s.TLS
	if tlsMode == "" {
		tlsMode = config.DBTLSPrefer
		if s.Engine == "oracle" || s.Engine == "mongodb" {
			tlsMode = config.DBTLSDisable
		}
	}
	var schemas []string
	if s.Schema != "" {
		schemas = []string{s.Schema}
	}
	return dbsource.Target{Engine: s.Engine, Host: s.Host, Port: port, Database: s.Database, Username: user,
		Password: secrets.Value(password), ServiceName: s.Service, Schemas: schemas,
		TLS:     dbsource.TLSSettings{Mode: tlsMode, CAFile: s.CAFile, ServerName: s.ServerName},
		Timeout: 20 * time.Second}
}

func TestEngines(t *testing.T) {
	for _, engine := range config.Engines {
		t.Run(engine, func(t *testing.T) {
			target := targetFromEnv(t, engine)
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			conn, err := dbsource.Open(ctx, target)
			if err != nil {
				t.Fatalf("open: %v", err)
			}
			defer conn.Close()
			t.Logf("connected: %s, default schema %q, TLS %v", conn.ServerVersion(ctx), conn.DefaultSchema(), deref(conn.TLSInUse()))
			tables, total, err := scan.ListTables(ctx, conn, scan.DBOptions{})
			if err != nil || total == 0 {
				t.Fatalf("list tables: %d %v", total, err)
			}
			var customers *dbsource.Table
			for i := range tables {
				if strings.EqualFold(tables[i].Name, "customers") {
					customers = &tables[i]
				}
			}
			if customers == nil {
				t.Skip("fixture table customers not found; load testdata/integration first")
			}
			found, ok, err := conn.FindTable(ctx, customers.Ref, "")
			if err != nil || !ok {
				t.Fatalf("find table %q: %v %v", customers.Ref, ok, err)
			}
			a, err := scan.AnalyzeTable(ctx, conn, found, scan.DBOptions{Sampling: true, Rows: 50,
				Thresholds: detect.DefaultThresholds})
			if err != nil {
				t.Fatalf("analyze: %v", err)
			}
			if !a.Sampled {
				t.Fatalf("sampling failed: %s", a.SamplingError)
			}
			var nik, notes *scan.ColumnAnalysis
			for i := range a.Columns {
				switch strings.ToLower(a.Columns[i].Name) {
				case "nik":
					nik = &a.Columns[i]
				case "notes", "keterangan":
					notes = &a.Columns[i]
				}
			}
			if nik == nil || nik.Finding.Category != detect.NIK || nik.Finding.Source != detect.SourceNameContent {
				t.Fatalf("nik column: %+v", nik)
			}
			if notes == nil || notes.Finding.Category != detect.Phone || !notes.Finding.Shadow {
				t.Fatalf("notes column must reveal phone numbers by content: %+v", notes)
			}
		})
	}
}

// TestEngineErrors checks that real servers' failures get the kinds the platform shows:
// a wrong password is auth (answered 422 and never retried, so retries cannot lock the
// account), a closed port is unreachable, and a certificate for another name is tls.
func TestEngineErrors(t *testing.T) {
	for _, engine := range []string{"postgresql", "mysql", "mssql", "oracle"} {
		t.Run(engine, func(t *testing.T) {
			s, ok := itenv.Lookup(engine)
			if !ok {
				t.Skipf("BRIDGE_IT_%s_HOST is not set", strings.ToUpper(engine))
			}
			ctx := context.Background()
			wrong := targetOf(t, s, s.User, "not-the-password")
			if _, err := dbsource.Open(ctx, wrong); dbsource.KindOf(err) != dbsource.KindAuth {
				t.Fatalf("wrong password: kind %s (%v)", dbsource.KindOf(err), err)
			}
			if engine != "oracle" {
				other := targetOf(t, s, s.User, s.Password)
				other.Database = "bridge_it_does_not_exist"
				// MySQL and MariaDB answer "access denied to database" for a database the
				// account may not see, so as not to reveal whether it exists.
				_, err := dbsource.Open(ctx, other)
				if k := dbsource.KindOf(err); k != dbsource.KindNotFound && k != dbsource.KindPermission {
					t.Fatalf("unknown database: kind %s (%v)", k, err)
				}
			}
			closed := targetOf(t, s, s.User, s.Password)
			closed.Host, closed.Port = "127.0.0.1", closedPort(t)
			closed.Timeout = 5 * time.Second
			if _, err := dbsource.Open(ctx, closed); dbsource.KindOf(err) != dbsource.KindUnreachable {
				t.Fatalf("closed port: kind %s (%v)", dbsource.KindOf(err), err)
			}
			if s.CAFile == "" {
				t.Log("BRIDGE_IT_*_CA_FILE is not set: the certificate checks are skipped")
				return
			}
			verified := targetOf(t, s, s.User, s.Password)
			verified.TLS.Mode = config.DBTLSVerifyFull
			conn, err := dbsource.Open(ctx, verified)
			if err != nil {
				t.Fatalf("verify-full with the CA: %v", err)
			}
			if on := conn.TLSInUse(); on == nil || !*on {
				t.Fatalf("verify-full must report TLS in use: %v", on)
			}
			_ = conn.Close()
			misnamed := verified
			misnamed.TLS.ServerName = "not-this-server.invalid"
			if _, err := dbsource.Open(ctx, misnamed); dbsource.KindOf(err) != dbsource.KindTLS {
				t.Fatalf("certificate for another name: kind %s (%v)", dbsource.KindOf(err), err)
			}
			if os.Getenv("BRIDGE_IT_SYSTEM_TRUSTS_CA") == "" {
				untrusted := verified
				untrusted.TLS.CAFile = ""
				if _, err := dbsource.Open(ctx, untrusted); dbsource.KindOf(err) != dbsource.KindTLS {
					t.Fatalf("certificate from an untrusted CA: kind %s (%v)", dbsource.KindOf(err), err)
				}
			}
		})
	}
}

// closedPort returns a loopback port nothing listens on.
func closedPort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	_ = l.Close()
	return port
}

func deref(b *bool) any {
	if b == nil {
		return "unknown"
	}
	return *b
}
