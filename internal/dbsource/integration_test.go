//go:build integration

package dbsource_test

// Integration tests against real databases. They run only with the build tag and only for
// the engines whose environment variables are set, for example:
//
//	BRIDGE_IT_POSTGRESQL_HOST=127.0.0.1 BRIDGE_IT_POSTGRESQL_DB=bridge_it \
//	BRIDGE_IT_POSTGRESQL_USER=bridge_ro BRIDGE_IT_POSTGRESQL_PASSWORD=... \
//	go test -tags integration ./internal/dbsource/
//
// Engines: POSTGRESQL, MYSQL, MSSQL, ORACLE, MONGODB. Optional per engine: _PORT, _SCHEMA,
// _TLS (disable|prefer|require|verify-full), _SERVICE (Oracle). Load
// testdata/integration/<engine>.sql (or mongodb.js) first: it creates a "customers" table
// with synthetic values, and the test checks that its NIK column is found by sampling.

import (
	"context"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/privasimu/bridge/internal/config"
	"github.com/privasimu/bridge/internal/dbsource"
	"github.com/privasimu/bridge/internal/detect"
	"github.com/privasimu/bridge/internal/scan"
	"github.com/privasimu/bridge/internal/secrets"
)

func targetFromEnv(t *testing.T, engine string) dbsource.Target {
	prefix := "BRIDGE_IT_" + strings.ToUpper(engine) + "_"
	get := func(k string) string { return os.Getenv(prefix + k) }
	if get("HOST") == "" {
		t.Skipf("%sHOST is not set", prefix)
	}
	port, _ := strconv.Atoi(get("PORT"))
	if port == 0 {
		port = config.DefaultPort(engine)
	}
	tlsMode := get("TLS")
	if tlsMode == "" {
		tlsMode = config.DBTLSPrefer
		if engine == "oracle" || engine == "mongodb" {
			tlsMode = config.DBTLSDisable
		}
	}
	var schemas []string
	if s := get("SCHEMA"); s != "" {
		schemas = []string{s}
	}
	return dbsource.Target{Engine: engine, Host: get("HOST"), Port: port, Database: get("DB"), Username: get("USER"),
		Password: secrets.Value(get("PASSWORD")), ServiceName: get("SERVICE"), Schemas: schemas,
		TLS: dbsource.TLSSettings{Mode: tlsMode}, Timeout: 20 * time.Second}
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
			t.Logf("connected: %s, default schema %q", conn.ServerVersion(ctx), conn.DefaultSchema())
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
