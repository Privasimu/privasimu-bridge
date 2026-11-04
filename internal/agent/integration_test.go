//go:build integration

package agent

// Mode B end to end against real databases (internal/testutil/itenv lists the variables):
// the agent runs test_source and scan_database jobs of the in-memory platform against a
// real server with sampling on, and nothing it sends may hold a fixture value or the
// password.

import (
	"bytes"
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/privasimu/bridge/internal/config"
	"github.com/privasimu/bridge/internal/testutil/itenv"
)

func TestJobsAgainstRealDatabases(t *testing.T) {
	for _, engine := range config.Engines {
		t.Run(engine, func(t *testing.T) {
			s, ok := itenv.Lookup(engine)
			if !ok {
				t.Skipf("BRIDGE_IT_%s_HOST is not set", strings.ToUpper(engine))
			}
			e := newEnv(t, func(c *config.Config) {
				port := s.Port
				if port == 0 {
					port = config.DefaultPort(engine)
				}
				tlsMode := s.TLS
				if tlsMode == "" {
					tlsMode = config.DBTLSPrefer
					if engine == "oracle" || engine == "mongodb" {
						tlsMode = config.DBTLSDisable
					}
				}
				on := true
				src := config.SourceConfig{ID: "real", Label: "Real " + engine, Engine: engine, Host: s.Host, Port: port,
					Database: s.Database, Username: s.User, Password: config.SecretRef("env:" + itenv.PasswordEnv(engine)),
					ServiceName: s.Service, TLS: config.SourceTLS{Mode: tlsMode, CAFile: s.CAFile, ServerName: s.ServerName},
					Sampling: &config.SamplingOptions{Enabled: &on, Rows: 50}, Timeout: config.Duration(20 * time.Second)}
				if s.Schema != "" {
					src.Schemas = []string{s.Schema}
				}
				c.Sources = []config.SourceConfig{src}
			})
			e.enroll()
			if !slices.Contains(config.ProtocolEngines, engine) {
				e.fp.setFeatures([]string{FeatureSourceEnginePrefix + engine}) // a platform of revision 4
			}
			e.fp.enqueue(Job{JobID: "job-test", Type: JobTestSource, SourceID: "real"})
			e.fp.enqueue(Job{JobID: "job-scan", Type: JobScanDatabase, SourceID: "real"})
			a, err := New(Deps{Config: e.cfg, Client: e.client, Resolver: e.resolver, Files: e.files, Log: testLogger()})
			if err != nil {
				t.Fatal(err)
			}
			a.sleep = func(ctx context.Context, d time.Duration) bool { return sleepCtx(ctx, 20*time.Millisecond) }
			both := func() bool { return e.finished("job-test")() && e.finished("job-scan")() }
			if !e.run(a, 2*time.Minute, both) {
				t.Fatal("the jobs did not finish")
			}
			for _, id := range []string{"job-test", "job-scan"} {
				if j := e.fp.job(id); j.completed == nil {
					t.Fatalf("%s failed: %+v", id, j.failed)
				}
			}
			raw, _ := json.Marshal(e.fp.job("job-test").completed.Result)
			var tr TestResult
			_ = json.Unmarshal(raw, &tr)
			if !tr.Success || tr.TablesFound == nil || *tr.TablesFound < 1 || tr.ServerVersion == nil {
				t.Fatalf("test_source: %s", raw)
			}
			t.Logf("test_source: %s", raw)
			var customers *TableItem
			for _, it := range e.fp.items("job-scan") {
				var ti TableItem
				if err := json.Unmarshal(it, &ti); err != nil {
					t.Fatal(err)
				}
				if strings.EqualFold(ti.Name, "customers") {
					customers = &ti
				}
			}
			if customers == nil {
				t.Skip("fixture table customers not found; load internal/dbsource/testdata/integration first")
			}
			cols := map[string]ColumnItem{}
			for _, c := range customers.Columns {
				cols[strings.ToLower(c.Name)] = c
			}
			if c := cols["nik"]; !c.PII || c.Category != "nik" || c.Detection != "name+content" || c.Content == nil || c.Content.Matching != 5 {
				t.Fatalf("nik: %+v", c)
			}
			if c := cols["notes"]; !c.PII || c.Category != "phone" || !c.Shadow || c.ProtectionState != "plaintext" {
				t.Fatalf("notes: %+v", c)
			}
			body := e.fp.allBodies()
			for _, v := range append(itenv.FixtureValues, s.Password) {
				if v != "" && bytes.Contains(body, []byte(v)) {
					t.Fatal("a value or the password reached the platform")
				}
			}
		})
	}
}
