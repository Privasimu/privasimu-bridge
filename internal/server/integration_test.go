//go:build integration

package server

// Mode A end to end against real databases (internal/testutil/itenv lists the variables):
// both platform clients test and scan a configured source through the HTTPS server with
// local credentials and sampling on, and no fixture value may appear in any response.

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/privasimu/bridge/internal/config"
	"github.com/privasimu/bridge/internal/dbsource"
	"github.com/privasimu/bridge/internal/testutil/itenv"
)

// itSource is a configured source for real database settings, matched by an alias.
func itSource(s itenv.Settings, id, alias string, password config.SecretRef) config.SourceConfig {
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
	on := true
	src := config.SourceConfig{ID: id, Label: id, Engine: s.Engine, Host: s.Host, Port: port, Database: s.Database,
		Username: s.User, Password: password, ServiceName: s.Service,
		TLS:      config.SourceTLS{Mode: tlsMode, CAFile: s.CAFile, ServerName: s.ServerName},
		Sampling: &config.SamplingOptions{Enabled: &on, Rows: 50}, Match: config.SourceMatch{Host: alias, Database: alias},
		Timeout: config.Duration(20 * time.Second)}
	if s.Schema != "" {
		src.Schemas = []string{s.Schema}
	}
	return src
}

func TestModeAAgainstRealDatabases(t *testing.T) {
	for _, engine := range []string{"postgresql", "mysql", "mssql", "oracle"} {
		t.Run(engine, func(t *testing.T) {
			s, ok := itenv.Lookup(engine)
			if !ok {
				t.Skipf("BRIDGE_IT_%s_HOST is not set", strings.ToUpper(engine))
			}
			t.Setenv("BRIDGE_IT_WRONG_PASSWORD", "not-the-password")
			h := newHarness(t, func(c *config.Config) {
				c.Sources = []config.SourceConfig{
					itSource(s, "real", "corebank", config.SecretRef("env:"+itenv.PasswordEnv(engine))),
					itSource(s, "wrong-password", "corebank-wrong", "env:BRIDGE_IT_WRONG_PASSWORD"),
				}
			})
			h.srv.pool.Open = dbsource.Open
			source := h.source()
			if engine == "oracle" {
				source["service_name"] = "corebank"
			}
			ctx := context.Background()
			for _, line := range []string{lineGo, lineLaravel} {
				pc := h.pc.forLine(line)
				res := pc.Test(ctx, h.ts.URL, h.key, engine, source)
				if !res.Success || res.TablesFound < 1 {
					t.Fatalf("%s test: %+v", line, res)
				}
				out := pc.Scan(ctx, h.ts.URL, h.key, engine, source)
				if out.Kind != "" || len(out.Failed) != 0 {
					t.Fatalf("%s scan: kind %q, failed %+v", line, out.Kind, out.Failed)
				}
				var customers *pcTable
				for i := range out.Tables {
					if strings.EqualFold(out.Tables[i].Name, "customers") {
						customers = &out.Tables[i]
					}
				}
				if customers == nil {
					t.Skip("fixture table customers not found; load internal/dbsource/testdata/integration first")
				}
				cols := map[string]pcColumn{}
				for _, c := range customers.Columns {
					cols[strings.ToLower(*c.ColumnName)] = c
				}
				if c := cols["nik"]; c.IsPII == nil || !*c.IsPII || c.PDPCategory == nil || *c.PDPCategory != "spesifik" {
					t.Fatalf("%s nik: %+v", line, c)
				}
				if c := cols["notes"]; c.IsPII == nil || !*c.IsPII {
					t.Fatalf("%s notes must be personal data by content: %+v", line, c)
				}
			}
			// The raw answers: names and counts, never a value.
			var raw bytes.Buffer
			resp, body := h.post(PathTableNames, h.body(map[string]any{"db_type": engine}), nil)
			raw.Write(body)
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("table list: %d %s", resp.StatusCode, body)
			}
			var names namesResponse
			_ = json.Unmarshal(body, &names)
			table := "customers"
			for _, n := range names.Results {
				if strings.EqualFold(n, "customers") {
					table = n
				}
			}
			resp, body = h.post(PathTableColumns, h.body(map[string]any{"db_type": engine, "table_name": table}), nil)
			raw.Write(body)
			var cols columnsResponse
			if err := json.Unmarshal(body, &cols); err != nil || resp.StatusCode != http.StatusOK || !cols.AnalysisSummary.Sampled {
				t.Fatalf("columns: %d %s", resp.StatusCode, body)
			}
			for _, v := range append(itenv.FixtureValues, s.Password) {
				if v != "" && bytes.Contains(raw.Bytes(), []byte(v)) {
					t.Fatalf("a value or setting appeared in a response")
				}
			}
			// The bridge's own password is wrong: 422 database_auth_failed, which the
			// platform never retries.
			resp, body = h.post(PathTableNames, h.body(map[string]any{"db_type": engine, "host": "corebank-wrong", "database": "corebank-wrong"}), nil)
			if resp.StatusCode != http.StatusUnprocessableEntity || !bytes.Contains(body, []byte(`"code":"`+CodeDBAuth+`"`)) {
				t.Fatalf("wrong password: %d %s", resp.StatusCode, body)
			}
		})
	}
}
