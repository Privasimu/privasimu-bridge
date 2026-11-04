package server

import (
	"bytes"
	"net/http"
	"testing"
	"time"

	"github.com/privasimu/bridge/internal/config"
)

// The engines beyond the platform's registry (Redshift, ClickHouse) are served from a
// configured source only: with request credentials they are refused, so their credentials
// always stay on the bridge.
func TestFurtherEnginesNeedALocalSource(t *testing.T) {
	h := newHarness(t, func(c *config.Config) {
		c.Sources = append(c.Sources, config.SourceConfig{ID: "events", Label: "Events", Engine: "clickhouse", Host: "ch.internal",
			Port: 8123, Database: "events", Username: "ro", Password: "secret:corebank_pg",
			TLS: config.SourceTLS{Mode: config.DBTLSDisable}, Timeout: config.Duration(20 * time.Second),
			Match: config.SourceMatch{Host: "events"}})
	})
	h.db.Engine = "clickhouse"
	resp, body := h.post(PathTableNames, h.body(map[string]any{"db_type": "clickhouse", "host": "events", "database": "events"}), nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("a configured ClickHouse source: %d %s", resp.StatusCode, body)
	}
	if got := h.db.LastTarget(); got.Engine != "clickhouse" || got.Host != "ch.internal" || got.Password.Reveal() != localPassword {
		t.Fatalf("the local source must be used: %s %s", got.Engine, got.Host)
	}

	r := newHarness(t, func(c *config.Config) {
		c.Server.Credentials = config.CredentialsRequest
		c.Server.AllowedTargets = []string{"10.10.0.0/16"}
	})
	for _, dbType := range []string{"clickhouse", "redshift"} {
		resp, body := r.post(PathTableNames, r.body(map[string]any{"db_type": dbType, "host": "10.10.1.20"}), nil)
		if resp.StatusCode != http.StatusBadRequest || !bytes.Contains(body, []byte(CodeUnsupportedDBType)) {
			t.Fatalf("%s with request credentials: %d %s", dbType, resp.StatusCode, body)
		}
	}
	if len(r.db.Opened) != 0 {
		t.Fatal("nothing may be opened with request credentials for these engines")
	}
}
