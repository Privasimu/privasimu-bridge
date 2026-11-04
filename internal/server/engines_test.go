package server

import (
	"bytes"
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/privasimu/bridge/internal/config"
	"github.com/privasimu/bridge/internal/dbsource"
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

// Snowflake is in the platform's registry: a configured Snowflake source answers the
// platform's calls with its own key pair, never with the password typed in Privasimu.
func TestSnowflakeFromAConfiguredSource(t *testing.T) {
	h := newHarness(t, func(c *config.Config) {
		c.Sources = append(c.Sources, config.SourceConfig{ID: "dwh", Label: "DWH", Engine: "snowflake", Host: "myorg-myaccount",
			Port: 443, Database: "corebank", Username: "privasimu_ro", PrivateKey: "secret:corebank_pg", Warehouse: "scan_wh",
			TLS: config.SourceTLS{Mode: config.DBTLSVerifyFull}, Timeout: config.Duration(20 * time.Second),
			Match: config.SourceMatch{Host: "corebank"}})
	})
	h.db.Engine = "snowflake"
	if res := h.pc.Test(context.Background(), h.ts.URL, h.key, "snowflake", h.source()); !res.Success {
		t.Fatalf("%+v", res)
	}
	got := h.db.LastTarget()
	if got.Engine != "snowflake" || got.PrivateKey.Reveal() != localPassword || got.Password.Reveal() != "" || got.Warehouse != "scan_wh" {
		t.Fatalf("the configured source's own credentials must be used: %s %s", got.Engine, got.Warehouse)
	}
}

func TestTableAccessEndpoint(t *testing.T) {
	h := newHarness(t, func(c *config.Config) {
		c.Server.AccessEndpoint = true
		c.Sources[0].AccessInventory = true
	})
	h.db.Access = map[string]dbsource.Access{"users": {Readers: 4, Roles: []string{"crm_reader"}, RolesTotal: 1, Admins: 1, Complete: true}}
	resp, body := h.post(PathTableAccess, h.body(map[string]any{"table_name": "users"}), nil)
	if resp.StatusCode != http.StatusOK || !bytes.Contains(body, []byte(`"access":{"readers":4,"roles":["crm_reader"],"roles_total":1,"admins":1,"public":false,"complete":true}`)) {
		t.Fatalf("%d %s", resp.StatusCode, body)
	}
	if resp, _ := h.post(PathTableAccess, h.body(map[string]any{"table_name": "nope"}), nil); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("unknown table: %d", resp.StatusCode)
	}
	off := newHarness(t, nil)
	if resp, _ := off.post(PathTableAccess, off.body(map[string]any{"table_name": "users"}), nil); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("the endpoint is off by default: %d", resp.StatusCode)
	}
	notOptedIn := newHarness(t, func(c *config.Config) { c.Server.AccessEndpoint = true })
	if resp, _ := notOptedIn.post(PathTableAccess, notOptedIn.body(map[string]any{"table_name": "users"}), nil); resp.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("a source without access_inventory: %d", resp.StatusCode)
	}
}
