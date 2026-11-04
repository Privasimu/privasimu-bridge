package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/privasimu/bridge/internal/config"
)

// TestCheckWarnsAboutUnprotectedTransports: ClickHouse without a TLS mode (plain HTTP, the
// password in a header) and Redshift with its default prefer (no certificate check) are
// warned about, whether or not the source answers; the defaults themselves stay.
func TestCheckWarnsAboutUnprotectedTransports(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "bridge.yaml")
	src := ", host: 127.0.0.1, port: 1, username: ro, password: \"env:PRIVASIMU_BRIDGE_TEST_UNSET\""
	yaml := "sources:\n" +
		"  - {id: events, engine: clickhouse, database: events" + src + "}\n" +
		"  - {id: events-tls, engine: clickhouse, database: events, tls: {mode: verify-full}" + src + "}\n" +
		"  - {id: dwh, engine: redshift, database: dev" + src + "}\n" +
		"  - {id: dwh-verified, engine: redshift, database: dev, tls: {mode: verify-full}" + src + "}\n"
	if err := os.WriteFile(cfgPath, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	r := run(t, "", "--config", cfgPath, "check")
	for _, want := range []string{"[WARN] source events: ClickHouse is reached over plain HTTP", "X-ClickHouse-Key",
		"[WARN] source dwh: Redshift with tls.mode prefer does not verify"} {
		if !strings.Contains(r.stdout, want) {
			t.Errorf("check output lacks %q:\n%s", want, r.stdout)
		}
	}
	for _, unwanted := range []string{"source events-tls: ClickHouse", "source dwh-verified: Redshift"} {
		if strings.Contains(r.stdout, unwanted) {
			t.Errorf("verified TLS needs no warning (%q):\n%s", unwanted, r.stdout)
		}
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Sources[0].TLS.Mode != config.DBTLSDisable || cfg.Sources[2].TLS.Mode != config.DBTLSPrefer {
		t.Fatalf("the defaults are unchanged: %s %s", cfg.Sources[0].TLS.Mode, cfg.Sources[2].TLS.Mode)
	}
}
