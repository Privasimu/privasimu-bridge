package config

import (
	"strings"
	"testing"
)

func TestEngineDefaults(t *testing.T) {
	c, err := Parse([]byte(`
sources:
  - {id: dwh, engine: redshift, host: dwh.example.redshift.amazonaws.com, database: dev, username: ro, password: "secret:rs"}
  - {id: events, engine: clickhouse, host: ch.internal, database: events, username: ro, password: "secret:ch"}
  - {id: events-tls, engine: clickhouse, host: ch.internal, database: events, username: ro, password: "secret:ch", tls: {mode: verify-full}}
  - {id: events-port, engine: clickhouse, host: ch.internal, port: 9443, database: events, username: ro, password: "secret:ch", tls: {mode: require}}
`))
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	want := map[string]struct {
		port int
		tls  string
	}{
		"dwh":         {5439, DBTLSPrefer},
		"events":      {8123, DBTLSDisable},
		"events-tls":  {ClickHouseTLSPort, DBTLSVerifyFull},
		"events-port": {9443, DBTLSRequire},
	}
	for id, w := range want {
		s, _ := c.Source(id)
		if s.Port != w.port || s.TLS.Mode != w.tls {
			t.Errorf("%s: port %d tls %s, want %d %s", id, s.Port, s.TLS.Mode, w.port, w.tls)
		}
	}
}

func TestNewEnginesNeedADatabase(t *testing.T) {
	for _, engine := range []string{"redshift", "clickhouse"} {
		c, err := Parse([]byte("sources:\n  - {id: x, engine: " + engine + ", host: db.internal, username: ro, password: \"secret:x\"}\n"))
		if err != nil {
			t.Fatal(err)
		}
		err = c.Validate()
		if err == nil || !strings.Contains(err.Error(), "sources[0].database") {
			t.Errorf("%s without a database: %v", engine, err)
		}
	}
}

func TestProtocolEnginesAreKnownEngines(t *testing.T) {
	for _, e := range ProtocolEngines {
		if !knownEngine(e) {
			t.Errorf("%s is a protocol engine but not a known engine", e)
		}
	}
}

func TestCloudEngineValidation(t *testing.T) {
	valid := `
sources:
  - {id: sf, engine: snowflake, host: myorg-myaccount, database: corebank, username: privasimu_ro, private_key: "secret:sf_key", warehouse: scan_wh, role: privasimu_reader}
  - {id: sf-pat, engine: snowflake, host: myorg-myaccount, database: corebank, username: privasimu_ro, password: "secret:sf_pat"}
  - {id: bq, engine: bigquery, database: my-project, schemas: [crm], credentials: "secret:bq_key"}
  - {id: dbx, engine: databricks, host: adb-123.4.azuredatabricks.net, database: main, warehouse: /sql/1.0/warehouses/abc123, password: "secret:dbx"}
  - {id: ath, engine: athena, region: ap-southeast-3, username: AKIAPLACEHOLDER00001, password: "secret:aws", session_token: "env:AWS_SESSION_TOKEN"}
`
	c, err := Parse([]byte(valid))
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, s := range c.Sources {
		if s.TLS.Mode != DBTLSVerifyFull || s.Port != 443 {
			t.Errorf("%s: a cloud source is reached on 443 with verify-full, got %d %s", s.ID, s.Port, s.TLS.Mode)
		}
	}
	on := true
	ath, _ := c.Source("ath")
	c.Detection.Sampling.Enabled = &on
	if c.SamplingFor(ath).On() {
		t.Error("Athena is never sampled, even when sampling is on globally")
	}
	bad := map[string]string{
		"tls":            "{id: x, engine: snowflake, host: a, database: d, username: u, password: \"secret:p\", tls: {mode: require}}",
		"snowflake auth": "{id: x, engine: snowflake, host: a, database: d, username: u, password: \"secret:p\", private_key: \"secret:k\"}",
		"no auth":        "{id: x, engine: snowflake, host: a, database: d, username: u}",
		"project":        "{id: x, engine: bigquery, database: My_Project, credentials: \"secret:k\"}",
		"no key":         "{id: x, engine: bigquery, database: my-project}",
		"warehouse":      "{id: x, engine: databricks, host: h, database: main, warehouse: \"../x\", password: \"secret:t\"}",
		"region":         "{id: x, engine: athena, region: jakarta, username: AKIAPLACEHOLDER00001, password: \"secret:s\"}",
		"athena sample":  "{id: x, engine: athena, region: ap-southeast-3, username: AKIAPLACEHOLDER00001, password: \"secret:s\", sampling: {enabled: true}}",
		"literal key":    "{id: x, engine: snowflake, host: a, database: d, username: u, private_key: \"-----BEGIN PRIVATE KEY-----\"}",
		"field":          "{id: x, engine: postgresql, host: h, database: d, username: u, password: \"secret:p\", warehouse: w}",
		"role elsewhere": "{id: x, engine: databricks, host: h, database: main, warehouse: abc, password: \"secret:t\", role: r}",
	}
	for name, src := range bad {
		c, err := Parse([]byte("sources:\n  - " + src + "\n"))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if err := c.Validate(); err == nil {
			t.Errorf("%s must be refused", name)
		}
	}
}
