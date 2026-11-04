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

func TestNLPEndpointMustBeLocalOrPrivate(t *testing.T) {
	for endpoint, ok := range map[string]bool{
		"http://127.0.0.1:8333/":                true,
		"http://localhost:8333/":                true, // a name is checked when connecting
		"https://nlp.internal.example.co.id/v1": true,
		"http://10.20.0.5:8333/":                true,
		"http://[::1]:8333/":                    true,
		"http://203.0.113.10:8333/":             false,
		"http://169.254.169.254/":               false,
		"ftp://127.0.0.1/":                      false,
		"http://user:pass@127.0.0.1/":           false,
		"http://127.0.0.1/?token=x":             false,
		"":                                      false,
	} {
		c, err := Parse([]byte("detection:\n  nlp: {enabled: true, endpoint: \"" + endpoint + "\"}\n"))
		if err != nil {
			t.Fatal(err)
		}
		if err := c.Validate(); (err == nil) != ok {
			t.Errorf("%q: accepted %v, want %v (%v)", endpoint, err == nil, ok, err)
		}
	}
	c, _ := Parse([]byte("detection:\n  nlp: {enabled: true, endpoint: \"http://127.0.0.1:8333/\", timeout: 5m}\n"))
	if err := c.Validate(); err == nil {
		t.Error("a timeout of 5 minutes must be refused")
	}
	c, _ = Parse([]byte("{}"))
	if n := c.Detection.NLP; n.Enabled || n.MinChars != 200 || n.MaxBytes != 32<<10 || n.MinScore != 0.8 || n.Concurrency != 2 {
		t.Errorf("defaults: %+v", n)
	}
}

func TestAccessInventoryEngines(t *testing.T) {
	for engine, ok := range map[string]bool{"postgresql": true, "mysql": true, "mariadb": true, "mssql": false, "oracle": false} {
		c, err := Parse([]byte("sources:\n  - {id: x, engine: " + engine + ", host: h, database: d, username: u, password: \"secret:p\", access_inventory: true}\n"))
		if err != nil {
			t.Fatal(err)
		}
		if err := c.Validate(); (err == nil) != ok {
			t.Errorf("%s: accepted %v, want %v (%v)", engine, err == nil, ok, err)
		}
	}
}

func TestAccessInventoryRoleNames(t *testing.T) {
	source := "sources:\n  - {id: x, engine: mysql, host: h, database: d, username: u, password: \"secret:p\", access_inventory: true}\n"
	for block, want := range map[string]string{"": RoleNamesHashed, "access_inventory: {role_names: hashed}\n": RoleNamesHashed,
		"access_inventory: {role_names: plain}\n": RoleNamesPlain, "access_inventory: {role_names: names}\n": ""} {
		c, err := Parse([]byte(block + source))
		if err != nil {
			t.Fatal(err)
		}
		err = c.Validate()
		if want == "" {
			if err == nil || !strings.Contains(err.Error(), "access_inventory.role_names") {
				t.Errorf("%q: %v", block, err)
			}
			continue
		}
		if err != nil || c.AccessInventory.RoleNames != want || !c.UsesAccessInventory() {
			t.Errorf("%q: %q %v", block, c.AccessInventory.RoleNames, err)
		}
	}
}
