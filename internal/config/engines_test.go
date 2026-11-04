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
