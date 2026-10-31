package server

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/privasimu/bridge/internal/apikey"
	"github.com/privasimu/bridge/internal/audit"
	"github.com/privasimu/bridge/internal/config"
	"github.com/privasimu/bridge/internal/dbsource"
	"github.com/privasimu/bridge/internal/secrets"
	"github.com/privasimu/bridge/internal/testutil/fakedb"
)

var update = flag.Bool("update", false, "rewrite the golden files")

// Placeholders only: no real credential appears in the tests.
const (
	localPassword    = "local-placeholder-password"
	platformPassword = "typed-in-privasimu-placeholder"
)

const baseYAML = `
language: en
server:
  listen: "127.0.0.1:0"
  tls: {mode: file, cert_file: cert.pem, key_file: key.pem}
  api_keys:
    - {id: placeholder, hash: "sha256:0000000000000000000000000000000000000000000000000000000000000000"}
sources:
  - id: core-banking
    engine: postgresql
    host: 10.10.1.20
    database: corebank
    username: privasimu_ro
    password: "secret:corebank_pg"
    match: {host: corebank}
  - id: crm
    engine: mysql
    host: crm.internal
    database: crm
    username: ro
    password: "secret:corebank_pg"
    schemas: [crm]
`

func sampleDB() *fakedb.DB {
	users := fakedb.Table{Schema: "public", Name: "users", Columns: []dbsource.Column{
		fakedb.Int("id"), fakedb.Text("email"), fakedb.Text("nama_lengkap"), fakedb.Text("kontak"), fakedb.Text("catatan"),
	}}
	for i := 0; i < 8; i++ {
		users.Rows = append(users.Rows, map[string]string{
			"email": "budi.contoh@example.co.id", "nama_lengkap": "Budi Contoh", "kontak": "0812-3456-7890",
			"catatan": "nasabah prioritas, NIK 3171012303900001",
		})
	}
	orders := fakedb.Table{Schema: "public", Name: "orders", Columns: []dbsource.Column{fakedb.Int("id"), fakedb.Int("total")}}
	logs := fakedb.Table{Schema: "audit", Name: "log", Columns: []dbsource.Column{fakedb.Int("id"), fakedb.Text("client_ip")}}
	return &fakedb.DB{Engine: "postgresql", Version: "PostgreSQL 16.4", Tables: []fakedb.Table{users, orders, logs}}
}

type harness struct {
	t         *testing.T
	cfg       *config.Config
	srv       *Server
	ts        *httptest.Server
	db        *fakedb.DB
	key       string
	keyID     string
	auditPath string
	pc        *platformClient

	mu       sync.Mutex
	received []received
}

// received is a request as the bridge saw it.
type received struct {
	header http.Header
	body   []byte
	proto  string
}

func (h *harness) record(r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	r.Body = io.NopCloser(bytes.NewReader(body))
	h.mu.Lock()
	h.received = append(h.received, received{header: r.Header.Clone(), body: body, proto: r.Proto})
	h.mu.Unlock()
}

func (h *harness) requests() []received {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]received(nil), h.received...)
}

func newHarness(t *testing.T, mutate func(*config.Config)) *harness {
	t.Helper()
	dir := t.TempDir()
	key, id, hash, err := apikey.Generate()
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Parse([]byte(baseYAML))
	if err != nil {
		t.Fatal(err)
	}
	cfg.SetPath(filepath.Join(dir, "bridge.yaml"))
	cfg.Server.APIKeys = []config.APIKey{{ID: id, Hash: hash}}
	if mutate != nil {
		mutate(cfg)
	}
	store, err := secrets.Open(filepath.Join(dir, "secrets.enc"), make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	_ = store.Set("corebank_pg", localPassword)
	db := sampleDB()
	pool := dbsource.NewPool(8, time.Minute)
	pool.Open = db.Opener()
	auditPath := filepath.Join(dir, "audit.jsonl")
	auditLog, err := audit.Open(auditPath, 10, 2)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = auditLog.Close() })
	s, err := New(Deps{Config: cfg, Resolver: secrets.NewResolverForStore(store), Pool: pool, Audit: auditLog,
		Log: slog.New(slog.DiscardHandler)})
	if err != nil {
		t.Fatal(err)
	}
	h := &harness{t: t, cfg: cfg, srv: s, db: db, key: key, keyID: id, auditPath: auditPath}
	ts := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.record(r)
		s.ServeHTTP(w, r)
	}))
	ts.Config.ErrorLog = log.New(io.Discard, "", 0)
	ts.StartTLS()
	t.Cleanup(ts.Close)
	client := ts.Client()
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	h.ts = ts
	h.pc = &platformClient{client: client, callTimeout: 5 * time.Second, deadline: 30 * time.Second,
		retryDelay: time.Millisecond, concurrency: 4, line: lineGo}
	return h
}

// source is the connection_config the platform stores for a bridge source.
func (h *harness) source() map[string]any {
	return map[string]any{
		"host": "corebank", "port": float64(5432), "database": "corebank", "username": "app_user",
		"password": platformPassword, "bridge_url": h.ts.URL, "bridge_api_key": h.key, "last_test": "x",
	}
}

func (h *harness) post(path string, body any, headers map[string]string) (*http.Response, []byte) {
	h.t.Helper()
	var r io.Reader
	switch b := body.(type) {
	case string:
		r = strings.NewReader(b)
	default:
		raw, _ := json.Marshal(b)
		r = bytes.NewReader(raw)
	}
	req, _ := http.NewRequest(http.MethodPost, h.ts.URL+path, r)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", h.key)
	req.Header.Set("X-Contract-Version", "1")
	for k, v := range headers {
		if v == "" {
			req.Header.Del(k)
		} else {
			req.Header.Set(k, v)
		}
	}
	resp, err := h.pc.client.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	return resp, data
}

func (h *harness) body(extra map[string]any) map[string]any {
	b := map[string]any{"db_type": "postgresql", "host": "corebank", "port": 5432, "database": "corebank",
		"user": "app_user", "password": platformPassword}
	for k, v := range extra {
		b[k] = v
	}
	return b
}

func (h *harness) auditEvents() []audit.Event {
	h.t.Helper()
	f, err := os.Open(h.auditPath)
	if err != nil {
		h.t.Fatal(err)
	}
	defer f.Close()
	var out []audit.Event
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var e audit.Event
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			h.t.Fatalf("audit line is not JSON: %v", err)
		}
		out = append(out, e)
	}
	return out
}

func TestPlatformConnectionTest(t *testing.T) {
	h := newHarness(t, nil)
	res := h.pc.Test(context.Background(), h.ts.URL, h.key, "postgresql", h.source())
	if !res.Success || res.TablesFound != 3 {
		t.Fatalf("%+v", res)
	}
	got := h.db.LastTarget()
	if got.Password.Reveal() != localPassword || got.Host != "10.10.1.20" || got.Username != "privasimu_ro" {
		t.Fatalf("local credentials must be used, not the platform's: host=%s user=%s", got.Host, got.Username)
	}
}

func TestPlatformScanReadsNamesAndFindings(t *testing.T) {
	h := newHarness(t, nil)
	out := h.pc.Scan(context.Background(), h.ts.URL, h.key, "postgresql", h.source())
	if out.Kind != "" || len(out.Tables) != 3 || len(out.Failed) != 0 {
		t.Fatalf("%+v", out)
	}
	if out.Tables[0].Name != "orders" || out.Tables[1].Name != "users" || out.Tables[2].Name != "audit.log" {
		t.Fatalf("order: %+v", out.Tables)
	}
	cols := map[string]pcColumn{}
	for _, c := range out.Tables[1].Columns {
		cols[*c.ColumnName] = c
	}
	if !*cols["email"].IsPII || *cols["email"].PDPCategory != "umum" || *cols["id"].IsPII || cols["id"].PDPCategory != nil {
		t.Fatalf("users: %+v", out.Tables[1].Columns)
	}
	if *cols["kontak"].IsPII {
		t.Fatal("without sampling, kontak is not personal data by name")
	}
	if h.db.Sampled != 0 {
		t.Fatal("sampling is off by default: no value may be read")
	}
}

func TestPlatformScanWithLocalSampling(t *testing.T) {
	h := newHarness(t, func(c *config.Config) {
		on := true
		c.Sources[0].Sampling = &config.SamplingOptions{Enabled: &on, Rows: 50}
	})
	out := h.pc.Scan(context.Background(), h.ts.URL, h.key, "postgresql", h.source())
	if out.Kind != "" {
		t.Fatalf("%+v", out)
	}
	cols := map[string]pcColumn{}
	for _, c := range out.Tables[1].Columns {
		cols[*c.ColumnName] = c
	}
	if !*cols["kontak"].IsPII || !*cols["catatan"].IsPII || *cols["catatan"].PDPCategory != "spesifik" {
		t.Fatalf("sampling must reveal the phone column and the NIK in free text: %+v", out.Tables[1].Columns)
	}
	// Nothing sampled leaves: every response of the scan is checked.
	_, raw := h.post(PathTableColumns, h.body(map[string]any{"table_name": "users"}), nil)
	for _, v := range []string{"budi.contoh", "Budi Contoh", "0812-3456-7890", "3171012303900001"} {
		if bytes.Contains(raw, []byte(v)) {
			t.Fatalf("the response carries a sampled value %q: %s", v, raw)
		}
	}
}

func TestErrorKindsAsThePlatformSeesThem(t *testing.T) {
	t.Run("wrong key is auth and not retried", func(t *testing.T) {
		h := newHarness(t, nil)
		res := h.pc.Test(context.Background(), h.ts.URL, "pvbk_wrong", "postgresql", h.source())
		if res.Kind != pcKindAuth {
			t.Fatalf("%+v", res)
		}
	})
	t.Run("unknown source is rejected, not retried", func(t *testing.T) {
		h := newHarness(t, nil)
		src := h.source()
		src["host"] = "other-db"
		if res := h.pc.Test(context.Background(), h.ts.URL, h.key, "postgresql", src); res.Kind != pcKindRejected {
			t.Fatalf("%+v", res)
		}
		if len(h.db.Opened) != 0 {
			t.Fatal("no database may be opened for an unknown source")
		}
	})
	t.Run("database login failure is rejected, not retried", func(t *testing.T) {
		h := newHarness(t, nil)
		h.db.Fail = map[string]error{"open": &dbsource.Error{Kind: dbsource.KindAuth, Op: "connect"}}
		if res := h.pc.Test(context.Background(), h.ts.URL, h.key, "postgresql", h.source()); res.Kind != pcKindRejected {
			t.Fatalf("%+v", res)
		}
		if len(h.db.Opened) != 1 {
			t.Fatalf("a failed login must not be retried, opened %d times", len(h.db.Opened))
		}
	})
	t.Run("unreachable database is retried then unavailable", func(t *testing.T) {
		h := newHarness(t, nil)
		h.db.Fail = map[string]error{"open": &dbsource.Error{Kind: dbsource.KindUnreachable, Op: "connect"}}
		if res := h.pc.Test(context.Background(), h.ts.URL, h.key, "postgresql", h.source()); res.Kind != pcKindUnavailable {
			t.Fatalf("%+v", res)
		}
		if len(h.db.Opened) != 3 {
			t.Fatalf("the platform retries a 502 twice; opened %d times", len(h.db.Opened))
		}
	})
	t.Run("unsupported type is rejected", func(t *testing.T) {
		h := newHarness(t, nil)
		if res := h.pc.Test(context.Background(), h.ts.URL, h.key, "snowflake", h.source()); res.Kind != pcKindRejected {
			t.Fatalf("%+v", res)
		}
	})
}

func TestPlatformLimitsAreHonored(t *testing.T) {
	h := newHarness(t, func(c *config.Config) {
		c.Server.Limits.RatePerSecond, c.Server.Limits.Burst = 10000, 10000
	})
	h.db.Tables = nil
	for i := 0; i < 520; i++ {
		h.db.Tables = append(h.db.Tables, fakedb.Table{Schema: "public", Name: fmt.Sprintf("t%03d", i),
			Columns: []dbsource.Column{fakedb.Int("id")}})
	}
	out := h.pc.Scan(context.Background(), h.ts.URL, h.key, "postgresql", h.source())
	if out.Kind != "" || len(out.Tables) != 500 {
		t.Fatalf("kind %q, %d tables", out.Kind, len(out.Tables))
	}
	if len(out.Failed) != 1 || out.Failed[0].Kind != pcKindLimit {
		t.Fatalf("%+v", out.Failed)
	}
}

func TestOnlyNameEndpointsExist(t *testing.T) {
	h := newHarness(t, nil)
	for _, p := range []string{"/v1/scan-table", "/v1/scan-database", "/v1/scan-file", "/v2/scan-database-columns", "/v1/sample"} {
		resp, _ := h.post(p, h.body(nil), nil)
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("%s: %d", p, resp.StatusCode)
		}
	}
	refused := 0
	for _, e := range h.auditEvents() {
		if e.Event == "raw_endpoint_refused" {
			refused++
		}
	}
	if refused != 5 {
		t.Fatalf("raw endpoint requests must be audited, got %d", refused)
	}
}

func TestAuthentication(t *testing.T) {
	h := newHarness(t, func(c *config.Config) { c.Server.Limits.AuthFailures = 3 })
	for _, hdr := range []map[string]string{{"X-API-Key": ""}, {"X-API-Key": "pvbk_nope"}, {"X-API-Key": strings.Repeat("a", 300)}} {
		resp, body := h.post(PathTableNames, h.body(nil), hdr)
		if resp.StatusCode != http.StatusUnauthorized || !bytes.Contains(body, []byte(`"code":"unauthorized"`)) {
			t.Fatalf("%d %s", resp.StatusCode, body)
		}
	}
	// Three failures lock the address out, even with the right key.
	resp, body := h.post(PathTableNames, h.body(nil), nil)
	if resp.StatusCode != http.StatusTooManyRequests || resp.Header.Get("Retry-After") == "" || !bytes.Contains(body, []byte("locked_out")) {
		t.Fatalf("%d %s", resp.StatusCode, body)
	}
	for _, e := range h.auditEvents() {
		raw, _ := json.Marshal(e)
		if bytes.Contains(raw, []byte(h.key)) || bytes.Contains(raw, []byte("pvbk_nope")) || bytes.Contains(raw, []byte(platformPassword)) {
			t.Fatalf("the audit log carries a secret: %s", raw)
		}
	}
}

func TestKeysAreVerifiedAndAudited(t *testing.T) {
	h := newHarness(t, nil)
	resp, _ := h.post(PathTableNames, h.body(nil), nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("%d", resp.StatusCode)
	}
	events := h.auditEvents()
	last := events[len(events)-1]
	if last.KeyID != h.keyID || last.Outcome != audit.OK || last.SourceID != "core-banking" || last.Tables != 3 || last.Credentials != "local" {
		t.Fatalf("%+v", last)
	}
}

func TestRequestLimits(t *testing.T) {
	h := newHarness(t, func(c *config.Config) { c.Server.Limits.MaxBodyBytes = 512 })
	cases := []struct {
		name    string
		path    string
		body    any
		headers map[string]string
		status  int
		code    string
	}{
		{"too large", PathTableNames, h.body(map[string]any{"password": strings.Repeat("x", 1000)}), nil, 413, CodeTooLarge},
		{"content type", PathTableNames, h.body(nil), map[string]string{"Content-Type": "text/plain"}, 415, CodeMediaType},
		{"contract version", PathTableNames, h.body(nil), map[string]string{"X-Contract-Version": "2"}, 400, CodeUnsupportedVersion},
		{"not json", PathTableNames, "{", nil, 400, CodeInvalidRequest},
		{"trailing data", PathTableNames, `{"db_type":"postgresql","host":"corebank","database":"corebank"} {}`, nil, 400, CodeInvalidRequest},
		{"bad host", PathTableNames, h.body(map[string]any{"host": "a b"}), nil, 400, CodeInvalidRequest},
		{"bad port", PathTableNames, h.body(map[string]any{"port": 70000}), nil, 400, CodeInvalidRequest},
		{"port as text", PathTableNames, h.body(map[string]any{"port": "5432"}), nil, 400, CodeInvalidRequest},
		{"injection in database", PathTableNames, h.body(map[string]any{"database": "x;drop"}), nil, 400, CodeInvalidRequest},
		{"missing table", PathTableColumns, h.body(nil), nil, 400, CodeInvalidRequest},
		{"control char in table", PathTableColumns, h.body(map[string]any{"table_name": "a\nb"}), nil, 400, CodeInvalidRequest},
		{"unknown table", PathTableColumns, h.body(map[string]any{"table_name": "nope"}), nil, 404, CodeTableNotFound},
		{"unsupported db", PathTableNames, h.body(map[string]any{"db_type": "db2i"}), nil, 400, CodeUnsupportedDBType},
		{"unknown path", "/v3/anything", h.body(nil), nil, 404, CodeNotFound},
	}
	for _, c := range cases {
		resp, body := h.post(c.path, c.body, c.headers)
		if resp.StatusCode != c.status || !bytes.Contains(body, []byte(`"code":"`+c.code+`"`)) {
			t.Errorf("%s: %d %s", c.name, resp.StatusCode, body)
		}
		if resp.Header.Get("Cache-Control") != "no-store" || resp.Header.Get("X-Content-Type-Options") != "nosniff" {
			t.Errorf("%s: security headers missing", c.name)
		}
	}
	req, _ := http.NewRequest(http.MethodGet, h.ts.URL+PathTableNames, nil)
	resp, err := h.pc.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed || resp.Header.Get("Allow") != "POST" {
		t.Fatalf("GET: %d", resp.StatusCode)
	}
	resp, err = h.pc.client.Get(h.ts.URL + PathHealth)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || strings.TrimSpace(string(body)) != `{"status":"ok"}` {
		t.Fatalf("health: %d %s", resp.StatusCode, body)
	}
}

func TestRateLimitAndBusy(t *testing.T) {
	h := newHarness(t, func(c *config.Config) { c.Server.Limits.RatePerSecond, c.Server.Limits.Burst = 1, 2 })
	statuses := []int{}
	for i := 0; i < 4; i++ {
		resp, _ := h.post(PathTableNames, h.body(nil), nil)
		statuses = append(statuses, resp.StatusCode)
		if resp.StatusCode == http.StatusTooManyRequests && resp.Header.Get("Retry-After") == "" {
			t.Fatal("429 needs Retry-After")
		}
	}
	if statuses[0] != 200 || statuses[1] != 200 || statuses[3] != http.StatusTooManyRequests {
		t.Fatalf("statuses = %v", statuses)
	}

	h2 := newHarness(t, func(c *config.Config) { c.Server.Limits.MaxConcurrent = 1 })
	h2.db.Delay = 300 * time.Millisecond
	var wg sync.WaitGroup
	codes := make([]int, 3)
	for i := range codes {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			resp, _ := h2.post(PathTableNames, h2.body(nil), nil)
			codes[i] = resp.StatusCode
		}(i)
	}
	wg.Wait()
	busy := 0
	for _, c := range codes {
		if c == http.StatusServiceUnavailable {
			busy++
		}
	}
	if busy == 0 {
		t.Fatalf("a full server must answer 503 at once: %v", codes)
	}
}

func TestSlowDatabaseTimesOut(t *testing.T) {
	h := newHarness(t, func(c *config.Config) { c.Server.Limits.RequestTimeout = config.Duration(100 * time.Millisecond) })
	h.db.Delay = 2 * time.Second
	started := time.Now()
	resp, body := h.post(PathTableNames, h.body(nil), nil)
	if resp.StatusCode != http.StatusGatewayTimeout || time.Since(started) > 1500*time.Millisecond {
		t.Fatalf("%d %s after %v", resp.StatusCode, body, time.Since(started))
	}
}

func TestLocalSourceMatching(t *testing.T) {
	h := newHarness(t, nil)
	cases := []struct {
		body   map[string]any
		status int
		source string
	}{
		{h.body(nil), 200, "core-banking"},
		{h.body(map[string]any{"host": "CoreBank"}), 200, "core-banking"},
		{h.body(map[string]any{"host": "10.10.1.20"}), 422, ""}, // the alias replaces the real host
		{h.body(map[string]any{"database": "other"}), 422, ""},
		{h.body(map[string]any{"db_type": "mysql"}), 422, ""},
		{map[string]any{"db_type": "mysql", "host": "crm.internal", "database": "crm", "user": "x", "password": "y"}, 200, "crm"},
		{map[string]any{"db_type": "mysql", "host": "crm.internal", "database": "crm", "user": "x", "password": "y", "schema_name": "hr"}, 422, ""},
	}
	for i, c := range cases {
		resp, body := h.post(PathTableNames, c.body, nil)
		if resp.StatusCode != c.status {
			t.Fatalf("case %d: %d %s", i, resp.StatusCode, body)
		}
	}
	for _, tgt := range h.db.Opened {
		if tgt.Password.Reveal() != localPassword || strings.Contains(tgt.Username, "x") {
			t.Fatal("a local source never uses the credentials of the request")
		}
	}
}

func TestRequestCredentialsUseTheAllowList(t *testing.T) {
	h := newHarness(t, func(c *config.Config) {
		c.Server.Credentials = config.CredentialsRequest
		c.Server.AllowedTargets = []string{"10.10.0.0/16"}
	})
	resp, body := h.post(PathTableNames, h.body(map[string]any{"host": "10.10.1.20"}), nil)
	if resp.StatusCode != 200 {
		t.Fatalf("%d %s", resp.StatusCode, body)
	}
	got := h.db.LastTarget()
	if got.Password.Reveal() != platformPassword || got.Host != "10.10.1.20" || got.Dial == nil || got.Username != "app_user" {
		t.Fatalf("request credentials must be used through the guarded dialer: %+v", got.Host)
	}
	// The fake opener does not dial, so check the guard itself the way a driver would use it.
	if _, err := got.Dial(context.Background(), "tcp", "169.254.169.254:5432"); err == nil {
		t.Fatal("the metadata address must be refused")
	}
	if _, err := got.Dial(context.Background(), "tcp", "10.99.0.1:5432"); err == nil {
		t.Fatal("an address outside allowed_targets must be refused")
	}
}

func TestProxyModeUsesTheForwardedClient(t *testing.T) {
	h := newHarness(t, func(c *config.Config) {
		c.Server.TLS.Mode = config.TLSModeProxy
		c.Server.Listen = "127.0.0.1:8080"
		c.Server.TrustedProxies = []string{"127.0.0.1/32", "::1/128"}
		c.Server.AllowedClients = []string{"203.0.113.10/32"}
	})
	resp, _ := h.post(PathTableNames, h.body(nil), map[string]string{"X-Forwarded-For": "198.51.100.7"})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("a client outside allowed_clients: %d", resp.StatusCode)
	}
	resp, _ = h.post(PathTableNames, h.body(nil), map[string]string{"X-Forwarded-For": "198.51.100.7, 203.0.113.10"})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("the right-most untrusted address is the client: %d", resp.StatusCode)
	}
}

func TestListenerRefusesClientsOutsideTheAllowList(t *testing.T) {
	for _, tc := range []struct {
		allowed string
		accept  bool
	}{{"203.0.113.0/24", false}, {"127.0.0.1/32", true}} {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		p, _ := config.ParsePrefix(tc.allowed)
		var refused int
		var mu sync.Mutex
		fl := filteredListener{Listener: ln, allowed: []netip.Prefix{p}, refused: func(netip.Addr) {
			mu.Lock()
			refused++
			mu.Unlock()
		}}
		accepted := make(chan net.Conn, 1)
		go func() {
			if c, err := fl.Accept(); err == nil {
				accepted <- c
			}
		}()
		c, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		_ = c.SetReadDeadline(time.Now().Add(time.Second))
		buf := make([]byte, 1)
		_, readErr := c.Read(buf)
		c.Close()
		select {
		case sc := <-accepted:
			sc.Close()
			if !tc.accept {
				t.Fatalf("%s: a refused client was accepted", tc.allowed)
			}
		case <-time.After(300 * time.Millisecond):
			if tc.accept {
				t.Fatalf("%s: an allowed client was not accepted", tc.allowed)
			}
			mu.Lock()
			n := refused
			mu.Unlock()
			if n == 0 || readErr == nil {
				t.Fatalf("%s: the connection must be closed before any byte (refused=%d, read=%v)", tc.allowed, n, readErr)
			}
		}
		ln.Close()
	}
}

func TestGoldenResponses(t *testing.T) {
	h := newHarness(t, func(c *config.Config) {
		on := true
		c.Sources[0].Sampling = &config.SamplingOptions{Enabled: &on, Rows: 20}
	})
	cases := map[string]struct {
		path string
		body any
		hdr  map[string]string
	}{
		"v1_table_names":         {PathTableNames, h.body(nil), nil},
		"v1_table_names_schema":  {PathTableNames, h.body(map[string]any{"schema_name": "audit"}), nil},
		"v2_table_columns":       {PathTableColumns, h.body(map[string]any{"table_name": "users"}), nil},
		"v2_table_columns_other": {PathTableColumns, h.body(map[string]any{"table_name": "audit.log"}), nil},
		"error_unauthorized":     {PathTableNames, h.body(nil), map[string]string{"X-API-Key": "pvbk_wrong"}},
		"error_source":           {PathTableNames, h.body(map[string]any{"host": "unknown"}), nil},
	}
	for name, c := range cases {
		_, got := h.post(c.path, c.body, c.hdr)
		file := filepath.Join("testdata", "golden", name+".json")
		if *update {
			var pretty bytes.Buffer
			_ = json.Indent(&pretty, got, "", "  ")
			if err := os.MkdirAll(filepath.Dir(file), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(file, append(pretty.Bytes(), '\n'), 0o644); err != nil {
				t.Fatal(err)
			}
			continue
		}
		want, err := os.ReadFile(file)
		if err != nil {
			t.Fatalf("%s: %v (run with -update to create)", name, err)
		}
		var g, w any
		_ = json.Unmarshal(got, &g)
		_ = json.Unmarshal(want, &w)
		gj, _ := json.Marshal(g)
		wj, _ := json.Marshal(w)
		if !bytes.Equal(gj, wj) {
			t.Errorf("%s differs from the golden file:\n got %s\nwant %s", name, gj, wj)
		}
	}
}
