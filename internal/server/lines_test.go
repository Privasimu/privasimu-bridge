package server

// Tests that the bridge serves both Privasimu Nexus lines the same way. The Laravel line
// (App\Services\Discovery\Bridge\BridgeClient) and the Go line (internal/dbscan Bridge)
// implement contract v1 identically, but they do not send the same bytes; see
// platformclient_test.go for what each one sends and how it reads the answer.

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/privasimu/bridge/internal/config"
	"github.com/privasimu/bridge/internal/dbsource"
	"github.com/privasimu/bridge/internal/testutil/fakedb"
)

// summary reduces an outcome to what the platform stores, so two lines can be compared.
func summary(o pcOutcome) []string {
	var out []string
	for _, t := range o.Tables {
		for _, c := range t.Columns {
			pdp := "-"
			if c.PDPCategory != nil {
				pdp = *c.PDPCategory
			}
			out = append(out, t.Name+"."+*c.ColumnName+"="+map[bool]string{true: "pii", false: "no"}[*c.IsPII]+"/"+pdp)
		}
	}
	for _, f := range o.Failed {
		out = append(out, "failed:"+f.Name+":"+f.Kind)
	}
	return append(out, "kind:"+o.Kind)
}

func TestBothPlatformLinesGetTheSameResults(t *testing.T) {
	h := newHarness(t, func(c *config.Config) {
		on := true
		c.Sources[0].Sampling = &config.SamplingOptions{Enabled: &on, Rows: 20}
	})
	var results [][]string
	for _, line := range []string{lineGo, lineLaravel} {
		pc := h.pc.forLine(line)
		res := pc.Test(context.Background(), h.ts.URL, h.key, "postgresql", h.source())
		if !res.Success || res.TablesFound != 3 {
			t.Fatalf("%s test: %+v", line, res)
		}
		out := pc.Scan(context.Background(), h.ts.URL, h.key, "postgresql", h.source())
		if out.Kind != "" || len(out.Tables) != 3 {
			t.Fatalf("%s scan: %+v", line, out)
		}
		results = append(results, summary(out))
	}
	if !reflect.DeepEqual(results[0], results[1]) {
		t.Fatalf("the lines differ:\n go:      %v\n laravel: %v", results[0], results[1])
	}
}

func TestWhatEachLineSends(t *testing.T) {
	h := newHarness(t, nil)
	for _, line := range []string{lineGo, lineLaravel} {
		if res := h.pc.forLine(line).Test(context.Background(), h.ts.URL, h.key, "postgresql", h.source()); !res.Success {
			t.Fatalf("%s: %+v", line, res)
		}
	}
	reqs := h.requests()
	if len(reqs) != 2 {
		t.Fatalf("requests = %d", len(reqs))
	}
	goReq, phpReq := reqs[0], reqs[1]
	for _, r := range reqs {
		for k, want := range map[string]string{"X-Contract-Version": "1", "User-Agent": "privasimu-nexus-discovery",
			"Accept": "application/json", "Content-Type": "application/json", "X-Api-Key": h.key} {
			if got := r.header.Get(k); got != want {
				t.Errorf("%s = %q, want %q", k, got, want)
			}
		}
		if r.proto != "HTTP/1.1" {
			t.Errorf("protocol %s", r.proto)
		}
	}
	if goReq.header.Get("Accept-Encoding") != "gzip" || phpReq.header.Get("Accept-Encoding") != "" {
		t.Fatalf("Accept-Encoding: go %q, laravel %q", goReq.header.Get("Accept-Encoding"), phpReq.header.Get("Accept-Encoding"))
	}
	if !bytes.HasPrefix(phpReq.body, []byte(`{"db_type":"postgresql","host":"corebank","port":5432,`)) {
		t.Fatalf("laravel body order: %s", phpReq.body)
	}
	if !bytes.HasPrefix(goReq.body, []byte(`{"database":"corebank","db_type":"postgresql",`)) {
		t.Fatalf("go body order: %s", goReq.body)
	}
}

func TestBothRequestEncodingsGetIdenticalResponses(t *testing.T) {
	h := newHarness(t, func(c *config.Config) {
		c.Server.Credentials = config.CredentialsRequest
		c.Server.AllowedTargets = []string{"10.10.0.0/16"}
	})
	// A password with characters PHP escapes ("/", non-ASCII, a character outside the
	// Basic Multilingual Plane) must reach the database driver unchanged from both lines.
	password := `p/w "é" 😀 \ end`
	body := map[string]any{"db_type": "postgresql", "host": "10.10.1.20", "port": 5432, "database": "corebank",
		"user": "app_user", "password": password, "schema_name": "public", "use_ssl": false, "table_name": "users"}
	var responses [][]byte
	for _, payload := range [][]byte{mustJSON(body), phpBody(body)} {
		for _, path := range []string{PathTableNames, PathTableColumns} {
			resp, raw := h.post(path, string(payload), nil)
			if resp.StatusCode != 200 {
				t.Fatalf("%s: %d %s", path, resp.StatusCode, raw)
			}
			if got := h.db.LastTarget().Password.Reveal(); got != password {
				t.Fatalf("password changed on the way: %q", got)
			}
			responses = append(responses, raw)
		}
	}
	if !bytes.Equal(responses[0], responses[2]) || !bytes.Equal(responses[1], responses[3]) {
		t.Fatalf("responses differ by request encoding:\n%s\n%s", responses[0], responses[2])
	}
}

func mustJSON(v any) []byte {
	raw, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return raw
}

func TestResponsesSuitBothDecoders(t *testing.T) {
	h := newHarness(t, nil)
	for _, path := range []string{PathTableNames, PathTableColumns} {
		resp, raw := h.post(path, h.body(map[string]any{"table_name": "users"}), map[string]string{"Accept-Encoding": "gzip"})
		if resp.StatusCode != 200 || resp.Header.Get("Content-Encoding") != "" {
			t.Fatalf("%s: %d, Content-Encoding %q: the bridge never compresses (Laravel reads raw bytes)", path,
				resp.StatusCode, resp.Header.Get("Content-Encoding"))
		}
		if !utf8.Valid(raw) || !strings.HasPrefix(resp.Header.Get("Content-Type"), "application/json") {
			t.Fatalf("%s: not UTF-8 JSON", path)
		}
		// json_decode turns 3.0 into a float and BridgeClient.php requires is_int().
		if bytes.Contains(raw, []byte(`"tables_scanned":3.`)) || bytes.Contains(raw, []byte("e+")) {
			t.Fatalf("%s: numbers must be plain integers: %s", path, raw)
		}
	}
}

func TestNamesNotEveryLineCanReadAreLeftOut(t *testing.T) {
	h := newHarness(t, nil)
	h.db.Tables = append(h.db.Tables, fakedb.Table{Schema: "public", Name: "bad\xffname", Columns: []dbsource.Column{fakedb.Int("id")}})
	h.db.Tables[0].Columns = append(h.db.Tables[0].Columns, fakedb.Int("kolom\xfe"))
	for _, line := range []string{lineGo, lineLaravel} {
		out := h.pc.forLine(line).Scan(context.Background(), h.ts.URL, h.key, "postgresql", h.source())
		if out.Kind != "" || len(out.Tables) != 3 {
			t.Fatalf("%s: %+v", line, out)
		}
		if len(out.Failed) != 1 || out.Failed[0].Name != "*" || out.Failed[0].Kind != pcKindIncomplete {
			t.Fatalf("%s: the omitted table must show as an incomplete listing: %+v", line, out.Failed)
		}
		for _, c := range out.Tables[1].Columns {
			if !utf8.ValidString(*c.ColumnName) {
				t.Fatalf("%s: a column name that is not UTF-8 reached the platform", line)
			}
		}
	}
	_, raw := h.post(PathTableColumns, h.body(map[string]any{"table_name": "users"}), nil)
	if !bytes.Contains(raw, []byte(`"omitted_columns":1`)) {
		t.Fatalf("the omitted column is counted: %s", raw)
	}
}

func TestServerTLSIsHTTP11Only(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := writeTestCert(t, dir)
	h := newHarness(t, func(c *config.Config) {
		c.Server.TLS.CertFile, c.Server.TLS.KeyFile = certFile, keyFile
	})
	tc, err := h.srv.TLSConfig()
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(tc.NextProtos, []string{"http/1.1"}) || tc.MinVersion < 0x0303 {
		t.Fatalf("%v %x", tc.NextProtos, tc.MinVersion)
	}
}

func writeTestCert(t *testing.T, dir string) (string, string) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "bridge.test"},
		DNSNames: []string{"bridge.test"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	kb, _ := x509.MarshalECPrivateKey(key)
	certFile, keyFile := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	_ = os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600)
	_ = os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}), 0o600)
	return certFile, keyFile
}

// TestRefusedClientIsAClosedConnection documents what the platform sees when
// allowed_clients refuses it: the connection closes before the TLS handshake. The Go line
// reports bridge_unavailable (and retries); the Laravel line reports curl error 35 as
// "tls" ("Sertifikat layanan jembatan tidak tepercaya"). The bridge logs the refusal.
func TestRefusedClientIsAClosedConnection(t *testing.T) {
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p, _ := config.ParsePrefix("203.0.113.0/24")
	srv := &http.Server{Handler: http.NotFoundHandler()}
	dir := t.TempDir()
	certFile, keyFile := writeTestCert(t, dir)
	go func() {
		_ = srv.ServeTLS(filteredListener{Listener: raw, allowed: []netip.Prefix{p}}, certFile, keyFile)
	}()
	defer srv.Close()
	pool := x509.NewCertPool()
	pemBytes, _ := os.ReadFile(certFile)
	pool.AppendCertsFromPEM(pemBytes)
	pc := &platformClient{client: &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}},
		callTimeout: 2 * time.Second, deadline: 5 * time.Second, retryDelay: time.Millisecond, concurrency: 4, line: lineGo}
	res := pc.Test(context.Background(), "https://"+raw.Addr().String(), "pvbk_x", "postgresql",
		map[string]any{"host": "h", "database": "d", "username": "u", "password": "p"})
	if res.Success || res.Kind != pcKindUnavailable {
		t.Fatalf("go line: %+v", res)
	}
}
