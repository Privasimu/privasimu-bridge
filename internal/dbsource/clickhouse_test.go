package dbsource

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/privasimu/bridge/internal/config"
	"github.com/privasimu/bridge/internal/secrets"
)

// fakeClickHouse answers the queries of chConn like ClickHouse's HTTP interface, and
// records the requests.
type fakeClickHouse struct {
	t        *testing.T
	mu       sync.Mutex
	requests []*http.Request
	password string
}

func (f *fakeClickHouse) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.requests = append(f.requests, r.Clone(context.Background()))
	f.mu.Unlock()
	q := r.URL.Query()
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if r.Header.Get("X-ClickHouse-User") != "privasimu_ro" || r.Header.Get("X-ClickHouse-Key") != f.password {
		w.Header().Set("X-ClickHouse-Exception-Code", "516")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte("Code: 516. DB::Exception: privasimu_ro: Authentication failed. (AUTHENTICATION_FAILED)\n"))
		return
	}
	query := q.Get("query")
	write := func(lines ...string) { _, _ = w.Write([]byte(strings.Join(lines, "\n") + "\n")) }
	switch {
	case query == "SELECT version()":
		write(`["24.8.4.13"]`)
	case strings.Contains(query, "FROM system.tables") && strings.Contains(query, "name = {n:String}"):
		if q.Get("param_s") == "crm" && q.Get("param_n") == "customers" {
			write(`["crm","customers","1200"]`)
		}
	case strings.Contains(query, "FROM system.tables"):
		write(`["analytics","events",null]`, `["crm","customers","1200"]`, `["crm","orders","5"]`)
	case strings.Contains(query, "FROM system.columns"):
		write(`["id","UInt32","NO"]`, `["nik","String","NO"]`, `["kontak","Nullable(String)","YES"]`, `["created","DateTime","NO"]`)
	case strings.HasPrefix(query, "SELECT toString(") && strings.Contains(query, "`customers`"):
		for i := 0; i < 5; i++ {
			write(`["3171012303900001","0812-3456-7890"]`)
		}
		write(`["3171012303900001",null]`)
	default:
		w.Header().Set("X-ClickHouse-Exception-Code", "62")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte("Code: 62. DB::Exception: Syntax error"))
	}
}

func clickHouseTarget(srv *httptest.Server, password string) Target {
	u, _ := url.Parse(srv.URL)
	port, _ := strconv.Atoi(u.Port())
	return Target{Engine: "clickhouse", Host: u.Hostname(), Port: port, Database: "crm", Username: "privasimu_ro",
		Password: secrets.Value(password), Schemas: []string{"crm", "analytics"}, Timeout: 5 * time.Second, MaxOpen: 2,
		TLS: TLSSettings{Mode: config.DBTLSDisable}}
}

func TestClickHouseReadsTheCatalogAndSamplesReadOnly(t *testing.T) {
	fake := &fakeClickHouse{t: t, password: "placeholder-password"}
	srv := httptest.NewServer(fake)
	defer srv.Close()
	conn, err := Open(context.Background(), clickHouseTarget(srv, fake.password))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if conn.Engine() != "clickhouse" || conn.ServerVersion(context.Background()) != "ClickHouse 24.8.4.13" || conn.DefaultSchema() != "crm" {
		t.Fatalf("%s %s %s", conn.Engine(), conn.ServerVersion(context.Background()), conn.DefaultSchema())
	}
	tables, err := conn.ListTables(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	var refs []string
	for _, tb := range tables {
		refs = append(refs, tb.Ref)
	}
	if strings.Join(refs, ",") != "customers,orders,analytics.events" || tables[0].RowEstimate == nil || *tables[0].RowEstimate != 1200 ||
		tables[2].RowEstimate != nil {
		t.Fatalf("listing: %v", refs)
	}
	tb, ok, err := conn.FindTable(context.Background(), "customers", "")
	if err != nil || !ok || tb.Schema != "crm" || tb.Name != "customers" {
		t.Fatalf("find: %+v %v %v", tb, ok, err)
	}
	cols, err := conn.Columns(context.Background(), tb)
	if err != nil || len(cols) != 4 {
		t.Fatalf("columns: %+v %v", cols, err)
	}
	if cols[1].DataType != "string" || !cols[1].Sampleable || cols[0].Sampleable || cols[3].Sampleable ||
		cols[2].Nullable == nil || !*cols[2].Nullable || !cols[2].Sampleable {
		t.Fatalf("column metadata: %+v", cols)
	}
	values := map[int]int{}
	nulls := 0
	if err := conn.Sample(context.Background(), tb, cols, 50, func(i int, v string, null bool) {
		if null {
			nulls++
			return
		}
		values[i]++
	}); err != nil {
		t.Fatal(err)
	}
	if values[1] != 6 || values[2] != 5 || nulls != 1 {
		t.Fatalf("visited %v, %d nulls", values, nulls)
	}
	for _, r := range fake.requests {
		q := r.URL.Query()
		if r.Method != http.MethodGet || q.Get("max_execution_time") != "5" || q.Get("cancel_http_readonly_queries_on_client_close") != "1" ||
			q.Get("default_format") != "JSONCompactEachRow" || q.Get("database") != "crm" || q.Has("readonly") {
			t.Fatalf("every request is a bounded read-only GET: %s %s", r.Method, r.URL.RawQuery)
		}
		if strings.Contains(r.URL.RawQuery, fake.password) {
			t.Fatal("the password must never be in the URL")
		}
		query := q.Get("query")
		if strings.HasPrefix(query, "SELECT toString(") {
			if !strings.Contains(query, "FROM `crm`.`customers` LIMIT {limit:UInt32}") || q.Get("param_limit") != "50" ||
				q.Get("max_result_rows") != "50" || q.Get("result_overflow_mode") != "break" {
				t.Fatalf("sample: %s", r.URL.RawQuery)
			}
		}
		if strings.Contains(query, "system.tables") && !strings.Contains(query, "{s0:String}") && !strings.Contains(query, "{s:String}") {
			t.Fatalf("catalog names must be bound: %s", query)
		}
	}
}

func TestClickHouseErrors(t *testing.T) {
	fake := &fakeClickHouse{t: t, password: "placeholder-password"}
	srv := httptest.NewServer(fake)
	defer srv.Close()
	if _, err := Open(context.Background(), clickHouseTarget(srv, "wrong")); KindOf(err) != KindAuth {
		t.Fatalf("wrong password: %s (%v)", KindOf(err), err)
	}
	for code, want := range map[int]string{chUnknownDatabase: KindNotFound, chAccessDenied: KindPermission, chReadonly: KindPermission,
		chTimeoutExceeded: KindTimeout, 62: KindDatabase} {
		if got := classify(&chError{Code: code, Status: 500}); got != want {
			t.Errorf("code %d: %s, want %s", code, got, want)
		}
	}
	if got := classify(&chError{Status: http.StatusForbidden}); got != KindPermission {
		t.Errorf("403 without a code: %s", got)
	}
	conn, err := Open(context.Background(), clickHouseTarget(srv, fake.password))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.ListTables(context.Background(), "secret_schema"); KindOf(err) != KindPermission {
		t.Fatalf("a schema outside the allow-list: %v", err)
	}
	// A sampling error never shows ClickHouse's text, which can quote a value.
	err = conn.Sample(context.Background(), Table{Schema: "crm", Name: "x"}, []Column{{Name: "a", Sampleable: true}}, 5, func(int, string, bool) {})
	var e *Error
	if !asError(err, &e) || e.Safe || strings.Contains(e.Message(), "Syntax") {
		t.Fatalf("sampling error: %v", err)
	}
}

func asError(err error, target **Error) bool {
	e, ok := err.(*Error)
	if ok {
		*target = e
	}
	return ok
}

func TestClickHouseQuoting(t *testing.T) {
	for in, want := range map[string]string{"plain": "`plain`", "a`b": "`a\\`b`", `back\slash`: "`back\\\\slash`",
		"x`; DROP TABLE t; --": "`x\\`; DROP TABLE t; --`"} {
		if got := quoteClickHouse(in); got != want {
			t.Errorf("quote(%q) = %q, want %q", in, got, want)
		}
	}
	for typ, ok := range map[string]bool{"string": true, "nullable(string)": true, "lowcardinality(string)": true, "fixedstring(16)": true,
		"int64": true, "uint64": true, "decimal(18, 2)": true, "array(string)": true, "uint8": false, "datetime": false, "uuid": false,
		"float64": false, "ipv4": false} {
		if chSampleable(typ) != ok {
			t.Errorf("sampleable(%s) != %v", typ, ok)
		}
	}
}

func TestClickHouseRefusesRedirects(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://169.254.169.254/", http.StatusFound)
	}))
	defer srv.Close()
	if _, err := Open(context.Background(), clickHouseTarget(srv, "x")); err == nil {
		t.Fatal("a redirect must not be followed")
	}
}
