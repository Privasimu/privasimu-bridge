package dbsource

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// fakeDatabricks answers the Statement Execution API: a statement that is first PENDING, a
// second chunk, named parameters, OAuth for a service principal, and failures.
type fakeDatabricks struct {
	t        *testing.T
	mu       sync.Mutex
	bodies   []map[string]any
	badChunk bool
}

func (f *fakeDatabricks) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.URL.Path == "/oidc/v1/token" {
		user, pass, ok := r.BasicAuth()
		_ = r.ParseForm()
		if !ok || user != "sp-application-id" || pass != "placeholder-oauth-secret" || r.PostForm.Get("grant_type") != "client_credentials" {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"invalid_client"}`))
			return
		}
		_, _ = w.Write([]byte(`{"access_token":"placeholder-oauth-token","expires_in":3600}`))
		return
	}
	if a := r.Header.Get("Authorization"); a != "Bearer placeholder-pat" && a != "Bearer placeholder-oauth-token" {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error_code":"UNAUTHENTICATED","message":"Invalid access token."}`))
		return
	}
	ok := func(id, rows, next string) string {
		link := ""
		if next != "" {
			link = `,"next_chunk_internal_link":"` + next + `"`
		}
		return `{"statement_id":"` + id + `","status":{"state":"SUCCEEDED"},"result":{"data_array":[` + rows + `]` + link + `}}`
	}
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/api/2.0/sql/statements/s-tables":
		next := "/api/2.0/sql/statements/s-tables/result/chunks/1"
		if f.badChunk {
			next = "/api/2.0/other"
		}
		_, _ = w.Write([]byte(ok("s-tables", `["default","customers"]`, next)))
		return
	case r.Method == http.MethodGet && r.URL.Path == "/api/2.0/sql/statements/s-tables/result/chunks/1":
		_, _ = w.Write([]byte(`{"chunk_index":1,"data_array":[["sales","orders"]]}`))
		return
	}
	raw, _ := io.ReadAll(r.Body)
	var body map[string]any
	_ = json.Unmarshal(raw, &body)
	f.mu.Lock()
	f.bodies = append(f.bodies, body)
	f.mu.Unlock()
	params := map[string]string{}
	if list, isList := body["parameters"].([]any); isList {
		for _, p := range list {
			m := p.(map[string]any)
			params[m["name"].(string)] = m["value"].(string)
		}
	}
	stmt, _ := body["statement"].(string)
	switch {
	case stmt == "SELECT 1":
		_, _ = w.Write([]byte(ok("s-ping", `["1"]`, "")))
	case strings.HasPrefix(stmt, "SELECT table_schema, table_name") && strings.Contains(stmt, "IN (:s0, :s1)") && params["s0"] == "default":
		_, _ = w.Write([]byte(`{"statement_id":"s-tables","status":{"state":"PENDING"}}`))
	case strings.HasPrefix(stmt, "SELECT table_schema, table_name") && params["s"] == "default" && params["n"] == "customers":
		_, _ = w.Write([]byte(ok("s-find", `["default","customers"]`, "")))
	case strings.HasPrefix(stmt, "SELECT table_schema, table_name"):
		_, _ = w.Write([]byte(ok("s-none", ``, "")))
	case strings.HasPrefix(stmt, "SELECT column_name, full_data_type") && params["n"] == "customers":
		_, _ = w.Write([]byte(ok("s-cols", `["id","int","NO"],["nik","string","YES"],["kontak","varchar(20)","YES"],["joined","date","YES"]`, "")))
	case stmt == "SELECT CAST(`nik` AS STRING), CAST(`kontak` AS STRING) FROM `main`.`default`.`customers` LIMIT 50" && body["row_limit"] == float64(50):
		_, _ = w.Write([]byte(ok("s-sample", `["3171012303900001","0812-3456-7890"],["3171012303900001",null]`, "")))
	default:
		_, _ = w.Write([]byte(`{"statement_id":"s-err","status":{"state":"FAILED","error":{"error_code":"PERMISSION_DENIED","message":"User does not have SELECT on Table"}}}`))
	}
}

func databricksTarget(srv *httptest.Server) Target {
	t := cloudTarget(srv, "databricks")
	t.Host, t.Database, t.Warehouse, t.Password = "adb-123.4.azuredatabricks.net", "main", "/sql/1.0/warehouses/abc123", "placeholder-pat"
	t.Schemas = []string{"default", "sales"}
	return t
}

func TestDatabricksReadsUnityCatalog(t *testing.T) {
	fake := &fakeDatabricks{t: t}
	srv := httptest.NewTLSServer(fake)
	defer srv.Close()
	ctx := context.Background()
	conn, err := Open(ctx, databricksTarget(srv))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	tables, err := conn.ListTables(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(tables) != 2 || tables[0].Ref != "customers" || tables[1].Ref != "sales.orders" {
		t.Fatalf("listing (pending, then two chunks): %+v", tables)
	}
	tb, ok, err := conn.FindTable(ctx, "customers", "")
	if err != nil || !ok || tb.Schema != "default" {
		t.Fatalf("find: %+v %v %v", tb, ok, err)
	}
	if _, ok, err := conn.FindTable(ctx, "nothing", ""); ok || err != nil {
		t.Fatalf("a missing table: %v %v", ok, err)
	}
	cols, err := conn.Columns(ctx, tb)
	if err != nil || len(cols) != 4 || cols[0].Sampleable || !cols[1].Sampleable || !cols[2].Sampleable || cols[3].Sampleable {
		t.Fatalf("columns: %+v %v", cols, err)
	}
	n, nulls := 0, 0
	if err := conn.Sample(ctx, tb, cols, 50, func(i int, v string, null bool) {
		if null {
			nulls++
		} else {
			n++
		}
	}); err != nil {
		t.Fatal(err)
	}
	if n != 3 || nulls != 1 {
		t.Fatalf("sampled %d values, %d nulls", n, nulls)
	}
	for _, b := range fake.bodies {
		if b["warehouse_id"] != "abc123" || b["catalog"] != "main" || b["disposition"] != "INLINE" || b["format"] != "JSON_ARRAY" {
			t.Fatalf("request: %v", b)
		}
	}
}

func TestDatabricksOAuthAndFailures(t *testing.T) {
	fake := &fakeDatabricks{t: t}
	srv := httptest.NewTLSServer(fake)
	defer srv.Close()
	ctx := context.Background()
	oauth := databricksTarget(srv)
	oauth.Username, oauth.Password = "sp-application-id", "placeholder-oauth-secret"
	conn, err := Open(ctx, oauth)
	if err != nil {
		t.Fatalf("OAuth for a service principal: %v", err)
	}
	if _, err := conn.Columns(ctx, Table{Schema: "default", Name: "secret"}); KindOf(err) != KindPermission {
		t.Fatalf("a failed statement: %s (%v)", KindOf(err), err)
	}
	oauth.Password = "wrong"
	if _, err := Open(ctx, oauth); KindOf(err) != KindAuth {
		t.Fatalf("a refused secret: %s (%v)", KindOf(err), err)
	}
	pat := databricksTarget(srv)
	pat.Password = "wrong"
	if _, err := Open(ctx, pat); KindOf(err) != KindAuth {
		t.Fatalf("a refused token: %s (%v)", KindOf(err), err)
	}
	fake.badChunk = true
	conn, err = Open(ctx, databricksTarget(srv))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.ListTables(ctx, ""); err == nil {
		t.Fatal("a chunk link outside the statement must be refused")
	}
	if got := dbxWarehouseID("/sql/1.0/warehouses/abc123/"); got != "abc123" {
		t.Fatalf("warehouse id: %s", got)
	}
}
