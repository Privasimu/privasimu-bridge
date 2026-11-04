package dbsource

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/privasimu/bridge/internal/secrets"
)

// fakeSnowflake answers the SQL API like Snowflake: SHOW for the catalog, a 202 for a
// statement still running, a second partition, and SQL errors as 422.
type fakeSnowflake struct {
	t       *testing.T
	key     *rsa.PublicKey
	pat     string
	mu      sync.Mutex
	bodies  []map[string]any
	headers []http.Header
}

func (f *fakeSnowflake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	raw, _ := io.ReadAll(r.Body)
	var body map[string]any
	_ = json.Unmarshal(raw, &body)
	f.mu.Lock()
	f.bodies = append(f.bodies, body)
	f.headers = append(f.headers, r.Header.Clone())
	f.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	ok := false
	switch r.Header.Get("X-Snowflake-Authorization-Token-Type") {
	case "KEYPAIR_JWT":
		claims, err := verifyJWT(token, f.key)
		ok = err == nil && claims["sub"] == "MYORG-MYACCOUNT.PRIVASIMU_RO" && strings.HasPrefix(claims["iss"].(string), "MYORG-MYACCOUNT.PRIVASIMU_RO.SHA256:")
	case "PROGRAMMATIC_ACCESS_TOKEN":
		ok = token == f.pat
	}
	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"code":"390144","message":"JWT token is invalid."}`))
		return
	}
	answer := func(rowType []string, rows ...string) string {
		names := make([]string, len(rowType))
		for i, n := range rowType {
			names[i] = `{"name":"` + n + `"}`
		}
		return `{"resultSetMetaData":{"partitionInfo":[{"rowCount":` + itoa(len(rows)) + `}],"rowType":[` + strings.Join(names, ",") +
			`]},"data":[` + strings.Join(rows, ",") + `],"statementHandle":"h0"}`
	}
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/api/v2/statements/h-version":
		_, _ = w.Write([]byte(answer([]string{"CURRENT_VERSION()"}, `["9.34.1"]`)))
		return
	case r.Method == http.MethodGet && r.URL.Path == "/api/v2/statements/h-tables" && r.URL.Query().Get("partition") == "1":
		_, _ = w.Write([]byte(`{"data":[["2026-01-01","ORDERS","COREBANK","PUBLIC","TABLE","","","5"]]}`))
		return
	}
	stmt, _ := body["statement"].(string)
	showTables := []string{"created_on", "name", "database_name", "schema_name", "kind", "comment", "cluster_by", "rows"}
	switch stmt {
	case "SHOW SCHEMAS IN DATABASE corebank LIMIT 1":
		_, _ = w.Write([]byte(answer([]string{"name"}, `["PUBLIC"]`)))
	case "SELECT CURRENT_VERSION()":
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"code":"333334","message":"Asynchronous execution in progress.","statementHandle":"h-version"}`))
	case "SHOW TABLES IN DATABASE corebank":
		_, _ = w.Write([]byte(`{"resultSetMetaData":{"partitionInfo":[{"rowCount":3},{"rowCount":1}],"rowType":[{"name":"created_on"},{"name":"name"},` +
			`{"name":"database_name"},{"name":"schema_name"},{"name":"kind"},{"name":"comment"},{"name":"cluster_by"},{"name":"rows"}]},` +
			`"data":[["2026-01-01","CUSTOMERS","COREBANK","PUBLIC","TABLE","","","1200"],["2026-01-01","LOG","COREBANK","AUDIT","TABLE","","",null],` +
			`["2026-01-01","TABLES","COREBANK","INFORMATION_SCHEMA","VIEW","","",null]],"statementHandle":"h-tables"}`))
	case "SHOW TABLES LIKE 'CUSTOMERS' IN DATABASE corebank":
		_, _ = w.Write([]byte(answer(showTables, `["2026-01-01","CUSTOMERS","COREBANK","PUBLIC","TABLE","","","1200"]`,
			`["2026-01-01","CUSTOMERS","COREBANK","AUDIT","TABLE","","","3"]`)))
	case `SHOW COLUMNS IN TABLE corebank."PUBLIC"."CUSTOMERS"`:
		_, _ = w.Write([]byte(answer([]string{"table_name", "schema_name", "column_name", "data_type", "null?"},
			`["CUSTOMERS","PUBLIC","ID","{\"type\":\"FIXED\",\"precision\":38,\"scale\":0,\"nullable\":false}","false"]`,
			`["CUSTOMERS","PUBLIC","NIK","{\"type\":\"TEXT\",\"length\":16,\"nullable\":true}","true"]`,
			`["CUSTOMERS","PUBLIC","BALANCE","{\"type\":\"FIXED\",\"precision\":18,\"scale\":2,\"nullable\":true}","true"]`,
			`["CUSTOMERS","PUBLIC","CREATED","{\"type\":\"TIMESTAMP_NTZ\",\"nullable\":true}","true"]`)))
	case `SELECT TO_VARCHAR("ID"), TO_VARCHAR("NIK") FROM corebank."PUBLIC"."CUSTOMERS" LIMIT 50`:
		_, _ = w.Write([]byte(answer([]string{"A", "B"}, `["1","3171012303900001"]`, `["2","3171012303900001"]`, `["3",null]`)))
	default:
		w.WriteHeader(http.StatusUnprocessableEntity)
		_, _ = w.Write([]byte(`{"code":"002003","message":"SQL compilation error: Object 'X' does not exist or not authorized."}`))
	}
}

func itoa(n int) string { b, _ := json.Marshal(n); return string(b) }

func snowflakeTarget(srv *httptest.Server) Target {
	t := cloudTarget(srv, "snowflake")
	t.Host, t.Database, t.Username, t.Warehouse, t.Role = "myorg.myaccount", "corebank", "privasimu_ro", "scan_wh", "privasimu_reader"
	return t
}

func TestSnowflakeReadsTheCatalogWithAKeyPair(t *testing.T) {
	key := rsaTestKey(t)
	fake := &fakeSnowflake{t: t, key: &key.PublicKey}
	srv := httptest.NewTLSServer(fake)
	defer srv.Close()
	target := snowflakeTarget(srv)
	target.PrivateKey = secrets.Value(pkcs8PEM(t, key))
	ctx := context.Background()
	conn, err := Open(ctx, target)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if conn.ServerVersion(ctx) != "Snowflake 9.34.1" || conn.DefaultSchema() != "PUBLIC" || !*conn.TLSInUse() {
		t.Fatalf("%s %s", conn.ServerVersion(ctx), conn.DefaultSchema())
	}
	tables, err := conn.ListTables(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	var refs []string
	for _, tb := range tables {
		refs = append(refs, tb.Ref)
	}
	if strings.Join(refs, ",") != "CUSTOMERS,ORDERS,AUDIT.LOG" || *tables[0].RowEstimate != 1200 {
		t.Fatalf("listing (two partitions, information_schema left out): %v", refs)
	}
	tb, ok, err := conn.FindTable(ctx, "CUSTOMERS", "")
	if err != nil || !ok || tb.Schema != "PUBLIC" {
		t.Fatalf("find: %+v %v %v", tb, ok, err)
	}
	cols, err := conn.Columns(ctx, tb)
	if err != nil || len(cols) != 4 {
		t.Fatalf("columns: %+v %v", cols, err)
	}
	if cols[0].DataType != "number(38,0)" || !cols[0].Sampleable || cols[1].DataType != "varchar(16)" || !cols[1].Sampleable ||
		cols[2].Sampleable || cols[3].Sampleable || *cols[0].Nullable {
		t.Fatalf("types: %+v", cols)
	}
	got := map[int]int{}
	nulls := 0
	if err := conn.Sample(ctx, tb, cols, 50, func(i int, v string, null bool) {
		if null {
			nulls++
		} else {
			got[i]++
		}
	}); err != nil {
		t.Fatal(err)
	}
	if got[0] != 3 || got[1] != 2 || nulls != 1 {
		t.Fatalf("sampled %v, %d nulls", got, nulls)
	}
	pemText := pkcs8PEM(t, key)
	for i, b := range fake.bodies {
		raw, _ := json.Marshal(b)
		if strings.Contains(string(raw), "PRIVATE KEY") || strings.Contains(string(raw), pemText[40:80]) {
			t.Fatal("the private key must never be sent")
		}
		if b["statement"] == nil {
			continue // a poll or a partition
		}
		if b["database"] != "COREBANK" || b["warehouse"] != "SCAN_WH" || b["role"] != "PRIVASIMU_READER" || b["timeout"] != float64(5) {
			t.Fatalf("request %d: %v", i, b)
		}
	}
}

func TestSnowflakeErrorsAndTokens(t *testing.T) {
	fake := &fakeSnowflake{t: t, key: &rsaTestKey(t).PublicKey, pat: "placeholder-pat"}
	srv := httptest.NewTLSServer(fake)
	defer srv.Close()
	target := snowflakeTarget(srv)
	target.Password = "wrong-pat"
	if _, err := Open(context.Background(), target); KindOf(err) != KindAuth {
		t.Fatalf("a refused token: %s (%v)", KindOf(err), err)
	}
	target.Password = "placeholder-pat"
	conn, err := Open(context.Background(), target)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Columns(context.Background(), Table{Schema: "PUBLIC", Name: "MISSING"}); KindOf(err) != KindNotFound {
		t.Fatalf("an unknown table: %v", err)
	}
	noWarehouse := target
	noWarehouse.Warehouse = ""
	c2, err := Open(context.Background(), noWarehouse)
	if err != nil {
		t.Fatal(err)
	}
	if err := c2.Sample(context.Background(), Table{Schema: "PUBLIC", Name: "CUSTOMERS"}, []Column{{Name: "NIK", Sampleable: true}}, 5,
		func(int, string, bool) {}); KindOf(err) != KindConfig {
		t.Fatalf("sampling without a warehouse: %v", err)
	}
	bad := target
	bad.Password, bad.PrivateKey = "", "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n"
	if _, err := Open(context.Background(), bad); KindOf(err) != KindConfig {
		t.Fatalf("a broken key: %v", err)
	}
}

func TestSnowflakeNames(t *testing.T) {
	for host, want := range map[string][2]string{
		"myorg-myaccount":        {"MYORG-MYACCOUNT", "myorg-myaccount.snowflakecomputing.com"},
		"myorg.myaccount":        {"MYORG-MYACCOUNT", "myorg-myaccount.snowflakecomputing.com"},
		"xy12345":                {"XY12345", "xy12345.snowflakecomputing.com"},
		"xy12345.ap-southeast-1": {"XY12345", "xy12345.ap-southeast-1.snowflakecomputing.com"},
		"XY12345.us-east-2.aws":  {"XY12345", "xy12345.us-east-2.aws.snowflakecomputing.com"},
		"myorg-myaccount.privatelink.snowflakecomputing.com": {"MYORG-MYACCOUNT", "myorg-myaccount.privatelink.snowflakecomputing.com"},
	} {
		account, api := sfAccount(host)
		if account != want[0] || api != want[1] {
			t.Errorf("%s: %s %s, want %v", host, account, api, want)
		}
	}
	for in, want := range map[string]string{"corebank": "COREBANK", "Core_Bank$1": "CORE_BANK$1", "core-bank": "core-bank", "1db": "1db"} {
		if got := sfObjectName(in); got != want {
			t.Errorf("sfObjectName(%q) = %q, want %q", in, got, want)
		}
	}
	if got := sfQuote(`A"B`); got != `"A""B"` {
		t.Errorf("quote: %s", got)
	}
	if got := sfLike(`it's\x`); got != `'it''s\\x'` {
		t.Errorf("like: %s", got)
	}
	for typ, ok := range map[string]bool{"varchar(16)": true, "number(38,0)": true, "number(18,2)": false, "variant": true,
		"timestamp_ntz": false, "boolean": false, "binary": false} {
		if sfSampleable(typ) != ok {
			t.Errorf("sampleable(%s) != %v", typ, ok)
		}
	}
}
