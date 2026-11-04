package dbsource

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"sync"
	"testing"
)

// pagedSnowflake is a database with more tables than one SHOW returns (10,000 rows): SHOW
// stops at its row limit, and LIMIT n FROM '<name>' starts again at that name (the cursor's
// row comes again). With ignoreFrom it always answers the first page.
type pagedSnowflake struct {
	schemas    map[string][]string
	ignoreFrom bool
	mu         sync.Mutex
	statements []string
}

var (
	sfShowSchemasPage = regexp.MustCompile(`^SHOW SCHEMAS IN DATABASE corebank LIMIT (\d+)(?: FROM '([^']*)')?$`)
	sfShowTablesPage  = regexp.MustCompile(`^SHOW TABLES IN SCHEMA corebank\."([^"]*)" LIMIT (\d+)(?: FROM '([^']*)')?$`)
)

func (f *pagedSnowflake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Header.Get("Authorization") != "Bearer placeholder-pat" {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"code":"394304","message":"invalid token"}`))
		return
	}
	raw, _ := io.ReadAll(r.Body)
	var body map[string]any
	_ = json.Unmarshal(raw, &body)
	stmt, _ := body["statement"].(string)
	f.mu.Lock()
	f.statements = append(f.statements, stmt)
	f.mu.Unlock()
	answer := func(rowType []string, rows [][]any) {
		meta := []map[string]string{}
		for _, n := range rowType {
			meta = append(meta, map[string]string{"name": n})
		}
		out, _ := json.Marshal(map[string]any{"resultSetMetaData": map[string]any{"partitionInfo": []map[string]int{{"rowCount": len(rows)}},
			"rowType": meta}, "data": rows, "statementHandle": "h1"})
		_, _ = w.Write(out)
	}
	tableRow := func(schema, name string) []any {
		return []any{"2026-01-01", name, "COREBANK", schema, "TABLE", "", "", "1"}
	}
	tableCols := []string{"created_on", "name", "database_name", "schema_name", "kind", "comment", "cluster_by", "rows"}
	page := func(names []string, limit, from string) []string {
		n, _ := strconv.Atoi(limit)
		start := 0
		if from != "" && !f.ignoreFrom {
			start = sort.SearchStrings(names, from)
		}
		return names[start:min(start+n, len(names))]
	}
	schemaNames := make([]string, 0, len(f.schemas))
	for s := range f.schemas {
		schemaNames = append(schemaNames, s)
	}
	sort.Strings(schemaNames)
	switch m1, m2 := sfShowSchemasPage.FindStringSubmatch(stmt), sfShowTablesPage.FindStringSubmatch(stmt); {
	case stmt == "SHOW SCHEMAS IN DATABASE corebank LIMIT 1":
		answer([]string{"created_on", "name"}, [][]any{{"2026-01-01", schemaNames[0]}})
	case stmt == "SELECT CURRENT_VERSION()":
		answer([]string{"CURRENT_VERSION()"}, [][]any{{"9.34.1"}})
	case stmt == "SHOW TABLES IN DATABASE corebank":
		var rows [][]any
		for _, s := range schemaNames {
			for _, t := range f.schemas[s] {
				if len(rows) < sfShowLimit {
					rows = append(rows, tableRow(s, t))
				}
			}
		}
		answer(tableCols, rows)
	case m1 != nil:
		var rows [][]any
		for _, s := range page(schemaNames, m1[1], m1[2]) {
			rows = append(rows, []any{"2026-01-01", s})
		}
		answer([]string{"created_on", "name"}, rows)
	case m2 != nil && f.schemas[m2[1]] != nil:
		var rows [][]any
		for _, t := range page(f.schemas[m2[1]], m2[2], m2[3]) {
			rows = append(rows, tableRow(m2[1], t))
		}
		answer(tableCols, rows)
	default:
		w.WriteHeader(http.StatusUnprocessableEntity)
		_, _ = w.Write([]byte(`{"code":"002003","message":"SQL compilation error: Object does not exist or not authorized."}`))
	}
}

func newPagedSnowflake(t *testing.T) (*pagedSnowflake, Target) {
	t.Helper()
	public := make([]string, 0, sfShowLimit+50)
	for i := range sfShowLimit + 50 {
		public = append(public, fmt.Sprintf("T%05d", i))
	}
	fake := &pagedSnowflake{schemas: map[string][]string{"AUDIT": {"A1", "A2", "A3"}, "INFORMATION_SCHEMA": {"TABLES"}, "PUBLIC": public}}
	srv := httptest.NewTLSServer(fake)
	t.Cleanup(srv.Close)
	target := cloudTarget(srv, "snowflake")
	target.Host, target.Database, target.Username, target.Password = "myorg.myaccount", "corebank", "privasimu_ro", "placeholder-pat"
	return fake, target
}

// TestSnowflakeListsPastTheShowLimit: a database with more than 10,000 tables is listed
// schema by schema, page by page, and every table is reported once.
func TestSnowflakeListsPastTheShowLimit(t *testing.T) {
	fake, target := newPagedSnowflake(t)
	ctx := context.Background()
	conn, err := Open(ctx, target)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	tables, err := conn.ListTables(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, tb := range tables {
		if seen[tb.Schema+"."+tb.Name] || tb.Schema == "INFORMATION_SCHEMA" {
			t.Fatalf("listed twice or a system schema: %s.%s", tb.Schema, tb.Name)
		}
		seen[tb.Schema+"."+tb.Name] = true
	}
	if len(tables) != sfShowLimit+50+3 || !seen["PUBLIC.T10049"] || !seen["AUDIT.A3"] {
		t.Fatalf("%d tables listed, want %d", len(tables), sfShowLimit+53)
	}
	if !slices.Contains(fake.statements, `SHOW TABLES IN SCHEMA corebank."PUBLIC" LIMIT 10000 FROM 'T09999'`) {
		t.Fatalf("the second page starts at the last name of the first: %q", fake.statements)
	}
	audit, err := conn.ListTables(ctx, "AUDIT")
	if err != nil || len(audit) != 3 || audit[0].Ref != "A1" {
		t.Fatalf("a requested schema: %+v %v", audit, err)
	}
	// A cursor that does not move must not end the listing early.
	fake.ignoreFrom = true
	if _, err := conn.ListTables(ctx, ""); !errors.Is(err, errSfPaging) {
		t.Fatalf("an incomplete listing is an error: %v", err)
	}
}
