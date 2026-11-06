package agent

// Contract P-4 (schemas per source): the inventory reports the schemas a database source's
// account can see, within the platforms' limits, and a scan covers the chosen schemas only.

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/privasimu/bridge/internal/config"
	"github.com/privasimu/bridge/internal/dbsource"
	"github.com/privasimu/bridge/internal/testutil/fakedb"
)

// withSchemas adds tables in the schemas hr and sales to the environment's database.
func withSchemas(e *env) {
	e.db.Tables = append(e.db.Tables,
		fakedb.Table{Schema: "hr", Name: "employees", Columns: []dbsource.Column{fakedb.Int("id"), fakedb.Text("nik")}},
		fakedb.Table{Schema: "sales", Name: "orders", Columns: []dbsource.Column{fakedb.Int("id"), fakedb.Text("email")}})
}

// inventoryHas reports whether the platform received an inventory body that contains want.
func (e *env) inventoryHas(want string) func() bool {
	return func() bool {
		e.fp.mu.Lock()
		defer e.fp.mu.Unlock()
		for _, b := range e.fp.bodies {
			if bytes.Contains(b, []byte(`"sources_digest"`)) && bytes.Contains(b, []byte(want)) {
				return true
			}
		}
		return false
	}
}

func TestInventoryReportsTheSchemasOfASource(t *testing.T) {
	e := newEnv(t, nil)
	withSchemas(e)
	e.enroll()
	a := e.agent()
	// After the start, the entry carries the schemas right after its capabilities.
	want := `"label":"Core banking","capabilities":["sampling"],"schemas":["hr","public","sales"]}`
	if !e.run(a, 10*time.Second, e.inventoryHas(want)) {
		t.Fatalf("no inventory with %s:\n%s", want, e.fp.allBodies())
	}
	// The file root has no schemas.
	if bytes.Contains(e.fp.allBodies(), []byte(`"engine":"filesystem","label":"HR share","capabilities":["path_mode:hashed","content_scan"],"schemas"`)) {
		t.Fatal("a file root has no schemas")
	}
	// The list is kept for the next start, before the database is read again.
	raw, err := os.ReadFile(filepath.Join(e.cfg.Resolve(e.cfg.StateDir), schemasFile))
	if err != nil || !bytes.Contains(raw, []byte(`"hr"`)) {
		t.Fatalf("state file: %v %s", err, raw)
	}
	next := e.agent()
	if l := next.schemaLists()["core-banking"]; !slices.Equal(l.Names, []string{"hr", "public", "sales"}) {
		t.Fatalf("a new agent starts with %+v", l)
	}
}

func TestSchemasFollowTheAllowList(t *testing.T) {
	e := newEnv(t, func(c *config.Config) { c.Sources[0].Schemas = []string{"PUBLIC", "hr"} })
	withSchemas(e)
	// Before the database is read, the allow-list itself is offered (byte order).
	list, _ := Inventory(e.cfg, nil, nil, nil)
	if !slices.Equal(list[0].Schemas, []string{"PUBLIC", "hr"}) {
		t.Fatalf("%+v", list[0])
	}
	// Once read, the database's names that the allow-list admits, in its spelling.
	list, _ = inventory(e.cfg, nil, nil, nil, map[string]schemaList{"core-banking": {Names: []string{"hr", "public", "sales"}}})
	if !slices.Equal(list[0].Schemas, []string{"hr", "public"}) {
		t.Fatalf("%+v", list[0])
	}
	// Without an allow-list nothing is known before the database is read: no key at all.
	e.cfg.Sources[0].Schemas = nil
	list, _ = Inventory(e.cfg, nil, nil, nil)
	raw, _ := json.Marshal(list[0])
	if list[0].Schemas != nil || bytes.Contains(raw, []byte(`"schemas"`)) {
		t.Fatalf("%s", raw)
	}
	// A database read with nothing visible is reported as an empty list.
	list, _ = inventory(e.cfg, nil, nil, nil, map[string]schemaList{"core-banking": {Names: []string{}}})
	if raw, _ = json.Marshal(list[0]); !bytes.HasSuffix(raw, []byte(`"schemas":[]}`)) {
		t.Fatalf("%s", raw)
	}
}

func TestSchemaListsKeepThePlatformLimits(t *testing.T) {
	cfg := &config.Config{Sources: []config.SourceConfig{
		{ID: "a-many", Engine: "oracle"}, {ID: "b-long", Engine: "postgresql"}, {ID: "c-mongo", Engine: "mongodb"},
	}}
	many := make([]string, 250)
	for i := range many {
		many[i] = "OWNER_" + strconv.Itoa(1000+i)
	}
	long := []string{strings.Repeat("x", 129), "public"} // a name over 128 characters cannot be chosen
	lists := map[string]schemaList{"a-many": {Names: many}, "b-long": {Names: long}, "c-mongo": {Names: []string{"app"}}}
	out := []Source{{ID: "a-many", Kind: "database", Capabilities: []string{}}, {ID: "b-long", Kind: "database", Capabilities: []string{}},
		{ID: "c-mongo", Kind: "database", Capabilities: []string{}}}
	addSchemas(cfg, out, lists)
	if len(out[0].Schemas) != maxSchemasPerSource || !slices.Contains(out[0].Capabilities, capSchemasPartial) {
		t.Fatalf("a-many: %d names, %v", len(out[0].Schemas), out[0].Capabilities)
	}
	if !slices.Equal(out[1].Schemas, []string{"public"}) || !slices.Contains(out[1].Capabilities, capSchemasPartial) {
		t.Fatalf("b-long: %+v", out[1])
	}
	if out[2].Schemas != nil {
		t.Fatal("MongoDB has no schemas")
	}
	// The names of the whole inventory stay within 32 768 bytes.
	big := make([]string, 200)
	for i := range big {
		big[i] = strings.Repeat("s", 100) + strconv.Itoa(1000+i) // 104 bytes each: 20 800 per source
	}
	out = []Source{{ID: "a-many", Kind: "database", Capabilities: []string{}}, {ID: "b-long", Kind: "database", Capabilities: []string{}}}
	addSchemas(cfg, out, map[string]schemaList{"a-many": {Names: big}, "b-long": {Names: big}})
	total := 0
	for _, s := range out {
		for _, n := range s.Schemas {
			total += len(n)
		}
	}
	if total > maxSchemaBytes || len(out[0].Schemas) != 200 || len(out[1].Schemas) == 0 || !slices.Contains(out[1].Capabilities, capSchemasPartial) {
		t.Fatalf("total %d bytes; %d and %d names; %v", total, len(out[0].Schemas), len(out[1].Schemas), out[1].Capabilities)
	}
	// What the agent sends is what the platforms accept.
	raw, _ := json.Marshal(map[string]any{"sources_digest": "sha256:" + strings.Repeat("0", 64), "sources": []Source{
		{ID: "a-many", Kind: "database", Engine: "oracle", Label: "a", Capabilities: out[0].Capabilities, Schemas: out[0].Schemas},
		{ID: "b-long", Kind: "database", Engine: "postgresql", Label: "b", Capabilities: out[1].Capabilities, Schemas: out[1].Schemas}}})
	m, _ := object(raw)
	if !validInventory(m, nil) {
		t.Fatal("the platforms would refuse this inventory")
	}
}

func TestPlatformSchemaRule(t *testing.T) {
	entry := func(kind, engine string, schemas any) map[string]any {
		s := map[string]any{"id": "src", "kind": kind, "engine": engine, "label": "Source", "capabilities": []any{}}
		if schemas != "absent" {
			s["schemas"] = schemas
		}
		raw, _ := json.Marshal(map[string]any{"sources_digest": "sha256:" + strings.Repeat("0", 64), "sources": []any{s}})
		m, _ := object(raw)
		return m
	}
	names := func(n int, name string) []string {
		out := make([]string, n)
		for i := range out {
			out[i] = name + strconv.Itoa(i)
		}
		return out
	}
	cases := []struct {
		name    string
		kind    string
		engine  string
		schemas any
		ok      bool
	}{
		{"absent", "database", "oracle", "absent", true},
		{"null", "database", "oracle", nil, true},
		{"empty", "database", "oracle", []string{}, true},
		{"200 names", "database", "oracle", names(200, "S"), true},
		{"201 names", "database", "oracle", names(201, "S"), false},
		{"128 characters", "database", "postgresql", []string{strings.Repeat("é", 128)}, true},
		{"129 characters", "database", "postgresql", []string{strings.Repeat("é", 129)}, false},
		{"empty name", "database", "postgresql", []string{""}, false},
		{"control character", "database", "postgresql", []string{"a\tb"}, false},
		{"not a list", "database", "postgresql", "public", false},
		{"over 32 KiB", "database", "postgresql", names(200, strings.Repeat("n", 170)), false},
		{"ignored on a file root", "files", "filesystem", "public", true},
	}
	for _, c := range cases {
		if got := validInventory(entry(c.kind, c.engine, c.schemas), nil); got != c.ok {
			t.Errorf("%s: accepted %v, want %v", c.name, got, c.ok)
		}
	}
}

func TestScanCoversTheChosenSchemas(t *testing.T) {
	e := newEnv(t, nil)
	withSchemas(e)
	e.enroll()
	e.fp.enqueue(Job{JobID: "j", Type: JobScanDatabase, SourceID: "core-banking", Options: JobOptions{Schemas: []string{"sales", "hr", "hr"}}})
	a := e.agent()
	if !e.run(a, 15*time.Second, e.finished("j")) {
		t.Fatal("job did not finish")
	}
	j := e.fp.job("j")
	if j.completed == nil {
		t.Fatalf("failed: %+v", j.failed)
	}
	var names []string
	for _, it := range e.fp.items("j") {
		var item struct {
			Name string `json:"name"`
		}
		_ = json.Unmarshal(it, &item)
		names = append(names, item.Name)
	}
	slices.Sort(names)
	if !slices.Equal(names, []string{"hr.employees", "sales.orders"}) {
		t.Fatalf("tables %v, want only the chosen schemas", names)
	}
	var res DatabaseResult
	raw, _ := json.Marshal(j.completed.Result)
	_ = json.Unmarshal(raw, &res)
	if res.TablesTotal != 2 || res.Truncated {
		t.Fatalf("%+v", res)
	}
}

func TestChosenSchemasMustBeAllowed(t *testing.T) {
	allow := &config.SourceConfig{ID: "s", Engine: "oracle", Schemas: []string{"HR", "Sales"}}
	open := &config.SourceConfig{ID: "s", Engine: "postgresql"}
	mongo := &config.SourceConfig{ID: "s", Engine: "mongodb"}
	if got, err := chosenSchemas(allow, []string{"SALES", "hr", "hr"}); err != nil || !slices.Equal(got, []string{"SALES", "hr"}) {
		t.Fatalf("%v %v", got, err)
	}
	if got, err := chosenSchemas(open, []string{"crm"}); err != nil || !slices.Equal(got, []string{"crm"}) {
		t.Fatalf("without an allow-list any name may be chosen: %v %v", got, err)
	}
	refused := map[string]struct {
		src   *config.SourceConfig
		names []string
	}{
		"outside the allow-list": {allow, []string{"HR", "FIN"}},
		"MongoDB":                {mongo, []string{"app"}},
		"empty name":             {open, []string{""}},
		"too long":               {open, []string{strings.Repeat("x", 129)}},
		"control character":      {open, []string{"a\nb"}},
		"over 100 names":         {open, make([]string, 101)},
	}
	for name, c := range refused {
		var je *jobError
		if _, err := chosenSchemas(c.src, c.names); !errors.As(err, &je) || je.code != FailInvalidOptions || je.stage != "accept" {
			t.Errorf("%s: %v", name, err)
		}
	}
	// A job with a refused choice fails before connecting.
	e := newEnv(t, func(c *config.Config) { c.Sources[0].Schemas = []string{"public"} })
	e.enroll()
	e.fp.enqueue(Job{JobID: "j", Type: JobScanDatabase, SourceID: "core-banking", Options: JobOptions{Schemas: []string{"hr"}}})
	a := e.agent()
	if !e.run(a, 10*time.Second, e.finished("j")) {
		t.Fatal("job did not finish")
	}
	if f := e.fp.job("j").failed; f == nil || f.ErrorCode != FailInvalidOptions || f.Stage != "accept" || f.Retryable {
		t.Fatalf("%+v", f)
	}
}

// TestConnectionTestRefreshesTheSchemas: "Uji Koneksi" on the platform reads the list again,
// and the changed list reaches the platform with the next inventory.
func TestConnectionTestRefreshesTheSchemas(t *testing.T) {
	e := newEnv(t, nil)
	withSchemas(e)
	e.enroll()
	a := e.agent()
	if !e.run(a, 10*time.Second, e.inventoryHas(`"schemas":["hr","public","sales"]`)) {
		t.Fatal("no first list")
	}
	e.db.SetSchemaList([]string{"finance", "hr", "public", "sales"})
	e.fp.enqueue(Job{JobID: "t", Type: JobTestSource, SourceID: "core-banking"})
	if !e.run(a, 10*time.Second, e.inventoryHas(`"schemas":["finance","hr","public","sales"]`)) {
		t.Fatalf("the test did not refresh the list:\n%s", e.fp.allBodies())
	}
	if j := e.fp.job("t"); j.completed == nil {
		t.Fatalf("test failed: %+v", j.failed)
	}
}
