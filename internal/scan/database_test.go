package scan

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/privasimu/bridge/internal/dbsource"
	"github.com/privasimu/bridge/internal/detect"
	"github.com/privasimu/bridge/internal/testutil/fakedb"
)

func customers() fakedb.Table {
	rows := []map[string]string{}
	for i := 0; i < 10; i++ {
		rows = append(rows, map[string]string{
			"nik": "3171012303900001", "kontak": "0812-3456-7890", "kode": "ABC", "email_pelanggan": "budi.contoh@example.co.id",
		})
	}
	return fakedb.Table{Schema: "public", Name: "nasabah", Rows: rows, Columns: []dbsource.Column{
		fakedb.Int("id"), fakedb.Text("nik"), fakedb.Text("kontak"), fakedb.Text("kode"), fakedb.Text("email_pelanggan"),
		fakedb.Text("bad\nname"),
	}}
}

func open(t *testing.T, db *fakedb.DB) dbsource.Conn {
	t.Helper()
	c, err := db.Opener()(context.Background(), dbsource.Target{Engine: "postgresql"})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestAnalyzeTableByNameOnly(t *testing.T) {
	db := &fakedb.DB{Tables: []fakedb.Table{customers()}}
	c := open(t, db)
	tbl, ok, _ := c.FindTable(context.Background(), "nasabah", "")
	if !ok {
		t.Fatal("table not found")
	}
	a, err := AnalyzeTable(context.Background(), c, tbl, DBOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if db.Sampled != 0 || a.Sampled {
		t.Fatal("no value may be read when sampling is off")
	}
	if len(a.Columns) != 5 || a.Omitted != 1 {
		t.Fatalf("a column name the platform cannot store is left out and counted: %+v", a)
	}
	got := map[string]detect.Finding{}
	for _, col := range a.Columns {
		got[col.Name] = col.Finding
	}
	if !got["nik"].IsPII || got["nik"].Category != detect.NIK || got["nik"].Source != detect.SourceName {
		t.Fatalf("nik: %+v", got["nik"])
	}
	if got["kontak"].IsPII || got["kode"].IsPII || got["id"].IsPII {
		t.Fatalf("names alone do not reveal kontak/kode/id: %+v", got)
	}
}

func TestAnalyzeTableWithSamplingFindsHiddenData(t *testing.T) {
	db := &fakedb.DB{Tables: []fakedb.Table{customers()}}
	c := open(t, db)
	tbl, _, _ := c.FindTable(context.Background(), "nasabah", "")
	a, err := AnalyzeTable(context.Background(), c, tbl, DBOptions{Sampling: true, Rows: 50, Thresholds: detect.DefaultThresholds})
	if err != nil {
		t.Fatal(err)
	}
	if !a.Sampled {
		t.Fatalf("%+v", a)
	}
	got := map[string]detect.Finding{}
	for _, col := range a.Columns {
		got[col.Name] = col.Finding
	}
	if f := got["kontak"]; !f.IsPII || f.Category != detect.Phone || !f.Shadow || f.Source != detect.SourceContent {
		t.Fatalf("kontak: %+v", f)
	}
	if f := got["nik"]; f.Source != detect.SourceNameContent || f.Content == nil || f.Content.Protection != detect.ProtectionPlaintext {
		t.Fatalf("nik: %+v", f)
	}
	if f := got["kode"]; f.IsPII {
		t.Fatalf("kode: %+v", f)
	}
	raw, _ := json.Marshal(a)
	for _, v := range []string{"3171012303900001", "0812-3456-7890", "budi.contoh"} {
		if strings.Contains(string(raw), v) {
			t.Fatalf("the analysis carries a value %q: %s", v, raw)
		}
	}
}

func TestSamplingFailureKeepsNameFindings(t *testing.T) {
	db := &fakedb.DB{Tables: []fakedb.Table{customers()}, Fail: map[string]error{"sample": &dbsource.Error{Kind: dbsource.KindPermission, Op: "sample"}}}
	c := open(t, db)
	tbl, _, _ := c.FindTable(context.Background(), "nasabah", "")
	a, err := AnalyzeTable(context.Background(), c, tbl, DBOptions{Sampling: true, Rows: 10})
	if err != nil {
		t.Fatal(err)
	}
	if a.Sampled || a.SamplingError != dbsource.KindPermission {
		t.Fatalf("%+v", a)
	}
	if a.Columns[1].Finding.Category != detect.NIK {
		t.Fatalf("%+v", a.Columns[1])
	}
}

func TestListTablesIsBounded(t *testing.T) {
	db := &fakedb.DB{}
	for _, n := range []string{"a", "b", "c", "d"} {
		db.Tables = append(db.Tables, fakedb.Table{Schema: "public", Name: n})
	}
	db.Tables = append(db.Tables, fakedb.Table{Schema: "hr", Name: "staff"})
	c := open(t, db)
	tables, total, err := ListTables(context.Background(), c, DBOptions{MaxTables: 3})
	if err != nil || total != 5 || len(tables) != 3 {
		t.Fatalf("%v %d %v", tables, total, err)
	}
	all, _, _ := ListTables(context.Background(), c, DBOptions{})
	if all[len(all)-1].Ref != "hr.staff" {
		t.Fatalf("tables outside the default schema are qualified and listed last: %+v", all)
	}
}

func TestDatabaseScan(t *testing.T) {
	db := &fakedb.DB{Tables: []fakedb.Table{customers(), {Schema: "public", Name: "empty", Columns: []dbsource.Column{fakedb.Int("id")}}}}
	c := open(t, db)
	var calls int
	res, err := Database(context.Background(), c, DBOptions{Sampling: true, Rows: 5, Concurrency: 2}, func(done, total int) { calls++ })
	if err != nil {
		t.Fatal(err)
	}
	if res.TablesTotal != 2 || len(res.Tables) != 2 || len(res.Failed) != 0 || calls != 2 || !res.Sampling {
		t.Fatalf("%+v calls=%d", res, calls)
	}
	db.Fail = map[string]error{"columns": &dbsource.Error{Kind: dbsource.KindPermission, Op: "columns"}}
	res, err = Database(context.Background(), c, DBOptions{}, nil)
	if err != nil || len(res.Failed) != 2 || res.Failed[0].Kind != dbsource.KindPermission {
		t.Fatalf("%+v %v", res, err)
	}
}

func TestDatabaseScanStopsAtTheDeadline(t *testing.T) {
	db := &fakedb.DB{Tables: []fakedb.Table{customers()}, Delay: 200 * time.Millisecond}
	c := open(t, db)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := Database(ctx, c, DBOptions{}, nil); !errors.Is(err, context.DeadlineExceeded) && dbsource.KindOf(err) != dbsource.KindTimeout {
		t.Fatalf("%v", err)
	}
}
