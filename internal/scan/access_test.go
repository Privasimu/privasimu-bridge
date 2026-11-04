package scan

import (
	"context"
	"testing"

	"github.com/privasimu/bridge/internal/dbsource"
	"github.com/privasimu/bridge/internal/detect"
	"github.com/privasimu/bridge/internal/testutil/fakedb"
)

func TestAccessIsReadForTablesWithPersonalData(t *testing.T) {
	plain := fakedb.Table{Schema: "public", Name: "kurs", Columns: []dbsource.Column{fakedb.Int("id"), fakedb.Int("nilai")}}
	db := &fakedb.DB{Tables: []fakedb.Table{customers(), plain},
		Access: map[string]dbsource.Access{"nasabah": {Readers: 3, Complete: true}, "kurs": {Readers: 9}}}
	c := open(t, db)
	for name, want := range map[string]bool{"nasabah": true, "kurs": false} {
		tbl, _, _ := c.FindTable(context.Background(), name, "")
		a, err := AnalyzeTable(context.Background(), c, tbl, DBOptions{Access: true, Thresholds: detect.DefaultThresholds})
		if err != nil {
			t.Fatal(err)
		}
		if (a.Access != nil) != want {
			t.Fatalf("%s: access %+v", name, a.Access)
		}
	}
	tbl, _, _ := c.FindTable(context.Background(), "nasabah", "")
	if a, _ := AnalyzeTable(context.Background(), c, tbl, DBOptions{}); a.Access != nil {
		t.Fatal("off unless asked")
	}
	db.Fail = map[string]error{"access": &dbsource.Error{Kind: dbsource.KindPermission, Op: "access"}}
	if a, err := AnalyzeTable(context.Background(), c, tbl, DBOptions{Access: true}); err != nil || a.Access != nil || a.AccessError != dbsource.KindPermission {
		t.Fatalf("a failure is reported as a kind, the table stays: %v %+v", err, a)
	}
	db.Fail, db.Access = nil, nil
	if a, err := AnalyzeTable(context.Background(), c, tbl, DBOptions{Access: true}); err != nil || a.Access != nil || a.AccessError != "" {
		t.Fatalf("an engine without the inventory: %v %+v", err, a)
	}
}
