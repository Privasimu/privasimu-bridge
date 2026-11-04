package scan

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/privasimu/bridge/internal/dbsource"
	"github.com/privasimu/bridge/internal/detect"
	"github.com/privasimu/bridge/internal/testutil/fakedb"
)

// fakeEntities finds a name in every text that holds "atas nama", like a model would.
type fakeEntities struct {
	texts [][]string
	fail  bool
}

func (f *fakeEntities) Count(_ context.Context, texts []string) ([]map[detect.Category]int, error) {
	f.texts = append(f.texts, append([]string(nil), texts...))
	if f.fail {
		return nil, errors.New("the service is down")
	}
	out := make([]map[detect.Category]int, len(texts))
	for i, t := range texts {
		if strings.Contains(t, "atas nama") {
			out[i] = map[detect.Category]int{detect.PersonName: 1}
		}
	}
	return out, nil
}

func notesTable() fakedb.Table {
	tbl := fakedb.Table{Schema: "public", Name: "kunjungan", Columns: []dbsource.Column{fakedb.Int("id"), fakedb.Text("keterangan")}}
	for i := 0; i < 10; i++ {
		tbl.Rows = append(tbl.Rows, map[string]string{"keterangan": "kunjungan cabang oleh nasabah atas nama Budi Contoh pada pagi hari, dilayani di loket dua"})
	}
	return tbl
}

func TestLongTextGoesToTheEntityCounter(t *testing.T) {
	db := &fakedb.DB{Tables: []fakedb.Table{notesTable()}}
	c := open(t, db)
	tbl, _, _ := c.FindTable(context.Background(), "kunjungan", "")
	ec := &fakeEntities{}
	a, err := AnalyzeTable(context.Background(), c, tbl, DBOptions{Sampling: true, Rows: 10, Thresholds: detect.DefaultThresholds,
		Entities: ec, EntityMinChars: 40, EntityMaxBytes: 300})
	if err != nil {
		t.Fatal(err)
	}
	if len(ec.texts) != 1 || len(ec.texts[0]) != 3 {
		t.Fatalf("one request per column, bounded by max_bytes: %d requests", len(ec.texts))
	}
	f := a.Columns[1].Finding
	if !f.IsPII || f.Category != detect.PersonName || f.Source != detect.SourceContent || !f.Shadow {
		t.Fatalf("keterangan must hold names by content: %+v", f)
	}
}

func TestAFailingEntityCounterLeavesThePatterns(t *testing.T) {
	db := &fakedb.DB{Tables: []fakedb.Table{notesTable()}}
	c := open(t, db)
	tbl, _, _ := c.FindTable(context.Background(), "kunjungan", "")
	a, err := AnalyzeTable(context.Background(), c, tbl, DBOptions{Sampling: true, Rows: 10, Thresholds: detect.DefaultThresholds,
		Entities: &fakeEntities{fail: true}, EntityMinChars: 40, EntityMaxBytes: 300})
	if err != nil || !a.Sampled {
		t.Fatalf("%v %+v", err, a)
	}
	if f := a.Columns[1].Finding; f.IsPII {
		t.Fatalf("without the model the column holds no validated identifier: %+v", f)
	}
}
