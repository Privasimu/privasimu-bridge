package scan

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/privasimu/bridge/internal/dbsource"
	"github.com/privasimu/bridge/internal/testutil/fakedb"
)

// TestDatabaseEndsAtTheDeadlineWhenATableNeverReturns: a sampling call that ignores its
// context (a stuck driver, or a detector that loops) must not hold the scan past its
// deadline. The scan returns the deadline error on time and its tracker names the table and
// the step it stopped at; nothing in it is a value.
func TestDatabaseEndsAtTheDeadlineWhenATableNeverReturns(t *testing.T) {
	stuck := make(chan struct{})
	t.Cleanup(func() { close(stuck) })
	db := &fakedb.DB{Tables: []fakedb.Table{customers()}, Stuck: map[string]chan struct{}{"sample": stuck}}
	c := open(t, db)
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	track := &Tracker{}
	started := time.Now()
	_, err := Database(ctx, c, DBOptions{Sampling: true, Rows: 5, Track: track}, nil)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want the deadline", err)
	}
	if took := time.Since(started); took > 5*time.Second {
		t.Fatalf("the scan returned after %s: it waited for a table that never returns", took)
	}
	w := track.Where()
	if w.Stage != StageTables || w.Table != "public.nasabah" || w.Step != StageSampling || w.Done != 0 || w.Total != 1 {
		t.Fatalf("where = %+v", w)
	}
}

// slowColumns reads columns slowly but honours its context, as a well-behaved driver does.
type slowColumns struct {
	dbsource.Conn
	delay time.Duration
}

func (s slowColumns) Columns(ctx context.Context, t dbsource.Table) ([]dbsource.Column, error) {
	select {
	case <-time.After(s.delay):
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	return s.Conn.Columns(ctx, t)
}

// TestTrackerNamesTheStepOfAStoppedTable: a table that ends because the scan's context
// ended stays named, with the step it was in, also after its worker returned.
func TestTrackerNamesTheStepOfAStoppedTable(t *testing.T) {
	db := &fakedb.DB{Tables: []fakedb.Table{customers()}}
	c := slowColumns{Conn: open(t, db), delay: time.Minute}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	track := &Tracker{}
	if _, err := Database(ctx, c, DBOptions{Track: track}, nil); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want the deadline", err)
	}
	time.Sleep(100 * time.Millisecond) // the worker has returned by now
	if w := track.Where(); w.Stage != StageTables || w.Table != "public.nasabah" || w.Step != StageColumns {
		t.Fatalf("where = %+v", w)
	}
}

// TestTrackerForgetsFinishedTables: tables that finish normally are not named; a scan that
// ends names no table.
func TestTrackerForgetsFinishedTables(t *testing.T) {
	db := &fakedb.DB{Tables: []fakedb.Table{customers()}}
	track := &Tracker{}
	if _, err := Database(context.Background(), open(t, db), DBOptions{Sampling: true, Rows: 5, Track: track}, nil); err != nil {
		t.Fatal(err)
	}
	if w := track.Where(); w.Stage != StageTables || w.Done != 1 || w.Total != 1 || w.Table != "" {
		t.Fatalf("where = %+v", w)
	}
}

// TestDatabaseFinishesOnFreeTextThatLoopedBefore runs a whole scan over a column whose values
// made the text counter loop for ever (B-1 of the 6 November 2026 staging report).
func TestDatabaseFinishesOnFreeTextThatLoopedBefore(t *testing.T) {
	rows := []map[string]string{}
	for _, v := range []string{"2+2 = 4", "Lantai(2) gedung timur", "kirim ke budi+0812345678@example.co.id", "rumus x+1 lalu f(3)"} {
		rows = append(rows, map[string]string{"catatan": v})
	}
	db := &fakedb.DB{Tables: []fakedb.Table{{Schema: "public", Name: "catatan_cabang", Rows: rows,
		Columns: []dbsource.Column{fakedb.Text("catatan")}}}}
	c := open(t, db)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := Database(ctx, c, DBOptions{Sampling: true, Rows: 10}, nil)
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the scan of free text did not finish: the detector loops")
	}
}

func TestQualifiedNamesFitTheNameRule(t *testing.T) {
	if got := qualified("HR", "EMPLOYEES"); got != "HR.EMPLOYEES" {
		t.Fatal(got)
	}
	if got := qualified("", "nasabah"); got != "nasabah" {
		t.Fatal(got)
	}
	long := qualified(strings.Repeat("é", 100), strings.Repeat("ü", 100)) // 401 bytes
	if len(long) > 255 || !strings.HasPrefix(long, "é") || strings.ContainsRune(long, '�') {
		t.Fatalf("%d bytes: %q", len(long), long)
	}
	for _, r := range long {
		if r == 0xFFFD {
			t.Fatal("cut inside a character")
		}
	}
}
