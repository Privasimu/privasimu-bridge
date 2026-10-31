package audit

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLogWritesJSONLinesAndRotates(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")
	l, err := Open(path, 1, 3)
	if err != nil {
		t.Fatal(err)
	}
	l.maxBytes = 2000
	tick := time.Date(2026, 10, 31, 0, 0, 0, 0, time.UTC)
	l.now = func() time.Time { tick = tick.Add(time.Second); return tick }
	for i := 0; i < 50; i++ {
		l.Log(Event{Event: "request", Endpoint: "/v1/name-database-tabels", Status: 200, Outcome: OK, Tables: i,
			Counts: map[string]int{"nik": i}})
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	lines := 0
	for sc.Scan() {
		var e Event
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			t.Fatalf("line %d is not JSON: %v", lines, err)
		}
		if e.Event != "request" || e.Time.IsZero() {
			t.Fatalf("%+v", e)
		}
		lines++
	}
	if lines == 0 {
		t.Fatal("the current file is empty")
	}
	rotated, _ := filepath.Glob(filepath.Join(dir, "audit-*.jsonl"))
	if len(rotated) == 0 || len(rotated) > 2 {
		t.Fatalf("rotated files = %d, want 1..2 (max_files 3 including the current one)", len(rotated))
	}
}

func TestDiscardAndNil(t *testing.T) {
	Discard().Log(Event{Event: "x"})
	var l *Logger
	l.Log(Event{Event: "x"})
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
}
