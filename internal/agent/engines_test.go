package agent

import (
	"context"
	"log/slog"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/privasimu/bridge/internal/config"
)

// countingHandler counts log records whose message contains a text.
type countingHandler struct {
	text string
	n    *atomic.Int32
}

func (h countingHandler) Enabled(context.Context, slog.Level) bool { return true }
func (h countingHandler) Handle(_ context.Context, r slog.Record) error {
	if strings.Contains(r.Message, h.text) {
		h.n.Add(1)
	}
	return nil
}
func (h countingHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h countingHandler) WithGroup(string) slog.Handler      { return h }

func (f *fakePlatform) inventoryIDs() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.sources == nil {
		return nil
	}
	ids := []string{}
	for _, s := range f.sources.Sources {
		ids = append(ids, s.ID)
	}
	return ids
}

func (f *fakePlatform) setFeatures(features []string) {
	f.mu.Lock()
	f.features = features
	f.mu.Unlock()
}

// TestFurtherEnginesAreOfferedOnlyToAPlatformThatAcceptsThem: a platform of revision 2 or
// 3 refuses a whole inventory with an engine it does not know, so a ClickHouse source is
// only sent once the poll answer lists source_engine:clickhouse (revision 4), and no
// longer after a downgrade.
func TestFurtherEnginesAreOfferedOnlyToAPlatformThatAcceptsThem(t *testing.T) {
	e := newEnv(t, func(c *config.Config) {
		c.Sources = append(c.Sources, config.SourceConfig{ID: "events", Label: "Events", Engine: "clickhouse", Host: "ch.internal",
			Port: 8123, Database: "events", Username: "ro", Password: "secret:corebank_pg",
			TLS: config.SourceTLS{Mode: config.DBTLSDisable}, Timeout: config.Duration(20 * time.Second)})
	})
	e.enroll()
	e.fp.setFeatures([]string{FeatureSourceKindPackages, FeatureJobScanPackages})
	a := e.agent()
	var warned atomic.Int32
	a.log = slog.New(countingHandler{text: "does not accept this engine", n: &warned})
	has := func(id string) bool { return slices.Contains(e.fp.inventoryIDs(), id) }
	polls := func(n int) func() bool {
		start := e.fp.pollCount()
		return func() bool { return e.fp.pollCount() >= start+n }
	}
	if !e.run(a, 10*time.Second, polls(3)) || has("events") || !has("core-banking") {
		t.Fatalf("a revision 3 platform must not get the ClickHouse source: %v", e.fp.inventoryIDs())
	}
	if warned.Load() != 1 {
		t.Fatalf("the operator is told once that the source is withheld, got %d", warned.Load())
	}
	e.fp.setFeatures([]string{FeatureSourceKindPackages, FeatureJobScanPackages, FeatureSourceEnginePrefix + "clickhouse"})
	if !e.run(a, 10*time.Second, func() bool { return has("events") }) {
		t.Fatalf("the source must be sent once the platform accepts its engine: %v", e.fp.inventoryIDs())
	}
	e.fp.setFeatures(nil) // a downgrade to revision 2
	if !e.run(a, 10*time.Second, func() bool { return !has("events") }) {
		t.Fatalf("after a downgrade the source must be left out again: %v", e.fp.inventoryIDs())
	}
}

func TestInventoryFeaturesAndWithheldSources(t *testing.T) {
	got := inventoryFeatures([]string{"job:scan_packages", "source_engine:redshift", "source_kind:packages", "x:y", "source_engine:redshift"})
	if strings.Join(got, ",") != "source_engine:redshift,source_kind:packages" {
		t.Fatalf("%v", got)
	}
	cfg := &config.Config{Sources: []config.SourceConfig{{ID: "a", Engine: "postgresql"}, {ID: "b", Engine: "redshift"}, {ID: "c", Engine: "clickhouse"}}}
	if w := Withheld(cfg, []string{"source_engine:redshift"}); strings.Join(w, ",") != "c" {
		t.Fatalf("%v", w)
	}
	list, _ := Inventory(cfg, nil, nil, []string{"source_engine:redshift"})
	if len(list) != 2 || list[1].ID != "b" || list[1].Engine != "redshift" || list[1].Kind != "database" {
		t.Fatalf("%+v", list)
	}
}

func (f *fakePlatform) pollCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.polls
}
