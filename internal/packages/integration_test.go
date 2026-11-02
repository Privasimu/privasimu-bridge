//go:build integration

package packages

// Opt-in test with the real scanners, which the operator installs (the tests never
// download a tool):
//
//	BRIDGE_IT_SYFT=/opt/privasimu-bridge/tools/syft \
//	BRIDGE_IT_GRYPE=/opt/privasimu-bridge/tools/grype \
//	BRIDGE_IT_GRYPE_DB_DIR=/var/lib/privasimu-bridge/grype-db \
//	go test -tags integration -run TestRealScanners ./internal/packages/
//
// Without BRIDGE_IT_GRYPE the inventory alone is checked. BRIDGE_IT_GRYPE_DB_DIR is copied
// into the test's state directory (the bridge only lets Grype use a database inside it).

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/privasimu/bridge/internal/config"
)

func fileSHA256(t *testing.T, p string) string {
	t.Helper()
	f, err := os.Open(p)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(h.Sum(nil))
}

func copyTree(t *testing.T, from, to string) {
	t.Helper()
	err := filepath.Walk(from, func(p string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(from, p)
		dst := filepath.Join(to, rel)
		if fi.IsDir() {
			return os.MkdirAll(dst, 0o700)
		}
		raw, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(dst, raw, 0o600)
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestRealScanners(t *testing.T) {
	syft := os.Getenv("BRIDGE_IT_SYFT")
	if syft == "" {
		t.Skip("set BRIDGE_IT_SYFT (and optionally BRIDGE_IT_GRYPE, BRIDGE_IT_GRYPE_DB_DIR)")
	}
	grype := os.Getenv("BRIDGE_IT_GRYPE")
	dir := t.TempDir()
	app := filepath.Join(dir, "app")
	// A small npm project with a known-vulnerable lodash.
	lock := `{"name":"it","version":"1.0.0","lockfileVersion":3,"requires":true,"packages":{"":{"name":"it","version":"1.0.0","dependencies":{"lodash":"4.17.20"}},"node_modules/lodash":{"version":"4.17.20","resolved":"https://registry.npmjs.org/lodash/-/lodash-4.17.20.tgz","license":"MIT"}}}`
	if err := os.MkdirAll(app, 0o755); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(app, "package.json"), []byte(`{"name":"it","version":"1.0.0","dependencies":{"lodash":"4.17.20"}}`), 0o644)
	_ = os.WriteFile(filepath.Join(app, "package-lock.json"), []byte(lock), 0o644)
	matcher := config.MatcherNone
	yaml := "state_dir: " + strconv.Quote(filepath.Join(dir, "state")) + "\npackages:\n  targets:\n    - {id: app, kind: directory, path: " +
		strconv.Quote(app) + "}\n  tools:\n    syft: {path: " + strconv.Quote(syft) + ", sha256: " + fileSHA256(t, syft) + "}\n"
	if grype != "" {
		matcher = config.MatcherGrype
		yaml += "    grype: {path: " + strconv.Quote(grype) + ", sha256: " + fileSHA256(t, grype) + "}\n"
	}
	yaml += "    matcher: " + matcher + "\n"
	cfg, err := config.Parse([]byte(yaml))
	if err != nil {
		t.Fatal(err)
	}
	cfg.SetPath(filepath.Join(dir, "bridge.yaml"))
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	if db := os.Getenv("BRIDGE_IT_GRYPE_DB_DIR"); db != "" && grype != "" {
		copyTree(t, db, cfg.Resolve(cfg.Packages.Tools.Grype.DBDir))
	}
	svc, err := NewService(cfg, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	rep, err := svc.Run(ctx, "app", ScanOptions{Refresh: true, Match: true}, nil)
	if err != nil {
		t.Fatal(err)
	}
	lodash := itemByName(rep, "lodash")
	if lodash == nil || lodash.Ecosystem != "npm" || rep.Result.InventoryToolVersion == "unknown" {
		t.Fatalf("%+v %+v", rep.Result, rep.Items)
	}
	if grype != "" && (len(lodash.Matches) == 0 || rep.Result.MatcherVersion == nil) {
		t.Fatalf("Grype found nothing for lodash 4.17.20: %+v", rep.Result)
	}
	t.Logf("syft %s, matcher %s, %d packages, %d matches", rep.Result.InventoryToolVersion, rep.Result.Matcher,
		rep.Result.PackagesTotal, rep.Result.MatchesTotal)
}
