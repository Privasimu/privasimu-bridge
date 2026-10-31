package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/privasimu/bridge/internal/config"
	"github.com/privasimu/bridge/internal/files"
)

func TestFileEndpoints(t *testing.T) {
	share := t.TempDir()
	if err := os.WriteFile(filepath.Join(share, "data.csv"), []byte("nik\n3171012303900001\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var svc *files.Service
	h := newHarness(t, func(c *config.Config) {
		c.Server.FileEndpoints = true
		c.Files.Roots = []config.FileRoot{{ID: "hr-share", Label: "HR", Path: share, MaxFiles: 100, MaxDepth: 5,
			ReportPaths: config.PathsHashed}}
		var err error
		svc, err = files.NewService(c, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
	})
	h.srv.files = svc

	resp, body := h.post(PathFileRoots, map[string]any{}, nil)
	if resp.StatusCode != 200 || !bytes.Contains(body, []byte(`"id":"hr-share"`)) || bytes.Contains(body, []byte(share)) {
		t.Fatalf("roots: %d %s", resp.StatusCode, body)
	}
	resp, body = h.post(PathFileRootReport, map[string]any{"root_id": "hr-share"}, nil)
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("a root that was never scanned: %d %s", resp.StatusCode, body)
	}
	for _, bad := range []map[string]any{{"root_id": "../etc"}, {"root_id": share}, {"root_id": "unknown"}} {
		resp, _ = h.post(PathFileRootScan, bad, nil)
		if resp.StatusCode != http.StatusBadRequest && resp.StatusCode != http.StatusNotFound {
			t.Fatalf("%v: %d", bad, resp.StatusCode)
		}
	}
	resp, _ = h.post(PathFileRootScan, map[string]any{"root_id": "hr-share"}, nil)
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("scan: %d", resp.StatusCode)
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		resp, body = h.post(PathFileRootReport, map[string]any{"root_id": "hr-share", "page": 1, "page_size": 10}, nil)
		if resp.StatusCode == 200 || time.Now().After(deadline) {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	var rep reportResponse
	if err := json.Unmarshal(body, &rep); err != nil || resp.StatusCode != 200 {
		t.Fatalf("%d %s", resp.StatusCode, body)
	}
	if rep.Summary.Totals["nik"] != 1 || len(rep.Files) != 1 || rep.Files[0].Path != "" || rep.Pages != 1 {
		t.Fatalf("%+v", rep)
	}
	for _, leak := range []string{"3171012303900001", "data.csv", share} {
		if bytes.Contains(body, []byte(leak)) {
			t.Fatalf("the report carries %q: %s", leak, body)
		}
	}
	// Without the switch the endpoints do not exist.
	h.cfg.Server.FileEndpoints = false
	if resp, _ = h.post(PathFileRoots, map[string]any{}, nil); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("%d", resp.StatusCode)
	}
}
