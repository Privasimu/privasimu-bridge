package files

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/privasimu/bridge/internal/config"
	"github.com/privasimu/bridge/internal/detect"
	"github.com/privasimu/bridge/internal/secrets"
)

// FileResult is one file in the local report. Path stays on this server; what leaves is
// the outbound view (View), where the path is replaced by a keyed hash unless the root
// is configured with report_paths: relative.
type FileResult struct {
	Path       string                  `json:"path"`
	ID         string                  `json:"id"`
	Ext        string                  `json:"ext"`
	SizeBytes  int64                   `json:"size_bytes"`
	Modified   string                  `json:"modified"`
	Categories map[detect.Category]int `json:"categories,omitempty"`
	// NameHint is the category the file name suggests (content scanning off).
	NameHint  detect.Category `json:"name_hint,omitempty"`
	Truncated bool            `json:"truncated,omitempty"`
	Skipped   string          `json:"skipped,omitempty"`
}

// Report is the local result of scanning one root.
type Report struct {
	RootID       string                  `json:"root_id"`
	Label        string                  `json:"label"`
	ContentScan  bool                    `json:"content_scan"`
	PathMode     string                  `json:"path_mode"`
	StartedAt    time.Time               `json:"started_at"`
	FinishedAt   time.Time               `json:"finished_at"`
	DurationMS   int64                   `json:"duration_ms"`
	FilesSeen    int                     `json:"files_seen"`
	FilesScanned int                     `json:"files_scanned"`
	FilesWithPII int                     `json:"files_with_pii"`
	Totals       map[detect.Category]int `json:"totals"`
	Skipped      map[string]int          `json:"skipped"`
	Extensions   map[string]int          `json:"extensions"`
	Truncated    bool                    `json:"truncated"`
	// Files lists the files with findings (and, locally, those that failed to parse).
	Files []FileResult `json:"files"`
}

// Summary is the part of a report that describes the whole root.
type Summary struct {
	RootID       string         `json:"root_id"`
	Label        string         `json:"label"`
	ContentScan  bool           `json:"content_scan"`
	PathMode     string         `json:"path_mode"`
	ScannedAt    time.Time      `json:"scanned_at"`
	DurationMS   int64          `json:"duration_ms"`
	FilesSeen    int            `json:"files_seen"`
	FilesScanned int            `json:"files_scanned"`
	FilesWithPII int            `json:"files_with_pii"`
	Totals       map[string]int `json:"totals"`
	Skipped      map[string]int `json:"skipped"`
	Extensions   map[string]int `json:"extensions"`
	Truncated    bool           `json:"truncated"`
}

// FileFinding is one file as reported outside the network: an id, the extension, size,
// modification date and counts per category. Path is present only with
// report_paths: relative.
type FileFinding struct {
	ID         string         `json:"id"`
	Path       string         `json:"path,omitempty"`
	Ext        string         `json:"ext"`
	SizeBytes  int64          `json:"size_bytes"`
	Modified   string         `json:"modified"`
	Categories map[string]int `json:"categories"`
	PDP        string         `json:"pdp_category,omitempty"`
	NameHint   string         `json:"name_hint,omitempty"`
	Truncated  bool           `json:"truncated,omitempty"`
}

// View is the outbound form of a report.
type View struct {
	Summary Summary       `json:"summary"`
	Files   []FileFinding `json:"files"`
}

func stringCounts(m map[detect.Category]int) map[string]int {
	out := make(map[string]int, len(m))
	for k, v := range m {
		out[string(k)] = v
	}
	return out
}

// Summary returns the root-level part of the report.
func (r *Report) Summary() Summary {
	return Summary{RootID: r.RootID, Label: r.Label, ContentScan: r.ContentScan, PathMode: r.PathMode,
		ScannedAt: r.FinishedAt, DurationMS: r.DurationMS, FilesSeen: r.FilesSeen, FilesScanned: r.FilesScanned,
		FilesWithPII: r.FilesWithPII, Totals: stringCounts(r.Totals), Skipped: r.Skipped, Extensions: r.Extensions,
		Truncated: r.Truncated}
}

// View returns what may leave the network: findings only, with paths hashed unless the
// root reports relative paths. Files that failed to parse are counted in the summary but
// not listed.
func (r *Report) View() View {
	v := View{Summary: r.Summary(), Files: []FileFinding{}}
	for _, f := range r.Files {
		if len(f.Categories) == 0 && f.NameHint == "" {
			continue
		}
		ff := FileFinding{ID: f.ID, Ext: f.Ext, SizeBytes: f.SizeBytes, Modified: f.Modified,
			Categories: stringCounts(f.Categories), NameHint: string(f.NameHint), Truncated: f.Truncated}
		if r.PathMode == config.PathsRelative {
			ff.Path = f.Path
		}
		ff.PDP = strongestPDP(f.Categories, f.NameHint)
		v.Files = append(v.Files, ff)
	}
	return v
}

func strongestPDP(cats map[detect.Category]int, hint detect.Category) string {
	pdp := ""
	for c, n := range cats {
		if n <= 0 {
			continue
		}
		switch detect.PDPOf(c) {
		case detect.PDPSpecific:
			return detect.PDPSpecific
		case detect.PDPGeneral:
			pdp = detect.PDPGeneral
		}
	}
	if pdp == "" && hint != "" {
		pdp = detect.PDPOf(hint)
	}
	return pdp
}

// FileID returns the keyed hash that names a file outside the network. The same file
// keeps its id across scans; without the key the id cannot be turned back into a path.
func FileID(key []byte, rootID, rel string) string {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(rootID))
	m.Write([]byte{0})
	m.Write([]byte(rel))
	return "f_" + hex.EncodeToString(m.Sum(nil)[:8])
}

// LoadOrCreateKey returns the file-id key kept in the state directory, creating it on
// first use with owner-only permissions.
func LoadOrCreateKey(stateDir string) ([]byte, error) {
	p := filepath.Join(stateDir, "file-id.key")
	data, err := os.ReadFile(p) // #nosec G304 -- inside the configured state directory
	if err == nil {
		key, derr := hex.DecodeString(string(trimNL(data)))
		if derr == nil && len(key) == 32 {
			return key, nil
		}
		return nil, errors.New("file-id.key is damaged; delete it to create a new one (file ids will change)")
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	if err := secrets.WriteFileAtomic(p, []byte(hex.EncodeToString(key)+"\n"), 0o600); err != nil {
		return nil, err
	}
	return key, nil
}

func trimNL(b []byte) []byte {
	for len(b) > 0 && (b[len(b)-1] == '\n' || b[len(b)-1] == '\r') {
		b = b[:len(b)-1]
	}
	return b
}

// store keeps the latest local report of each root in the state directory.
type store struct{ dir string }

func (s store) path(rootID string) string { return filepath.Join(s.dir, "reports", rootID+".json") }

func (s store) save(r *Report) error {
	data, err := json.Marshal(r)
	if err != nil {
		return err
	}
	return secrets.WriteFileAtomic(s.path(r.RootID), data, 0o600)
}

func (s store) load(rootID string) (*Report, error) {
	data, err := os.ReadFile(s.path(rootID))
	if err != nil {
		return nil, err
	}
	var r Report
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

func sortFiles(files []FileResult) {
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
}
