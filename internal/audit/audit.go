// Package audit writes the local audit log: one JSON object per line for every request
// served, job run and administrative command. Events have typed fields only (codes,
// counts, ids); there is no field that could carry a value, a password or a key.
package audit

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/privasimu/bridge/internal/fsutil"
)

// Event is one audit record.
type Event struct {
	Time        time.Time      `json:"ts"`
	Event       string         `json:"event"`
	Mode        string         `json:"mode,omitempty"`
	RequestID   string         `json:"request_id,omitempty"`
	ClientIP    string         `json:"client_ip,omitempty"`
	KeyID       string         `json:"key_id,omitempty"`
	AgentID     string         `json:"agent_id,omitempty"`
	JobID       string         `json:"job_id,omitempty"`
	JobType     string         `json:"job_type,omitempty"`
	Endpoint    string         `json:"endpoint,omitempty"`
	Status      int            `json:"status,omitempty"`
	Outcome     string         `json:"outcome,omitempty"`
	Code        string         `json:"code,omitempty"`
	SourceID    string         `json:"source_id,omitempty"`
	Engine      string         `json:"engine,omitempty"`
	Credentials string         `json:"credentials,omitempty"`
	Tables      int            `json:"tables,omitempty"`
	Columns     int            `json:"columns,omitempty"`
	PIIColumns  int            `json:"pii_columns,omitempty"`
	Files       int            `json:"files,omitempty"`
	Sampled     bool           `json:"sampled,omitempty"`
	Counts      map[string]int `json:"counts,omitempty"`
	DurationMS  int64          `json:"duration_ms,omitempty"`
}

// Outcomes.
const (
	OK     = "ok"
	Error  = "error"
	Denied = "denied"
)

// Logger appends events to a file and rotates it by size.
type Logger struct {
	mu       sync.Mutex
	path     string
	maxBytes int64
	maxFiles int
	f        *os.File
	size     int64
	now      func() time.Time
}

// Open opens (or creates) the audit log. An empty path discards events.
func Open(path string, maxSizeMB, maxFiles int) (*Logger, error) {
	l := &Logger{path: path, maxBytes: int64(maxSizeMB) << 20, maxFiles: maxFiles, now: time.Now}
	if path == "" {
		return l, nil
	}
	if l.maxBytes <= 0 {
		l.maxBytes = 50 << 20
	}
	if l.maxFiles <= 0 {
		l.maxFiles = 10
	}
	if err := l.open(); err != nil {
		return nil, err
	}
	return l, nil
}

// Discard returns a logger that drops every event.
func Discard() *Logger { return &Logger{now: time.Now} }

func (l *Logger) open() error {
	if err := os.MkdirAll(filepath.Dir(l.path), 0o750); err != nil {
		return err
	}
	// Readable by the group so that a log shipper (SIEM) in the service group can read it.
	_, statErr := os.Stat(l.path)
	f, err := os.OpenFile(l.path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o640) // #nosec G302 -- see above
	if err != nil {
		return err
	}
	if statErr != nil {
		// A new file created by a command run with sudo must stay writable by the service.
		fsutil.InheritOwner(l.path, "")
	}
	st, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return err
	}
	l.f, l.size = f, st.Size()
	return nil
}

// Log writes one event. Failures to write are reported to stderr, never dropped silently.
func (l *Logger) Log(e Event) {
	if l == nil || l.path == "" {
		return
	}
	if e.Time.IsZero() {
		e.Time = l.now().UTC()
	}
	line, err := json.Marshal(e)
	if err != nil {
		return
	}
	line = append(line, '\n')
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.f == nil {
		if err := l.open(); err != nil {
			fmt.Fprintln(os.Stderr, "audit log:", err)
			return
		}
	}
	if l.size+int64(len(line)) > l.maxBytes {
		l.rotate()
	}
	n, err := l.f.Write(line)
	l.size += int64(n)
	if err != nil {
		fmt.Fprintln(os.Stderr, "audit log:", err)
	}
}

func (l *Logger) rotate() {
	_ = l.f.Close()
	l.f = nil
	stamp := l.now().UTC().Format("20060102T150405.000000000")
	ext := filepath.Ext(l.path)
	base := strings.TrimSuffix(l.path, ext)
	_ = os.Rename(l.path, base+"-"+stamp+ext)
	matches, _ := filepath.Glob(base + "-*" + ext)
	sort.Strings(matches)
	for len(matches) > l.maxFiles-1 && len(matches) > 0 {
		_ = os.Remove(matches[0])
		matches = matches[1:]
	}
	if err := l.open(); err != nil {
		fmt.Fprintln(os.Stderr, "audit log:", err)
	}
}

// Close closes the file.
func (l *Logger) Close() error {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.f != nil {
		err := l.f.Close()
		l.f = nil
		return err
	}
	return nil
}
