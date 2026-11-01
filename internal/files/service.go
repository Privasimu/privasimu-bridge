package files

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"sort"
	"sync"
	"time"

	"github.com/privasimu/bridge/internal/audit"
	"github.com/privasimu/bridge/internal/config"
)

// Service owns the configured roots, runs at most one scan per root at a time, keeps the
// latest report of each root and rescans roots on their refresh interval.
type Service struct {
	roots   map[string]*Root
	order   []string
	scanner *Scanner
	store   store
	log     *slog.Logger
	audit   *audit.Logger
	mu      sync.Mutex
	running map[string]bool
	// Invalid lists roots that failed validation, by id (reported by check).
	Invalid map[string]error
}

// Errors of the service.
var (
	ErrUnknownRoot = errors.New("unknown file root")
	ErrRunning     = errors.New("a scan of this root is already running")
	ErrNoReport    = errors.New("this root has not been scanned yet")
)

// NewService validates the roots of the configuration. Invalid roots are left out and
// listed in Invalid; the service still serves the others.
func NewService(cfg *config.Config, log *slog.Logger, auditLog *audit.Logger) (*Service, error) {
	stateDir := cfg.Resolve(cfg.StateDir)
	key, err := LoadOrCreateKey(stateDir)
	if err != nil {
		return nil, err
	}
	protected := []string{cfg.Dir(), stateDir, cfg.Resolve(cfg.Secrets.File), cfg.Resolve(cfg.Secrets.KeyFile),
		cfg.Resolve(cfg.Audit.File), cfg.Resolve(cfg.Log.File)}
	if exe, err := os.Executable(); err == nil {
		protected = append(protected, exe)
	}
	s := &Service{roots: map[string]*Root{}, store: store{dir: stateDir}, log: log, audit: auditLog,
		running: map[string]bool{}, Invalid: map[string]error{},
		scanner: NewScanner(Options{MaxFileBytes: int64(cfg.Files.MaxFileBytes), MaxTextBytes: int64(cfg.Files.MaxTextBytes),
			PDFTimeout: cfg.Files.PDFTimeout.D(), Key: key})}
	if s.log == nil {
		s.log = slog.New(slog.DiscardHandler)
	}
	if s.audit == nil {
		s.audit = audit.Discard()
	}
	for _, rc := range cfg.Files.Roots {
		root, err := OpenRoot(rc, protected)
		if err != nil {
			s.Invalid[rc.ID] = err
			s.log.Error("file root is not usable", "root", rc.ID, "error", err.Error())
			continue
		}
		s.roots[rc.ID] = root
		s.order = append(s.order, rc.ID)
	}
	return s, nil
}

// SetScanner replaces the scanner (tests).
func (s *Service) SetScanner(sc *Scanner) { s.scanner = sc }

// RootInfo describes a root and its latest scan.
type RootInfo struct {
	ID              string   `json:"id"`
	Label           string   `json:"label"`
	ContentScan     bool     `json:"content_scan"`
	PathMode        string   `json:"path_mode"`
	Scanning        bool     `json:"scanning"`
	RefreshInterval string   `json:"refresh_interval,omitempty"`
	LastScan        *Summary `json:"last_scan"`
}

// Roots lists the usable roots in configuration order.
func (s *Service) Roots() []RootInfo {
	out := make([]RootInfo, 0, len(s.order))
	for _, id := range s.order {
		r := s.roots[id]
		info := RootInfo{ID: id, Label: r.Label, ContentScan: r.cfg.ContentScan == nil || *r.cfg.ContentScan,
			PathMode: r.cfg.ReportPaths}
		if iv := r.cfg.RefreshInterval.D(); iv > 0 {
			info.RefreshInterval = iv.String()
		}
		s.mu.Lock()
		info.Scanning = s.running[id]
		s.mu.Unlock()
		if rep, err := s.store.load(id); err == nil {
			sum := rep.Summary()
			info.LastScan = &sum
		}
		out = append(out, info)
	}
	return out
}

// Describe lists the usable roots without reading their reports (for the agent inventory,
// which is built on every poll).
func (s *Service) Describe() []RootInfo {
	out := make([]RootInfo, 0, len(s.order))
	for _, id := range s.order {
		r := s.roots[id]
		out = append(out, RootInfo{ID: id, Label: r.Label, ContentScan: r.cfg.ContentScan == nil || *r.cfg.ContentScan,
			PathMode: r.cfg.ReportPaths})
	}
	return out
}

// Root returns a usable root.
func (s *Service) Root(id string) (*Root, bool) {
	r, ok := s.roots[id]
	return r, ok
}

// IDs lists the usable root ids, sorted.
func (s *Service) IDs() []string {
	out := append([]string(nil), s.order...)
	sort.Strings(out)
	return out
}

func (s *Service) begin(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.roots[id]; !ok {
		return ErrUnknownRoot
	}
	if s.running[id] {
		return ErrRunning
	}
	s.running[id] = true
	return nil
}

func (s *Service) end(id string) {
	s.mu.Lock()
	delete(s.running, id)
	s.mu.Unlock()
}

// ScanNow scans a root, stores the report and returns it.
func (s *Service) ScanNow(ctx context.Context, id string, progress Progress) (*Report, error) {
	if err := s.begin(id); err != nil {
		return nil, err
	}
	defer s.end(id)
	return s.scan(ctx, id, progress)
}

// scan runs a scan that begin has registered.
func (s *Service) scan(ctx context.Context, id string, progress Progress) (*Report, error) {
	started := time.Now()
	rep, err := s.scanner.Scan(ctx, s.roots[id], progress)
	ev := audit.Event{Event: "file_scan", SourceID: id, DurationMS: time.Since(started).Milliseconds()}
	if err != nil {
		ev.Outcome, ev.Code = audit.Error, "scan_failed"
		s.audit.Log(ev)
		return nil, err
	}
	ev.Outcome, ev.Files, ev.Counts = audit.OK, rep.FilesScanned, stringCounts(rep.Totals)
	s.audit.Log(ev)
	if err := s.store.save(rep); err != nil {
		s.log.Error("file report could not be saved", "root", id, "error", err.Error())
	}
	return rep, nil
}

// StartScan scans a root in the background; it returns ErrRunning when one is running.
func (s *Service) StartScan(id string) error {
	if err := s.begin(id); err != nil {
		return err
	}
	go func() {
		defer s.end(id)
		ctx, cancel := context.WithTimeout(context.Background(), 12*time.Hour)
		defer cancel()
		if _, err := s.scan(ctx, id, nil); err != nil {
			s.log.Error("background file scan failed", "root", id, "error", err.Error())
		}
	}()
	return nil
}

// Latest returns the latest stored report of a root.
func (s *Service) Latest(id string) (*Report, error) {
	if _, ok := s.roots[id]; !ok {
		return nil, ErrUnknownRoot
	}
	rep, err := s.store.load(id)
	if err != nil {
		return nil, ErrNoReport
	}
	return rep, nil
}

// RunSchedule rescans roots whose report is older than their refresh interval.
func (s *Service) RunSchedule(ctx context.Context) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		for _, id := range s.order {
			iv := s.roots[id].cfg.RefreshInterval.D()
			if iv <= 0 {
				continue
			}
			rep, err := s.store.load(id)
			if err == nil && time.Since(rep.FinishedAt) < iv {
				continue
			}
			if err := s.StartScan(id); err == nil {
				s.log.Info("scheduled file scan started", "root", id)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
