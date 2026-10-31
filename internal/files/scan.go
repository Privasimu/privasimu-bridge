package files

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/privasimu/bridge/internal/detect"
)

// Options configure a scanner.
type Options struct {
	MaxFileBytes int64
	MaxTextBytes int64
	PDFTimeout   time.Duration
	Workers      int
	// Key names files by a keyed hash (FileID).
	Key []byte
	// ChildCommand overrides how the PDF child process is started (tests).
	ChildCommand func() (string, []string, error)
}

// Scanner scans roots.
type Scanner struct {
	opts Options
	pdf  *pdfExtractor
}

// NewScanner returns a scanner with defaults for unset options.
func NewScanner(o Options) *Scanner {
	if o.MaxFileBytes <= 0 {
		o.MaxFileBytes = 100 << 20
	}
	if o.MaxTextBytes <= 0 {
		o.MaxTextBytes = 16 << 20
	}
	if o.PDFTimeout <= 0 {
		o.PDFTimeout = 30 * time.Second
	}
	if o.Workers <= 0 {
		o.Workers = 4
	}
	cmd := o.ChildCommand
	if cmd == nil {
		cmd = defaultChildCommand
	}
	return &Scanner{opts: o, pdf: &pdfExtractor{command: cmd, timeout: o.PDFTimeout, maxIn: o.MaxFileBytes, maxOut: o.MaxTextBytes}}
}

// Progress reports how many files were seen and examined so far.
type Progress func(seen, scanned int)

type job struct {
	rel  string
	ext  string
	kind string
	size int64
	mod  time.Time
}

// Scan walks a root and returns its local report. The walk never leaves the root: entries
// are read through os.Root, links and special files are skipped, and the bridge's own
// directories are never entered.
func (s *Scanner) Scan(ctx context.Context, root *Root, progress Progress) (*Report, error) {
	r, err := os.OpenRoot(root.Path)
	if err != nil {
		return nil, ErrRootMissing
	}
	defer r.Close()
	rep := &Report{RootID: root.ID, Label: root.Label, ContentScan: root.cfg.ContentScan == nil || *root.cfg.ContentScan,
		PathMode: root.cfg.ReportPaths, StartedAt: time.Now().UTC(), Totals: map[detect.Category]int{},
		Skipped: map[string]int{}, Extensions: map[string]int{}, Files: []FileResult{}}
	var mu sync.Mutex
	skip := func(reason string) {
		mu.Lock()
		rep.Skipped[reason]++
		mu.Unlock()
	}
	jobs := make(chan job)
	var wg sync.WaitGroup
	for i := 0; i < s.opts.Workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				res := s.examine(ctx, r, root, rep.ContentScan, j)
				mu.Lock()
				if res.Skipped != "" {
					rep.Skipped[res.Skipped]++
					if res.Skipped == SkipParse || res.Skipped == SkipTimeout || res.Skipped == SkipEncrypted {
						rep.Files = append(rep.Files, res)
					}
				} else {
					rep.FilesScanned++
					found := false
					for c, n := range res.Categories {
						if n > 0 {
							rep.Totals[c] += n
							found = true
						}
					}
					if found || res.NameHint != "" {
						if found {
							rep.FilesWithPII++
						}
						rep.Files = append(rep.Files, res)
					}
				}
				scanned, seen := rep.FilesScanned, rep.FilesSeen
				mu.Unlock()
				if progress != nil {
					progress(seen, scanned)
				}
			}
		}()
	}
	maxDepth, maxFiles := root.cfg.MaxDepth, root.cfg.MaxFiles
	walkErr := fs.WalkDir(r.FS(), ".", func(p string, d fs.DirEntry, err error) error {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err != nil {
			if errors.Is(err, fs.ErrPermission) {
				skip(SkipPermission)
			} else {
				skip(SkipError)
			}
			if d != nil && d.IsDir() && p != "." {
				return fs.SkipDir
			}
			return nil
		}
		if p == "." {
			return nil
		}
		typ := d.Type()
		if typ&fs.ModeSymlink != 0 || typ&fs.ModeIrregular != 0 {
			skip(SkipLink) // symbolic links, junctions and other reparse points
			return nil
		}
		if typ&(fs.ModeDevice|fs.ModeNamedPipe|fs.ModeSocket|fs.ModeCharDevice) != 0 {
			skip(SkipSpecial)
			return nil
		}
		if root.isProtected(p) {
			skip(SkipProtected)
			if d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			if strings.Count(p, "/")+1 > maxDepth {
				skip(SkipDepth)
				return fs.SkipDir
			}
			if root.excluded(p, true) {
				skip(SkipExcluded)
				return fs.SkipDir
			}
			return nil
		}
		mu.Lock()
		rep.FilesSeen++
		over := rep.FilesSeen > maxFiles
		if over {
			rep.Truncated = true
			rep.FilesSeen--
		}
		mu.Unlock()
		if over {
			return fs.SkipAll
		}
		ext := strings.ToLower(path.Ext(p))
		mu.Lock()
		rep.Extensions[ext]++
		mu.Unlock()
		if root.excluded(p, false) || !root.included(p) {
			skip(SkipExcluded)
			return nil
		}
		kind, ok := supported[ext]
		if !ok {
			skip(SkipUnsupported)
			return nil
		}
		info, err := d.Info()
		if err != nil {
			skip(SkipError)
			return nil
		}
		if info.Size() > s.opts.MaxFileBytes {
			skip(SkipTooLarge)
			return nil
		}
		select {
		case jobs <- job{rel: p, ext: ext, kind: kind, size: info.Size(), mod: info.ModTime()}:
		case <-ctx.Done():
			return ctx.Err()
		}
		return nil
	})
	close(jobs)
	wg.Wait()
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if walkErr != nil && !errors.Is(walkErr, fs.SkipAll) {
		return nil, walkErr
	}
	rep.FinishedAt = time.Now().UTC()
	rep.DurationMS = rep.FinishedAt.Sub(rep.StartedAt).Milliseconds()
	sortFiles(rep.Files)
	return rep, nil
}

// examine reads one file and counts identifiers in its text.
func (s *Scanner) examine(ctx context.Context, r *os.Root, root *Root, content bool, j job) FileResult {
	res := FileResult{Path: j.rel, ID: FileID(s.opts.Key, root.ID, j.rel), Ext: j.ext, SizeBytes: j.size,
		Modified: j.mod.UTC().Format("2006-01-02")}
	base := strings.TrimSuffix(path.Base(j.rel), j.ext)
	if nm, ok := detect.ClassifyName(base); ok {
		res.NameHint = nm.Category
	}
	if !content {
		return res
	}
	f, err := r.OpenFile(j.rel, openFlags, 0)
	if err != nil {
		res.Skipped = SkipPermission
		if !errors.Is(err, fs.ErrPermission) {
			res.Skipped = SkipError
		}
		return res
	}
	defer f.Close()
	// The entry may have been swapped since it was listed: only regular files are read.
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() {
		res.Skipped = SkipSpecial
		return res
	}
	if st.Size() > s.opts.MaxFileBytes {
		res.Skipped = SkipTooLarge
		return res
	}
	tc := detect.NewTextCounter(s.opts.MaxTextBytes)
	switch j.kind {
	case kindText:
		err = writeText(tc, io.LimitReader(f, s.opts.MaxFileBytes))
	case kindDOCX:
		err = extractDOCX(tc, f, st.Size(), ooxmlLimits{maxEntryBytes: s.opts.MaxTextBytes * 8, maxTotalBytes: s.opts.MaxTextBytes * 8})
	case kindXLSX:
		err = extractXLSX(tc, f, st.Size(), ooxmlLimits{maxEntryBytes: s.opts.MaxTextBytes * 8, maxTotalBytes: s.opts.MaxTextBytes * 8})
	case kindPDF:
		var truncated bool
		truncated, err = s.pdf.extract(ctx, tc, f)
		res.Truncated = truncated
	}
	_ = tc.Close()
	switch {
	case err == nil, errors.Is(err, errTooMuchText):
		if err != nil {
			res.Truncated = true
		}
	case errors.Is(err, errEncrypted):
		res.Skipped = SkipEncrypted
		return res
	case errors.Is(err, errTimeout):
		res.Skipped = SkipTimeout
		return res
	case errors.Is(err, errTooLarge):
		res.Skipped = SkipTooLarge
		return res
	default:
		res.Skipped = SkipParse
		return res
	}
	if tc.Truncated() {
		res.Truncated = true
	}
	counts := tc.Counts()
	if len(counts) > 0 {
		res.Categories = counts
	}
	return res
}
