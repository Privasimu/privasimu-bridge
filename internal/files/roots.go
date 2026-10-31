// Package files scans allow-listed directories (file shares mounted on the bridge's
// server) for personal data. Roots come only from the local configuration; the platform
// names a root by its id and can never supply a path. Every file is opened through
// os.Root, which refuses names and links that lead outside the root, and the walker skips
// symbolic links, junctions and special files altogether. Only counts per category per
// file leave the network; file content never does.
package files

import (
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/privasimu/bridge/internal/config"
)

// Root is an allow-listed directory, resolved to its canonical absolute path.
type Root struct {
	ID    string
	Label string
	// Path is canonical: absolute, cleaned, with symbolic links in the configured path
	// resolved once at start-up.
	Path string
	cfg  config.FileRoot
	// protected are paths relative to Path ("a/b") that are never entered: the bridge's
	// own configuration, secrets, state and logs.
	protected []string
}

// Errors of root validation.
var (
	ErrRootMissing   = errors.New("the root directory does not exist or is not a directory")
	ErrRootSystem    = errors.New("the root is a filesystem root or a system directory")
	ErrRootProtected = errors.New("the root is inside the bridge's own data directory")
)

// systemDirs may never be roots (case-insensitive on Windows).
var systemDirs = func() []string {
	if runtime.GOOS == "windows" {
		windir := os.Getenv("SystemRoot")
		if windir == "" {
			windir = `C:\Windows`
		}
		return []string{windir, `C:\Program Files`, `C:\Program Files (x86)`, `C:\ProgramData`, `C:\Users\Default`,
			`C:\System Volume Information`, `C:\$Recycle.Bin`, `C:\Recovery`, `C:\Boot`}
	}
	return []string{"/etc", "/proc", "/sys", "/dev", "/boot", "/root", "/run", "/var/run", "/usr", "/bin", "/sbin",
		"/lib", "/lib64", "/var/lib", "/var/log", "/snap"}
}()

func samePath(a, b string) bool {
	if runtime.GOOS == "windows" {
		return strings.EqualFold(a, b)
	}
	return a == b
}

// within reports whether p is base or below it.
func within(p, base string) bool {
	rel, err := filepath.Rel(base, p)
	if err != nil {
		return false
	}
	if runtime.GOOS == "windows" && !strings.EqualFold(filepath.VolumeName(p), filepath.VolumeName(base)) {
		return false
	}
	return rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)))
}

func canonical(p string) (string, error) {
	abs, err := filepath.Abs(p)
	if err != nil {
		return "", err
	}
	return filepath.EvalSymlinks(abs)
}

// OpenRoot validates a configured root. protected lists the bridge's own directories and
// files (configuration, secrets, state, logs): a root may contain them, they are skipped,
// but a root may not be inside them.
func OpenRoot(r config.FileRoot, protected []string) (*Root, error) {
	if !filepath.IsAbs(r.Path) {
		return nil, ErrRootMissing
	}
	p, err := canonical(r.Path)
	if err != nil {
		return nil, ErrRootMissing
	}
	st, err := os.Stat(p)
	if err != nil || !st.IsDir() {
		return nil, ErrRootMissing
	}
	if filepath.Dir(p) == p || (runtime.GOOS == "windows" && len(strings.TrimRight(p, `\/`)) <= 2) {
		return nil, ErrRootSystem
	}
	for _, sys := range systemDirs {
		if samePath(p, sys) || (within(p, sys) && !samePath(sys, `C:\ProgramData`)) {
			return nil, ErrRootSystem
		}
		// A root that contains a system directory would include it.
		if within(sys, p) {
			return nil, ErrRootSystem
		}
	}
	root := &Root{ID: r.ID, Label: r.Label, Path: p, cfg: r}
	for _, q := range protected {
		if q == "" {
			continue
		}
		cq, err := canonical(q)
		if err != nil {
			cq = filepath.Clean(q)
		}
		if within(p, cq) {
			return nil, ErrRootProtected
		}
		if within(cq, p) {
			rel, _ := filepath.Rel(p, cq)
			root.protected = append(root.protected, filepath.ToSlash(rel))
		}
	}
	return root, nil
}

// isProtected reports whether rel (slash-separated, relative to the root) is one of the
// bridge's own paths or below one.
func (r *Root) isProtected(rel string) bool {
	for _, p := range r.protected {
		if rel == p || strings.HasPrefix(rel, p+"/") || (runtime.GOOS == "windows" && strings.EqualFold(rel, p)) {
			return true
		}
	}
	return false
}

// matchGlob matches a slash-separated path against a pattern where "**" matches any
// number of path segments and "*", "?" and character classes match within a segment.
func matchGlob(pattern, name string) bool {
	if runtime.GOOS == "windows" {
		pattern, name = strings.ToLower(pattern), strings.ToLower(name)
	}
	return matchSegments(strings.Split(pattern, "/"), strings.Split(name, "/"))
}

func matchSegments(p, n []string) bool {
	for len(p) > 0 {
		if p[0] == "**" {
			if len(p) == 1 {
				return true
			}
			for i := 0; i <= len(n); i++ {
				if matchSegments(p[1:], n[i:]) {
					return true
				}
			}
			return false
		}
		if len(n) == 0 {
			return false
		}
		ok, err := path.Match(p[0], n[0])
		if err != nil || !ok {
			return false
		}
		p, n = p[1:], n[1:]
	}
	return len(n) == 0
}

// DefaultExclude are skipped in every root: Office lock files, thumbnails caches and
// version-control metadata.
var DefaultExclude = []string{"**/~$*", "**/Thumbs.db", "**/.DS_Store", "**/.git/**", "**/.svn/**"}

func (r *Root) excluded(rel string, dir bool) bool {
	candidates := []string{rel}
	if dir {
		candidates = append(candidates, rel+"/")
	}
	for _, list := range [][]string{DefaultExclude, r.cfg.Exclude} {
		for _, g := range list {
			for _, c := range candidates {
				if matchGlob(g, c) || (dir && strings.HasSuffix(g, "/**") && matchGlob(strings.TrimSuffix(g, "/**"), c)) {
					return true
				}
			}
		}
	}
	return false
}

func (r *Root) included(rel string) bool {
	if len(r.cfg.Include) == 0 {
		return true
	}
	for _, g := range r.cfg.Include {
		if matchGlob(g, rel) {
			return true
		}
	}
	return false
}

// String describes the root for logs (id and canonical path; paths stay on this server).
func (r *Root) String() string { return fmt.Sprintf("%s (%s)", r.ID, r.Path) }
