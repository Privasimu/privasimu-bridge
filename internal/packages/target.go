package packages

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"errors"
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"

	"github.com/privasimu/bridge/internal/config"
)

// Errors of target checks (kept local; the platform hears target_unreadable).
var (
	errTargetMissing = errors.New("the target does not exist or has the wrong type")
	errNotAnImage    = errors.New("the file is not an OCI or docker image archive")
)

// checkTarget makes sure a target can be read before a scanner starts, and returns the
// Syft source of an image archive ("oci-archive" or "docker-archive"; "" otherwise).
func checkTarget(t *config.PackageTarget) (string, error) {
	fi, err := os.Stat(t.Path)
	if err != nil {
		return "", errTargetMissing
	}
	if t.Kind != config.PackageImageArchive {
		if !fi.IsDir() {
			return "", errTargetMissing
		}
		d, err := os.Open(t.Path)
		if err != nil {
			return "", err
		}
		defer d.Close()
		if _, err := d.Readdirnames(1); err != nil && !errors.Is(err, io.EOF) {
			return "", err
		}
		return "", nil
	}
	if !fi.Mode().IsRegular() {
		return "", errTargetMissing
	}
	return archiveScheme(t.Path)
}

// archiveScheme looks at the entries of a local image archive (a plain or gzip tar file)
// to tell an OCI layout from a "docker save" archive. Nothing is extracted.
func archiveScheme(file string) (string, error) {
	f, err := os.Open(file) // #nosec G304 -- the operator-configured image archive
	if err != nil {
		return "", err
	}
	defer f.Close()
	br := bufio.NewReader(f)
	var r io.Reader = br
	if magic, err := br.Peek(2); err == nil && magic[0] == 0x1f && magic[1] == 0x8b {
		gz, err := gzip.NewReader(br)
		if err != nil {
			return "", errNotAnImage
		}
		defer gz.Close()
		r = gz
	}
	tr := tar.NewReader(r)
	oci, docker := false, false
	for n := 0; n < 10000; n++ {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return "", errNotAnImage
		}
		switch strings.TrimPrefix(path.Clean(h.Name), "./") {
		case "manifest.json":
			docker = true
		case "oci-layout":
			oci = true
		}
		if docker {
			break
		}
	}
	switch {
	case docker:
		return "docker-archive", nil
	case oci:
		return "oci-archive", nil
	}
	return "", errNotAnImage
}

// mandatoryExcludes are never read on a host scan: virtual and runtime filesystems, below
// the target's root (a host mounted at /host in a container keeps them at /host/proc).
var mandatoryExcludes = []string{"proc", "sys", "dev", "run"}

// excludeGlobs turns a target's exclusions into Syft --exclude patterns, which are
// relative to the scanned directory ("./proc/**"). Absolute paths outside the target are
// ignored. The bridge's own directories (configuration, state, secrets) are always added.
func excludeGlobs(t *config.PackageTarget, own []string) []string {
	root := filepath.Clean(t.Path)
	var paths []string
	if t.Kind == config.PackageHost && runtime.GOOS != "windows" {
		for _, d := range mandatoryExcludes {
			paths = append(paths, filepath.Join(root, d))
		}
	}
	paths = append(paths, t.Exclude...)
	paths = append(paths, own...)
	var out []string
	seen := map[string]bool{}
	add := func(g string) {
		if !seen[g] {
			seen[g] = true
			out = append(out, g)
		}
	}
	for _, p := range paths {
		if p == "" {
			continue
		}
		if strings.HasPrefix(p, "./") {
			add(p)
			continue
		}
		rel, err := filepath.Rel(root, filepath.Clean(p))
		if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			continue
		}
		rel = filepath.ToSlash(rel)
		add("./" + rel)
		add("./" + rel + "/**")
	}
	return out
}

var osIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,40}$`)

// hostOS reads the ID and VERSION_ID of os-release below a host target's root (used for
// the inventory capability "os:<id>" before the first scan).
func hostOS(root string) *OSInfo {
	for _, rel := range []string{"etc/os-release", "usr/lib/os-release"} {
		data, err := readSmall(filepath.Join(root, filepath.FromSlash(rel)), 64<<10)
		if err != nil {
			continue
		}
		info := &OSInfo{}
		for _, line := range bytes.Split(data, []byte("\n")) {
			k, v, ok := strings.Cut(strings.TrimSpace(string(line)), "=")
			if !ok {
				continue
			}
			v = strings.Trim(v, `"'`)
			switch k {
			case "ID":
				info.ID = strings.ToLower(v)
			case "VERSION_ID":
				info.Version = v
			}
		}
		if osIDPattern.MatchString(info.ID) {
			return info
		}
	}
	return nil
}

func readSmall(name string, max int64) ([]byte, error) {
	f, err := os.Open(name) // #nosec G304 -- os-release below an allow-listed target
	if err != nil {
		return nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil || !fi.Mode().IsRegular() {
		return nil, errTargetMissing
	}
	return io.ReadAll(io.LimitReader(f, max))
}
