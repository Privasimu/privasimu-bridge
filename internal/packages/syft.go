package packages

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"
)

// maxRecords bounds how many components are kept from one SBOM (the rest is only
// counted), so a huge or hostile SBOM cannot exhaust memory.
const maxRecords = 100000

// maxNesting bounds the depth of nested components that is followed.
const maxNesting = 64

// record is the part of a CycloneDX component the bridge keeps. Locations, hashes, file
// paths and every other property stay on the server.
type record struct {
	name, group, version, purl string
	cdxType, syftType          string
	licenses                   []string
}

// sbom is what the bridge reads from Syft's CycloneDX output.
type sbom struct {
	records []record
	// total counts every package component, including those beyond maxRecords.
	total       int
	os          *OSInfo
	toolVersion string
}

type cdxProperty struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type cdxComponent struct {
	Type     string `json:"type"`
	Name     string `json:"name"`
	Group    string `json:"group"`
	Version  string `json:"version"`
	PURL     string `json:"purl"`
	Licenses []struct {
		License *struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"license"`
		Expression string `json:"expression"`
	} `json:"licenses"`
	Properties []cdxProperty   `json:"properties"`
	Components []*cdxComponent `json:"components"`
}

func (c *cdxComponent) property(name string) string {
	for _, p := range c.Properties {
		if p.Name == name {
			return p.Value
		}
	}
	return ""
}

type cdxTool struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// readCycloneDX reads a CycloneDX JSON document as a stream: the components array is
// decoded one element at a time, everything else that is not needed is skipped token by
// token. The document is data: no reference is resolved, nothing it names is opened.
func readCycloneDX(r io.Reader) (*sbom, error) {
	dec := json.NewDecoder(r)
	if err := expectDelim(dec, '{'); err != nil {
		return nil, err
	}
	out := &sbom{}
	format := ""
	for dec.More() {
		key, err := objectKey(dec)
		if err != nil {
			return nil, err
		}
		switch key {
		case "bomFormat":
			if err := dec.Decode(&format); err != nil {
				return nil, err
			}
		case "metadata":
			var meta struct {
				Tools json.RawMessage `json:"tools"`
			}
			if err := dec.Decode(&meta); err != nil {
				return nil, err
			}
			out.toolVersion = syftVersion(meta.Tools)
		case "components":
			if err := expectDelim(dec, '['); err != nil {
				return nil, err
			}
			for dec.More() {
				var c cdxComponent
				if err := dec.Decode(&c); err != nil {
					return nil, err
				}
				out.visit(&c, 0)
			}
			if err := expectDelim(dec, ']'); err != nil {
				return nil, err
			}
		default:
			if err := skipValue(dec); err != nil {
				return nil, err
			}
		}
	}
	if format != "CycloneDX" {
		return nil, errors.New("the inventory is not a CycloneDX document")
	}
	return out, nil
}

func (s *sbom) visit(c *cdxComponent, depth int) {
	if depth > maxNesting {
		return
	}
	switch c.Type {
	case "operating-system":
		if s.os == nil {
			id := strings.ToLower(firstNonEmpty(c.property("syft:distro:id"), c.Name))
			s.os = &OSInfo{ID: id, Version: firstNonEmpty(c.property("syft:distro:versionID"), c.Version)}
		}
	case "file":
	default:
		if c.Name != "" && c.Version != "" {
			s.total++
			if len(s.records) < maxRecords {
				rec := record{name: c.Name, group: c.Group, version: c.Version, purl: c.PURL, cdxType: c.Type,
					syftType: c.property("syft:package:type")}
				for _, l := range c.Licenses {
					switch {
					case l.License != nil && l.License.ID != "":
						rec.licenses = append(rec.licenses, l.License.ID)
					case l.License != nil && l.License.Name != "":
						rec.licenses = append(rec.licenses, l.License.Name)
					case l.Expression != "":
						rec.licenses = append(rec.licenses, l.Expression)
					}
				}
				s.records = append(s.records, rec)
			}
		}
	}
	for _, sub := range c.Components {
		if sub != nil {
			s.visit(sub, depth+1)
		}
	}
}

// syftVersion finds Syft's version in metadata.tools: a list of tools (CycloneDX 1.4) or
// an object with a components list (1.5 and later).
func syftVersion(raw json.RawMessage) string {
	var list []cdxTool
	if json.Unmarshal(raw, &list) != nil {
		var obj struct {
			Components []cdxTool `json:"components"`
		}
		if json.Unmarshal(raw, &obj) != nil {
			return ""
		}
		list = obj.Components
	}
	for _, t := range list {
		if strings.EqualFold(t.Name, "syft") {
			return t.Version
		}
	}
	return ""
}

// ── JSON streaming helpers ──

func expectDelim(dec *json.Decoder, want json.Delim) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	if d, ok := tok.(json.Delim); !ok || d != want {
		return fmt.Errorf("unexpected JSON token %v, want %v", tok, want)
	}
	return nil
}

func objectKey(dec *json.Decoder) (string, error) {
	tok, err := dec.Token()
	if err != nil {
		return "", err
	}
	key, ok := tok.(string)
	if !ok {
		return "", fmt.Errorf("unexpected JSON token %v, want an object key", tok)
	}
	return key, nil
}

// skipValue reads one JSON value without keeping it.
func skipValue(dec *json.Decoder) error {
	depth := 0
	for {
		tok, err := dec.Token()
		if err != nil {
			return err
		}
		if d, ok := tok.(json.Delim); ok {
			switch d {
			case '{', '[':
				depth++
			case '}', ']':
				depth--
			}
		}
		if depth == 0 {
			return nil
		}
	}
}

// ── package URL ──

// purl is the part of a package URL (pkg:type/namespace/name@version?qualifiers) the
// mapping needs.
type purl struct {
	typ, namespace string
	distro         string
}

func parsePURL(s string) purl {
	var p purl
	rest, ok := strings.CutPrefix(s, "pkg:")
	if !ok {
		return p
	}
	rest, _, _ = strings.Cut(rest, "#")
	rest, query, _ := strings.Cut(rest, "?")
	rest = strings.TrimLeft(rest, "/")
	typ, path, _ := strings.Cut(rest, "/")
	p.typ = strings.ToLower(typ)
	if i := strings.LastIndex(path, "/"); i >= 0 {
		p.namespace, _ = url.PathUnescape(path[:i])
		p.namespace = strings.ToLower(p.namespace)
	}
	if q, err := url.ParseQuery(query); err == nil {
		p.distro = q.Get("distro")
	}
	return p
}

// splitDistro splits a purl distro qualifier such as "ubuntu-24.04" or
// "opensuse-leap-15.5" into id and version (at the last '-' followed by a digit).
func splitDistro(d string) (id, version string) {
	for i := len(d) - 1; i > 0; i-- {
		if d[i] == '-' && i+1 < len(d) && d[i+1] >= '0' && d[i+1] <= '9' {
			return strings.ToLower(d[:i]), d[i+1:]
		}
	}
	return strings.ToLower(d), ""
}

// ── mapping to the protocol's closed lists ──

// ecosystemOf maps a Syft package type (or, without one, the purl type) to an OSV
// ecosystem name, and gives the release for OS ecosystems. distroID and distroVersion
// come from the purl's distro qualifier or else the scanned system.
func ecosystemOf(rec record, p purl, sys *OSInfo) (ecosystem, release string) {
	kind := rec.syftType
	if kind == "" {
		kind = map[string]string{"deb": "deb", "apk": "apk", "rpm": "rpm", "npm": "npm", "composer": "php-composer",
			"golang": "go-module", "maven": "java-archive", "pypi": "python", "gem": "gem", "cargo": "rust-crate",
			"nuget": "dotnet"}[p.typ]
	}
	distroID, distroVersion := splitDistro(p.distro)
	if distroID == "" && sys != nil {
		distroID, distroVersion = sys.ID, sys.Version
	}
	if distroID == "" {
		distroID = p.namespace
	}
	switch kind {
	case "deb":
		switch distroID {
		case "debian":
			return "Debian", distroVersion
		case "ubuntu":
			return "Ubuntu", distroVersion
		}
	case "apk":
		if distroID == "alpine" {
			return "Alpine", distroVersion
		}
	case "rpm":
		switch distroID {
		case "rhel", "redhat":
			return "Red Hat", distroVersion
		case "rocky":
			return "Rocky Linux", distroVersion
		case "almalinux":
			return "AlmaLinux", distroVersion
		}
	case "npm":
		return "npm", ""
	case "php-composer":
		return "Packagist", ""
	case "go-module":
		return "Go", ""
	case "java-archive":
		if p.typ == "" || p.typ == "maven" {
			return "Maven", ""
		}
	case "python":
		return "PyPI", ""
	case "gem":
		return "RubyGems", ""
	case "rust-crate":
		return "crates.io", ""
	case "dotnet":
		return "NuGet", ""
	}
	return "other", ""
}

// packageName returns the name in the form the ecosystem's advisories use: Maven
// groupId:artifactId, npm @scope/name, Packagist vendor/name.
func packageName(rec record, ecosystem string) string {
	g := strings.TrimSpace(rec.group)
	switch {
	case g == "":
	case ecosystem == "Maven" && !strings.Contains(rec.name, ":"):
		return g + ":" + rec.name
	case ecosystem == "npm" && !strings.HasPrefix(rec.name, "@"):
		return "@" + strings.TrimPrefix(g, "@") + "/" + rec.name
	case ecosystem == "Packagist" && !strings.Contains(rec.name, "/"):
		return g + "/" + rec.name
	}
	return rec.name
}

// runtimeNames are packages that are a language runtime rather than a library.
var runtimeNames = map[string]bool{"node": true, "nodejs": true, "php": true, "python": true, "python3": true,
	"openjdk": true, "java": true, "jdk": true, "jre": true, "dotnet": true, "go": true, "golang": true, "ruby": true}

// typeAndLayer maps a component to the protocol's type and layer.
func typeAndLayer(rec record, ecosystem string) (typ, layer string) {
	osPkg := osEcosystems[ecosystem] || rec.syftType == "deb" || rec.syftType == "apk" || rec.syftType == "rpm"
	switch {
	case osPkg:
		typ = "os_package"
	case rec.cdxType == "library", rec.cdxType == "application", rec.cdxType == "framework", rec.cdxType == "container",
		rec.cdxType == "firmware":
		typ = rec.cdxType
	default:
		typ = "other"
	}
	switch {
	case osPkg:
		layer = "os"
	case typ == "framework" || rec.cdxType == "platform" || runtimeNames[strings.ToLower(rec.name)]:
		layer = "runtime"
	default:
		layer = "application"
	}
	return typ, layer
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}
