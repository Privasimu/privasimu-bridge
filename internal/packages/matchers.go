package packages

import (
	"encoding/json"
	"io"
	"math"
	"regexp"
	"sort"
	"strings"
	"time"
)

// found is one match before it is attached to an item: the package it names and the
// match itself.
type found struct {
	name, version, purl string
	match               Match
}

// matcherReport is what a matcher run leaves: the matches, its version and the build time
// of its vulnerability database when it reports one.
type matcherReport struct {
	matches   []found
	version   string
	dbBuiltAt *time.Time
}

// ── Grype (grype sbom:<file> -o json) ──

type grypeVuln struct {
	ID       string `json:"id"`
	Severity string `json:"severity"`
	CVSS     []struct {
		Version string `json:"version"`
		Vector  string `json:"vector"`
		Metrics struct {
			BaseScore *float64 `json:"baseScore"`
		} `json:"metrics"`
	} `json:"cvss"`
	Fix struct {
		Versions []string `json:"versions"`
	} `json:"fix"`
}

type grypeMatch struct {
	Vulnerability grypeVuln   `json:"vulnerability"`
	Related       []grypeVuln `json:"relatedVulnerabilities"`
	Artifact      struct {
		Name    string `json:"name"`
		Version string `json:"version"`
		PURL    string `json:"purl"`
	} `json:"artifact"`
}

// readGrype reads Grype's JSON report as a stream (matches one by one).
func readGrype(r io.Reader) (*matcherReport, error) {
	dec := json.NewDecoder(r)
	if err := expectDelim(dec, '{'); err != nil {
		return nil, err
	}
	out := &matcherReport{}
	for dec.More() {
		key, err := objectKey(dec)
		if err != nil {
			return nil, err
		}
		switch key {
		case "matches":
			if err := expectDelim(dec, '['); err != nil {
				return nil, err
			}
			for dec.More() {
				var m grypeMatch
				if err := dec.Decode(&m); err != nil {
					return nil, err
				}
				out.matches = append(out.matches, grypeFound(&m))
			}
			if err := expectDelim(dec, ']'); err != nil {
				return nil, err
			}
		case "descriptor":
			var d struct {
				Version string `json:"version"`
				DB      struct {
					Built  string `json:"built"`
					Status struct {
						Built string `json:"built"`
					} `json:"status"`
				} `json:"db"`
			}
			if err := dec.Decode(&d); err != nil {
				return nil, err
			}
			out.version = d.Version
			out.dbBuiltAt = parseTime(firstNonEmpty(d.DB.Status.Built, d.DB.Built))
		default:
			if err := skipValue(dec); err != nil {
				return nil, err
			}
		}
	}
	return out, nil
}

func grypeFound(m *grypeMatch) found {
	v := m.Vulnerability
	match := Match{ID: v.ID, Severity: severity(v.Severity), FixVersions: v.Fix.Versions, Matcher: "grype"}
	// The related records (often the NVD record of a distro or GHSA advisory) give the CVE
	// alias and the authoritative CVSS.
	for _, rv := range append([]grypeVuln{v}, m.Related...) {
		if rv.ID != v.ID {
			match.Aliases = append(match.Aliases, rv.ID)
		}
		for _, c := range rv.CVSS {
			if c.Metrics.BaseScore != nil {
				match.CVSS = append(match.CVSS, CVSS{Version: c.Version, Vector: c.Vector, ScoreTenths: tenths(*c.Metrics.BaseScore)})
			}
		}
		if match.Severity == "unknown" {
			match.Severity = severity(rv.Severity)
		}
	}
	return found{name: m.Artifact.Name, version: m.Artifact.Version, purl: m.Artifact.PURL, match: match}
}

// ── Trivy (trivy sbom <file> --format json) ──

type trivyVuln struct {
	VulnerabilityID  string   `json:"VulnerabilityID"`
	VendorIDs        []string `json:"VendorIDs"`
	PkgName          string   `json:"PkgName"`
	InstalledVersion string   `json:"InstalledVersion"`
	FixedVersion     string   `json:"FixedVersion"`
	Severity         string   `json:"Severity"`
	PkgIdentifier    struct {
		PURL string `json:"PURL"`
	} `json:"PkgIdentifier"`
	CVSS map[string]struct {
		V2Vector  string   `json:"V2Vector"`
		V3Vector  string   `json:"V3Vector"`
		V40Vector string   `json:"V40Vector"`
		V2Score   *float64 `json:"V2Score"`
		V3Score   *float64 `json:"V3Score"`
		V40Score  *float64 `json:"V40Score"`
	} `json:"CVSS"`
}

// readTrivy reads Trivy's JSON report as a stream (results one by one).
func readTrivy(r io.Reader) (*matcherReport, error) {
	dec := json.NewDecoder(r)
	if err := expectDelim(dec, '{'); err != nil {
		return nil, err
	}
	out := &matcherReport{}
	for dec.More() {
		key, err := objectKey(dec)
		if err != nil {
			return nil, err
		}
		switch key {
		case "Results":
			if err := expectDelim(dec, '['); err != nil {
				return nil, err
			}
			for dec.More() {
				var res struct {
					Vulnerabilities []trivyVuln `json:"Vulnerabilities"`
				}
				if err := dec.Decode(&res); err != nil {
					return nil, err
				}
				for i := range res.Vulnerabilities {
					out.matches = append(out.matches, trivyFound(&res.Vulnerabilities[i]))
				}
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
	return out, nil
}

func trivyFound(v *trivyVuln) found {
	match := Match{ID: v.VulnerabilityID, Aliases: v.VendorIDs, Severity: severity(v.Severity), Matcher: "trivy"}
	for _, f := range strings.Split(v.FixedVersion, ",") {
		if f = strings.TrimSpace(f); f != "" {
			match.FixVersions = append(match.FixVersions, f)
		}
	}
	// NVD first, then the other sources in a stable order.
	sources := make([]string, 0, len(v.CVSS))
	for s := range v.CVSS {
		sources = append(sources, s)
	}
	sort.Slice(sources, func(i, j int) bool {
		if (sources[i] == "nvd") != (sources[j] == "nvd") {
			return sources[i] == "nvd"
		}
		return sources[i] < sources[j]
	})
	for _, s := range sources {
		c := v.CVSS[s]
		if c.V3Vector != "" && c.V3Score != nil {
			match.CVSS = append(match.CVSS, CVSS{Version: vectorVersion(c.V3Vector, "3.1"), Vector: c.V3Vector, ScoreTenths: tenths(*c.V3Score)})
		}
		if c.V40Vector != "" && c.V40Score != nil {
			match.CVSS = append(match.CVSS, CVSS{Version: "4.0", Vector: c.V40Vector, ScoreTenths: tenths(*c.V40Score)})
		}
		if c.V2Vector != "" && c.V2Score != nil {
			match.CVSS = append(match.CVSS, CVSS{Version: "2.0", Vector: c.V2Vector, ScoreTenths: tenths(*c.V2Score)})
		}
	}
	return found{name: v.PkgName, version: v.InstalledVersion, purl: v.PkgIdentifier.PURL, match: match}
}

// readTrivyVersion reads "trivy version --format json".
func readTrivyVersion(r io.Reader) (version string, dbBuiltAt *time.Time) {
	var v struct {
		Version         string `json:"Version"`
		VulnerabilityDB *struct {
			UpdatedAt string `json:"UpdatedAt"`
		} `json:"VulnerabilityDB"`
	}
	if json.NewDecoder(io.LimitReader(r, 1<<20)).Decode(&v) != nil {
		return "", nil
	}
	if v.VulnerabilityDB != nil {
		dbBuiltAt = parseTime(v.VulnerabilityDB.UpdatedAt)
	}
	return v.Version, dbBuiltAt
}

// ── shared normalisation ──

var cvssVersionPattern = regexp.MustCompile(`^CVSS:(\d\.\d)/`)

// vectorVersion reads the version from a "CVSS:3.1/..." vector.
func vectorVersion(vector, fallback string) string {
	if m := cvssVersionPattern.FindStringSubmatch(vector); m != nil {
		return m[1]
	}
	return fallback
}

// tenths turns a CVSS score into the integer tenths the protocol sends; -1 when the score
// is not a valid CVSS score (the entry is dropped).
func tenths(score float64) int {
	if math.IsNaN(score) || score < 0 || score > 10 {
		return -1
	}
	return int(math.Round(score * 10))
}

// severity maps a matcher severity to the protocol's closed list.
func severity(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical":
		return "critical"
	case "high", "important":
		return "high"
	case "medium", "moderate":
		return "medium"
	case "low":
		return "low"
	case "negligible", "none":
		return "negligible"
	}
	return "unknown"
}

var severityRank = map[string]int{"critical": 5, "high": 4, "medium": 3, "low": 2, "negligible": 1, "unknown": 0}

// parseTime reads an RFC 3339 time; nil when absent or not valid.
func parseTime(s string) *time.Time {
	if s == "" {
		return nil
	}
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return nil
	}
	t = t.UTC()
	return &t
}
