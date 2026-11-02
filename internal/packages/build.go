package packages

import (
	"regexp"
	"slices"
	"sort"
	"strings"
	"unicode/utf8"
)

var (
	matchIDPattern     = regexp.MustCompile(`^[A-Za-z0-9._:-]{3,64}$`)
	cvssVersionValue   = regexp.MustCompile(`^\d\.\d$`)
	printableASCIIOnly = regexp.MustCompile(`^[\x21-\x7e]+$`)
)

// validText is the agent protocol's text rule: valid UTF-8, min to max characters, no C0
// control character and no DEL.
func validText(s string, min, max int) bool {
	if !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	n := utf8.RuneCountInString(s)
	return n >= min && n <= max
}

// inventory is the list of items built from an SBOM and a matcher report.
type inventory struct {
	items []Item
	// total is the number of distinct packages found (before max_packages).
	total int
	// dropped counts packages, matches or match fields that could not be sent; any drop
	// marks the result truncated.
	dropped int
}

// buildItems turns the SBOM records into protocol items: mapped to the closed lists,
// deduplicated by (ecosystem, name, version), with the matcher's matches attached, every
// field within the protocol's bounds, ordered (packages with matches first, then by
// ecosystem, name and version) and cut to maxPackages.
func buildItems(s *sbom, mr *matcherReport, maxPackages int) inventory {
	var inv inventory
	index := map[string]int{}  // ecosystem|name|version → item
	byPURL := map[string]int{} // purl → item
	byName := map[string]int{} // name|version (as the SBOM and the matcher spell it) → item
	for _, rec := range s.records {
		p := parsePURL(rec.purl)
		eco, release := ecosystemOf(rec, p, s.os)
		name := packageName(rec, eco)
		if !validText(name, 1, maxNameChars) || !validText(rec.version, 1, maxVersionChars) {
			inv.dropped++
			continue
		}
		key := eco + "|" + name + "|" + rec.version
		i, dup := index[key]
		if !dup {
			typ, layer := typeAndLayer(rec, eco)
			it := Item{Name: name, Version: rec.version, Ecosystem: eco, Type: typ, Layer: layer, Dependency: "unknown",
				Licenses: []string{}, Matches: []Match{}}
			if validText(release, 1, maxReleaseChars) {
				it.EcosystemRelease = release
			}
			if rec.purl != "" && validText(rec.purl, 1, maxPURLChars) {
				it.PURL = rec.purl
			}
			i = len(inv.items)
			index[key] = i
			inv.items = append(inv.items, it)
		}
		it := &inv.items[i]
		if it.PURL == "" && rec.purl != "" && validText(rec.purl, 1, maxPURLChars) {
			it.PURL = rec.purl
		}
		for _, l := range rec.licenses {
			if validText(l, 1, maxLicenseChars) && !slices.Contains(it.Licenses, l) && len(it.Licenses) < maxLicenses {
				it.Licenses = append(it.Licenses, l)
			}
		}
		if rec.purl != "" {
			byPURL[rec.purl] = i
		}
		byName[rec.name+"|"+rec.version] = i
		byName[name+"|"+rec.version] = i
	}
	inv.total = len(inv.items) + (s.total - len(s.records))
	if mr != nil {
		for _, f := range mr.matches {
			i, ok := byPURL[f.purl]
			if !ok || f.purl == "" {
				i, ok = byName[f.name+"|"+f.version]
			}
			if !ok {
				inv.dropped++
				continue
			}
			addMatch(&inv.items[i], f.match, &inv.dropped)
		}
	}
	for i := range inv.items {
		finishMatches(&inv.items[i], &inv.dropped)
	}
	sort.SliceStable(inv.items, func(a, b int) bool {
		x, y := &inv.items[a], &inv.items[b]
		if (len(x.Matches) > 0) != (len(y.Matches) > 0) {
			return len(x.Matches) > 0
		}
		if x.Ecosystem != y.Ecosystem {
			return x.Ecosystem < y.Ecosystem
		}
		if x.Name != y.Name {
			return x.Name < y.Name
		}
		return x.Version < y.Version
	})
	if len(inv.items) > maxPackages {
		inv.items = inv.items[:maxPackages]
	}
	return inv
}

// addMatch merges a match into an item: the same id twice (several locations of one
// package, or a vulnerability listed for each) becomes one match.
func addMatch(it *Item, m Match, dropped *int) {
	m = cleanMatch(m, dropped)
	if m.ID == "" {
		return
	}
	for i := range it.Matches {
		cur := &it.Matches[i]
		if cur.ID != m.ID {
			continue
		}
		cur.Aliases = mergeStrings(cur.Aliases, m.Aliases, maxAliases)
		cur.FixVersions = mergeStrings(cur.FixVersions, m.FixVersions, maxFixVersions)
		for _, c := range m.CVSS {
			if !slices.Contains(cur.CVSS, c) && len(cur.CVSS) < maxCVSS {
				cur.CVSS = append(cur.CVSS, c)
			}
		}
		if severityRank[m.Severity] > severityRank[cur.Severity] {
			cur.Severity = m.Severity
		}
		return
	}
	it.Matches = append(it.Matches, m)
}

// cleanMatch keeps only fields within the protocol's bounds; a match without a valid id
// is dropped (ID "").
func cleanMatch(m Match, dropped *int) Match {
	if !matchIDPattern.MatchString(m.ID) {
		*dropped++
		return Match{}
	}
	out := Match{ID: m.ID, Aliases: []string{}, Severity: severity(m.Severity), CVSS: []CVSS{}, FixVersions: []string{}, Matcher: m.Matcher}
	for _, a := range m.Aliases {
		if a != m.ID && matchIDPattern.MatchString(a) && !slices.Contains(out.Aliases, a) && len(out.Aliases) < maxAliases {
			out.Aliases = append(out.Aliases, a)
		}
	}
	for _, c := range m.CVSS {
		if c.ScoreTenths < 0 || c.ScoreTenths > 100 || !cvssVersionValue.MatchString(c.Version) ||
			len(c.Vector) > maxVectorChars || !printableASCIIOnly.MatchString(c.Vector) {
			continue
		}
		if !slices.Contains(out.CVSS, c) && len(out.CVSS) < maxCVSS {
			out.CVSS = append(out.CVSS, c)
		}
	}
	for _, f := range m.FixVersions {
		if validText(f, 1, maxFixChars) && !slices.Contains(out.FixVersions, f) && len(out.FixVersions) < maxFixVersions {
			out.FixVersions = append(out.FixVersions, f)
		}
	}
	return out
}

// finishMatches orders an item's matches (most severe first, then by id) and keeps at
// most maxMatches.
func finishMatches(it *Item, dropped *int) {
	sort.SliceStable(it.Matches, func(a, b int) bool {
		x, y := it.Matches[a], it.Matches[b]
		if severityRank[x.Severity] != severityRank[y.Severity] {
			return severityRank[x.Severity] > severityRank[y.Severity]
		}
		return x.ID < y.ID
	})
	if len(it.Matches) > maxMatches {
		*dropped += len(it.Matches) - maxMatches
		it.Matches = it.Matches[:maxMatches]
	}
}

func mergeStrings(cur, more []string, max int) []string {
	for _, s := range more {
		if !slices.Contains(cur, s) && len(cur) < max {
			cur = append(cur, s)
		}
	}
	return cur
}

// toolVersion keeps a version string within 40 printable ASCII characters (like the
// bridge's own version on the wire); "" when nothing is left.
func toolVersion(v string) string {
	v = strings.TrimPrefix(strings.TrimSpace(v), "v")
	b := make([]byte, 0, maxToolVersionLen)
	for i := 0; i < len(v) && len(b) < maxToolVersionLen; i++ {
		if c := v[i]; c > 0x20 && c <= 0x7e {
			b = append(b, c)
		}
	}
	return string(b)
}
