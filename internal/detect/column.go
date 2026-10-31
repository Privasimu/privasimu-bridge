package detect

import (
	"encoding/base64"
	"encoding/json"
	"math"
	"regexp"
	"strings"
)

// Thresholds decide when sampled values make a column personal data.
type Thresholds struct {
	// MinMatches is the least number of matching values.
	MinMatches int
	// Ratio is the least share of non-empty values that must match.
	Ratio float64
}

// DefaultThresholds are used when a configuration leaves them out.
var DefaultThresholds = Thresholds{MinMatches: 3, Ratio: 0.2}

// Protection states of a column, decided from its sampled values (same codes as the
// platform's protection_state).
const (
	ProtectionUnknown   = "unknown"
	ProtectionPlaintext = "plaintext"
	ProtectionMasked    = "masked"
	ProtectionEncrypted = "encrypted"
	ProtectionMixed     = "mixed"
)

// longValue is the length from which a value is treated as free text and searched for
// embedded identifiers instead of being classified as a whole.
const longValue = 64

// maxValueBytes is the part of a sampled value that is examined.
const maxValueBytes = 4096

// ColumnSampler accumulates the sampled values of one column. Each value is examined when
// it is added and then dropped: only counters are kept.
type ColumnSampler struct {
	hints              Hints
	sampled, nonEmpty  int
	matches            map[Category]int
	strength           map[Category]float64
	enc, masked, plain int
}

// NewColumnSampler starts sampling a column; the column name gives context hints.
func NewColumnSampler(columnName string) *ColumnSampler {
	return &ColumnSampler{hints: HintsFromName(columnName), matches: map[Category]int{}, strength: map[Category]float64{}}
}

// Add examines one value. null marks a SQL NULL.
func (s *ColumnSampler) Add(value string, null bool) {
	s.sampled++
	if null {
		return
	}
	v := strings.TrimSpace(value)
	if v == "" {
		return
	}
	if len(v) > maxValueBytes {
		v = v[:maxValueBytes]
	}
	s.nonEmpty++
	switch {
	case looksEncrypted(v):
		s.enc++
	case looksMasked(v):
		s.masked++
	default:
		s.plain++
	}
	if len(v) <= longValue {
		if m, ok := ClassifyValue(v, s.hints); ok {
			s.matches[m.Category]++
			s.strength[m.Category] += m.Strength
			return
		}
		if !strings.ContainsAny(v, " \t,;:") {
			return // a single token that is not an identifier
		}
	}
	// Free text: count the value once for each kind of identifier it contains.
	tc := NewTextCounter(maxValueBytes)
	_, _ = tc.WriteString(v)
	_ = tc.Close()
	for c, n := range tc.Counts() {
		if n > 0 {
			s.matches[c]++
			s.strength[c] += 0.8
		}
	}
}

// ContentResult summarizes the sampled values of a column. It holds counts, never values.
type ContentResult struct {
	Sampled    int              `json:"sampled"`
	NonEmpty   int              `json:"non_empty"`
	Matches    map[Category]int `json:"matches,omitempty"`
	Category   Category         `json:"category,omitempty"`
	Detected   bool             `json:"detected"`
	Confidence float64          `json:"confidence"`
	Protection string           `json:"protection_state"`
}

// Result decides whether the sampled values show personal data.
func (s *ColumnSampler) Result(th Thresholds) ContentResult {
	if th.MinMatches <= 0 {
		th.MinMatches = DefaultThresholds.MinMatches
	}
	if th.Ratio <= 0 {
		th.Ratio = DefaultThresholds.Ratio
	}
	r := ContentResult{Sampled: s.sampled, NonEmpty: s.nonEmpty, Protection: s.protection()}
	if len(s.matches) > 0 {
		r.Matches = make(map[Category]int, len(s.matches))
		for k, v := range s.matches {
			r.Matches[k] = v
		}
	}
	best, bestN := Category(""), 0
	for _, c := range ValueCategories() { // fixed order breaks ties deterministically
		if n := s.matches[c]; n > bestN {
			best, bestN = c, n
		}
	}
	if best == "" || s.nonEmpty == 0 {
		return r
	}
	ratio := float64(bestN) / float64(s.nonEmpty)
	r.Category = best
	r.Confidence = round2(math.Min(1, s.strength[best]/float64(s.nonEmpty)))
	r.Detected = bestN >= th.MinMatches && ratio >= th.Ratio
	return r
}

func (s *ColumnSampler) protection() string {
	n := s.nonEmpty
	switch {
	case n == 0:
		return ProtectionUnknown
	case s.enc == n:
		return ProtectionEncrypted
	case s.masked == n:
		return ProtectionMasked
	case s.plain == n:
		return ProtectionPlaintext
	}
	return ProtectionMixed
}

func round2(f float64) float64 { return math.Round(f*100) / 100 }

var (
	hexBlob    = regexp.MustCompile(`^[0-9a-fA-F]{32,}$`)
	base64Blob = regexp.MustCompile(`^[A-Za-z0-9+/]{24,}={0,2}$`)
	maskRun    = regexp.MustCompile(`\*{2,}|•{2,}|#{4,}`)
	maskDigits = regexp.MustCompile(`(?i)\dx{3,}\d|x{4,}`)
)

// looksEncrypted reports whether a value looks like ciphertext (same heuristics as the
// platform's ContentPiiScanner): a Laravel Crypt payload, a long hex string, or a long
// high-entropy base64 string.
func looksEncrypted(v string) bool {
	if raw, err := base64.StdEncoding.DecodeString(v); err == nil && len(raw) > 0 {
		var payload map[string]any
		if json.Unmarshal(raw, &payload) == nil {
			_, iv := payload["iv"]
			_, value := payload["value"]
			_, mac := payload["mac"]
			_, tag := payload["tag"]
			if iv && value && (mac || tag) {
				return true
			}
		}
	}
	if strings.ContainsAny(v, " \t\r\n") {
		return false
	}
	if hexBlob.MatchString(v) {
		return true
	}
	return base64Blob.MatchString(v) && entropy(v) >= 3.6
}

// looksMasked reports whether a value looks masked ("1234****", "08xx-xxxx-1234").
func looksMasked(v string) bool {
	if maskRun.MatchString(v) {
		return true
	}
	return maskDigits.MatchString(v) && strings.ContainsAny(v, "0123456789")
}

// entropy is the Shannon entropy of s in bits per byte.
func entropy(s string) float64 {
	if s == "" {
		return 0
	}
	var freq [256]int
	for i := 0; i < len(s); i++ {
		freq[s[i]]++
	}
	h := 0.0
	n := float64(len(s))
	for _, c := range freq {
		if c > 0 {
			p := float64(c) / n
			h -= p * math.Log2(p)
		}
	}
	return h
}
