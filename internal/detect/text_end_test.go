package detect

import (
	"strings"
	"testing"
	"time"
)

// returnsWithin runs fn and fails the test when it has not returned after d. A detector that
// loops for ever leaves its goroutine spinning; the test still ends and reports it.
func returnsWithin(t *testing.T, d time.Duration, what string, fn func()) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		defer close(done)
		fn()
	}()
	select {
	case <-done:
	case <-time.After(d):
		t.Fatalf("%s did not return within %s: the detector loops", what, d)
	}
}

// loopShapes are text shapes that kept TextCounter.process on the same byte for ever before
// the fix (B-1 of the 6 November 2026 staging report): a '+' or '(' that follows a letter, a
// digit, '_' or '@' and precedes a digit starts no candidate, and skipToken did not move
// over it. Free text in a sampled column ("2+2", "Lantai(2)", plus addressing with digits)
// was enough to hang a scan at full CPU, without I/O, past its deadline.
var loopShapes = []string{
	"2+2 = 4",
	"Lantai(2) gedung timur",
	"x+1 y",
	"abc(1) def",
	"user_(5) catatan",
	"kirim ke budi+0812345678@example.co.id besok",
	"rumus: a+12, b(3)",
	"@(1) tanda",
	"Pasal 28G(1) UUD",
}

func TestTextCounterEndsOnGluedPlusOrParenthesis(t *testing.T) {
	for _, v := range loopShapes {
		returnsWithin(t, 5*time.Second, "column sampler on "+v, func() {
			s := NewColumnSampler("catatan")
			s.Add(v, false)
		})
		// The same shape inside long text, written in small chunks: the counter then examines
		// it before Close, with text held back after it.
		long := strings.Repeat("keterangan nasabah tanpa nomor apa pun. ", 20) + v + strings.Repeat(" sisa catatan", 50)
		returnsWithin(t, 5*time.Second, "text counter on long text with "+v, func() {
			tc := NewTextCounter(0)
			for i := 0; i < len(long); i += 7 {
				_, _ = tc.WriteString(long[i:min(len(long), i+7)])
			}
			_ = tc.Close()
		})
	}
}

func TestTextCounterStillCountsAroundGluedSigns(t *testing.T) {
	cases := []struct {
		text string
		want map[Category]int
	}{
		// A glued '+' or '(' starts nothing, but the number after it is a candidate.
		{"hubungi WA+6281234567890 segera", map[Category]int{Phone: 1}},
		{"NIK(" + nikMale + ") terlampir", map[Category]int{NIK: 1}},
		// Plus addressing: the address counts once, its digits are not a phone number.
		{"kirim ke budi+0812345678@example.co.id besok", map[Category]int{Email: 1}},
		{"2+2 = 4, Lantai(2)", map[Category]int{}},
	}
	for _, c := range cases {
		var got map[Category]int
		returnsWithin(t, 5*time.Second, c.text, func() { got = countsOf(t, c.text, len(c.text)) })
		if len(got) != len(c.want) {
			t.Fatalf("%q: %v, want %v", c.text, got, c.want)
		}
		for k, n := range c.want {
			if got[k] != n {
				t.Fatalf("%q: %v, want %v", c.text, got, c.want)
			}
		}
	}
}

// TestTextCounterAlwaysEnds feeds every string of up to five bytes over the characters the
// scanner treats specially, whole and byte by byte.
func TestTextCounterAlwaysEnds(t *testing.T) {
	const alphabet = "a1+()@_ .-"
	returnsWithin(t, 60*time.Second, "the exhaustive run", func() {
		var walk func(prefix []byte)
		walk = func(prefix []byte) {
			if len(prefix) > 0 {
				whole := NewTextCounter(0)
				_, _ = whole.Write(prefix)
				_ = whole.Close()
				bytewise := NewTextCounter(0)
				for i := range prefix {
					_, _ = bytewise.Write(prefix[i : i+1])
				}
				_ = bytewise.Close()
			}
			if len(prefix) == 5 {
				return
			}
			for i := 0; i < len(alphabet); i++ {
				walk(append(prefix, alphabet[i]))
			}
		}
		walk(nil)
	})
}

// FuzzTextCounterEnds checks that any text ends, whole and in chunks. The seeds run with
// go test; go test -fuzz=FuzzTextCounterEnds ./internal/detect explores further.
func FuzzTextCounterEnds(f *testing.F) {
	for _, s := range loopShapes {
		f.Add(s, uint8(3))
	}
	f.Add(sampleText, uint8(64))
	f.Fuzz(func(t *testing.T, text string, chunk uint8) {
		size := int(chunk%64) + 1
		returnsWithin(t, 10*time.Second, "text counter", func() {
			tc := NewTextCounter(0)
			for i := 0; i < len(text); i += size {
				_, _ = tc.WriteString(text[i:min(len(text), i+size)])
			}
			_ = tc.Close()
			s := NewColumnSampler("catatan")
			s.Add(text, false)
		})
	})
}
