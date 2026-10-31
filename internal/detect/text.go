package detect

const (
	contextBytes = 64   // bytes of context read on each side of a candidate
	keepBytes    = 400  // bytes held back until more text arrives (longest e-mail + context)
	maxRun       = 1024 // longest run of digits and separators examined at once
)

// TextCounter counts identifiers in a stream of text. Write text in any number of chunks
// and call Close after the last one. Each match is counted and forgotten; the counter
// never keeps a value. It implements io.Writer.
type TextCounter struct {
	buf       []byte
	cursor    int // index in buf of the next byte not examined yet
	counts    map[Category]int
	written   int64
	maxBytes  int64
	truncated bool
	closed    bool
}

// NewTextCounter returns a counter that reads at most maxBytes of text (0 = no limit).
func NewTextCounter(maxBytes int64) *TextCounter {
	return &TextCounter{counts: map[Category]int{}, maxBytes: maxBytes}
}

// Write examines p. It always reports len(p) so that io.Copy does not stop when the byte
// limit is reached; bytes past the limit are ignored and Truncated reports it.
func (t *TextCounter) Write(p []byte) (int, error) {
	n := len(p)
	if t.closed {
		return n, nil
	}
	if t.maxBytes > 0 && t.written+int64(len(p)) > t.maxBytes {
		allowed := t.maxBytes - t.written
		if allowed < 0 {
			allowed = 0
		}
		p = p[:allowed]
		t.truncated = true
	}
	t.written += int64(len(p))
	t.buf = append(t.buf, p...)
	t.process(false)
	return n, nil
}

// WriteString is Write for a string.
func (t *TextCounter) WriteString(s string) (int, error) { return t.Write([]byte(s)) }

// Close examines the text still held back.
func (t *TextCounter) Close() error {
	if !t.closed {
		t.process(true)
		t.closed = true
		t.buf = nil
	}
	return nil
}

// Counts returns the number of matches per category.
func (t *TextCounter) Counts() map[Category]int {
	out := make(map[Category]int, len(t.counts))
	for k, v := range t.counts {
		out[k] = v
	}
	return out
}

// Truncated reports whether text past the byte limit was ignored.
func (t *TextCounter) Truncated() bool { return t.truncated }

// BytesRead returns the number of bytes examined.
func (t *TextCounter) BytesRead() int64 { return t.written }

func isDigit(c byte) bool { return c >= '0' && c <= '9' }
func isAlnum(c byte) bool { return isDigit(c) || isLetter(c) }

// process examines candidates that start before the held-back tail (or all of them when
// final) and then drops what is no longer needed for context.
func (t *TextCounter) process(final bool) {
	b := t.buf
	end := len(b)
	if !final {
		end -= keepBytes
	}
	i := t.cursor
scan:
	for i < end {
		c := b[i]
		switch {
		case c == '@':
			i = t.email(i)
		case isDigit(c) || ((c == '+' || c == '(') && i+1 < len(b) && isDigit(b[i+1])):
			if !leftBoundary(b, i) {
				i = skipToken(b, i)
				continue
			}
			next, ok := t.number(i, final)
			if !ok {
				break scan // the run continues past the buffered text; wait for more
			}
			i = next
		case isLetter(c):
			j := i
			for j < len(b) && isAlnum(b[j]) {
				j++
			}
			if j == len(b) && !final {
				break scan
			}
			if j-i >= 7 && j-i <= 9 && leftBoundary(b, i) && rightBoundary(b, j) {
				t.word(i, j)
			}
			i = j
		default:
			i++
		}
	}
	t.cursor = i
	if drop := t.cursor - contextBytes; drop > 0 {
		n := copy(t.buf, t.buf[drop:])
		t.buf = t.buf[:n]
		t.cursor -= drop
	}
}

// leftBoundary reports whether a candidate may start at i: it must not continue a word,
// an identifier such as a hex string, or an e-mail address.
func leftBoundary(b []byte, i int) bool {
	if i == 0 {
		return true
	}
	c := b[i-1]
	return !(isAlnum(c) || c == '_' || c == '@')
}

// rightBoundary reports whether a candidate may end at k.
func rightBoundary(b []byte, k int) bool {
	if k >= len(b) {
		return true
	}
	c := b[k]
	if isAlnum(c) || c == '@' || c == '_' {
		return false
	}
	if c == '.' || c == '-' || c == '+' || c == '%' {
		// Part of an e-mail local part ("0812345678.budi@mail.example")?
		for j := k; j < len(b) && j < k+64; j++ {
			if b[j] == '@' {
				return false
			}
			if !isEmailLocalChar(b[j]) {
				break
			}
		}
	}
	return true
}

// skipToken moves past a token that a candidate cannot start inside. It stops at '@' so
// that an e-mail address after the token is still examined.
func skipToken(b []byte, i int) int {
	for i < len(b) && (isAlnum(b[i]) || b[i] == '_' || b[i] == '.' || b[i] == '-') {
		i++
	}
	return i
}

// windowHints derives hints from the words around [start, end).
func windowHints(b []byte, start, end int) Hints {
	lo, hi := start-contextBytes, end+contextBytes
	if lo < 0 {
		lo = 0
	}
	if hi > len(b) {
		hi = len(b)
	}
	var words []string
	w := make([]byte, 0, 32)
	for k := lo; k <= hi; k++ {
		if k < hi && isAlnum(b[k]) {
			c := b[k]
			if c >= 'A' && c <= 'Z' {
				c += 'a' - 'A'
			}
			if len(w) < 32 {
				w = append(w, c)
			}
			continue
		}
		if len(w) > 0 {
			words = append(words, string(w))
			w = w[:0]
		}
	}
	return HintsFromWords(words)
}

// email examines the address around the '@' at i and returns where scanning continues.
func (t *TextCounter) email(i int) int {
	b := t.buf
	j := i
	for j > 0 && i-j < 64 && isEmailLocalChar(b[j-1]) {
		j--
	}
	k := i + 1
	for k < len(b) && k-i <= 253 && (isAlnum(b[k]) || b[k] == '-' || b[k] == '.') {
		k++
	}
	for k > i+1 && (b[k-1] == '.' || b[k-1] == '-') {
		k--
	}
	for j < i && b[j] == '.' {
		j++
	}
	if j < i && k > i+1 && ValidEmail(string(b[j:k])) {
		t.counts[Email]++
		return k
	}
	return i + 1
}

// number examines the run of digits and separators that starts at i. ok is false when the
// run reaches the end of the buffered text and more may follow.
func (t *TextCounter) number(i int, final bool) (next int, ok bool) {
	b := t.buf
	j := i
	if b[j] == '+' || b[j] == '(' {
		j++
	}
	for j < len(b) && j-i < maxRun {
		c := b[j]
		if isDigit(c) {
			j++
			continue
		}
		if c == ' ' || c == '-' || c == '.' || c == '(' || c == ')' {
			if j+1 < len(b) && (isDigit(b[j+1]) || b[j+1] == '(' || (c == ')' && b[j+1] == ' ')) {
				j++
				continue
			}
			if c == ')' {
				j++ // a closing parenthesis ends the run, "(021)"
			}
		}
		break
	}
	if j == len(b) && !final && j-i < maxRun {
		return i, false
	}
	if !rightBoundary(b, j) {
		return skipToken(b, j), true
	}
	t.classifyRun(i, j)
	return j, true
}

type span struct{ start, end int }

// classifyRun splits a run into digit groups and greedily matches the longest group
// sequence that is a valid identifier, so that "3171012303900001 081234567890" counts a NIK
// and a phone number, and "4111 1111 1111 1111" counts one card.
func (t *TextCounter) classifyRun(start, end int) {
	b := t.buf
	var groups []span
	for k := start; k < end; {
		if !isDigit(b[k]) {
			k++
			continue
		}
		g := span{start: k}
		for k < end && isDigit(b[k]) {
			k++
		}
		g.end = k
		groups = append(groups, g)
	}
	total := 0
	for _, g := range groups {
		total += g.end - g.start
	}
	if total < 9 {
		return
	}
	hints := windowHints(b, start, end)
	for g := 0; g < len(groups); {
		matched := false
		for h := min(len(groups)-1, g+6); h >= g; h-- {
			digits := 0
			for x := g; x <= h; x++ {
				digits += groups[x].end - groups[x].start
			}
			if digits < 9 {
				break
			}
			if digits > 19 {
				continue
			}
			from := groups[g].start
			if g == 0 {
				from = start // keep a leading '+' or '('
			} else if from > start && b[from-1] == '(' {
				from--
			}
			to := groups[h].end
			if to < end && b[to] == ')' {
				to++
			}
			if vm, ok := ClassifyValue(string(b[from:to]), hints); ok {
				t.counts[vm.Category]++
				g = h + 1
				matched = true
				break
			}
		}
		if !matched {
			g++
		}
	}
}

// word examines a word of letters and digits that may be a passport number.
func (t *TextCounter) word(i, j int) {
	b := t.buf
	if !isLetter(b[i]) || !isDigit(b[j-1]) {
		return
	}
	hints := windowHints(b, i, j)
	if !hints.Has(HintPassport) {
		return
	}
	if vm, ok := ClassifyValue(string(b[i:j]), hints); ok {
		t.counts[vm.Category]++
	}
}
