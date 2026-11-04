package detect

import (
	"context"
	"slices"
	"sort"
)

// EntityCounter is an optional language-model service that finds personal data in free
// text that patterns cannot recognise: names, addresses, dates of birth, health, religion
// and the like. It runs on the bridge server or inside the client's network (package nlp);
// the bridge uses only the counts it returns and never keeps the text it sends.
type EntityCounter interface {
	// Count returns, for each text, how many entities of each category it holds. Only
	// EntityCategories appear in the answer.
	Count(ctx context.Context, texts []string) ([]map[Category]int, error)
}

// EntityCategories are the categories a language model may add: every category without a
// value validator. The validated identifiers (NIK, phone numbers, e-mail, ...) are counted
// by the validators alone, so a value or a file is never counted twice for them.
func EntityCategories() []Category {
	out := make([]Category, 0, len(registry))
	for c := range registry {
		if !slices.Contains(ValueCategories(), c) {
			out = append(out, c)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// IsEntityCategory reports whether a language model may report c.
func IsEntityCategory(c Category) bool {
	_, known := registry[c]
	return known && !slices.Contains(ValueCategories(), c)
}

// MergeEntityCounts adds the entity counts of a text to the pattern counts of the same
// text: for each entity category the larger of the two, so that a category found both
// ways is not counted twice.
func MergeEntityCounts(counts map[Category]int, entities map[Category]int) map[Category]int {
	for c, n := range entities {
		if n <= 0 || !IsEntityCategory(c) {
			continue
		}
		if counts == nil {
			counts = map[Category]int{}
		}
		if n > counts[c] {
			counts[c] = n
		}
	}
	return counts
}
