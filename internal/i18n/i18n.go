// Package i18n provides the English and Indonesian texts shown to operators: CLI output,
// configuration errors and the messages in error responses. Code, logs and audit records
// use stable English codes; only human-facing text goes through this package.
package i18n

import (
	"fmt"
	"os"
	"strings"
	"sync/atomic"
)

// Lang is a supported user interface language.
type Lang string

const (
	EN Lang = "en"
	ID Lang = "id"
)

var current atomic.Value // Lang

func init() { current.Store(EN) }

// Parse maps a language tag ("id", "id_ID.UTF-8", "in", "en-US", ...) to a supported
// language. Anything that is not Indonesian is English.
func Parse(tag string) Lang {
	t := strings.ToLower(strings.TrimSpace(tag))
	if t == "id" || t == "in" || strings.HasPrefix(t, "id_") || strings.HasPrefix(t, "id-") ||
		strings.HasPrefix(t, "in_") || strings.HasPrefix(t, "indonesia") {
		return ID
	}
	return EN
}

// Set changes the language used by T.
func Set(l Lang) { current.Store(l) }

// Current returns the language used by T.
func Current() Lang { return current.Load().(Lang) }

// Detect picks the language from, in order: an explicit flag value, the
// PRIVASIMU_BRIDGE_LANG environment variable, and the configuration file value.
// An empty value is skipped; the default is English.
func Detect(flagValue, configValue string) Lang {
	for _, v := range []string{flagValue, os.Getenv("PRIVASIMU_BRIDGE_LANG"), configValue} {
		if strings.TrimSpace(v) != "" {
			return Parse(v)
		}
	}
	return EN
}

// T returns the text for key in the current language, formatted with args.
// An unknown key returns the key itself so a missing entry is visible, never empty.
func T(key string, args ...any) string { return TL(Current(), key, args...) }

// TL is T for an explicit language.
func TL(l Lang, key string, args ...any) string {
	pair, ok := catalog[key]
	if !ok {
		return key
	}
	text := pair[0]
	if l == ID && pair[1] != "" {
		text = pair[1]
	}
	if len(args) == 0 {
		return text
	}
	return fmt.Sprintf(text, args...)
}

// Keys returns every catalog key (for tests).
func Keys() []string {
	out := make([]string, 0, len(catalog))
	for k := range catalog {
		out = append(out, k)
	}
	return out
}

// Pair returns the English and Indonesian template of a key (for tests).
func Pair(key string) (en, id string, ok bool) {
	p, ok := catalog[key]
	return p[0], p[1], ok
}
