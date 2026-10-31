package i18n

import (
	"regexp"
	"strings"
	"testing"
)

var verb = regexp.MustCompile(`%[-+# 0-9.]*[a-zA-Z%]`)

func TestCatalogIsComplete(t *testing.T) {
	for _, k := range Keys() {
		en, id, _ := Pair(k)
		if strings.TrimSpace(en) == "" || strings.TrimSpace(id) == "" {
			t.Errorf("%s: both English and Indonesian text are required", k)
		}
		if a, b := verb.FindAllString(en, -1), verb.FindAllString(id, -1); strings.Join(a, " ") != strings.Join(b, " ") {
			t.Errorf("%s: format verbs differ: %v vs %v", k, a, b)
		}
		if strings.Contains(strings.ToLower(en), "vendor") || strings.Contains(strings.ToLower(id), "vendor") {
			t.Errorf("%s: say third party / pihak ketiga, not vendor", k)
		}
	}
}

func TestParseAndFallback(t *testing.T) {
	for tag, want := range map[string]Lang{"id": ID, "id_ID.UTF-8": ID, "in": ID, "Indonesian": ID, "en": EN, "en-US": EN, "": EN, "fr": EN} {
		if got := Parse(tag); got != want {
			t.Errorf("Parse(%q) = %s, want %s", tag, got, want)
		}
	}
	if got := TL(ID, "api.not_found"); got != "Tidak ditemukan." {
		t.Fatalf("%q", got)
	}
	if got := TL(EN, "no.such.key"); got != "no.such.key" {
		t.Fatalf("an unknown key must show itself: %q", got)
	}
	if got := TL(EN, "config.port", "sources[0].port"); got != "sources[0].port must be between 1 and 65535" {
		t.Fatalf("%q", got)
	}
}
