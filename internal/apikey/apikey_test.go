package apikey

import (
	"strings"
	"testing"
	"time"

	"github.com/privasimu/bridge/internal/config"
)

func TestGenerateAndVerify(t *testing.T) {
	key, id, hash, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(key, Prefix) || len(key) < 40 || !strings.HasPrefix(id, "k_") || HashOf(key) != hash {
		t.Fatalf("%q %q %q", key, id, hash)
	}
	key2, id2, hash2, _ := Generate()
	v, err := NewVerifier([]config.APIKey{{ID: id, Hash: hash}, {ID: id2, Hash: hash2}})
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := v.Verify(key); !ok || got != id {
		t.Fatalf("key 1: %q %v", got, ok)
	}
	if got, ok := v.Verify(key2); !ok || got != id2 {
		t.Fatalf("key 2: %q %v", got, ok)
	}
	for _, bad := range []string{"", key + "x", strings.ToUpper(key), strings.Repeat("a", MaxLength+1), hash} {
		if _, ok := v.Verify(bad); ok {
			t.Fatalf("%q must be refused", bad)
		}
	}
}

func TestDisabledAndExpiredKeys(t *testing.T) {
	key, id, hash, _ := Generate()
	if _, err := NewVerifier([]config.APIKey{{ID: id, Hash: hash, Disabled: true}}); err != ErrNoKeys {
		t.Fatalf("only disabled keys: %v", err)
	}
	v, err := NewVerifier([]config.APIKey{{ID: id, Hash: hash, Expires: "2026-10-31"}})
	if err != nil {
		t.Fatal(err)
	}
	v.now = func() time.Time { return time.Date(2026, 10, 31, 23, 0, 0, 0, time.UTC) }
	if _, ok := v.Verify(key); !ok {
		t.Fatal("a key is valid through its expiry day")
	}
	v.now = func() time.Time { return time.Date(2026, 11, 1, 0, 0, 1, 0, time.UTC) }
	if _, ok := v.Verify(key); ok {
		t.Fatal("an expired key must be refused")
	}
}

func TestInvalidHashIsAConfigurationError(t *testing.T) {
	if _, err := NewVerifier([]config.APIKey{{ID: "k", Hash: "md5:abc"}}); err == nil {
		t.Fatal("expected an error")
	}
}
