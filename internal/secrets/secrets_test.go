package secrets

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/privasimu/bridge/internal/config"
)

const placeholder = "placeholder-password-for-tests"

func TestStoreRoundTripAndTamperDetection(t *testing.T) {
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "secrets.key")
	if err := CreateKeyFile(keyFile); err != nil {
		t.Fatal(err)
	}
	if err := CreateKeyFile(keyFile); err == nil {
		t.Fatal("an existing key file must not be overwritten")
	}
	key, err := LoadKey(keyFile)
	if err != nil {
		t.Fatal(err)
	}
	storePath := filepath.Join(dir, "secrets.enc")
	s, err := Open(storePath, key)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Set("corebank_pg", placeholder); err != nil {
		t.Fatal(err)
	}
	if err := s.Set("bad name", "x"); err == nil {
		t.Fatal("invalid names must be refused")
	}
	if err := s.Save(); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(storePath)
	if strings.Contains(string(raw), placeholder) || strings.Contains(string(raw), "corebank_pg") {
		t.Fatal("the store file must not contain names or values in clear text")
	}
	s2, err := Open(storePath, key)
	if err != nil {
		t.Fatal(err)
	}
	if v, ok := s2.Get("corebank_pg"); !ok || v.Reveal() != placeholder {
		t.Fatal("round trip failed")
	}
	// Flip one byte of the ciphertext: GCM must refuse it.
	var sf storeFile
	_ = json.Unmarshal(raw, &sf)
	// Replace the first character with a different one. A fixed "A" was a no-op whenever the
	// ciphertext already started with "A", so the tamper check passed by chance about 1 in 64 runs.
	first := "A"
	if strings.HasPrefix(sf.Ciphertext, "A") {
		first = "B"
	}
	sf.Ciphertext = first + sf.Ciphertext[1:]
	tampered, _ := json.Marshal(sf)
	_ = os.WriteFile(storePath, tampered, 0o600)
	if _, err := Open(storePath, key); err == nil {
		t.Fatal("a tampered store must not open")
	}
	other := make([]byte, 32)
	if _, err := Open(filepath.Join(dir, "missing.enc"), other); err != nil {
		t.Fatal("a missing store is empty, not an error")
	}
}

func TestKeyFromEnvironment(t *testing.T) {
	t.Setenv(EnvKey, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
	key, err := LoadKey("")
	if err != nil || len(key) != 32 {
		t.Fatalf("%v %d", err, len(key))
	}
	t.Setenv(EnvKey, "short")
	if _, err := LoadKey(""); err == nil {
		t.Fatal("a short key must be refused")
	}
}

func TestResolver(t *testing.T) {
	dir := t.TempDir()
	key := make([]byte, 32)
	s, _ := Open(filepath.Join(dir, "s.enc"), key)
	_ = s.Set("db", placeholder)
	r := NewResolverForStore(s)

	t.Setenv("BRIDGE_TEST_SECRET", placeholder)
	file := filepath.Join(dir, "pw.txt")
	_ = os.WriteFile(file, []byte(placeholder+"\r\n"), 0o600)

	for _, ref := range []config.SecretRef{"secret:db", "env:BRIDGE_TEST_SECRET", config.SecretRef("file:" + file)} {
		v, err := r.Resolve(ref)
		if err != nil || v.Reveal() != placeholder {
			t.Fatalf("%s: %v", ref, err)
		}
	}
	for _, ref := range []config.SecretRef{"secret:missing", "env:BRIDGE_TEST_MISSING", "file:" + config.SecretRef(filepath.Join(dir, "nope")), "literal"} {
		if _, err := r.Resolve(ref); err == nil {
			t.Fatalf("%s must fail", ref)
		} else if strings.Contains(err.Error(), placeholder) {
			t.Fatal("errors must not carry values")
		}
	}
}

func TestValuesNeverPrint(t *testing.T) {
	v := Value(placeholder)
	var sb strings.Builder
	logger := slog.New(slog.NewJSONHandler(&sb, nil))
	logger.Info("x", "password", v)
	js, _ := json.Marshal(map[string]any{"password": v})
	for _, out := range []string{fmt.Sprint(v), fmt.Sprintf("%v %s %+v %#v", v, v, v, v), sb.String(), string(js)} {
		if strings.Contains(out, placeholder) {
			t.Fatalf("value leaked: %s", out)
		}
	}
	if v.Reveal() != placeholder {
		t.Fatal("Reveal must return the value")
	}
}
