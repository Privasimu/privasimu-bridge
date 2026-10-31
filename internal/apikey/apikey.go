// Package apikey creates and verifies the API keys the platform sends in X-API-Key.
// Keys are 256-bit random values; only their SHA-256 hash is stored. A fast hash is
// enough for keys of this entropy (password hashing is for low-entropy secrets), and the
// comparison is constant-time over every configured key.
package apikey

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"github.com/privasimu/bridge/internal/config"
)

// Prefix marks bridge API keys so secret scanners can recognize a leaked key.
const Prefix = "pvbk_"

// MaxLength bounds a presented key; longer header values are refused before hashing.
const MaxLength = 256

// Generate returns a new key, its id and its stored hash. The key is shown once and never
// written anywhere by the bridge.
func Generate() (key, id, hash string, err error) {
	raw := make([]byte, 32)
	if _, err = rand.Read(raw); err != nil {
		return "", "", "", err
	}
	key = Prefix + base64.RawURLEncoding.EncodeToString(raw)
	sum := sha256.Sum256([]byte(key))
	hash = "sha256:" + hex.EncodeToString(sum[:])
	id = "k_" + hex.EncodeToString(sum[:4])
	return key, id, hash, nil
}

type entry struct {
	id      string
	digest  [32]byte
	expires time.Time // zero = never
}

// Verifier checks presented keys against the configured hashes.
type Verifier struct {
	keys []entry
	now  func() time.Time
}

// ErrNoKeys means no usable key is configured.
var ErrNoKeys = errors.New("no API key is configured")

// NewVerifier builds a verifier from the configuration; disabled keys are skipped.
func NewVerifier(keys []config.APIKey) (*Verifier, error) {
	v := &Verifier{now: time.Now}
	for _, k := range keys {
		if k.Disabled {
			continue
		}
		raw, err := hex.DecodeString(strings.TrimPrefix(k.Hash, "sha256:"))
		if err != nil || len(raw) != 32 || !strings.HasPrefix(k.Hash, "sha256:") {
			return nil, errors.New("api key " + k.ID + " has an invalid hash")
		}
		e := entry{id: k.ID}
		copy(e.digest[:], raw)
		if k.Expires != "" {
			t, err := time.Parse("2006-01-02", k.Expires)
			if err != nil {
				return nil, errors.New("api key " + k.ID + " has an invalid expiry date")
			}
			e.expires = t.Add(24 * time.Hour) // valid through the whole expiry day (UTC)
		}
		v.keys = append(v.keys, e)
	}
	if len(v.keys) == 0 {
		return nil, ErrNoKeys
	}
	return v, nil
}

// Verify returns the id of the key that matches presented. Every configured key is
// compared, so the time taken does not reveal which key (if any) matched.
func (v *Verifier) Verify(presented string) (id string, ok bool) {
	if presented == "" || len(presented) > MaxLength {
		return "", false
	}
	sum := sha256.Sum256([]byte(presented))
	now := v.now()
	matched := -1
	for i := range v.keys {
		if subtle.ConstantTimeCompare(sum[:], v.keys[i].digest[:]) == 1 {
			matched = i
		}
	}
	if matched < 0 {
		return "", false
	}
	k := v.keys[matched]
	if !k.expires.IsZero() && !now.Before(k.expires) {
		return "", false
	}
	return k.id, true
}

// HashOf returns the stored form of a key (for tests and the key command).
func HashOf(key string) string {
	sum := sha256.Sum256([]byte(key))
	return "sha256:" + hex.EncodeToString(sum[:])
}
