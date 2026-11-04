// Package secrets resolves the secret references of the configuration (env:, file:,
// secret:) and keeps the local encrypted secret store. Secret values are returned as the
// Value type, which prints and serializes as "[redacted]" so that a value cannot reach a
// log line by accident.
package secrets

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"

	"github.com/privasimu/bridge/internal/config"
	"github.com/privasimu/bridge/internal/fsutil"
)

// Value is a resolved secret. Use Reveal only where the value is handed to a driver or
// a header.
type Value string

const redacted = "[redacted]"

// Reveal returns the secret itself.
func (v Value) Reveal() string { return string(v) }

// String hides the value.
func (v Value) String() string { return redacted }

// GoString hides the value from %#v.
func (v Value) GoString() string { return redacted }

// MarshalJSON hides the value.
func (v Value) MarshalJSON() ([]byte, error) { return json.Marshal(redacted) }

// LogValue hides the value from slog.
func (v Value) LogValue() slog.Value { return slog.StringValue(redacted) }

// Environment variables that supply the store key instead of the key file.
const (
	EnvKey     = "PRIVASIMU_BRIDGE_SECRETS_KEY"
	EnvKeyFile = "PRIVASIMU_BRIDGE_SECRETS_KEY_FILE"
)

const (
	keySize       = 32
	maxSecretFile = 64 << 10
	maxStoreFile  = 4 << 20
	storeFormat   = "privasimu-bridge-secrets"
	storeAAD      = "privasimu-bridge-secrets/v1"
	keyPrefixRaw  = "v1:"
	keyPrefixDPAP = "dpapi:"
)

var namePattern = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`)

// ValidName reports whether a secret name is acceptable.
func ValidName(name string) bool { return namePattern.MatchString(name) }

// Errors that callers can test for.
var (
	ErrNoKey       = errors.New("the secret store key is missing")
	ErrBadKey      = errors.New("the secret store key is not valid")
	ErrDecrypt     = errors.New("the secret store cannot be decrypted with this key")
	ErrNotFound    = errors.New("secret not found")
	ErrEmptySecret = errors.New("secret is empty")
)

// CreateKeyFile writes a new random store key. On Windows the key is additionally
// protected with DPAPI (machine scope), so a copied file is useless on another machine.
// It refuses to overwrite an existing file.
func CreateKeyFile(path string) error {
	key := make([]byte, keySize)
	if _, err := rand.Read(key); err != nil {
		return err
	}
	content := keyPrefixRaw + base64.StdEncoding.EncodeToString(key) + "\n"
	if dpapiAvailable {
		blob, err := protect(key)
		if err != nil {
			return fmt.Errorf("protect the key with DPAPI: %w", err)
		}
		content = keyPrefixDPAP + base64.StdEncoding.EncodeToString(blob) + "\n"
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) // #nosec G304 -- key file path from the local configuration
	if err != nil {
		return err
	}
	if _, err := f.WriteString(content); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

// LoadKey returns the store key from PRIVASIMU_BRIDGE_SECRETS_KEY (base64),
// PRIVASIMU_BRIDGE_SECRETS_KEY_FILE, or the key file of the configuration.
func LoadKey(keyFile string) ([]byte, error) {
	if v := strings.TrimSpace(os.Getenv(EnvKey)); v != "" {
		return decodeKey(keyPrefixRaw + v)
	}
	if p := strings.TrimSpace(os.Getenv(EnvKeyFile)); p != "" {
		keyFile = p
	}
	if keyFile == "" {
		return nil, ErrNoKey
	}
	data, err := readLimited(keyFile, 4096)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, ErrNoKey
		}
		return nil, err
	}
	return decodeKey(strings.TrimSpace(string(data)))
}

func decodeKey(text string) ([]byte, error) {
	switch {
	case strings.HasPrefix(text, keyPrefixRaw):
		key, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(text, keyPrefixRaw))
		if err != nil || len(key) != keySize {
			return nil, ErrBadKey
		}
		return key, nil
	case strings.HasPrefix(text, keyPrefixDPAP):
		if !dpapiAvailable {
			return nil, fmt.Errorf("%w: it was protected with Windows DPAPI on another machine", ErrBadKey)
		}
		blob, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(text, keyPrefixDPAP))
		if err != nil {
			return nil, ErrBadKey
		}
		key, err := unprotect(blob)
		if err != nil || len(key) != keySize {
			return nil, fmt.Errorf("%w: DPAPI could not unprotect it (was it created on this machine?)", ErrBadKey)
		}
		return key, nil
	}
	return nil, ErrBadKey
}

// readLimited reads a local file named by the configuration or the operator (never by
// the network) up to max bytes.
func readLimited(path string, max int64) ([]byte, error) {
	f, err := os.Open(path) // #nosec G304 G703 -- local configuration path
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > max {
		return nil, fmt.Errorf("%s is larger than %d bytes", path, max)
	}
	return data, nil
}

// Store is the encrypted secret store: a map of names to values sealed with AES-256-GCM.
type Store struct {
	path string
	key  []byte
	// mu guards values: a running agent stores a rotated token while jobs read secrets.
	mu     sync.RWMutex
	values map[string]string
}

type storeFile struct {
	Format     string `json:"format"`
	Version    int    `json:"version"`
	Cipher     string `json:"cipher"`
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
}

// Open reads the store at path; a missing file is an empty store.
func Open(path string, key []byte) (*Store, error) {
	if len(key) != keySize {
		return nil, ErrBadKey
	}
	s := &Store{path: path, key: key, values: map[string]string{}}
	data, err := readLimited(path, maxStoreFile)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	var sf storeFile
	if err := json.Unmarshal(data, &sf); err != nil || sf.Format != storeFormat || sf.Version != 1 {
		return nil, fmt.Errorf("%s is not a bridge secret store", path)
	}
	nonce, err1 := base64.StdEncoding.DecodeString(sf.Nonce)
	ct, err2 := base64.StdEncoding.DecodeString(sf.Ciphertext)
	if err1 != nil || err2 != nil {
		return nil, ErrDecrypt
	}
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	if len(nonce) != gcm.NonceSize() {
		return nil, ErrDecrypt
	}
	plain, err := gcm.Open(nil, nonce, ct, []byte(storeAAD))
	if err != nil {
		return nil, ErrDecrypt
	}
	defer wipe(plain)
	if err := json.Unmarshal(plain, &s.values); err != nil {
		return nil, ErrDecrypt
	}
	return s, nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// Get returns a secret.
func (s *Store) Get(name string) (Value, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	v, ok := s.values[name]
	return Value(v), ok
}

// Set stores a secret in memory; call Save to write it.
func (s *Store) Set(name, value string) error {
	if !ValidName(name) {
		return fmt.Errorf("secret names use 1-64 letters, digits, '_', '.' or '-'")
	}
	if value == "" {
		return ErrEmptySecret
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.values[name] = value
	return nil
}

// Delete removes a secret in memory and reports whether it existed.
func (s *Store) Delete(name string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.values[name]
	delete(s.values, name)
	return ok
}

// Names lists the stored secret names, sorted. It never lists values.
func (s *Store) Names() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]string, 0, len(s.values))
	for k := range s.values {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Save writes the store atomically with owner-only permissions.
func (s *Store) Save() error {
	s.mu.RLock()
	plain, err := json.Marshal(s.values)
	s.mu.RUnlock()
	if err != nil {
		return err
	}
	defer wipe(plain)
	gcm, err := newGCM(s.key)
	if err != nil {
		return err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	ct := gcm.Seal(nil, nonce, plain, []byte(storeAAD))
	out, err := json.MarshalIndent(storeFile{Format: storeFormat, Version: 1, Cipher: "AES-256-GCM",
		Nonce: base64.StdEncoding.EncodeToString(nonce), Ciphertext: base64.StdEncoding.EncodeToString(ct)}, "", "  ")
	if err != nil {
		return err
	}
	return WriteFileAtomic(s.path, append(out, '\n'), 0o600)
}

// WriteFileAtomic writes data to a temporary file next to path and renames it into place.
func WriteFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	name := tmp.Name()
	cleanup := func() { _ = os.Remove(name) }
	if err := tmp.Chmod(perm); err != nil && !isWindows {
		_ = tmp.Close()
		cleanup()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		cleanup()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		cleanup()
		return err
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return err
	}
	// Keep the owner of the file being replaced (or of the folder), so that a command run
	// with sudo does not leave a root-owned file the service can no longer read.
	previous := ""
	if _, err := os.Stat(path); err == nil {
		previous = path
	}
	fsutil.InheritOwner(name, previous)
	if err := os.Rename(name, path); err != nil {
		cleanup()
		return err
	}
	return nil
}

// Resolver resolves secret references, opening the store on first use.
type Resolver struct {
	storePath, keyFile string
	mu                 sync.Mutex
	store              *Store
}

// NewResolver returns a resolver for the store and key file named in the configuration.
func NewResolver(c *config.Config) *Resolver {
	return &Resolver{storePath: c.Resolve(c.Secrets.File), keyFile: c.Resolve(c.Secrets.KeyFile)}
}

// NewResolverForStore returns a resolver over an already opened store (for tests).
func NewResolverForStore(s *Store) *Resolver { return &Resolver{store: s} }

// Store opens the secret store.
func (r *Resolver) Store() (*Store, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.store != nil {
		return r.store, nil
	}
	key, err := LoadKey(r.keyFile)
	if err != nil {
		return nil, err
	}
	s, err := Open(r.storePath, key)
	if err != nil {
		return nil, err
	}
	r.store = s
	return s, nil
}

// Resolve returns the secret a reference points at. Errors name the reference, never
// the value.
func (r *Resolver) Resolve(ref config.SecretRef) (Value, error) {
	kind, target, ok := ref.Parse()
	if !ok {
		return "", fmt.Errorf("%q is not a secret reference", ref.String())
	}
	switch kind {
	case config.RefEnv:
		v, found := os.LookupEnv(target)
		if !found || v == "" {
			return "", fmt.Errorf("%w: environment variable %s is not set", ErrNotFound, target)
		}
		return Value(v), nil
	case config.RefFile:
		data, err := readLimited(target, maxSecretFile)
		if err != nil {
			return "", fmt.Errorf("secret file: %w", err)
		}
		v := strings.TrimRight(string(data), "\r\n")
		if v == "" {
			return "", fmt.Errorf("%w: file %s", ErrEmptySecret, target)
		}
		return Value(v), nil
	case config.RefSecret:
		s, err := r.Store()
		if err != nil {
			return "", err
		}
		v, found := s.Get(target)
		if !found {
			return "", fmt.Errorf("%w: %s (add it with: privasimu-bridge secret set %s)", ErrNotFound, target, target)
		}
		return v, nil
	}
	return "", fmt.Errorf("%q is not a secret reference", ref.String())
}
