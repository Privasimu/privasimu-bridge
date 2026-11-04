package secrets

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
)

// IDKeyFile is the name of the install's id key in the state directory. It names files
// (files.report_paths: hashed) and group roles (access_inventory.role_names: hashed)
// outside the network; it never leaves the bridge server.
const IDKeyFile = "file-id.key"

// LoadOrCreateIDKey returns the install's id key kept in the state directory, creating it
// on first use with owner-only permissions. The same key gives the same ids, so ids stay
// stable within one install; without it an id cannot be turned back into a path or a name.
func LoadOrCreateIDKey(stateDir string) ([]byte, error) {
	p := filepath.Join(stateDir, IDKeyFile)
	data, err := os.ReadFile(p) // #nosec G304 -- inside the configured state directory
	if err == nil {
		key, derr := hex.DecodeString(string(trimNL(data)))
		if derr == nil && len(key) == 32 {
			return key, nil
		}
		return nil, errors.New(IDKeyFile + " is damaged; delete it to create a new one (file and role ids will change)")
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	if err := WriteFileAtomic(p, []byte(hex.EncodeToString(key)+"\n"), 0o600); err != nil {
		return nil, err
	}
	return key, nil
}

func trimNL(b []byte) []byte {
	for len(b) > 0 && (b[len(b)-1] == '\n' || b[len(b)-1] == '\r') {
		b = b[:len(b)-1]
	}
	return b
}
