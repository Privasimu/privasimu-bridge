package buildinfo

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// repoRoot is the repository root, two levels above this package.
var repoRoot = filepath.Join("..", "..")

// TestReleasePublicKeys: the files in release-keys/ are either the marked placeholders or
// real public keys (a minisign Ed25519 public key; a cosign PEM public key), never
// anything else.
func TestReleasePublicKeys(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(repoRoot, "release-keys", "minisign.pub"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(raw, []byte("PLACEHOLDER")) {
		lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
		key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(lines[len(lines)-1]))
		// "Ed" + 8-byte key id + 32-byte Ed25519 public key.
		if err != nil || len(key) != 42 || string(key[:2]) != "Ed" {
			t.Fatalf("release-keys/minisign.pub is neither the placeholder nor a minisign public key")
		}
	}
	raw, err = os.ReadFile(filepath.Join(repoRoot, "release-keys", "cosign.pub"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(raw, []byte("PLACEHOLDER")) {
		block, _ := pem.Decode(raw)
		if block == nil || block.Type != "PUBLIC KEY" {
			t.Fatal("release-keys/cosign.pub is neither the placeholder nor a PEM public key")
		}
		if _, err := x509.ParsePKIXPublicKey(block.Bytes); err != nil {
			t.Fatalf("release-keys/cosign.pub: %v", err)
		}
	}
}

// TestNoReleaseSecretKeyInTheRepository guards against committing a signing key: the
// minisign and cosign secret key formats are refused anywhere in the working tree.
func TestNoReleaseSecretKeyInTheRepository(t *testing.T) {
	// Built from parts so this file does not match itself.
	markers := []string{
		"untrusted comment: minisign " + "encrypted secret key",
		"untrusted comment: minisign " + "secret key",
		"BEGIN ENCRYPTED " + "SIGSTORE PRIVATE KEY",
		"BEGIN ENCRYPTED " + "COSIGN PRIVATE KEY",
	}
	err := filepath.WalkDir(repoRoot, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "dist", "bin":
				return filepath.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		if info, err := d.Info(); err != nil || info.Size() > 4<<20 {
			return nil
		}
		raw, err := os.ReadFile(p)
		if err != nil {
			return nil
		}
		for _, m := range markers {
			if bytes.Contains(raw, []byte(m)) {
				t.Errorf("%s looks like a release secret key (%q); keep secret keys off the repository", p, m)
			}
		}
		if strings.HasSuffix(p, ".key") && strings.Contains(filepath.ToSlash(p), "release-keys/") {
			t.Errorf("%s: no key file may live in release-keys/ except the public keys", p)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
