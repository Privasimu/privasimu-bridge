package dbsource

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"crypto"

	"github.com/privasimu/bridge/internal/config"
)

var (
	testKeyOnce sync.Once
	testKey     *rsa.PrivateKey
)

// rsaTestKey is one RSA key for all cloud tests (generated once).
func rsaTestKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	testKeyOnce.Do(func() {
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			panic(err)
		}
		testKey = k
	})
	return testKey
}

func pkcs8PEM(t *testing.T, key *rsa.PrivateKey) string {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

// cloudTarget points a cloud source at a test server that it trusts.
func cloudTarget(srv *httptest.Server, engine string) Target {
	cert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	return Target{Engine: engine, Timeout: 5 * time.Second, MaxOpen: 2, endpoint: srv.URL,
		TLS: TLSSettings{Mode: config.DBTLSVerifyFull, ExtraRootsPEM: cert}}
}

// verifyJWT checks an RS256 token against the key and returns its claims.
func verifyJWT(token string, key *rsa.PublicKey) (map[string]any, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("not a JWT")
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(key, crypto.SHA256, sum[:], sig); err != nil {
		return nil, err
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}
	var claims map[string]any
	return claims, json.Unmarshal(raw, &claims)
}

func TestParseRSAKeyFormats(t *testing.T) {
	key := rsaTestKey(t)
	if k, err := parseRSAKey(pkcs8PEM(t, key), ""); err != nil || !k.Equal(key) {
		t.Fatalf("PKCS#8: %v", err)
	}
	pkcs1 := string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}))
	if k, err := parseRSAKey(pkcs1, ""); err != nil || !k.Equal(key) {
		t.Fatalf("PKCS#1: %v", err)
	}
	for _, bad := range []string{"", "not a key", "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"} {
		if _, err := parseRSAKey(bad, ""); !errors.Is(err, errBadKey) {
			t.Errorf("%q: %v", bad, err)
		}
	}
}

func TestStatusKinds(t *testing.T) {
	for status, want := range map[int]string{401: KindAuth, 403: KindPermission, 404: KindNotFound, 408: KindTimeout, 429: KindUnreachable,
		503: KindUnreachable, 400: KindDatabase} {
		if got := statusKind(status); got != want {
			t.Errorf("%d: %s, want %s", status, got, want)
		}
	}
	if got := classify(&cloudError{Kind: KindPermission}); got != KindPermission {
		t.Errorf("a cloud error keeps its kind: %s", got)
	}
}
