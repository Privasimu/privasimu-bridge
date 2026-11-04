package dbsource

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/youmark/pkcs8"
)

// Shared HTTPS plumbing of the cloud warehouses (Snowflake, BigQuery, Databricks, Athena).
// They are services on the internet, reached with verified TLS only (the system trust
// store plus ca_file), through the operator's proxy when HTTPS_PROXY is set for the
// service, without redirects, and with every answer bounded. Only what the bridge needs
// is read: catalog metadata, and for sampling at most rows values per column, which are
// examined on this server like those of every other engine.

// cloudMaxAnswer bounds one answer of a cloud service.
const cloudMaxAnswer = 32 << 20

// cloudClient builds the HTTPS client of a cloud source.
func cloudClient(t Target) (*http.Client, error) {
	pool, err := t.TLS.rootPool()
	if err != nil {
		return nil, err
	}
	dialer := &net.Dialer{Timeout: t.Timeout, KeepAlive: 30 * time.Second}
	tr := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           dialer.DialContext,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool},
		TLSHandshakeTimeout:   t.Timeout,
		ResponseHeaderTimeout: 2 * time.Minute,
		MaxConnsPerHost:       max(t.MaxOpen, 1) * 2,
		IdleConnTimeout:       time.Minute,
		ForceAttemptHTTP2:     true,
	}
	if t.Dial != nil {
		tr.DialContext, tr.Proxy = t.Dial, nil
	}
	return &http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}, nil
}

// cloudError is a refusal of a cloud service: the HTTP status, the service's own error
// code, the kind the engine assigned and the beginning of the service's message (shown to
// the local operator only for connection and catalog errors; see Error.Safe).
type cloudError struct {
	Service    string
	Status     int
	Code       string
	Message    string
	Kind       string
	RetryAfter time.Duration
}

func (e *cloudError) Error() string {
	return fmt.Sprintf("%s: HTTP %d %s: %s", e.Service, e.Status, e.Code, oneLine(e.Message))
}

// cloudDo sends a request and decodes a 2xx JSON answer into out (nil = discard). Another
// status returns *cloudError with the body for the engine to classify (parse).
func cloudDo(c *http.Client, req *http.Request, service string, out any, parse func(*cloudError, []byte)) error {
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, cloudMaxAnswer+1))
	if err != nil {
		return err
	}
	if len(body) > cloudMaxAnswer {
		return fmt.Errorf("%s: the answer is larger than 32 MiB", service)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		e := &cloudError{Service: service, Status: resp.StatusCode}
		if s, err := strconv.Atoi(resp.Header.Get("Retry-After")); err == nil && s > 0 {
			e.RetryAfter = time.Duration(min(s, 30)) * time.Second
		}
		if parse != nil {
			parse(e, body)
		}
		if e.Kind == "" {
			e.Kind = statusKind(resp.StatusCode)
		}
		return e
	}
	if out == nil || len(body) == 0 {
		return nil
	}
	if err := json.Unmarshal(body, out); err != nil {
		// Never quote the answer: it can hold values.
		return fmt.Errorf("%s: the answer is not the expected JSON", service)
	}
	return nil
}

// statusKind is the kind of an HTTP status without a more precise service code.
func statusKind(status int) string {
	switch {
	case status == http.StatusUnauthorized:
		return KindAuth
	case status == http.StatusForbidden:
		return KindPermission
	case status == http.StatusNotFound:
		return KindNotFound
	case status == http.StatusRequestTimeout || status == http.StatusGatewayTimeout:
		return KindTimeout
	case status == http.StatusTooManyRequests || status >= 500:
		return KindUnreachable
	}
	return KindDatabase
}

// retryable reports whether a cloud request may be sent again: throttling and server
// errors, a few times, with a pause.
func retryable(err error) (time.Duration, bool) {
	var ce *cloudError
	if !errors.As(err, &ce) || (ce.Status != http.StatusTooManyRequests && ce.Status < 500) {
		return 0, false
	}
	if ce.RetryAfter > 0 {
		return ce.RetryAfter, true
	}
	return time.Second, true
}

// withRetry runs fn up to three times while it fails with a retryable error.
func withRetry(ctx context.Context, fn func() error) error {
	var err error
	for attempt := 0; attempt < 3; attempt++ {
		if err = fn(); err == nil {
			return nil
		}
		wait, ok := retryable(err)
		if !ok {
			return err
		}
		select {
		case <-ctx.Done():
			return err
		case <-time.After(wait * time.Duration(attempt+1)):
		}
	}
	return err
}

// jsonBody returns a request body for v.
func jsonBody(v any) (io.Reader, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return bytes.NewReader(raw), nil
}

// signJWT signs claims with RS256 (the header is {"alg":"RS256","typ":"JWT"} plus extra).
func signJWT(key *rsa.PrivateKey, extraHeader map[string]string, claims any) (string, error) {
	header := map[string]string{"alg": "RS256", "typ": "JWT"}
	for k, v := range extraHeader {
		header[k] = v
	}
	h, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	c, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	unsigned := base64.RawURLEncoding.EncodeToString(h) + "." + base64.RawURLEncoding.EncodeToString(c)
	sum := sha256.Sum256([]byte(unsigned))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	if err != nil {
		return "", err
	}
	return unsigned + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// errBadKey never describes the key: errors of key parsing could quote parts of it.
var errBadKey = errors.New("the private key is not an RSA key in PEM (PKCS#8, encrypted PKCS#8 or PKCS#1)")

// parseRSAKey reads an RSA private key from PEM: PKCS#8, encrypted PKCS#8 (with the
// passphrase) or PKCS#1.
func parseRSAKey(pemText, passphrase string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemText))
	if block == nil {
		return nil, errBadKey
	}
	var key any
	var err error
	switch block.Type {
	case "ENCRYPTED PRIVATE KEY":
		key, err = pkcs8.ParsePKCS8PrivateKey(block.Bytes, []byte(passphrase))
	case "PRIVATE KEY":
		key, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	case "RSA PRIVATE KEY":
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	default:
		return nil, errBadKey
	}
	rsaKey, ok := key.(*rsa.PrivateKey)
	if err != nil || !ok {
		return nil, errBadKey
	}
	return rsaKey, nil
}

// newRequestID returns a random identifier for idempotent retries (UUID version 4 form).
func newRequestID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
