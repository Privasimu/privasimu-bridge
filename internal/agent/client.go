package agent

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/privasimu/bridge/internal/buildinfo"
)

const (
	maxResponseBytes = 1 << 20
	requestTimeout   = 60 * time.Second
)

// APIError is an error answer of the platform.
type APIError struct {
	Status     int
	Code       string
	RetryAfter time.Duration
}

func (e *APIError) Error() string { return fmt.Sprintf("platform answered %d %s", e.Status, e.Code) }

// Retryable reports whether the same request may be sent again later.
func (e *APIError) Retryable() bool {
	return e.Status == http.StatusTooManyRequests || e.Status >= 500
}

// codeOf returns the platform error code of err ("" when err is not an APIError).
func codeOf(err error) string {
	var ae *APIError
	if errors.As(err, &ae) {
		return ae.Code
	}
	return ""
}

// Client talks to the platform's agent API.
type Client struct {
	base  string
	http  *http.Client
	mu    sync.RWMutex
	token string
}

// ClientOptions configure the connection to the platform.
type ClientOptions struct {
	PlatformURL string
	// CAFile adds trusted CA certificates (a platform with an internal certificate).
	CAFile string
	// RootCAs replaces the trusted CAs (tests).
	RootCAs *x509.CertPool
	// ProxyURL sends requests through an HTTP(S) proxy; ProxyAuth is "user:password".
	ProxyURL  string
	ProxyAuth string
}

// NewClient builds a client: TLS 1.2+ verified against the system trust store (plus the
// optional CA file), no redirects, no proxy unless configured, bounded responses.
func NewClient(o ClientOptions) (*Client, error) {
	u, err := url.Parse(strings.TrimRight(o.PlatformURL, "/"))
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return nil, errors.New("the platform URL must be https://")
	}
	pool := o.RootCAs
	if pool == nil {
		pool, err = x509.SystemCertPool()
		if err != nil || pool == nil {
			pool = x509.NewCertPool()
		}
	}
	if o.CAFile != "" {
		pem, err := os.ReadFile(o.CAFile)
		if err != nil {
			return nil, err
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("no certificate found in agent.ca_file")
		}
	}
	tr := &http.Transport{
		Proxy:                 nil,
		DialContext:           (&net.Dialer{Timeout: 15 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		TLSClientConfig:       &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout:   15 * time.Second,
		ResponseHeaderTimeout: 45 * time.Second,
		MaxIdleConns:          4,
		IdleConnTimeout:       90 * time.Second,
		ForceAttemptHTTP2:     true,
	}
	if o.ProxyURL != "" {
		pu, err := url.Parse(o.ProxyURL)
		if err != nil || (pu.Scheme != "http" && pu.Scheme != "https") {
			return nil, errors.New("agent.proxy_url must be http:// or https://")
		}
		tr.Proxy = http.ProxyURL(pu)
		if o.ProxyAuth != "" {
			auth := "Basic " + base64.StdEncoding.EncodeToString([]byte(o.ProxyAuth))
			tr.ProxyConnectHeader = http.Header{"Proxy-Authorization": {auth}}
		}
	}
	return &Client{
		base: u.String() + APIPrefix,
		http: &http.Client{Transport: tr, Timeout: requestTimeout,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
	}, nil
}

// SetToken sets the bearer token.
func (c *Client) SetToken(t string) {
	c.mu.Lock()
	c.token = t
	c.mu.Unlock()
}

func (c *Client) bearer() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.token
}

// do sends one JSON request and decodes the JSON answer into out.
func (c *Client) do(ctx context.Context, method, path string, headers map[string]string, in, out any) error {
	var body io.Reader
	if in != nil {
		raw, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, body)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", buildinfo.UserAgent())
	req.Header.Set("X-Bridge-Protocol", strconv.Itoa(ProtocolVersion))
	if t := c.bearer(); t != "" && path != PathEnroll {
		req.Header.Set("Authorization", "Bearer "+t)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return err
	}
	if len(data) > maxResponseBytes {
		return &APIError{Status: resp.StatusCode, Code: "response_too_large"}
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		ae := &APIError{Status: resp.StatusCode}
		var eb ErrorBody
		if json.Unmarshal(data, &eb) == nil {
			ae.Code = eb.Error.Code
		}
		if ae.Code == "" {
			ae.Code = defaultCode(resp.StatusCode)
		}
		if s, err := strconv.Atoi(resp.Header.Get("Retry-After")); err == nil && s > 0 {
			ae.RetryAfter = time.Duration(min(s, 3600)) * time.Second
		}
		return ae
	}
	if out != nil && len(data) > 0 {
		if err := json.Unmarshal(data, out); err != nil {
			return &APIError{Status: resp.StatusCode, Code: "invalid_response"}
		}
	}
	return nil
}

func defaultCode(status int) string {
	switch {
	case status == http.StatusUnauthorized:
		return ErrUnauthenticated
	case status == http.StatusTooManyRequests:
		return ErrRateLimited
	case status == http.StatusRequestEntityTooLarge:
		return ErrPayloadTooLarge
	case status == http.StatusServiceUnavailable:
		return ErrMaintenance
	case status >= 500:
		return ErrServer
	}
	return ErrInvalidRequest
}

// Enroll exchanges an enrollment token for agent credentials.
func (c *Client) Enroll(ctx context.Context, req EnrollRequest) (EnrollResponse, error) {
	var resp EnrollResponse
	err := c.do(ctx, http.MethodPost, PathEnroll, nil, req, &resp)
	if err == nil && (resp.AgentID == "" || resp.AgentToken == "") {
		err = &APIError{Status: 200, Code: "invalid_response"}
	}
	return resp, err
}

// Poll sends the heartbeat and receives jobs.
func (c *Client) Poll(ctx context.Context, req PollRequest) (PollResponse, error) {
	var resp PollResponse
	err := c.do(ctx, http.MethodPost, PathPoll, nil, req, &resp)
	return resp, err
}

// PutSources replaces the inventory.
func (c *Client) PutSources(ctx context.Context, req SourcesRequest) error {
	return c.do(ctx, http.MethodPut, PathSources, nil, req, &SourcesResponse{})
}

// Rotate asks for a new agent token.
func (c *Client) Rotate(ctx context.Context) (RotateResponse, error) {
	var resp RotateResponse
	err := c.do(ctx, http.MethodPost, PathTokenRotate, nil, struct{}{}, &resp)
	if err == nil && resp.AgentToken == "" {
		err = &APIError{Status: 200, Code: "invalid_response"}
	}
	return resp, err
}

func jobPath(id, action string) string { return pathJobs + url.PathEscape(id) + "/" + action }

func lease(job Job) map[string]string { return map[string]string{"X-Lease-Token": job.LeaseToken} }

// Progress renews a job's lease.
func (c *Client) Progress(ctx context.Context, job Job, req ProgressRequest) (ProgressResponse, error) {
	var resp ProgressResponse
	err := c.do(ctx, http.MethodPost, jobPath(job.JobID, "progress"), lease(job), req, &resp)
	return resp, err
}

// Part uploads one part.
func (c *Client) Part(ctx context.Context, job Job, req PartRequest) error {
	return c.do(ctx, http.MethodPost, jobPath(job.JobID, "parts"), lease(job), req, &PartResponse{})
}

// Complete finishes a job.
func (c *Client) Complete(ctx context.Context, job Job, req CompleteRequest) error {
	return c.do(ctx, http.MethodPost, jobPath(job.JobID, "complete"), lease(job), req, &StatusResponse{})
}

// Fail finishes a job with an error code.
func (c *Client) Fail(ctx context.Context, job Job, req FailRequest) error {
	return c.do(ctx, http.MethodPost, jobPath(job.JobID, "fail"), lease(job), req, &StatusResponse{})
}
