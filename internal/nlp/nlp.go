// Package nlp is the bridge's client of an optional language-model service that finds
// personal data in free text (the client's own nlp-data-discovery, or any service with the
// same interface): POST {"text": ...} answered by {"entities": [{"entity_group", "score",
// "start", "end", ...}]}, offsets in characters.
//
// The service must run on the bridge server or inside the client's network: every
// connection is checked against loopback and private ranges (config.NLPRanges) and pinned
// to the checked address, no proxy and no redirect are used. Only the text of one file or
// one column, bounded by max_bytes, is sent per request, and only the counts per category
// are kept: the entity texts the service returns are not even decoded. When the service
// fails, the bridge falls back to its patterns and validators for a minute.
package nlp

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/privasimu/bridge/internal/config"
	"github.com/privasimu/bridge/internal/detect"
	"github.com/privasimu/bridge/internal/netguard"
)

// maxAnswer bounds the answer of the service.
const maxAnswer = 4 << 20

// pause is how long the service is left alone after it failed.
const pause = time.Minute

// separator joins the texts of one request.
const separator = "\n\n"

// labels maps the service's entity labels to the bridge's categories. Labels of the
// identifiers the validators confirm (NIK, family card, tax number, phone, e-mail, passport,
// account numbers) are not taken from the model; unknown labels are ignored.
var labels = map[string]detect.Category{
	"NAME":            detect.PersonName,
	"ADDRESS":         detect.Address,
	"DOB":             detect.BirthDate,
	"POB":             detect.BirthDate,
	"GENDER":          detect.Gender,
	"RELIGION":        detect.Religion,
	"MARITAL":         detect.MaritalStatus,
	"NATIONALITY":     detect.Nationality,
	"RACE_ETHNICITY":  detect.Nationality,
	"HEALTH_DATA":     detect.Health,
	"MEDICAL_ID":      detect.Health,
	"BIOMETRIC":       detect.Biometric,
	"GENETIC":         detect.Genetic,
	"CRIMINAL_RECORD": detect.CriminalRecord,
	"FINANCIAL_DATA":  detect.Financial,
	"DL":              detect.DrivingLicense,
	"EMPLOYEE_ID":     detect.EmployeeID,
	"USERNAME":        detect.Username,
	"SOCIAL_MEDIA":    detect.Username,
	"IP":              detect.IPAddress,
	"VEHICLE_REG":     detect.VehiclePlate,
	"MAIDEN_NAME":     detect.MotherMaidenName,
}

// ErrUnavailable means the service failed recently; the caller uses its patterns only.
var ErrUnavailable = errors.New("the NLP service is unavailable")

// Client counts entities through the service. It implements detect.EntityCounter.
type Client struct {
	endpoint string
	http     *http.Client
	timeout  time.Duration
	maxBytes int
	minScore float64
	sem      chan struct{}
	log      *slog.Logger
	now      func() time.Time

	mu        sync.Mutex
	downUntil time.Time
}

// New returns a client for the configured service, or nil when NLP is off.
func New(cfg *config.Config, log *slog.Logger) (*Client, error) {
	n := cfg.Detection.NLP
	if !n.Enabled {
		return nil, nil
	}
	guard, err := netguard.New(config.NLPRanges)
	if err != nil {
		return nil, err
	}
	guard.Dialer.Timeout = n.Timeout.D()
	tr := &http.Transport{Proxy: nil, DialContext: guard.Dial, MaxConnsPerHost: n.Concurrency, MaxIdleConnsPerHost: n.Concurrency,
		IdleConnTimeout: time.Minute, ResponseHeaderTimeout: n.Timeout.D(), TLSHandshakeTimeout: n.Timeout.D()}
	if strings.HasPrefix(n.Endpoint, "https://") {
		pool, err := x509.SystemCertPool()
		if err != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		if n.CAFile != "" {
			pem, err := os.ReadFile(cfg.Resolve(n.CAFile)) // #nosec G304 -- the CA file the operator configured
			if err != nil {
				return nil, fmt.Errorf("detection.nlp.ca_file: %w", err)
			}
			if !pool.AppendCertsFromPEM(pem) {
				return nil, errors.New("detection.nlp.ca_file: no certificate found")
			}
		}
		tr.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool}
	}
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &Client{endpoint: n.Endpoint, timeout: n.Timeout.D(), maxBytes: int(n.MaxBytes), minScore: n.MinScore,
		sem: make(chan struct{}, n.Concurrency), log: log, now: time.Now,
		http: &http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}

// MaxBytes is the most text of one request.
func (c *Client) MaxBytes() int { return c.maxBytes }

// entity is one entity of an answer; the entity's text ("word") is never decoded.
type entity struct {
	Group string  `json:"entity_group"`
	Score float64 `json:"score"`
	Start int     `json:"start"`
}

// Count sends the texts as one request (joined, cut at MaxBytes) and returns the entities
// of each text per category. It fails fast with ErrUnavailable for a minute after a
// failure, so a scan falls back to its patterns instead of waiting.
func (c *Client) Count(ctx context.Context, texts []string) ([]map[detect.Category]int, error) {
	out := make([]map[detect.Category]int, len(texts))
	if len(texts) == 0 {
		return out, nil
	}
	c.mu.Lock()
	down := c.now().Before(c.downUntil)
	c.mu.Unlock()
	if down {
		return nil, ErrUnavailable
	}
	// starts[i] is the character offset where text i begins in the request.
	var b strings.Builder
	starts := make([]int, 0, len(texts))
	chars := 0
	for _, t := range texts {
		if b.Len() > 0 {
			if b.Len()+len(separator) >= c.maxBytes {
				break
			}
			b.WriteString(separator)
			chars += len(separator)
		}
		if room := c.maxBytes - b.Len(); len(t) > room {
			t = cutUTF8(t, room)
		}
		starts = append(starts, chars)
		b.WriteString(t)
		chars += utf8.RuneCountInString(t)
	}
	select {
	case c.sem <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	defer func() { <-c.sem }()
	entities, err := c.post(ctx, b.String())
	if err != nil {
		if ctx.Err() == nil {
			c.fail(err)
		}
		return nil, err
	}
	for _, e := range entities {
		cat, known := labels[strings.ToUpper(strings.TrimPrefix(strings.TrimPrefix(e.Group, "B-"), "I-"))]
		if !known || e.Score < c.minScore || e.Start < 0 {
			continue
		}
		i := len(starts) - 1
		for i > 0 && e.Start < starts[i] {
			i--
		}
		if out[i] == nil {
			out[i] = map[detect.Category]int{}
		}
		out[i][cat]++
	}
	return out, nil
}

// post sends one text and decodes the entities.
func (c *Client) post(ctx context.Context, text string) ([]entity, error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	body, err := json.Marshal(map[string]string{"text": text})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "privasimu-bridge")
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxAnswer))
		return nil, fmt.Errorf("the NLP service answered HTTP %d", resp.StatusCode)
	}
	var answer struct {
		Entities []entity `json:"entities"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxAnswer)).Decode(&answer); err != nil {
		return nil, errors.New("the NLP service's answer is not the expected JSON")
	}
	return answer.Entities, nil
}

// fail pauses the service and tells the operator once per outage (never the text).
func (c *Client) fail(err error) {
	c.mu.Lock()
	first := !c.now().Before(c.downUntil)
	c.downUntil = c.now().Add(pause)
	c.mu.Unlock()
	if first {
		c.log.Warn("the NLP service failed; patterns and validators only for a minute", "endpoint", c.endpoint, "error", err.Error())
	}
}

// Check sends a short synthetic text, for privasimu-bridge check.
func (c *Client) Check(ctx context.Context) (time.Duration, error) {
	started := time.Now()
	_, err := c.post(ctx, "Nama nasabah: Budi Contoh, alamat Jalan Contoh No. 1, Jakarta.")
	return time.Since(started), err
}

// cutUTF8 cuts s to at most n bytes without splitting a character.
func cutUTF8(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}
