package dbsource

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Pool keeps open connections between the calls of one platform scan (a table list and
// one call per table, each carrying the same settings). Connections are keyed by every
// connection setting including a hash of the password, so a call with other credentials
// never reuses a session another call authenticated. A failed login is remembered for a
// minute so that retries cannot lock the database account.
type Pool struct {
	mu       sync.Mutex
	entries  map[string]*poolEntry
	failures map[string]failure
	max      int
	idle     time.Duration
	authHold time.Duration
	now      func() time.Time
	// Open connects; tests replace it.
	Open func(ctx context.Context, t Target) (Conn, error)
	stop chan struct{}
}

type poolEntry struct {
	conn     Conn
	ready    chan struct{}
	err      error
	inflight int
	lastUsed time.Time
}

type failure struct {
	err   error
	until time.Time
}

// NewPool returns a pool of at most max idle databases, each closed after idle.
func NewPool(max int, idle time.Duration) *Pool {
	if max <= 0 {
		max = 32
	}
	if idle <= 0 {
		idle = 5 * time.Minute
	}
	return &Pool{entries: map[string]*poolEntry{}, failures: map[string]failure{}, max: max, idle: idle,
		authHold: time.Minute, now: time.Now, Open: Open, stop: make(chan struct{})}
}

// Key identifies a target by every setting that changes the session.
func Key(t Target) string {
	h := sha256.New()
	for _, part := range []string{t.Engine, strings.ToLower(t.Host), strconv.Itoa(t.Port), t.Database, t.Username,
		t.Password.Reveal(), t.URI.Reveal(), t.AuthSource, strings.Join(t.Schemas, ","), t.ServiceName, t.SID,
		t.Instance, t.TLS.Mode, t.TLS.CAFile, t.TLS.ServerName, strconv.FormatBool(t.TLS.TrustServerCertificate),
		strconv.FormatBool(t.Dial != nil), t.Warehouse, t.Role, t.PrivateKey.Reveal(), t.PrivateKeyPassphrase.Reveal(),
		t.Credentials.Reveal(), t.Region, t.SessionToken.Reveal()} {
		h.Write([]byte(part))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

// Get returns an open connection; call release when done with it.
func (p *Pool) Get(ctx context.Context, t Target) (Conn, func(), error) {
	key := Key(t)
	p.mu.Lock()
	if f, ok := p.failures[key]; ok {
		if p.now().Before(f.until) {
			p.mu.Unlock()
			return nil, nil, f.err
		}
		delete(p.failures, key)
	}
	e, ok := p.entries[key]
	if !ok {
		e = &poolEntry{ready: make(chan struct{})}
		p.entries[key] = e
		p.evictLocked()
		p.mu.Unlock()
		conn, err := p.Open(ctx, t)
		p.mu.Lock()
		e.conn, e.err = conn, err
		close(e.ready)
		if err != nil {
			delete(p.entries, key)
			if KindOf(err) == KindAuth {
				p.failures[key] = failure{err: err, until: p.now().Add(p.authHold)}
			}
			p.mu.Unlock()
			return nil, nil, err
		}
	} else {
		p.mu.Unlock()
		select {
		case <-e.ready:
		case <-ctx.Done():
			return nil, nil, wrap("connect", ctx.Err(), true)
		}
		p.mu.Lock()
		if e.err != nil {
			p.mu.Unlock()
			return nil, nil, e.err
		}
	}
	e.inflight++
	e.lastUsed = p.now()
	p.mu.Unlock()
	var once sync.Once
	release := func() {
		once.Do(func() {
			p.mu.Lock()
			e.inflight--
			e.lastUsed = p.now()
			p.mu.Unlock()
		})
	}
	return e.conn, release, nil
}

// evictLocked closes the least recently used idle connections above the limit.
func (p *Pool) evictLocked() {
	for len(p.entries) > p.max {
		var oldestKey string
		var oldest *poolEntry
		for k, e := range p.entries {
			if e.conn == nil || e.inflight > 0 {
				continue
			}
			if oldest == nil || e.lastUsed.Before(oldest.lastUsed) {
				oldestKey, oldest = k, e
			}
		}
		if oldest == nil {
			return
		}
		delete(p.entries, oldestKey)
		go oldest.conn.Close()
	}
}

// Sweep closes connections idle for longer than the idle time.
func (p *Pool) Sweep() {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := p.now()
	for k, e := range p.entries {
		if e.conn != nil && e.inflight == 0 && now.Sub(e.lastUsed) > p.idle {
			delete(p.entries, k)
			go e.conn.Close()
		}
	}
	for k, f := range p.failures {
		if now.After(f.until) {
			delete(p.failures, k)
		}
	}
}

// Run sweeps the pool every minute until ctx ends, then closes everything.
func (p *Pool) Run(ctx context.Context) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			p.Close()
			return
		case <-t.C:
			p.Sweep()
		}
	}
}

// Close closes every connection.
func (p *Pool) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for k, e := range p.entries {
		if e.conn != nil {
			_ = e.conn.Close()
		}
		delete(p.entries, k)
	}
}

// Len returns the number of pooled connections (for tests).
func (p *Pool) Len() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.entries)
}

// errPoolClosed is returned after Close.
var errPoolClosed = errors.New("pool closed")

var _ = errPoolClosed
