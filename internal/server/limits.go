package server

import (
	"context"
	"math"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"
)

// limiter applies a token bucket per client address and locks out an address after
// repeated authentication failures.
type limiter struct {
	mu        sync.Mutex
	clients   map[string]*clientState
	rate      float64 // tokens per second
	burst     float64
	failLimit int
	lockout   time.Duration
	now       func() time.Time
}

type clientState struct {
	tokens      float64
	last        time.Time
	failures    int
	firstFail   time.Time
	lockedUntil time.Time
}

func newLimiter(ratePerSecond float64, burst, failLimit int, lockout time.Duration) *limiter {
	return &limiter{clients: map[string]*clientState{}, rate: ratePerSecond, burst: float64(burst),
		failLimit: failLimit, lockout: lockout, now: time.Now}
}

func (l *limiter) state(ip string, now time.Time) *clientState {
	st, ok := l.clients[ip]
	if !ok {
		st = &clientState{tokens: l.burst, last: now}
		l.clients[ip] = st
	}
	return st
}

// allow takes one token. It reports whether the request may proceed, how long to wait
// otherwise, and whether the address is locked out.
func (l *limiter) allow(ip string) (ok bool, retryAfter time.Duration, locked bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	st := l.state(ip, now)
	if now.Before(st.lockedUntil) {
		return false, st.lockedUntil.Sub(now), true
	}
	st.tokens = math.Min(l.burst, st.tokens+now.Sub(st.last).Seconds()*l.rate)
	st.last = now
	if st.tokens < 1 {
		wait := time.Duration((1 - st.tokens) / l.rate * float64(time.Second))
		return false, wait, false
	}
	st.tokens--
	return true, 0, false
}

// authFailed records a failed authentication; the address is locked out when it reaches
// the limit within the lockout window.
func (l *limiter) authFailed(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	st := l.state(ip, now)
	if st.failures == 0 || now.Sub(st.firstFail) > l.lockout {
		st.failures, st.firstFail = 0, now
	}
	st.failures++
	if st.failures >= l.failLimit {
		st.lockedUntil = now.Add(l.lockout)
		st.failures = 0
	}
}

func (l *limiter) authOK(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if st, ok := l.clients[ip]; ok {
		st.failures = 0
	}
}

// sweep forgets addresses that have been quiet for a while.
func (l *limiter) sweep() {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	for ip, st := range l.clients {
		if now.Sub(st.last) > 30*time.Minute && now.After(st.lockedUntil) {
			delete(l.clients, ip)
		}
	}
}

func (l *limiter) run(ctx context.Context) {
	t := time.NewTicker(5 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			l.sweep()
		}
	}
}

// addrIn reports whether ip is inside one of the prefixes.
func addrIn(ip netip.Addr, list []netip.Prefix) bool {
	ip = ip.Unmap()
	for _, p := range list {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// remoteIP returns the IP address of a "host:port" remote address.
func remoteIP(remote string) netip.Addr {
	host, _, err := net.SplitHostPort(remote)
	if err != nil {
		host = remote
	}
	a, err := netip.ParseAddr(strings.Trim(host, "[]"))
	if err != nil {
		return netip.Addr{}
	}
	return a.Unmap()
}

// forwardedClient returns the client address behind trusted proxies: the right-most
// address of X-Forwarded-For that is not a trusted proxy.
func forwardedClient(peer netip.Addr, header string, trusted []netip.Prefix) netip.Addr {
	if !addrIn(peer, trusted) || header == "" {
		return peer
	}
	parts := strings.Split(header, ",")
	for i := len(parts) - 1; i >= 0; i-- {
		a, err := netip.ParseAddr(strings.TrimSpace(parts[i]))
		if err != nil {
			return peer
		}
		a = a.Unmap()
		if !addrIn(a, trusted) {
			return a
		}
	}
	return peer
}

// refusalLog reports a refused address at most once per interval, so a scanner cannot
// flood the log.
type refusalLog struct {
	mu    sync.Mutex
	every time.Duration
	last  map[string]time.Time
}

func newRefusalLog(every time.Duration) *refusalLog {
	return &refusalLog{every: every, last: map[string]time.Time{}}
}

// first reports whether ip should be logged now.
func (r *refusalLog) first(ip string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now()
	if t, ok := r.last[ip]; ok && now.Sub(t) < r.every {
		return false
	}
	if len(r.last) > 10000 {
		r.last = map[string]time.Time{}
	}
	r.last[ip] = now
	return true
}

// filteredListener closes connections from addresses that are not allowed before any
// TLS handshake, so the bridge does not even reveal itself to them.
type filteredListener struct {
	net.Listener
	allowed []netip.Prefix
	refused func(netip.Addr)
}

func (l filteredListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		if len(l.allowed) == 0 || addrIn(remoteIP(c.RemoteAddr().String()), l.allowed) {
			return c, nil
		}
		if l.refused != nil {
			l.refused(remoteIP(c.RemoteAddr().String()))
		}
		_ = c.Close()
	}
}
