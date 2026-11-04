// Package netguard restricts which addresses the bridge may connect to when the platform
// supplies the database address (mode A with request credentials). Every address a host
// resolves to is checked, the connection is made to the checked address only (so DNS
// rebinding cannot swap it), and link-local, multicast and unspecified addresses (which
// include cloud metadata services) are never reachable.
package netguard

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"time"
)

// ErrBlocked means the address is not on the allow-list.
var ErrBlocked = errors.New("the database address is not allowed")

// ErrUnresolved means the host name does not resolve.
var ErrUnresolved = errors.New("the database host does not resolve")

// neverAllowed cannot be opened by any allow-list entry: unspecified, link-local
// (169.254.169.254 is the metadata service of most clouds), multicast and broadcast
// addresses, AWS's IPv6 metadata address, and Alibaba Cloud's metadata address, which lies
// in the shared address space 100.64.0.0/10 rather than in link-local.
var neverAllowed = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("224.0.0.0/4"),
	netip.MustParsePrefix("255.255.255.255/32"),
	netip.MustParsePrefix("::/128"),
	netip.MustParsePrefix("fe80::/10"),
	netip.MustParsePrefix("ff00::/8"),
	netip.MustParsePrefix("fd00:ec2::254/128"),
	netip.MustParsePrefix("100.100.100.200/32"),
}

// LookupFunc resolves a host name.
type LookupFunc func(ctx context.Context, host string) ([]netip.Addr, error)

// Guard checks and dials database addresses.
type Guard struct {
	prefixes []netip.Prefix
	hosts    map[string]bool
	Lookup   LookupFunc
	Dialer   *net.Dialer
}

// New builds a guard from allow-list entries: CIDR ranges, IP addresses or host names.
// A host name entry allows that exact name (whatever it resolves to, except the
// never-allowed ranges); a range allows any host that resolves inside it.
func New(entries []string) (*Guard, error) {
	g := &Guard{hosts: map[string]bool{}, Dialer: &net.Dialer{Timeout: 10 * time.Second}}
	for _, e := range entries {
		e = strings.TrimSpace(e)
		if p, err := netip.ParsePrefix(e); err == nil {
			g.prefixes = append(g.prefixes, p.Masked())
			continue
		}
		if a, err := netip.ParseAddr(e); err == nil {
			a = a.Unmap()
			g.prefixes = append(g.prefixes, netip.PrefixFrom(a, a.BitLen()))
			continue
		}
		if e == "" || strings.ContainsAny(e, "/ :") {
			return nil, errors.New("allow-list entry is not a range, an address or a host name")
		}
		g.hosts[strings.ToLower(strings.TrimSuffix(e, "."))] = true
	}
	return g, nil
}

// Allowed reports whether a connection to addr (reached through a name that is or is
// not on the list) is allowed.
func (g *Guard) Allowed(addr netip.Addr, nameListed bool) bool {
	addr = addr.Unmap().WithZone("")
	for _, p := range neverAllowed {
		if p.Contains(addr) {
			return false
		}
	}
	if nameListed {
		return true
	}
	for _, p := range g.prefixes {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

func (g *Guard) lookup(ctx context.Context, host string) ([]netip.Addr, error) {
	if g.Lookup != nil {
		return g.Lookup(ctx, host)
	}
	return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
}

// Resolve returns the checked addresses of host; one address that is not allowed rejects
// the host.
func (g *Guard) Resolve(ctx context.Context, host string) ([]netip.Addr, error) {
	host = strings.Trim(strings.TrimSpace(host), "[]")
	if a, err := netip.ParseAddr(host); err == nil {
		if !g.Allowed(a, false) {
			return nil, ErrBlocked
		}
		return []netip.Addr{a.Unmap()}, nil
	}
	listed := g.hosts[strings.ToLower(strings.TrimSuffix(host, "."))]
	addrs, err := g.lookup(ctx, host)
	if err != nil || len(addrs) == 0 {
		// An unlisted name that does not resolve is reported as blocked, so the bridge
		// cannot be used to find out which internal names exist.
		if !listed {
			return nil, ErrBlocked
		}
		return nil, ErrUnresolved
	}
	out := make([]netip.Addr, 0, len(addrs))
	for _, a := range addrs {
		if !g.Allowed(a, listed) {
			return nil, ErrBlocked
		}
		out = append(out, a.Unmap())
	}
	return out, nil
}

// Dial connects to addr ("host:port") through the checked addresses only.
func (g *Guard) Dial(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, ErrBlocked
	}
	addrs, err := g.Resolve(ctx, host)
	if err != nil {
		return nil, err
	}
	var last error
	for _, a := range addrs {
		c, err := g.Dialer.DialContext(ctx, network, net.JoinHostPort(a.String(), port))
		if err == nil {
			return c, nil
		}
		last = err
	}
	return nil, last
}
