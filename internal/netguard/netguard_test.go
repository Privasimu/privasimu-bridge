package netguard

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
)

func lookupOf(m map[string][]string) LookupFunc {
	return func(_ context.Context, host string) ([]netip.Addr, error) {
		list, ok := m[host]
		if !ok {
			return nil, errors.New("no such host")
		}
		out := make([]netip.Addr, 0, len(list))
		for _, s := range list {
			out = append(out, netip.MustParseAddr(s))
		}
		return out, nil
	}
}

func TestGuardResolve(t *testing.T) {
	g, err := New([]string{"10.10.0.0/16", "192.168.1.5", "db.partner.example"})
	if err != nil {
		t.Fatal(err)
	}
	g.Lookup = lookupOf(map[string][]string{
		"db.internal":        {"10.10.1.20"},
		"rebind.internal":    {"10.10.1.20", "10.99.0.1"},
		"db.partner.example": {"203.0.113.7"},
		"metadata.partner":   {"169.254.169.254"},
		"evil.partner":       {"169.254.169.254"},
	})
	ok := []string{"10.10.1.20", "192.168.1.5", "db.internal", "db.partner.example", "::ffff:10.10.3.4"}
	for _, h := range ok {
		if _, err := g.Resolve(context.Background(), h); err != nil {
			t.Errorf("%s must be allowed: %v", h, err)
		}
	}
	blocked := []string{"10.11.0.1", "127.0.0.1", "169.254.169.254", "rebind.internal", "unknown.internal", "8.8.8.8", "[::1]"}
	for _, h := range blocked {
		if _, err := g.Resolve(context.Background(), h); !errors.Is(err, ErrBlocked) {
			t.Errorf("%s must be blocked, got %v", h, err)
		}
	}
	// A listed name may not point at the metadata service either.
	g2, _ := New([]string{"evil.partner"})
	g2.Lookup = g.Lookup
	if _, err := g2.Resolve(context.Background(), "evil.partner"); !errors.Is(err, ErrBlocked) {
		t.Fatalf("link-local is never allowed: %v", err)
	}
	// Even an explicit range cannot open link-local addresses.
	g3, _ := New([]string{"169.254.0.0/16"})
	if _, err := g3.Resolve(context.Background(), "169.254.169.254"); !errors.Is(err, ErrBlocked) {
		t.Fatalf("link-local is never allowed: %v", err)
	}
	// Nor Alibaba Cloud's metadata address in the shared address space, while the rest of
	// that range can be allowed.
	g4, _ := New([]string{"100.64.0.0/10"})
	if _, err := g4.Resolve(context.Background(), "100.100.100.200"); !errors.Is(err, ErrBlocked) {
		t.Fatalf("the metadata address is never allowed: %v", err)
	}
	if _, err := g4.Resolve(context.Background(), "100.100.100.201"); err != nil {
		t.Fatalf("the rest of an allowed range: %v", err)
	}
}

func TestGuardDialsOnlyTheCheckedAddress(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	g, _ := New([]string{"127.0.0.1/32"})
	g.Lookup = lookupOf(map[string][]string{"local.test": {"127.0.0.1"}})
	c, err := g.Dial(context.Background(), "tcp", net.JoinHostPort("local.test", port))
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	if _, err := g.Dial(context.Background(), "tcp", "nonsense"); !errors.Is(err, ErrBlocked) {
		t.Fatalf("%v", err)
	}
}

func TestBadEntries(t *testing.T) {
	if _, err := New([]string{"10.0.0.0/8", "bad/entry/x"}); err == nil {
		t.Fatal("expected an error")
	}
}
