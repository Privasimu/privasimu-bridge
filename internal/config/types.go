package config

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"
)

// Duration is a time.Duration written as "30s", "15m" or a number of seconds.
type Duration time.Duration

// D returns the value as a time.Duration.
func (d Duration) D() time.Duration { return time.Duration(d) }

// UnmarshalYAML accepts "30s" or a plain number of seconds.
func (d *Duration) UnmarshalYAML(n *yaml.Node) error {
	s := strings.TrimSpace(n.Value)
	if s == "" {
		*d = 0
		return nil
	}
	if secs, err := strconv.ParseFloat(s, 64); err == nil {
		*d = Duration(time.Duration(secs * float64(time.Second)))
		return nil
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("line %d: %q is not a duration such as 30s or 15m", n.Line, s)
	}
	*d = Duration(v)
	return nil
}

// MarshalYAML writes the duration as text.
func (d Duration) MarshalYAML() (any, error) { return time.Duration(d).String(), nil }

// ByteSize is a size written as "50MiB", "8MB", "512KiB" or a plain number of bytes.
type ByteSize int64

// UnmarshalYAML accepts a number of bytes or a number with a unit.
func (b *ByteSize) UnmarshalYAML(n *yaml.Node) error {
	v, err := ParseByteSize(n.Value)
	if err != nil {
		return fmt.Errorf("line %d: %w", n.Line, err)
	}
	*b = ByteSize(v)
	return nil
}

// ParseByteSize reads "50MiB", "8MB", "512KiB", "1GiB" or a plain number of bytes.
// MB and MiB both mean 1024*1024 bytes, which is what operators expect for file limits.
func ParseByteSize(text string) (int64, error) {
	s := strings.TrimSpace(strings.ToUpper(text))
	if s == "" {
		return 0, nil
	}
	units := []struct {
		suffix string
		mult   int64
	}{
		{"GIB", 1 << 30}, {"GB", 1 << 30}, {"MIB", 1 << 20}, {"MB", 1 << 20}, {"KIB", 1 << 10}, {"KB", 1 << 10}, {"B", 1},
	}
	mult := int64(1)
	for _, u := range units {
		if strings.HasSuffix(s, u.suffix) {
			mult = u.mult
			s = strings.TrimSpace(strings.TrimSuffix(s, u.suffix))
			break
		}
	}
	v, err := strconv.ParseInt(s, 10, 64)
	if err != nil || v < 0 {
		return 0, fmt.Errorf("%q is not a size such as 50MiB", text)
	}
	return v * mult, nil
}

// SecretRef points at a secret without containing it: "env:NAME" (environment variable),
// "file:/path" (a file, for example a Docker or systemd credential) or "secret:NAME" (the
// bridge's encrypted secret store). A literal value is refused by Validate so that no
// password is ever written in the configuration file.
type SecretRef string

// Secret reference kinds.
const (
	RefEnv    = "env"
	RefFile   = "file"
	RefSecret = "secret"
)

// Parse splits a reference into its kind and target.
func (r SecretRef) Parse() (kind, target string, ok bool) {
	s := strings.TrimSpace(string(r))
	k, t, found := strings.Cut(s, ":")
	if !found || strings.TrimSpace(t) == "" {
		return "", "", false
	}
	switch k {
	case RefEnv, RefFile, RefSecret:
		return k, strings.TrimSpace(t), true
	}
	return "", "", false
}

// IsSet reports whether a reference was given.
func (r SecretRef) IsSet() bool { return strings.TrimSpace(string(r)) != "" }

// String returns the reference itself, which names a secret but does not contain it.
func (r SecretRef) String() string { return string(r) }
