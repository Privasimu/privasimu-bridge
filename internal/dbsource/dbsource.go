// Package dbsource connects to customer databases and reads their catalog: schemas,
// tables, columns and data types. Sampling reads a bounded number of values per column and
// hands each value to a callback that must examine and drop it; this package never keeps,
// logs or returns values. Sessions are opened read-only wherever the engine allows it.
package dbsource

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/privasimu/bridge/internal/config"
	"github.com/privasimu/bridge/internal/netguard"
	"github.com/privasimu/bridge/internal/secrets"
)

// DialFunc dials a TCP connection. Request-credential mode passes a guarded dialer that
// only reaches allow-listed addresses.
type DialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

// Target is everything needed to connect to one database.
type Target struct {
	Engine      string
	Host        string
	Port        int
	Database    string
	Username    string
	Password    secrets.Value
	URI         secrets.Value // MongoDB connection string (holds credentials)
	AuthSource  string
	Schemas     []string // allowed schemas; empty means every non-system schema
	ServiceName string   // Oracle
	SID         string   // Oracle
	Instance    string   // SQL Server named instance
	TLS         TLSSettings
	Timeout     time.Duration // per statement
	Dial        DialFunc
	// MaxOpen bounds concurrent connections to this database (default 4).
	MaxOpen int

	// Cloud warehouses (see config.SourceConfig).
	Warehouse            string
	Role                 string
	PrivateKey           secrets.Value
	PrivateKeyPassphrase secrets.Value
	Credentials          secrets.Value
	Region               string
	SessionToken         secrets.Value

	// endpoint replaces a cloud service's public address (tests only).
	endpoint string
}

// TLSSettings configures TLS to the database.
type TLSSettings struct {
	Mode       string // config.DBTLS*
	CAFile     string
	ServerName string
	// ExtraRootsPEM are additional trusted CA certificates (server.targets_ca_file).
	ExtraRootsPEM []byte
	// TrustServerCertificate is the SQL Server flag: encrypt without verifying.
	TrustServerCertificate bool
}

// Table is a table (or collection) in the catalog.
type Table struct {
	Schema string
	Name   string
	// Ref is the name reported to the platform: the bare name in the default or requested
	// schema, "schema.name" otherwise.
	Ref         string
	RowEstimate *int64
}

// Column is a column (or document field) of a table.
type Column struct {
	Name     string
	DataType string
	Nullable *bool
	// Sampleable is true for text and integer-like types the sampler can read as text.
	Sampleable bool
}

// Conn is an open connection to one database.
type Conn interface {
	Engine() string
	ServerVersion(ctx context.Context) string
	// DefaultSchema is the schema whose tables are reported without a prefix.
	DefaultSchema() string
	// ListTables lists tables, sorted by schema and name. schema narrows the listing.
	ListTables(ctx context.Context, schema string) ([]Table, error)
	// FindTable resolves a name reported by ListTables (or a bare name in schema).
	FindTable(ctx context.Context, ref, schema string) (Table, bool, error)
	Columns(ctx context.Context, t Table) ([]Column, error)
	// Sample reads up to rows values of each sampleable column and calls visit for each
	// value; visit must examine and drop it.
	Sample(ctx context.Context, t Table, cols []Column, rows int, visit func(col int, value string, null bool)) error
	// TLSInUse reports whether the connection is encrypted, when known.
	TLSInUse() *bool
	Close() error
}

// Error kinds. They are stable codes shown to operators and reported to the platform.
const (
	KindConfig      = "config"
	KindUnreachable = "unreachable"
	KindTimeout     = "timeout"
	KindAuth        = "auth"
	KindTLS         = "tls"
	KindPermission  = "permission"
	KindNotFound    = "not_found"
	KindBlocked     = "blocked"
	KindUnsupported = "unsupported"
	KindDatabase    = "database"
)

// Error is a classified database error. Message() is safe to show to an operator on this
// server (it may name the host or the database, never a password or a value); only Kind
// leaves the network.
type Error struct {
	Kind  string
	Op    string
	Cause error
	// Safe marks a cause that cannot contain a value from the data (connection and
	// catalog errors). Errors of sampling queries are never shown with their cause.
	Safe bool
}

func (e *Error) Error() string { return e.Op + ": " + e.Kind }

// Unwrap returns the driver error.
func (e *Error) Unwrap() error { return e.Cause }

// Message describes the error for the local operator.
func (e *Error) Message() string {
	if e.Safe && e.Cause != nil {
		return e.Op + ": " + e.Kind + ": " + oneLine(e.Cause.Error())
	}
	return e.Op + ": " + e.Kind
}

func oneLine(s string) string {
	s = strings.ReplaceAll(strings.ReplaceAll(s, "\r", " "), "\n", " ")
	if len(s) > 300 {
		s = s[:300] + "..."
	}
	return s
}

// KindOf returns the kind of err (KindDatabase when unclassified).
func KindOf(err error) string {
	var e *Error
	if errors.As(err, &e) {
		return e.Kind
	}
	return KindDatabase
}

func wrap(op string, err error, safe bool) error {
	if err == nil {
		return nil
	}
	var e *Error
	if errors.As(err, &e) {
		return err
	}
	return &Error{Kind: classify(err), Op: op, Cause: err, Safe: safe}
}

// classify maps driver and network errors to a kind.
func classify(err error) string {
	if errors.Is(err, netguard.ErrBlocked) {
		return KindBlocked
	}
	if errors.Is(err, netguard.ErrUnresolved) {
		return KindUnreachable
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return KindTimeout
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return KindTimeout
	}
	if k := classifyDriver(err); k != "" {
		return k
	}
	var x509err x509.UnknownAuthorityError
	var hostErr x509.HostnameError
	var certErr x509.CertificateInvalidError
	var tlsRecord tls.RecordHeaderError
	if errors.As(err, &x509err) || errors.As(err, &hostErr) || errors.As(err, &certErr) || errors.As(err, &tlsRecord) {
		return KindTLS
	}
	var opErr *net.OpError
	var dnsErr *net.DNSError
	if errors.As(err, &opErr) || errors.As(err, &dnsErr) {
		return KindUnreachable
	}
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "x509") || strings.Contains(msg, "certificate") || strings.Contains(msg, "tls:"):
		return KindTLS
	case strings.Contains(msg, "connection refused") || strings.Contains(msg, "no such host") ||
		strings.Contains(msg, "no route to host") || strings.Contains(msg, "network is unreachable") ||
		strings.Contains(msg, "actively refused") || strings.Contains(msg, "i/o timeout"):
		if strings.Contains(msg, "timeout") {
			return KindTimeout
		}
		return KindUnreachable
	case strings.Contains(msg, "password authentication failed") || strings.Contains(msg, "access denied") ||
		strings.Contains(msg, "login failed") || strings.Contains(msg, "authentication failed") ||
		strings.Contains(msg, "ora-01017"):
		return KindAuth
	case strings.Contains(msg, "permission denied") || strings.Contains(msg, "ora-01031") || strings.Contains(msg, "not authorized"):
		return KindPermission
	}
	return KindDatabase
}

// TLSConfig builds the client TLS configuration for a database connection.
func (s TLSSettings) TLSConfig(host string) (*tls.Config, error) {
	serverName := s.ServerName
	if serverName == "" {
		serverName = strings.Trim(host, "[]")
	}
	switch s.Mode {
	case "", config.DBTLSDisable:
		return nil, nil
	case config.DBTLSPrefer, config.DBTLSRequire:
		// Encryption without verification, as the operator chose; verify-full is the
		// recommended mode wherever the database has a certificate.
		return &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12, ServerName: serverName}, nil // #nosec G402
	case config.DBTLSVerifyCA, config.DBTLSVerifyFull:
		pool, err := s.rootPool()
		if err != nil {
			return nil, err
		}
		cfg := &tls.Config{RootCAs: pool, ServerName: serverName, MinVersion: tls.VersionTLS12}
		if s.Mode == config.DBTLSVerifyCA {
			// Verify the chain but not the host name (PostgreSQL verify-ca semantics).
			cfg.InsecureSkipVerify = true // #nosec G402 -- the chain is verified below
			cfg.VerifyConnection = func(cs tls.ConnectionState) error {
				if len(cs.PeerCertificates) == 0 {
					return errors.New("tls: the server sent no certificate")
				}
				inter := x509.NewCertPool()
				for _, c := range cs.PeerCertificates[1:] {
					inter.AddCert(c)
				}
				_, err := cs.PeerCertificates[0].Verify(x509.VerifyOptions{Roots: pool, Intermediates: inter})
				return err
			}
		}
		return cfg, nil
	}
	return nil, &Error{Kind: KindConfig, Op: "tls", Cause: fmt.Errorf("unknown TLS mode %q", s.Mode), Safe: true}
}

func (s TLSSettings) rootPool() (*x509.CertPool, error) {
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	if len(s.ExtraRootsPEM) > 0 && !pool.AppendCertsFromPEM(s.ExtraRootsPEM) {
		return nil, &Error{Kind: KindConfig, Op: "tls targets_ca_file", Cause: errors.New("no certificate found"), Safe: true}
	}
	if s.CAFile != "" {
		pem, err := os.ReadFile(s.CAFile)
		if err != nil {
			return nil, &Error{Kind: KindConfig, Op: "tls ca_file", Cause: err, Safe: true}
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, &Error{Kind: KindConfig, Op: "tls ca_file", Cause: errors.New("no certificate found in the CA file"), Safe: true}
		}
	}
	return pool, nil
}

// Open connects to a database and checks the connection.
func Open(ctx context.Context, t Target) (Conn, error) {
	if t.Timeout <= 0 {
		t.Timeout = 20 * time.Second
	}
	if t.MaxOpen <= 0 {
		t.MaxOpen = 4
	}
	switch t.Engine {
	case "postgresql":
		return openPostgres(ctx, t)
	case "mysql", "mariadb":
		return openMySQL(ctx, t)
	case "mssql":
		return openMSSQL(ctx, t)
	case "oracle":
		return openOracle(ctx, t)
	case "mongodb":
		return openMongo(ctx, t)
	case "redshift":
		return openRedshift(ctx, t)
	case "clickhouse":
		return openClickHouse(ctx, t)
	case "snowflake":
		return openSnowflake(ctx, t)
	case "bigquery":
		return openBigQuery(ctx, t)
	case "databricks":
		return openDatabricks(ctx, t)
	case "athena":
		return openAthena(ctx, t)
	}
	return nil, &Error{Kind: KindUnsupported, Op: "open", Cause: fmt.Errorf("engine %q is not supported", t.Engine), Safe: true}
}

// FromSource builds a target from a configured source; resolve turns secret references
// into values.
func FromSource(src *config.SourceConfig, resolve func(config.SecretRef) (secrets.Value, error)) (Target, error) {
	t := Target{
		Engine: src.Engine, Host: src.Host, Port: src.Port, Database: src.Database, Username: src.Username,
		AuthSource: src.AuthSource, Schemas: src.Schemas, ServiceName: src.ServiceName, SID: src.SID,
		Instance: src.Instance, Timeout: src.Timeout.D(),
		TLS:       TLSSettings{Mode: src.TLS.Mode, CAFile: src.TLS.CAFile, ServerName: src.TLS.ServerName},
		Warehouse: src.Warehouse, Role: src.Role, Region: src.Region,
	}
	for _, s := range []struct {
		name string
		ref  config.SecretRef
		dst  *secrets.Value
	}{{"password", src.Password, &t.Password}, {"uri", src.URI, &t.URI}, {"private_key", src.PrivateKey, &t.PrivateKey},
		{"private_key_passphrase", src.PrivateKeyPassphrase, &t.PrivateKeyPassphrase},
		{"credentials", src.Credentials, &t.Credentials}, {"session_token", src.SessionToken, &t.SessionToken}} {
		if !s.ref.IsSet() {
			continue
		}
		v, err := resolve(s.ref)
		if err != nil {
			return Target{}, &Error{Kind: KindConfig, Op: s.name, Cause: err, Safe: true}
		}
		*s.dst = v
	}
	return t, nil
}

// schemaAllowed reports whether a schema may be read under the target's allow-list.
func (t Target) schemaAllowed(schema string) bool {
	if len(t.Schemas) == 0 {
		return true
	}
	for _, s := range t.Schemas {
		if strings.EqualFold(s, schema) {
			return true
		}
	}
	return false
}

// validName refuses names that cannot be sent to the platform or quoted safely: empty,
// longer than 255 bytes, with control characters, or not valid UTF-8 (the Laravel client
// rejects a whole response that is not valid UTF-8; the Go client would see U+FFFD).
func validName(s string) bool {
	if s == "" || len(s) > 255 || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}
