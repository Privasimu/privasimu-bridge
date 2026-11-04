// Package config loads and validates the bridge configuration file (YAML). The file holds
// no secrets: passwords and tokens are references (env:, file:, secret:) resolved at run
// time, and API keys are stored as SHA-256 hashes.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"go.yaml.in/yaml/v3"
)

// Config is the whole configuration file.
type Config struct {
	Language  string          `yaml:"language"`
	StateDir  string          `yaml:"state_dir"`
	Server    ServerConfig    `yaml:"server"`
	Agent     AgentConfig     `yaml:"agent"`
	Sources   []SourceConfig  `yaml:"sources"`
	Files     FilesConfig     `yaml:"files"`
	Packages  PackagesConfig  `yaml:"packages"`
	Detection DetectionConfig `yaml:"detection"`
	Secrets   SecretsConfig   `yaml:"secrets"`
	Audit     AuditConfig     `yaml:"audit"`
	Log       LogConfig       `yaml:"log"`

	// path is the absolute path of the loaded file; relative paths resolve against its directory.
	path string
}

// ServerConfig configures mode A: the HTTPS server the platform calls.
type ServerConfig struct {
	Listen         string    `yaml:"listen"`
	PublicURL      string    `yaml:"public_url"`
	BasePath       string    `yaml:"base_path"`
	TLS            ServerTLS `yaml:"tls"`
	AllowedClients []string  `yaml:"allowed_clients"`
	TrustedProxies []string  `yaml:"trusted_proxies"`
	APIKeys        []APIKey  `yaml:"api_keys"`
	Credentials    string    `yaml:"credentials"`
	AllowedTargets []string  `yaml:"allowed_targets"`
	TargetsCAFile  string    `yaml:"targets_ca_file"`
	FileEndpoints  bool      `yaml:"file_endpoints"`
	// AccessEndpoint serves /ext/v1/table-access (a proposal, off by default): who can read a
	// table of a source with access_inventory, as counts and role names.
	AccessEndpoint bool             `yaml:"access_endpoint"`
	Limits         ServerLimits     `yaml:"limits"`
	Sampling       *SamplingOptions `yaml:"sampling"`
}

// Credential modes of mode A.
const (
	// CredentialsLocal: the platform may only scan sources defined in this file, matched by
	// engine, host and database; the passwords it sends are ignored.
	CredentialsLocal = "local"
	// CredentialsRequest: the connection settings the platform sends are used, but only
	// for hosts listed in allowed_targets (contract v1 behaviour).
	CredentialsRequest = "request"
)

// TLS modes of mode A.
const (
	TLSModeFile  = "file"  // the bridge terminates TLS with a certificate and key file
	TLSModeProxy = "proxy" // a reverse proxy on the same host terminates TLS
)

// ServerTLS configures the certificate of mode A.
type ServerTLS struct {
	Mode       string `yaml:"mode"`
	CertFile   string `yaml:"cert_file"`
	KeyFile    string `yaml:"key_file"`
	MinVersion string `yaml:"min_version"`
}

// APIKey is one accepted API key, stored as its SHA-256 hash.
type APIKey struct {
	ID       string `yaml:"id"`
	Hash     string `yaml:"hash"`
	Created  string `yaml:"created,omitempty"`
	Expires  string `yaml:"expires,omitempty"`
	Disabled bool   `yaml:"disabled,omitempty"`
}

// ServerLimits bound what one client can make the bridge do.
type ServerLimits struct {
	MaxBodyBytes         ByteSize `yaml:"max_body_bytes"`
	RatePerSecond        float64  `yaml:"rate_per_second"`
	Burst                int      `yaml:"burst"`
	MaxConcurrent        int      `yaml:"max_concurrent"`
	PerSourceConcurrency int      `yaml:"per_source_concurrency"`
	RequestTimeout       Duration `yaml:"request_timeout"`
	MaxTables            int      `yaml:"max_tables"`
	MaxColumns           int      `yaml:"max_columns"`
	AuthFailures         int      `yaml:"auth_failures"`
	Lockout              Duration `yaml:"lockout"`
}

// AgentConfig configures mode B: the outbound agent that polls the platform.
type AgentConfig struct {
	PlatformURL     string    `yaml:"platform_url"`
	AgentID         string    `yaml:"agent_id"`
	Token           SecretRef `yaml:"token"`
	CAFile          string    `yaml:"ca_file"`
	ProxyURL        string    `yaml:"proxy_url"`
	ProxyAuth       SecretRef `yaml:"proxy_auth"`
	AllowedJobs     []string  `yaml:"allowed_jobs"`
	MaxParallelJobs int       `yaml:"max_parallel_jobs"`
	PollMin         Duration  `yaml:"poll_min"`
	PollMax         Duration  `yaml:"poll_max"`
}

// Job types of mode B.
const (
	JobTestSource   = "test_source"
	JobScanDatabase = "scan_database"
	JobScanFiles    = "scan_files"
)

// SourceConfig is a database the bridge may scan.
type SourceConfig struct {
	ID          string           `yaml:"id"`
	Label       string           `yaml:"label"`
	Description string           `yaml:"description"`
	Engine      string           `yaml:"engine"`
	Host        string           `yaml:"host"`
	Port        int              `yaml:"port"`
	Database    string           `yaml:"database"`
	Username    string           `yaml:"username"`
	Password    SecretRef        `yaml:"password"`
	URI         SecretRef        `yaml:"uri"`
	AuthSource  string           `yaml:"auth_source"`
	Schemas     []string         `yaml:"schemas"`
	ServiceName string           `yaml:"service_name"`
	SID         string           `yaml:"sid"`
	Instance    string           `yaml:"instance"`
	TLS         SourceTLS        `yaml:"tls"`
	Sampling    *SamplingOptions `yaml:"sampling"`
	Match       SourceMatch      `yaml:"match"`
	Timeout     Duration         `yaml:"timeout"`
	// AccessInventory also reports who can read each table with personal data: counts and
	// group role names, never account names (PostgreSQL, MySQL, MariaDB).
	AccessInventory bool `yaml:"access_inventory"`

	// Cloud warehouses. Warehouse: the Snowflake warehouse (needed for sampling only) or the
	// Databricks SQL warehouse id (its HTTP path is accepted too). Role: the Snowflake role.
	// PrivateKey (+ PrivateKeyPassphrase): the Snowflake key pair, PEM. Credentials: the
	// BigQuery service account key, JSON. Region and SessionToken: Athena.
	Warehouse            string    `yaml:"warehouse"`
	Role                 string    `yaml:"role"`
	PrivateKey           SecretRef `yaml:"private_key"`
	PrivateKeyPassphrase SecretRef `yaml:"private_key_passphrase"`
	Credentials          SecretRef `yaml:"credentials"`
	Region               string    `yaml:"region"`
	SessionToken         SecretRef `yaml:"session_token"`
}

// CloudEngine reports whether an engine is a cloud service reached over HTTPS with
// verified TLS only (Snowflake, BigQuery, Databricks, Athena).
func CloudEngine(engine string) bool {
	switch engine {
	case "snowflake", "bigquery", "databricks", "athena":
		return true
	}
	return false
}

// EngineSamples reports whether the bridge can sample values of an engine. Athena runs
// every query into an S3 bucket, so the bridge reads its catalog only.
func EngineSamples(engine string) bool { return engine != "athena" }

// SourceTLS configures the TLS connection to a database.
type SourceTLS struct {
	// Mode is disable, prefer (encrypt when the server offers it, without verifying),
	// require (encrypt without verifying), verify-ca or verify-full.
	Mode       string `yaml:"mode"`
	CAFile     string `yaml:"ca_file"`
	ServerName string `yaml:"server_name"`
}

// Database TLS modes (the PostgreSQL sslmode names, applied to every engine).
const (
	DBTLSDisable    = "disable"
	DBTLSPrefer     = "prefer"
	DBTLSRequire    = "require"
	DBTLSVerifyCA   = "verify-ca"
	DBTLSVerifyFull = "verify-full"
)

// SourceMatch is how the platform names a source in mode A with local credentials: the
// host and database typed in the Privasimu form. They default to the source's own host and
// database; setting them lets the real address stay on-premise.
type SourceMatch struct {
	Host     string `yaml:"host"`
	Database string `yaml:"database"`
}

// SamplingOptions turns local value sampling on and tunes it. A source may override the
// global setting.
type SamplingOptions struct {
	Enabled    *bool   `yaml:"enabled"`
	Rows       int     `yaml:"rows"`
	MinMatches int     `yaml:"min_matches"`
	Ratio      float64 `yaml:"ratio"`
}

// FilesConfig configures file-share scanning.
type FilesConfig struct {
	ReportPaths  string     `yaml:"report_paths"`
	MaxFileBytes ByteSize   `yaml:"max_file_bytes"`
	MaxTextBytes ByteSize   `yaml:"max_text_bytes"`
	PDFTimeout   Duration   `yaml:"pdf_timeout"`
	Roots        []FileRoot `yaml:"roots"`
}

// Path reporting modes of file scans.
const (
	// PathsHashed reports a keyed hash per file instead of its path (default).
	PathsHashed = "hashed"
	// PathsRelative reports the path relative to the root.
	PathsRelative = "relative"
)

// FileRoot is an allow-listed directory the bridge may scan. Only roots listed here can be
// scanned; the platform names a root by its id and can never supply a path.
type FileRoot struct {
	ID          string   `yaml:"id"`
	Label       string   `yaml:"label"`
	Description string   `yaml:"description"`
	Path        string   `yaml:"path"`
	Include     []string `yaml:"include"`
	Exclude     []string `yaml:"exclude"`
	ContentScan *bool    `yaml:"content_scan"`
	MaxFiles    int      `yaml:"max_files"`
	MaxDepth    int      `yaml:"max_depth"`
	ReportPaths string   `yaml:"report_paths"`
	// RefreshInterval rescans the root in the background when its report is older
	// (0 = only on request).
	RefreshInterval Duration `yaml:"refresh_interval"`
}

// DetectionConfig holds the global detection settings.
type DetectionConfig struct {
	Sampling SamplingOptions `yaml:"sampling"`
	NLP      NLPConfig       `yaml:"nlp"`
}

// NLPConfig turns on an optional language-model service that finds personal data the
// patterns cannot (names, addresses, health, religion, ...) in long text: sampled text
// values of a column and the text of files. The service runs on this server or the
// client's internal network (for example the client's own nlp-data-discovery): text is
// sent to it only, and only the counts it returns are used. Off by default.
type NLPConfig struct {
	Enabled bool `yaml:"enabled"`
	// Endpoint is the URL the text is posted to; its host must be loopback or a private
	// address (checked at every connection).
	Endpoint string `yaml:"endpoint"`
	CAFile   string `yaml:"ca_file"`
	// Timeout of one request; MinChars the shortest text sent; MaxBytes the most text of one
	// file or one column sent in one request; MinScore the least confidence of an entity.
	Timeout     Duration `yaml:"timeout"`
	MinChars    int      `yaml:"min_chars"`
	MaxBytes    ByteSize `yaml:"max_bytes"`
	MinScore    float64  `yaml:"min_score"`
	Concurrency int      `yaml:"concurrency"`
}

// SecretsConfig locates the encrypted secret store.
type SecretsConfig struct {
	File    string `yaml:"file"`
	KeyFile string `yaml:"key_file"`
}

// AuditConfig configures the JSON-lines audit log.
type AuditConfig struct {
	File      string `yaml:"file"`
	MaxSizeMB int    `yaml:"max_size_mb"`
	MaxFiles  int    `yaml:"max_files"`
}

// LogConfig configures the operational log.
type LogConfig struct {
	Level string `yaml:"level"`
	File  string `yaml:"file"`
}

// MaxConfigBytes bounds the configuration file.
const MaxConfigBytes = 1 << 20

// ErrNotFound means the configuration file does not exist.
var ErrNotFound = errors.New("configuration file not found")

// Load reads, defaults and validates a configuration file.
func Load(path string) (*Config, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	f, err := os.Open(abs) // #nosec G304 -- the configuration file chosen by the operator
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("%w: %s", ErrNotFound, abs)
		}
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, MaxConfigBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > MaxConfigBytes {
		return nil, fmt.Errorf("%s: the file is larger than %d bytes", abs, MaxConfigBytes)
	}
	c, err := Parse(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", abs, err)
	}
	c.path = abs
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return c, nil
}

// Parse decodes YAML strictly (unknown keys are errors, which catches typos) and applies
// defaults. It does not validate.
func Parse(data []byte) (*Config, error) {
	var c Config
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	c.applyDefaults()
	return &c, nil
}

// Path returns the absolute path of the loaded file ("" when parsed from memory).
func (c *Config) Path() string { return c.path }

// SetPath sets the file path used to resolve relative paths (for tests and init).
func (c *Config) SetPath(p string) { c.path = p }

// Dir returns the directory relative paths resolve against.
func (c *Config) Dir() string {
	if c.path == "" {
		wd, _ := os.Getwd()
		return wd
	}
	return filepath.Dir(c.path)
}

// Resolve turns a path from the file into an absolute path.
func (c *Config) Resolve(p string) string {
	if p == "" || filepath.IsAbs(p) {
		return p
	}
	return filepath.Join(c.Dir(), p)
}

func (c *Config) applyDefaults() {
	if c.Language == "" {
		c.Language = "en"
	}
	if c.StateDir == "" {
		c.StateDir = "state"
	}
	s := &c.Server
	if s.Listen == "" {
		s.Listen = "0.0.0.0:8443"
	}
	if s.TLS.Mode == "" {
		s.TLS.Mode = TLSModeFile
	}
	if s.TLS.MinVersion == "" {
		s.TLS.MinVersion = "1.2"
	}
	if s.Credentials == "" {
		s.Credentials = CredentialsLocal
	}
	if len(s.TrustedProxies) == 0 && s.TLS.Mode == TLSModeProxy {
		s.TrustedProxies = []string{"127.0.0.1/32", "::1/128"}
	}
	s.BasePath = strings.TrimRight(s.BasePath, "/")
	l := &s.Limits
	if l.MaxBodyBytes <= 0 {
		l.MaxBodyBytes = 64 << 10
	}
	if l.RatePerSecond <= 0 {
		l.RatePerSecond = 100
	}
	if l.Burst <= 0 {
		l.Burst = 400
	}
	if l.MaxConcurrent <= 0 {
		l.MaxConcurrent = 16
	}
	if l.PerSourceConcurrency <= 0 {
		l.PerSourceConcurrency = 4
	}
	if l.RequestTimeout <= 0 {
		l.RequestTimeout = Duration(25e9)
	}
	if l.MaxTables <= 0 {
		l.MaxTables = 10000
	}
	if l.MaxColumns <= 0 {
		l.MaxColumns = 5000
	}
	if l.AuthFailures <= 0 {
		l.AuthFailures = 10
	}
	if l.Lockout <= 0 {
		l.Lockout = Duration(15 * 60e9)
	}
	a := &c.Agent
	if len(a.AllowedJobs) == 0 {
		a.AllowedJobs = []string{JobTestSource, JobScanDatabase, JobScanFiles}
	}
	if a.MaxParallelJobs <= 0 {
		a.MaxParallelJobs = 1
	}
	if a.PollMin <= 0 {
		a.PollMin = Duration(5e9)
	}
	if a.PollMax <= 0 {
		a.PollMax = Duration(300e9)
	}
	if !a.Token.IsSet() {
		a.Token = "secret:agent_token"
	}
	for i := range c.Sources {
		src := &c.Sources[i]
		// The platform requires a label of 1 to 128 characters for every inventory entry;
		// without one, the id is the label.
		if strings.TrimSpace(src.Label) == "" {
			src.Label = src.ID
		}
		src.Engine = strings.ToLower(strings.TrimSpace(src.Engine))
		if src.Engine == "mariadb" {
			src.Engine = "mysql"
		}
		if src.TLS.Mode == "" {
			src.TLS.Mode = defaultDBTLS(src.Engine)
		}
		if src.Port == 0 {
			src.Port = DefaultPort(src.Engine)
			// ClickHouse serves HTTPS on its own port.
			if src.Engine == "clickhouse" && src.TLS.Mode != DBTLSDisable {
				src.Port = ClickHouseTLSPort
			}
		}
		if src.Timeout <= 0 {
			src.Timeout = Duration(20e9)
		}
	}
	f := &c.Files
	if f.ReportPaths == "" {
		f.ReportPaths = PathsHashed
	}
	if f.MaxFileBytes <= 0 {
		f.MaxFileBytes = 100 << 20
	}
	if f.MaxTextBytes <= 0 {
		f.MaxTextBytes = 16 << 20
	}
	if f.PDFTimeout <= 0 {
		f.PDFTimeout = Duration(30e9)
	}
	for i := range f.Roots {
		r := &f.Roots[i]
		if strings.TrimSpace(r.Label) == "" {
			r.Label = r.ID
		}
		if r.MaxFiles <= 0 {
			r.MaxFiles = 500000
		}
		if r.MaxDepth <= 0 {
			r.MaxDepth = 64
		}
		if r.ReportPaths == "" {
			r.ReportPaths = f.ReportPaths
		}
	}
	sp := &c.Detection.Sampling
	if sp.Enabled == nil {
		off := false
		sp.Enabled = &off
	}
	if sp.Rows <= 0 {
		sp.Rows = 100
	}
	if sp.MinMatches <= 0 {
		sp.MinMatches = 3
	}
	if sp.Ratio <= 0 {
		sp.Ratio = 0.2
	}
	nlp := &c.Detection.NLP
	if nlp.Timeout <= 0 {
		nlp.Timeout = Duration(10e9)
	}
	if nlp.MinChars <= 0 {
		nlp.MinChars = 200
	}
	if nlp.MaxBytes <= 0 {
		nlp.MaxBytes = 32 << 10
	}
	if nlp.MinScore <= 0 {
		nlp.MinScore = 0.8
	}
	if nlp.Concurrency <= 0 {
		nlp.Concurrency = 2
	}
	if c.Secrets.File == "" {
		c.Secrets.File = "secrets.enc"
	}
	if c.Secrets.KeyFile == "" {
		c.Secrets.KeyFile = "secrets.key"
	}
	if c.Audit.File == "" {
		c.Audit.File = "logs/audit.jsonl"
	}
	if c.Audit.MaxSizeMB <= 0 {
		c.Audit.MaxSizeMB = 50
	}
	if c.Audit.MaxFiles <= 0 {
		c.Audit.MaxFiles = 10
	}
	if c.Log.Level == "" {
		c.Log.Level = "info"
	}
	c.applyPackageDefaults()
}

// DefaultPort returns the usual port of an engine (0 when unknown).
func DefaultPort(engine string) int {
	switch engine {
	case "postgresql":
		return 5432
	case "mysql":
		return 3306
	case "mssql":
		return 1433
	case "oracle":
		return 1521
	case "mongodb":
		return 27017
	case "redshift":
		return 5439
	case "clickhouse":
		return 8123
	case "snowflake", "bigquery", "databricks", "athena":
		return 443
	}
	return 0
}

// ClickHouseTLSPort is the default HTTPS port of ClickHouse, used when a ClickHouse
// source has a TLS mode and no port.
const ClickHouseTLSPort = 8443

// defaultDBTLS is the TLS mode used when a source does not set one: opportunistic
// encryption where the engine negotiates TLS on its normal port (the same default as
// libpq), plain connections where TLS needs a separate listener (Oracle TCPS, ClickHouse
// HTTPS) or a URI option (MongoDB). verify-full is recommended wherever the database has a
// certificate.
func defaultDBTLS(engine string) string {
	switch {
	case CloudEngine(engine):
		return DBTLSVerifyFull
	case engine == "postgresql" || engine == "mysql" || engine == "mssql" || engine == "redshift":
		return DBTLSPrefer
	}
	return DBTLSDisable
}

// SamplingFor returns the effective sampling settings of a source: its own override on
// top of the global setting.
func (c *Config) SamplingFor(src *SourceConfig) SamplingOptions {
	out := c.Detection.Sampling
	if src != nil && src.Sampling != nil {
		o := src.Sampling
		if o.Enabled != nil {
			out.Enabled = o.Enabled
		}
		if o.Rows > 0 {
			out.Rows = o.Rows
		}
		if o.MinMatches > 0 {
			out.MinMatches = o.MinMatches
		}
		if o.Ratio > 0 {
			out.Ratio = o.Ratio
		}
	}
	if src != nil && !EngineSamples(src.Engine) {
		off := false
		out.Enabled = &off
	}
	return out
}

// On reports whether sampling is enabled.
func (s SamplingOptions) On() bool { return s.Enabled != nil && *s.Enabled }

// Source returns the source with the given id.
func (c *Config) Source(id string) (*SourceConfig, bool) {
	for i := range c.Sources {
		if c.Sources[i].ID == id {
			return &c.Sources[i], true
		}
	}
	return nil, false
}

// Root returns the file root with the given id.
func (c *Config) Root(id string) (*FileRoot, bool) {
	for i := range c.Files.Roots {
		if c.Files.Roots[i].ID == id {
			return &c.Files.Roots[i], true
		}
	}
	return nil, false
}

// ContentScanOn reports whether file content is examined for a root (default on).
func (r *FileRoot) ContentScanOn() bool { return r.ContentScan == nil || *r.ContentScan }

// JobAllowed reports whether the agent accepts a job type.
func (a *AgentConfig) JobAllowed(job string) bool {
	for _, j := range a.AllowedJobs {
		if j == job {
			return true
		}
	}
	return false
}
