package config

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/privasimu/bridge/internal/i18n"
)

var (
	idPattern         = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,62}$`)
	keyIDPattern      = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`)
	hostPattern       = regexp.MustCompile(`^[A-Za-z0-9._:\-\[\]]{1,255}$`)
	identifierPattern = regexp.MustCompile(`^[A-Za-z0-9_.$@\-]{1,128}$`)
	hashPattern       = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	agentIDPattern    = regexp.MustCompile(`^[A-Za-z0-9-]{1,64}$`)
)

// Engines lists the database engines the bridge can scan.
var Engines = []string{"postgresql", "mysql", "mssql", "oracle", "mongodb", "redshift", "clickhouse",
	"snowflake", "bigquery", "databricks", "athena"}

var (
	// projectPattern is a Google Cloud project id.
	projectPattern = regexp.MustCompile(`^[a-z][a-z0-9-]{4,28}[a-z0-9]$`)
	// warehousePattern is a Databricks SQL warehouse id, alone or in its HTTP path.
	warehousePattern = regexp.MustCompile(`^(/sql/1\.0/(warehouses|endpoints)/)?[A-Za-z0-9]{1,64}$`)
	// regionPattern is an AWS region.
	regionPattern = regexp.MustCompile(`^[a-z]{2}(-[a-z]+)+-[0-9]{1,2}$`)
	// accessKeyPattern is an AWS access key id.
	accessKeyPattern = regexp.MustCompile(`^[A-Z0-9]{16,128}$`)
)

// ProtocolEngines are the engines every platform of agent protocol revision 2 or 3 accepts
// in an inventory. The others are sent only to a platform whose poll answer lists
// "source_engine:<engine>" (revision 4).
var ProtocolEngines = []string{"postgresql", "mysql", "mssql", "oracle", "mongodb"}

func knownEngine(e string) bool {
	for _, x := range Engines {
		if x == e {
			return true
		}
	}
	return false
}

// problems collects validation messages.
type problems []string

func (p *problems) add(key string, args ...any) { *p = append(*p, i18n.T(key, args...)) }

func (p problems) err() error {
	if len(p) == 0 {
		return nil
	}
	return &ValidationError{Problems: p}
}

// ValidationError lists every problem found in the configuration.
type ValidationError struct{ Problems []string }

func (e *ValidationError) Error() string {
	return i18n.T("config.invalid") + "\n  - " + strings.Join(e.Problems, "\n  - ")
}

func hasControl(s string) bool {
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return true
		}
	}
	return false
}

// validText is the agent protocol's text rule (labels, descriptions): valid UTF-8, min to
// max Unicode characters, no C0 control character (U+0000-U+001F) and no DEL (U+007F).
// C1 characters (U+0080-U+009F) are allowed, as in both platform lines.
func validText(s string, min, max int) bool {
	if !utf8.ValidString(s) || hasControl(s) {
		return false
	}
	n := utf8.RuneCountInString(s)
	return n >= min && n <= max
}

// MaxInventory is the most sources, file roots and packages targets the platform accepts
// in one inventory.
const MaxInventory = 200

// Validate checks the parts every command uses: sources, file roots, detection, language.
func (c *Config) Validate() error {
	var p problems
	if l := strings.ToLower(c.Language); l != "en" && l != "id" {
		p.add("config.language")
	}
	ids := map[string]string{}
	seen := func(where, id string) {
		if prev, dup := ids[id]; dup {
			p.add("config.duplicate_id", where, id, prev)
			return
		}
		ids[id] = where
	}
	for i := range c.Sources {
		c.validateSource(&p, i)
		if s := c.Sources[i]; s.ID != "" {
			seen(fmt.Sprintf("sources[%d]", i), s.ID)
		}
	}
	if m := c.AccessInventory.RoleNames; m != RoleNamesHashed && m != RoleNamesPlain {
		p.add("config.role_names", "access_inventory.role_names")
	}
	if m := c.Files.ReportPaths; m != PathsHashed && m != PathsRelative {
		p.add("config.report_paths", "files.report_paths")
	}
	for i := range c.Files.Roots {
		c.validateRoot(&p, i)
		if r := c.Files.Roots[i]; r.ID != "" {
			seen(fmt.Sprintf("files.roots[%d]", i), r.ID)
		}
	}
	c.validatePackages(&p, seen)
	validateSampling(&p, "detection.sampling", &c.Detection.Sampling)
	validateNLP(&p, &c.Detection.NLP)
	if n := len(c.Sources) + len(c.Files.Roots) + len(c.Packages.Targets); n > MaxInventory {
		p.add("config.inventory_size", n, MaxInventory)
	}
	return p.err()
}

func (c *Config) validateSource(p *problems, i int) {
	s := &c.Sources[i]
	at := fmt.Sprintf("sources[%d]", i)
	if !idPattern.MatchString(s.ID) {
		p.add("config.id", at+".id")
	}
	if !validText(s.Label, 1, 128) || !validText(s.Description, 0, 512) {
		p.add("config.text", at)
	}
	if !knownEngine(s.Engine) {
		p.add("config.engine", at+".engine", strings.Join(Engines, ", "))
		return
	}
	if CloudEngine(s.Engine) {
		if s.AccessInventory {
			p.add("config.access_engine", at+".access_inventory")
		}
		validateCloudSource(p, at, s)
		return
	}
	for name, set := range map[string]bool{"warehouse": s.Warehouse != "", "role": s.Role != "", "private_key": s.PrivateKey.IsSet(),
		"private_key_passphrase": s.PrivateKeyPassphrase.IsSet(), "credentials": s.Credentials.IsSet(), "region": s.Region != "",
		"session_token": s.SessionToken.IsSet()} {
		if set {
			p.add("config.cloud_field", at+"."+name)
		}
	}
	if s.AccessInventory && s.Engine != "postgresql" && s.Engine != "mysql" {
		p.add("config.access_engine", at+".access_inventory")
	}
	mongoURI := s.Engine == "mongodb" && s.URI.IsSet()
	if !mongoURI {
		if !hostPattern.MatchString(s.Host) {
			p.add("config.host", at+".host")
		}
		if s.Port < 1 || s.Port > 65535 {
			p.add("config.port", at+".port")
		}
		if s.Username == "" || hasControl(s.Username) || len(s.Username) > 128 {
			p.add("config.required", at+".username")
		}
		if !s.Password.IsSet() {
			p.add("config.required", at+".password")
		}
	}
	checkRef(p, at+".password", s.Password)
	checkRef(p, at+".uri", s.URI)
	if s.URI.IsSet() && s.Engine != "mongodb" {
		p.add("config.uri_mongo_only", at+".uri")
	}
	switch s.Engine {
	case "postgresql", "mysql", "mongodb", "redshift", "clickhouse":
		if !identifierPattern.MatchString(s.Database) {
			p.add("config.database", at+".database")
		}
	default:
		if s.Database != "" && !identifierPattern.MatchString(s.Database) {
			p.add("config.database", at+".database")
		}
	}
	for j, sc := range s.Schemas {
		if !identifierPattern.MatchString(sc) {
			p.add("config.identifier", fmt.Sprintf("%s.schemas[%d]", at, j))
		}
	}
	for name, v := range map[string]string{"service_name": s.ServiceName, "sid": s.SID, "instance": s.Instance,
		"auth_source": s.AuthSource, "match.database": s.Match.Database} {
		if v != "" && !identifierPattern.MatchString(v) {
			p.add("config.identifier", at+"."+name)
		}
	}
	if s.Match.Host != "" && !hostPattern.MatchString(s.Match.Host) {
		p.add("config.host", at+".match.host")
	}
	switch s.TLS.Mode {
	case DBTLSDisable, DBTLSPrefer, DBTLSRequire, DBTLSVerifyCA, DBTLSVerifyFull:
	default:
		p.add("config.db_tls", at+".tls.mode")
	}
	if s.Sampling != nil {
		validateSampling(p, at+".sampling", s.Sampling)
	}
}

// validateCloudSource checks a Snowflake, BigQuery, Databricks or Athena source: verified
// TLS only, the engine's own required settings, and every secret as a reference.
func validateCloudSource(p *problems, at string, s *SourceConfig) {
	if s.TLS.Mode != DBTLSVerifyFull {
		p.add("config.cloud_tls", at+".tls.mode")
	}
	for name, ref := range map[string]SecretRef{"password": s.Password, "private_key": s.PrivateKey,
		"private_key_passphrase": s.PrivateKeyPassphrase, "credentials": s.Credentials, "session_token": s.SessionToken} {
		checkRef(p, at+"."+name, ref)
	}
	if s.URI.IsSet() {
		p.add("config.uri_mongo_only", at+".uri")
	}
	if s.Port < 1 || s.Port > 65535 {
		p.add("config.port", at+".port")
	}
	for j, sc := range s.Schemas {
		if !identifierPattern.MatchString(sc) {
			p.add("config.identifier", fmt.Sprintf("%s.schemas[%d]", at, j))
		}
	}
	if s.Username != "" && (hasControl(s.Username) || len(s.Username) > 128) {
		p.add("config.identifier", at+".username")
	}
	if s.Role != "" && !identifierPattern.MatchString(s.Role) {
		p.add("config.identifier", at+".role")
	}
	switch s.Engine {
	case "snowflake":
		if !hostPattern.MatchString(s.Host) {
			p.add("config.host", at+".host")
		}
		if !identifierPattern.MatchString(s.Database) {
			p.add("config.database", at+".database")
		}
		if s.Username == "" {
			p.add("config.required", at+".username")
		}
		if s.Password.IsSet() == s.PrivateKey.IsSet() {
			p.add("config.snowflake_auth", at)
		}
		if s.Warehouse != "" && !identifierPattern.MatchString(s.Warehouse) {
			p.add("config.identifier", at+".warehouse")
		}
	case "bigquery":
		if !projectPattern.MatchString(s.Database) {
			p.add("config.project", at+".database")
		}
		if !s.Credentials.IsSet() {
			p.add("config.required", at+".credentials")
		}
	case "databricks":
		if !hostPattern.MatchString(s.Host) {
			p.add("config.host", at+".host")
		}
		if !identifierPattern.MatchString(s.Database) {
			p.add("config.database", at+".database")
		}
		if !warehousePattern.MatchString(s.Warehouse) {
			p.add("config.warehouse", at+".warehouse")
		}
		if !s.Password.IsSet() {
			p.add("config.required", at+".password")
		}
	case "athena":
		if !regionPattern.MatchString(s.Region) {
			p.add("config.region", at+".region")
		}
		if !accessKeyPattern.MatchString(s.Username) {
			p.add("config.access_key", at+".username")
		}
		if !s.Password.IsSet() {
			p.add("config.required", at+".password")
		}
		if s.Database != "" && !identifierPattern.MatchString(s.Database) {
			p.add("config.identifier", at+".database")
		}
		if s.Sampling != nil && s.Sampling.On() {
			p.add("config.sampling_unsupported", at)
		}
	}
	if s.Engine != "snowflake" {
		for name, set := range map[string]bool{"role": s.Role != "", "private_key": s.PrivateKey.IsSet(),
			"private_key_passphrase": s.PrivateKeyPassphrase.IsSet()} {
			if set {
				p.add("config.snowflake_field", at+"."+name)
			}
		}
	}
	if s.Sampling != nil {
		validateSampling(p, at+".sampling", s.Sampling)
	}
}

// NLPRanges are the addresses an NLP endpoint may resolve to: loopback and private ranges
// (the service runs on this server or inside the client's network, never outside it).
var NLPRanges = []string{"127.0.0.0/8", "::1/128", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "fc00::/7"}

// validateNLP checks the optional NLP service: an http(s) URL without credentials, query or
// fragment, whose host is a name (checked when connecting) or an address in NLPRanges, and
// bounded limits.
func validateNLP(p *problems, n *NLPConfig) {
	if !n.Enabled {
		return
	}
	u, err := url.Parse(n.Endpoint)
	ok := err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Host != "" && u.User == nil && u.RawQuery == "" &&
		u.Fragment == "" && !hasControl(n.Endpoint)
	if ok {
		if a, err := netip.ParseAddr(strings.Trim(u.Hostname(), "[]")); err == nil {
			ok = false
			for _, r := range NLPRanges {
				if pfx, _ := netip.ParsePrefix(r); pfx.Contains(a.Unmap()) {
					ok = true
				}
			}
		} else if !hostPattern.MatchString(u.Hostname()) {
			ok = false
		}
	}
	if !ok {
		p.add("config.nlp_endpoint", "detection.nlp.endpoint")
	}
	if n.Timeout.D() < time.Second || n.Timeout.D() > time.Minute || n.MinChars < 20 || n.MinChars > 100000 ||
		n.MaxBytes < 1<<10 || n.MaxBytes > 1<<20 || n.MinScore < 0 || n.MinScore > 1 || n.Concurrency < 1 || n.Concurrency > 16 {
		p.add("config.nlp_limits", "detection.nlp")
	}
}

// checkRef refuses a literal secret: the configuration file must never hold a password.
func checkRef(p *problems, where string, r SecretRef) {
	if !r.IsSet() {
		return
	}
	if _, _, ok := r.Parse(); !ok {
		p.add("config.secret_literal", where)
	}
}

func validateSampling(p *problems, where string, s *SamplingOptions) {
	if s.Rows < 0 || s.Rows > 10000 {
		p.add("config.sampling_rows", where+".rows")
	}
	if s.MinMatches < 0 {
		p.add("config.sampling_matches", where+".min_matches")
	}
	if s.Ratio < 0 || s.Ratio > 1 {
		p.add("config.sampling_ratio", where+".ratio")
	}
}

func (c *Config) validateRoot(p *problems, i int) {
	r := &c.Files.Roots[i]
	at := fmt.Sprintf("files.roots[%d]", i)
	if !idPattern.MatchString(r.ID) {
		p.add("config.id", at+".id")
	}
	if !validText(r.Label, 1, 128) || !validText(r.Description, 0, 512) {
		p.add("config.text", at)
	}
	if r.Path == "" || !filepath.IsAbs(r.Path) || hasControl(r.Path) {
		p.add("config.root_path", at+".path")
	}
	for j, g := range append(append([]string{}, r.Include...), r.Exclude...) {
		if _, err := path.Match(strings.ReplaceAll(g, "**", "*"), "x"); err != nil || g == "" {
			p.add("config.glob", fmt.Sprintf("%s pattern %d", at, j))
		}
	}
	if m := r.ReportPaths; m != PathsHashed && m != PathsRelative {
		p.add("config.report_paths", at+".report_paths")
	}
}

// ValidateServer checks the settings of mode A.
func (c *Config) ValidateServer() error {
	var p problems
	s := &c.Server
	host, port, err := net.SplitHostPort(s.Listen)
	if err != nil || port == "" {
		p.add("config.listen", "server.listen")
	}
	switch s.TLS.Mode {
	case TLSModeFile:
		if s.TLS.CertFile == "" || s.TLS.KeyFile == "" {
			p.add("config.tls_files")
		}
	case TLSModeProxy:
		if ip, perr := netip.ParseAddr(strings.Trim(host, "[]")); perr != nil || !ip.IsLoopback() {
			p.add("config.proxy_loopback")
		}
	default:
		p.add("config.tls_mode")
	}
	if v := s.TLS.MinVersion; v != "1.2" && v != "1.3" {
		p.add("config.tls_min")
	}
	for i, cidr := range s.AllowedClients {
		if _, err := ParsePrefix(cidr); err != nil {
			p.add("config.cidr", fmt.Sprintf("server.allowed_clients[%d]", i))
		}
	}
	for i, cidr := range s.TrustedProxies {
		if _, err := ParsePrefix(cidr); err != nil {
			p.add("config.cidr", fmt.Sprintf("server.trusted_proxies[%d]", i))
		}
	}
	active := 0
	keyIDs := map[string]bool{}
	for i, k := range s.APIKeys {
		at := fmt.Sprintf("server.api_keys[%d]", i)
		if !keyIDPattern.MatchString(k.ID) || keyIDs[k.ID] {
			p.add("config.key_id", at+".id")
		}
		keyIDs[k.ID] = true
		if !hashPattern.MatchString(k.Hash) {
			p.add("config.key_hash", at+".hash")
		}
		if k.Expires != "" {
			if _, err := time.Parse("2006-01-02", k.Expires); err != nil {
				p.add("config.key_expires", at+".expires")
			}
		}
		if !k.Disabled {
			active++
		}
	}
	if active == 0 {
		p.add("config.no_keys")
	}
	switch s.Credentials {
	case CredentialsLocal:
	case CredentialsRequest:
		if len(s.AllowedTargets) == 0 {
			p.add("config.targets_required")
		}
	default:
		p.add("config.credentials")
	}
	for i, t := range s.AllowedTargets {
		if _, err := ParsePrefix(t); err != nil && !hostPattern.MatchString(t) {
			p.add("config.target", fmt.Sprintf("server.allowed_targets[%d]", i))
		}
	}
	if s.PublicURL != "" {
		if u, err := url.Parse(s.PublicURL); err != nil || u.Scheme != "https" || u.Host == "" {
			p.add("config.public_url")
		}
	}
	if s.BasePath != "" && (!strings.HasPrefix(s.BasePath, "/") || strings.ContainsAny(s.BasePath, "?#% ") || hasControl(s.BasePath)) {
		p.add("config.base_path")
	}
	if s.Sampling != nil {
		validateSampling(&p, "server.sampling", s.Sampling)
	}
	return p.err()
}

// ValidateAgent checks the settings of mode B. The agent id normally comes from the
// state directory (written by enroll); agent.agent_id only overrides it.
func (c *Config) ValidateAgent() error {
	var p problems
	a := &c.Agent
	if u, err := url.Parse(a.PlatformURL); err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" {
		p.add("config.platform_url")
	}
	if a.AgentID != "" && !agentIDPattern.MatchString(a.AgentID) {
		p.add("config.agent_id")
	}
	checkRef(&p, "agent.token", a.Token)
	checkRef(&p, "agent.proxy_auth", a.ProxyAuth)
	// A poll asks for at most 10 jobs (max_jobs 0..10 in the protocol).
	if a.MaxParallelJobs < 1 || a.MaxParallelJobs > 10 {
		p.add("config.parallel_jobs")
	}
	if a.ProxyURL != "" {
		if u, err := url.Parse(a.ProxyURL); err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil {
			p.add("config.proxy_url")
		}
	}
	for _, j := range a.AllowedJobs {
		if j != JobTestSource && j != JobScanDatabase && j != JobScanFiles && j != JobScanPackages {
			p.add("config.job", j)
		}
	}
	// The platform keeps the previous token 600 seconds after a rotation; with polls at most
	// 5 minutes apart a lost rotation answer is retried in time. (It also allows 20 polls a
	// minute; the agent follows next_poll_seconds, 5 or 15, unless poll_max is lower.)
	if a.PollMin.D() < time.Second || a.PollMax < a.PollMin || a.PollMax.D() > 5*time.Minute {
		p.add("config.poll")
	}
	return p.err()
}

// ParsePrefix reads a CIDR range or a single IP address.
func ParsePrefix(s string) (netip.Prefix, error) {
	s = strings.TrimSpace(s)
	if pfx, err := netip.ParsePrefix(s); err == nil {
		return pfx.Masked(), nil
	}
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, errors.New("not a CIDR range or IP address")
	}
	addr = addr.Unmap()
	return netip.PrefixFrom(addr, addr.BitLen()), nil
}
