package cli

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/privasimu/bridge/internal/agent"
	"github.com/privasimu/bridge/internal/config"
	"github.com/privasimu/bridge/internal/dbsource"
	"github.com/privasimu/bridge/internal/files"
	"github.com/privasimu/bridge/internal/i18n"
	"github.com/privasimu/bridge/internal/packages"
	"github.com/privasimu/bridge/internal/secrets"
)

// checker prints one line per check and remembers failures.
type checker struct {
	a        *app
	failures int
	warnings int
}

func (c *checker) ok(key string, args ...any) {
	fmt.Fprintln(c.a.stdout, "[OK]   "+i18n.T(key, args...))
}

func (c *checker) warn(key string, args ...any) {
	c.warnings++
	fmt.Fprintln(c.a.stdout, "[WARN] "+i18n.T(key, args...))
}

func (c *checker) fail(key string, args ...any) {
	c.failures++
	fmt.Fprintln(c.a.stdout, "[FAIL] "+i18n.T(key, args...))
}

// cmdCheck validates the configuration and tests every source, file root, the TLS
// certificate (mode A) and the enrollment (mode B). Database messages may name a host or
// a user; they are shown on this server only.
func (a *app) cmdCheck(args []string) error {
	fs := newFlags("check")
	only := fs.String("source", "", "")
	if err := parseFlags(a, fs, args, "cli.check.usage"); err != nil {
		return err
	}
	c := &checker{a: a}
	cfg, err := a.load()
	if err != nil {
		c.fail("cli.check.config", err.Error())
		return errors.New(i18n.T("cli.check.failed", c.failures))
	}
	c.ok("cli.check.config_ok", cfg.Path())
	resolver := a.resolver(cfg)
	c.checkSecrets(cfg, resolver)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	for i := range cfg.Sources {
		src := &cfg.Sources[i]
		if *only != "" && src.ID != *only {
			continue
		}
		c.checkSource(ctx, cfg, src, resolver)
	}
	if *only == "" {
		c.checkRoots(cfg)
		c.checkPackages(cfg)
		if len(cfg.Server.APIKeys) > 0 {
			c.checkServer(cfg)
		}
		if cfg.Agent.PlatformURL != "" {
			c.checkAgent(ctx, cfg)
		}
	}
	if c.failures > 0 {
		return errors.New(i18n.T("cli.check.failed", c.failures))
	}
	a.printf("cli.check.done", c.warnings)
	return nil
}

func (c *checker) checkSecrets(cfg *config.Config, r *secrets.Resolver) {
	if _, err := secrets.LoadKey(cfg.Resolve(cfg.Secrets.KeyFile)); err != nil {
		c.warn("cli.check.no_store_key", err.Error())
		return
	}
	store, err := r.Store()
	if err != nil {
		c.fail("cli.check.store", err.Error())
		return
	}
	c.ok("cli.check.store_ok", len(store.Names()))
}

func (c *checker) checkSource(ctx context.Context, cfg *config.Config, src *config.SourceConfig, r *secrets.Resolver) {
	t, err := dbsource.FromSource(src, r.Resolve)
	if err != nil {
		c.fail("cli.check.source_secret", src.ID, errMessage(err))
		return
	}
	sctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	conn, err := dbsource.Open(sctx, t)
	if err != nil {
		c.fail("cli.check.source_failed", src.ID, dbsource.KindOf(err), errMessage(err))
		return
	}
	defer conn.Close()
	tables, err := conn.ListTables(sctx, "")
	if err != nil {
		c.fail("cli.check.source_failed", src.ID, dbsource.KindOf(err), errMessage(err))
		return
	}
	tlsState := i18n.T("cli.check.tls_unknown")
	if on := conn.TLSInUse(); on != nil {
		tlsState = map[bool]string{true: i18n.T("cli.check.tls_on"), false: i18n.T("cli.check.tls_off")}[*on]
	}
	sampling := i18n.T("cli.check.sampling_off")
	if cfg.SamplingFor(src).On() {
		sampling = i18n.T("cli.check.sampling_on", cfg.SamplingFor(src).Rows)
	}
	c.ok("cli.check.source_ok", src.ID, conn.ServerVersion(sctx), len(tables), tlsState, sampling)
	if src.TLS.Mode == config.DBTLSPrefer || src.TLS.Mode == config.DBTLSRequire {
		c.warn("cli.check.tls_unverified", src.ID)
	}
}

func errMessage(err error) string {
	var e *dbsource.Error
	if errors.As(err, &e) {
		return e.Message()
	}
	return err.Error()
}

func (c *checker) checkRoots(cfg *config.Config) {
	if len(cfg.Files.Roots) == 0 {
		return
	}
	svc, err := files.NewService(cfg, nil, nil)
	if err != nil {
		c.fail("cli.check.files_failed", err.Error())
		return
	}
	for _, rc := range cfg.Files.Roots {
		if err, bad := svc.Invalid[rc.ID]; bad {
			c.fail("cli.check.root_failed", rc.ID, err.Error())
			continue
		}
		root, _ := svc.Root(rc.ID)
		entries, err := os.ReadDir(root.Path)
		if err != nil {
			c.fail("cli.check.root_failed", rc.ID, err.Error())
			continue
		}
		c.ok("cli.check.root_ok", rc.ID, root.Path, len(entries), rc.ReportPaths)
	}
}

// checkPackages verifies the package scanners (present, regular files, pinned checksum),
// the matcher database and every packages target.
func (c *checker) checkPackages(cfg *config.Config) {
	if len(cfg.Packages.Targets) == 0 {
		return
	}
	if !cfg.Agent.JobAllowed(config.JobScanPackages) {
		c.warn("cli.check.pkg_job_off")
	}
	tools := packages.Tools(cfg)
	for _, name := range []string{"syft", "grype", "trivy"} {
		t, ok := tools[name]
		if !ok {
			continue
		}
		if err := packages.VerifyTool(t); err != nil {
			c.fail("cli.check.tool_"+packages.ToolProblem(err), name, t.Path)
			continue
		}
		c.ok("cli.check.tool_ok", name, t.Path)
		if packages.WritableByOthers(t.Path) {
			c.warn("cli.check.tool_writable", name, t.Path)
		}
	}
	if cfg.Packages.Tools.Matcher == config.MatcherNone {
		c.warn("cli.check.matcher_none")
	} else if !packages.MatcherDatabaseReady(cfg) {
		c.warn("cli.check.matcher_db_missing", cfg.Packages.Tools.Matcher)
	}
	for i := range cfg.Packages.Targets {
		t := &cfg.Packages.Targets[i]
		if err := packages.CheckTarget(t); err != nil {
			c.fail("cli.check.target_failed", t.ID, t.Path, err.Error())
			continue
		}
		c.ok("cli.check.target_ok", t.ID, t.Kind, t.Path)
	}
}

func (c *checker) checkServer(cfg *config.Config) {
	if err := cfg.ValidateServer(); err != nil {
		c.fail("cli.check.server_config", err.Error())
		return
	}
	if len(cfg.Server.AllowedClients) == 0 {
		c.warn("cli.check.no_allowed_clients")
	}
	if cfg.Server.TLS.Mode != config.TLSModeFile {
		c.ok("cli.check.tls_proxy", cfg.Server.Listen)
		return
	}
	pair, err := tls.LoadX509KeyPair(cfg.Resolve(cfg.Server.TLS.CertFile), cfg.Resolve(cfg.Server.TLS.KeyFile))
	if err != nil {
		c.fail("cli.check.cert_failed", err.Error())
		return
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		c.fail("cli.check.cert_failed", err.Error())
		return
	}
	days := int(time.Until(leaf.NotAfter).Hours() / 24)
	switch {
	case days < 0:
		c.fail("cli.check.cert_expired", leaf.NotAfter.Format("2006-01-02"))
	case days < 21:
		c.warn("cli.check.cert_expiring", days)
	default:
		c.ok("cli.check.cert_ok", strings.Join(leaf.DNSNames, ", "), leaf.NotAfter.Format("2006-01-02"))
	}
	if leaf.Issuer.String() == leaf.Subject.String() {
		c.warn("cli.check.cert_self_signed")
	}
	if cfg.Server.PublicURL != "" {
		u, _ := url.Parse(cfg.Server.PublicURL)
		if err := leaf.VerifyHostname(u.Hostname()); err != nil {
			c.fail("cli.check.cert_name", u.Hostname())
		}
	}
}

func (c *checker) checkAgent(ctx context.Context, cfg *config.Config) {
	if err := cfg.ValidateAgent(); err != nil {
		c.fail("cli.check.agent_config", err.Error())
		return
	}
	st, err := agent.LoadState(cfg.Resolve(cfg.StateDir))
	if err != nil {
		c.warn("cli.check.not_enrolled")
	} else {
		c.ok("cli.check.enrolled", st.AgentID)
	}
	u, _ := url.Parse(cfg.Agent.PlatformURL)
	host := u.Host
	if u.Port() == "" {
		host = net.JoinHostPort(u.Hostname(), "443")
	}
	if cfg.Agent.ProxyURL != "" {
		c.ok("cli.check.platform_proxy", cfg.Agent.ProxyURL)
		return
	}
	pool, _ := x509.SystemCertPool()
	if pool == nil {
		pool = x509.NewCertPool()
	}
	if cfg.Agent.CAFile != "" {
		if pem, err := os.ReadFile(cfg.Resolve(cfg.Agent.CAFile)); err == nil {
			pool.AppendCertsFromPEM(pem)
		}
	}
	d := &tls.Dialer{NetDialer: &net.Dialer{Timeout: 10 * time.Second}, Config: &tls.Config{RootCAs: pool, ServerName: u.Hostname(), MinVersion: tls.VersionTLS12}}
	dctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	conn, err := d.DialContext(dctx, "tcp", host)
	if err != nil {
		c.fail("cli.check.platform_failed", host, err.Error())
		return
	}
	conn.Close()
	c.ok("cli.check.platform_ok", host)
}
