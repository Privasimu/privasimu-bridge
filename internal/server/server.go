// Package server is mode A: the HTTPS server the platform calls with contract v1. It
// serves only the endpoints that return names and findings; the endpoints of other
// bridges that return rows or raw values do not exist here.
package server

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/privasimu/bridge/internal/apikey"
	"github.com/privasimu/bridge/internal/audit"
	"github.com/privasimu/bridge/internal/buildinfo"
	"github.com/privasimu/bridge/internal/config"
	"github.com/privasimu/bridge/internal/dbsource"
	"github.com/privasimu/bridge/internal/detect"
	"github.com/privasimu/bridge/internal/files"
	"github.com/privasimu/bridge/internal/netguard"
	"github.com/privasimu/bridge/internal/secrets"
)

// Deps are the collaborators of the server.
type Deps struct {
	Config   *config.Config
	Resolver *secrets.Resolver
	Pool     *dbsource.Pool
	Audit    *audit.Logger
	Log      *slog.Logger
	// Files serves the optional file-root endpoints (nil = off).
	Files *files.Service
	// Entities is the optional local NLP service (detection.nlp); nil = patterns only.
	Entities detect.EntityCounter
}

// Server handles contract v1 requests.
type Server struct {
	cfg            *config.Config
	verifier       *apikey.Verifier
	resolver       *secrets.Resolver
	pool           *dbsource.Pool
	guard          *netguard.Guard
	targetsCA      []byte
	audit          *audit.Logger
	log            *slog.Logger
	limits         *limiter
	busy           chan struct{}
	slotsMu        sync.Mutex
	slots          map[string]chan struct{}
	allowedClients []netip.Prefix
	trustedProxies []netip.Prefix
	files          *files.Service
	entities       detect.EntityCounter
}

// New builds a server from a validated configuration.
func New(d Deps) (*Server, error) {
	cfg := d.Config
	if err := cfg.ValidateServer(); err != nil {
		return nil, err
	}
	v, err := apikey.NewVerifier(cfg.Server.APIKeys)
	if err != nil {
		return nil, err
	}
	s := &Server{
		cfg: cfg, verifier: v, resolver: d.Resolver, pool: d.Pool, audit: d.Audit, log: d.Log,
		limits:   newLimiter(cfg.Server.Limits.RatePerSecond, cfg.Server.Limits.Burst, cfg.Server.Limits.AuthFailures, cfg.Server.Limits.Lockout.D()),
		busy:     make(chan struct{}, cfg.Server.Limits.MaxConcurrent),
		slots:    map[string]chan struct{}{},
		files:    d.Files,
		entities: d.Entities,
	}
	if s.log == nil {
		s.log = slog.New(slog.DiscardHandler)
	}
	if s.audit == nil {
		s.audit = audit.Discard()
	}
	if s.pool == nil {
		s.pool = dbsource.NewPool(32, 5*time.Minute)
	}
	for _, c := range cfg.Server.AllowedClients {
		p, _ := config.ParsePrefix(c)
		s.allowedClients = append(s.allowedClients, p)
	}
	for _, c := range cfg.Server.TrustedProxies {
		p, _ := config.ParsePrefix(c)
		s.trustedProxies = append(s.trustedProxies, p)
	}
	if cfg.Server.Credentials == config.CredentialsRequest {
		if s.guard, err = netguard.New(cfg.Server.AllowedTargets); err != nil {
			return nil, err
		}
		if cfg.Server.TargetsCAFile != "" {
			if s.targetsCA, err = os.ReadFile(cfg.Resolve(cfg.Server.TargetsCAFile)); err != nil {
				return nil, err
			}
		}
	}
	return s, nil
}

func (s *Server) slot(key string) chan struct{} {
	s.slotsMu.Lock()
	defer s.slotsMu.Unlock()
	c, ok := s.slots[key]
	if !ok {
		c = make(chan struct{}, s.cfg.Server.Limits.PerSourceConcurrency)
		s.slots[key] = c
	}
	return c
}

func newRequestID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// clientIP returns the caller's address (behind trusted proxies in proxy mode).
func (s *Server) clientIP(r *http.Request) netip.Addr {
	peer := remoteIP(r.RemoteAddr)
	if s.cfg.Server.TLS.Mode == config.TLSModeProxy {
		return forwardedClient(peer, r.Header.Get("X-Forwarded-For"), s.trustedProxies)
	}
	return peer
}

// rawEndpoints are paths other bridges serve that return rows or raw values. They do not
// exist here; a request for one is answered 404 and audited, because it means a client
// expects data this bridge never sends.
var rawEndpoints = []string{"/scan-table", "/scan-database", "/scan-file", "/scan-database-columns", "/scan-rows", "/sample",
	"/scan-remote-document", "/scan-access", "/scan-access-s3", "/scan-access-application"}

func isRawEndpoint(path string) bool {
	for _, e := range rawEndpoints {
		if strings.HasSuffix(path, e) {
			return true
		}
	}
	return false
}

// ServeHTTP authenticates, limits and dispatches a request. Every request is audited.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	started := time.Now()
	ip := s.clientIP(r)
	ev := audit.Event{Event: "request", Mode: "serve", RequestID: newRequestID(), ClientIP: ip.String()}
	status := 0
	defer func() {
		if rec := recover(); rec != nil {
			s.log.Error("request handler panicked", "request_id", ev.RequestID, "panic", fmt.Sprint(rec))
			status = writeError(w, CodeInternal)
			ev.Code = CodeInternal
		}
		ev.Status = status
		ev.DurationMS = time.Since(started).Milliseconds()
		switch {
		case status >= 200 && status < 300:
			ev.Outcome = audit.OK
		case status == http.StatusUnauthorized || status == http.StatusForbidden || status == http.StatusTooManyRequests:
			ev.Outcome = audit.Denied
		default:
			ev.Outcome = audit.Error
		}
		s.audit.Log(ev)
	}()
	w.Header().Set("X-Request-Id", ev.RequestID)
	w.Header().Set("X-Contract-Version", buildinfo.ContractVersion)

	if len(s.allowedClients) > 0 && !addrIn(ip, s.allowedClients) {
		ev.Code = CodeClientNotAllowed
		status = writeError(w, CodeClientNotAllowed)
		return
	}
	if ok, wait, locked := s.limits.allow(ip.String()); !ok {
		ev.Code = CodeRateLimited
		if locked {
			ev.Code = CodeLockedOut
		}
		w.Header().Set("Retry-After", fmt.Sprint(int(wait.Seconds())+1))
		status = writeError(w, ev.Code)
		return
	}
	path := r.URL.Path
	if base := s.cfg.Server.BasePath; base != "" {
		if !strings.HasPrefix(path, base+"/") {
			ev.Endpoint, ev.Code = "other", CodeNotFound
			status = writeError(w, CodeNotFound)
			return
		}
		path = strings.TrimPrefix(path, base)
	}
	switch path {
	case PathHealth:
		ev.Endpoint = PathHealth
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			ev.Code = CodeMethod
			status = writeError(w, CodeMethod)
			return
		}
		status = http.StatusOK
		writeJSON(w, status, map[string]string{"status": "ok"})
		return
	case PathTableNames, PathTableColumns:
		ev.Endpoint = path
		status = s.serveV1(w, r, path, ip, &ev)
		return
	case PathTableAccess:
		if s.cfg.Server.AccessEndpoint {
			ev.Endpoint = path
			status = s.serveV1(w, r, path, ip, &ev)
			return
		}
	case PathFileRoots, PathFileRootReport, PathFileRootScan:
		if s.files != nil && s.cfg.Server.FileEndpoints {
			ev.Endpoint = path
			status = s.serveFiles(w, r, path, ip, &ev)
			return
		}
	}
	ev.Endpoint = "other"
	if isRawEndpoint(path) {
		ev.Event = "raw_endpoint_refused"
	}
	ev.Code = CodeNotFound
	status = writeError(w, CodeNotFound)
}

// authorize checks method, key, contract version and content type.
func (s *Server) authorize(w http.ResponseWriter, r *http.Request, ip netip.Addr, ev *audit.Event) *apiError {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		return fail(CodeMethod)
	}
	keyID, ok := s.verifier.Verify(r.Header.Get("X-API-Key"))
	if !ok {
		s.limits.authFailed(ip.String())
		return fail(CodeUnauthorized)
	}
	s.limits.authOK(ip.String())
	ev.KeyID = keyID
	if v := r.Header.Get("X-Contract-Version"); v != "" && v != buildinfo.ContractVersion {
		return fail(CodeUnsupportedVersion)
	}
	if mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mt != "application/json" {
		return fail(CodeMediaType)
	}
	return nil
}

func (s *Server) acquire() bool {
	select {
	case s.busy <- struct{}{}:
		return true
	default:
		return false
	}
}

func (s *Server) release() { <-s.busy }

func (s *Server) serveV1(w http.ResponseWriter, r *http.Request, path string, ip netip.Addr, ev *audit.Event) int {
	if aerr := s.authorize(w, r, ip, ev); aerr != nil {
		ev.Code = aerr.code
		return writeError(w, aerr.code)
	}
	req, aerr := decodeV1(http.MaxBytesReader(w, r.Body, int64(s.cfg.Server.Limits.MaxBodyBytes)))
	if aerr == nil {
		aerr = req.validate(path == PathTableColumns || path == PathTableAccess)
	}
	if aerr != nil {
		ev.Code = aerr.code
		return writeError(w, aerr.code)
	}
	if !s.acquire() {
		ev.Code = CodeBusy
		w.Header().Set("Retry-After", "2")
		return writeError(w, CodeBusy)
	}
	defer s.release()
	ctx, cancel := context.WithTimeout(r.Context(), s.cfg.Server.Limits.RequestTimeout.D())
	defer cancel()
	var resp any
	switch path {
	case PathTableNames:
		resp, aerr = s.tableNames(ctx, req, ev)
	case PathTableAccess:
		resp, aerr = s.tableAccess(ctx, req, ev)
	default:
		resp, aerr = s.tableColumns(ctx, req, ev)
	}
	if aerr != nil {
		ev.Code = aerr.code
		return writeError(w, aerr.code)
	}
	writeJSON(w, http.StatusOK, resp)
	return http.StatusOK
}

// certReloader serves the certificate files and reloads them when they change, so a
// renewed certificate is picked up without a restart.
type certReloader struct {
	certFile, keyFile string
	mu                sync.Mutex
	cert              *tls.Certificate
	modCert, modKey   time.Time
	checked           time.Time
}

func newCertReloader(certFile, keyFile string) (*certReloader, error) {
	c := &certReloader{certFile: certFile, keyFile: keyFile}
	if err := c.load(); err != nil {
		return nil, err
	}
	return c, nil
}

func (c *certReloader) load() error {
	cert, err := tls.LoadX509KeyPair(c.certFile, c.keyFile)
	if err != nil {
		return err
	}
	ci, _ := os.Stat(c.certFile)
	ki, _ := os.Stat(c.keyFile)
	c.cert = &cert
	if ci != nil {
		c.modCert = ci.ModTime()
	}
	if ki != nil {
		c.modKey = ki.ModTime()
	}
	return nil
}

func (c *certReloader) get(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if time.Since(c.checked) > time.Minute {
		c.checked = time.Now()
		ci, err1 := os.Stat(c.certFile)
		ki, err2 := os.Stat(c.keyFile)
		if err1 == nil && err2 == nil && (ci.ModTime() != c.modCert || ki.ModTime() != c.modKey) {
			if err := c.load(); err != nil {
				// Keep serving the previous certificate; the operator sees the error in check.
				c.modCert, c.modKey = ci.ModTime(), ki.ModTime()
			}
		}
	}
	return c.cert, nil
}

// TLSConfig returns the server TLS configuration for the configured certificate.
func (s *Server) TLSConfig() (*tls.Config, error) {
	reloader, err := newCertReloader(s.cfg.Resolve(s.cfg.Server.TLS.CertFile), s.cfg.Resolve(s.cfg.Server.TLS.KeyFile))
	if err != nil {
		return nil, err
	}
	minVersion := uint16(tls.VersionTLS12)
	if s.cfg.Server.TLS.MinVersion == "1.3" {
		minVersion = tls.VersionTLS13
	}
	return &tls.Config{MinVersion: minVersion, GetCertificate: reloader.get, NextProtos: []string{"http/1.1"}}, nil
}

// Run serves until ctx is cancelled, then shuts down gracefully.
func (s *Server) Run(ctx context.Context) error {
	raw, err := net.Listen("tcp", s.cfg.Server.Listen)
	if err != nil {
		return err
	}
	var ln net.Listener = raw
	if s.cfg.Server.TLS.Mode == config.TLSModeFile {
		tlsCfg, err := s.TLSConfig()
		if err != nil {
			_ = raw.Close()
			return err
		}
		// Refused connections are closed before the TLS handshake. The platform then reports a
		// network error (Go line: bridge_unavailable) or, through curl, a TLS error (Laravel
		// line: tls), so the refusal is logged where the operator will look for it.
		refusals := newRefusalLog(time.Minute)
		filtered := filteredListener{Listener: raw, allowed: s.allowedClients, refused: func(a netip.Addr) {
			if refusals.first(a.String()) {
				s.log.Warn("connection refused: the address is not in server.allowed_clients", "client_ip", a.String())
			}
		}}
		ln = tls.NewListener(filtered, tlsCfg)
	}
	srv := &http.Server{
		Handler:           s,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      s.cfg.Server.Limits.RequestTimeout.D() + 15*time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
		// HTTP/1.1 only: the platform needs nothing more, and it keeps the surface small.
		TLSNextProto: map[string]func(*http.Server, *tls.Conn, http.Handler){},
		ErrorLog:     slog.NewLogLogger(s.log.Handler(), slog.LevelDebug),
	}
	go s.pool.Run(ctx)
	go s.limits.run(ctx)
	if s.files != nil {
		go s.files.RunSchedule(ctx)
	}
	errc := make(chan error, 1)
	go func() { errc <- srv.Serve(ln) }()
	s.log.Info("bridge server listening", "listen", s.cfg.Server.Listen, "tls", s.cfg.Server.TLS.Mode,
		"credentials", s.cfg.Server.Credentials, "sources", len(s.cfg.Sources), "version", buildinfo.Version)
	select {
	case err := <-errc:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdown)
		return nil
	}
}
