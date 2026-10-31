package server

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"regexp"
	"strings"

	"github.com/privasimu/bridge/internal/audit"
	"github.com/privasimu/bridge/internal/config"
	"github.com/privasimu/bridge/internal/dbsource"
	"github.com/privasimu/bridge/internal/detect"
	"github.com/privasimu/bridge/internal/scan"
	"github.com/privasimu/bridge/internal/secrets"
)

// Paths of contract v1. They match the platform's BridgeClient exactly, including the
// spelling "tabels". Endpoints that return rows or raw values (scan-table, scan-database,
// scan-file) do not exist in this bridge.
const (
	PathTableNames   = "/v1/name-database-tabels"
	PathTableColumns = "/v2/scan-table-columns"
	PathHealth       = "/healthz"
)

// v1Request is the body the platform sends: db_type plus the fields of the source type's
// mapping (BridgeSourceTypes), and table_name for the column call. Unknown fields are
// ignored so that a newer platform can add fields.
type v1Request struct {
	DBType                 string `json:"db_type"`
	Host                   string `json:"host"`
	Port                   *int   `json:"port"`
	Database               string `json:"database"`
	User                   string `json:"user"`
	Password               string `json:"password"`
	SchemaName             string `json:"schema_name"`
	UseSSL                 *bool  `json:"use_ssl"`
	InstanceName           string `json:"instance_name"`
	ODBCDriver             string `json:"odbc_driver"`
	TrustServerCertificate *bool  `json:"trust_server_certificate"`
	ServiceName            string `json:"service_name"`
	SID                    string `json:"sid"`
	Warehouse              string `json:"warehouse"`
	Role                   string `json:"role"`
	TableName              string `json:"table_name"`
}

// Same patterns as the platform's registry, applied again here.
var (
	hostPattern       = regexp.MustCompile(`^[A-Za-z0-9._:\-\[\]]{1,255}$`)
	identifierPattern = regexp.MustCompile(`^[A-Za-z0-9_.$@\-]{1,128}$`)
)

// engineOf maps a platform db_type to a bridge engine.
func engineOf(dbType string) (string, bool) {
	switch dbType {
	case "postgresql", "mysql", "mssql", "oracle", "mongodb":
		return dbType, true
	case "mariadb":
		return "mysql", true
	}
	return "", false
}

func noControl(s string) bool {
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

// decodeV1 reads one JSON object from the body.
func decodeV1(body io.Reader) (*v1Request, *apiError) {
	dec := json.NewDecoder(body)
	var req v1Request
	if err := dec.Decode(&req); err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			return nil, fail(CodeTooLarge)
		}
		return nil, fail(CodeInvalidRequest)
	}
	if dec.More() {
		return nil, fail(CodeInvalidRequest)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, fail(CodeInvalidRequest)
	}
	return &req, nil
}

// validate checks the request like the platform does before sending it.
func (r *v1Request) validate(needTable bool) *apiError {
	if _, ok := engineOf(r.DBType); !ok {
		if r.DBType == "" {
			return fail(CodeInvalidRequest)
		}
		return fail(CodeUnsupportedDBType)
	}
	if !hostPattern.MatchString(r.Host) {
		return fail(CodeInvalidRequest)
	}
	if r.Port != nil && (*r.Port < 1 || *r.Port > 65535) {
		return fail(CodeInvalidRequest)
	}
	for _, v := range []string{r.Database, r.SchemaName, r.InstanceName, r.ServiceName, r.SID} {
		if v != "" && !identifierPattern.MatchString(v) {
			return fail(CodeInvalidRequest)
		}
	}
	if len(r.User) > 128 || len(r.Password) > 256 || !noControl(r.User) || !noControl(r.Password) {
		return fail(CodeInvalidRequest)
	}
	if needTable && (r.TableName == "" || len(r.TableName) > 255 || !noControl(r.TableName)) {
		return fail(CodeInvalidRequest)
	}
	return nil
}

// resolved is the database a request is served from.
type resolved struct {
	target   dbsource.Target
	source   *config.SourceConfig // nil in request-credential mode
	sampling config.SamplingOptions
}

// resolve finds the database for a request. With local credentials only a configured
// source can be scanned and the request's credentials are ignored; with request
// credentials the request's settings are used for allow-listed addresses only.
func (s *Server) resolve(req *v1Request, ev *audit.Event) (*resolved, *apiError) {
	engine, _ := engineOf(req.DBType)
	ev.Engine = engine
	ev.Credentials = s.cfg.Server.Credentials
	if s.cfg.Server.Credentials == config.CredentialsLocal {
		src := s.matchSource(engine, req)
		if src == nil {
			return nil, fail(CodeSourceNotAllowed)
		}
		ev.SourceID = src.ID
		if req.SchemaName != "" && len(src.Schemas) > 0 && !containsFold(src.Schemas, req.SchemaName) {
			return nil, fail(CodeSchemaNotAllowed)
		}
		t, err := dbsource.FromSource(src, s.resolveSecret)
		if err != nil {
			s.log.Error("source secret could not be resolved", "source", src.ID, "error", dbErrMessage(err))
			return nil, fail(CodeSourceNotAllowed)
		}
		t.MaxOpen = s.cfg.Server.Limits.PerSourceConcurrency
		return &resolved{target: t, source: src, sampling: s.cfg.SamplingFor(src)}, nil
	}
	port := config.DefaultPort(engine)
	if req.Port != nil {
		port = *req.Port
	}
	t := dbsource.Target{
		Engine: engine, Host: req.Host, Port: port, Database: req.Database, Username: req.User,
		Password: secrets.Value(req.Password), ServiceName: req.ServiceName, SID: req.SID, Instance: req.InstanceName,
		Timeout: s.cfg.Server.Limits.RequestTimeout.D(), Dial: s.guard.Dial, MaxOpen: s.cfg.Server.Limits.PerSourceConcurrency,
	}
	t.TLS = dbsource.TLSSettings{ExtraRootsPEM: s.targetsCA}
	switch {
	case req.UseSSL != nil && *req.UseSSL:
		t.TLS.Mode = config.DBTLSVerifyFull
	case engine == "postgresql" || engine == "mysql" || engine == "mssql":
		t.TLS.Mode = config.DBTLSPrefer
	default:
		t.TLS.Mode = config.DBTLSDisable
	}
	if req.TrustServerCertificate != nil && *req.TrustServerCertificate && engine == "mssql" {
		t.TLS.TrustServerCertificate = true
		if t.TLS.Mode == config.DBTLSVerifyFull {
			t.TLS.Mode = config.DBTLSRequire
		}
	}
	sampling := s.cfg.Detection.Sampling
	if s.cfg.Server.Sampling != nil {
		sampling = s.cfg.SamplingFor(&config.SourceConfig{Sampling: s.cfg.Server.Sampling})
	}
	return &resolved{target: t, sampling: sampling}, nil
}

func (s *Server) resolveSecret(ref config.SecretRef) (secrets.Value, error) {
	return s.resolver.Resolve(ref)
}

// matchSource finds the configured source the platform means: same engine, host and
// database as typed in Privasimu (or the source's match aliases).
func (s *Server) matchSource(engine string, req *v1Request) *config.SourceConfig {
	for i := range s.cfg.Sources {
		src := &s.cfg.Sources[i]
		if src.Engine != engine {
			continue
		}
		host := src.Host
		if src.Match.Host != "" {
			host = src.Match.Host
		}
		db := src.Match.Database
		for _, candidate := range []string{src.Database, src.ServiceName, src.SID} {
			if db == "" {
				db = candidate
			}
		}
		if strings.EqualFold(host, req.Host) && db != "" && strings.EqualFold(db, req.Database) {
			return src
		}
	}
	return nil
}

func containsFold(list []string, v string) bool {
	for _, x := range list {
		if strings.EqualFold(x, v) {
			return true
		}
	}
	return false
}

func dbErrMessage(err error) string {
	var e *dbsource.Error
	if errors.As(err, &e) {
		return e.Message()
	}
	return "error"
}

// open returns a pooled connection and a slot of the source's concurrency limit.
func (s *Server) open(ctx context.Context, r *resolved) (dbsource.Conn, func(), *apiError) {
	conn, release, err := s.pool.Get(ctx, r.target)
	if err != nil {
		if ctx.Err() != nil {
			return nil, nil, fail(CodeDBTimeout)
		}
		s.log.Warn("database connection failed", "engine", r.target.Engine, "source", sourceID(r), "error", dbErrMessage(err))
		return nil, nil, fail(codeForDB(dbsource.KindOf(err)))
	}
	slot := s.slot(dbsource.Key(r.target))
	select {
	case slot <- struct{}{}:
	case <-ctx.Done():
		release()
		return nil, nil, fail(CodeBusy)
	}
	return conn, func() { <-slot; release() }, nil
}

func sourceID(r *resolved) string {
	if r.source != nil {
		return r.source.ID
	}
	return "(request)"
}

// namesResponse is the response of PathTableNames.
type namesResponse struct {
	Status        string   `json:"status"`
	Database      string   `json:"database"`
	TablesScanned int      `json:"tables_scanned"`
	Results       []string `json:"results"`
}

func (s *Server) tableNames(ctx context.Context, req *v1Request, ev *audit.Event) (any, *apiError) {
	r, aerr := s.resolve(req, ev)
	if aerr != nil {
		return nil, aerr
	}
	conn, done, aerr := s.open(ctx, r)
	if aerr != nil {
		return nil, aerr
	}
	defer done()
	tables, total, err := scan.ListTables(ctx, conn, scan.DBOptions{Schema: req.SchemaName, MaxTables: s.cfg.Server.Limits.MaxTables})
	if err != nil {
		s.log.Warn("table list failed", "source", sourceID(r), "error", dbErrMessage(err))
		return nil, s.dbFailure(ctx, err)
	}
	refs := make([]string, 0, len(tables))
	for _, t := range tables {
		refs = append(refs, t.Ref)
	}
	ev.Tables = total
	return namesResponse{Status: "success", Database: req.Database, TablesScanned: total, Results: refs}, nil
}

func (s *Server) dbFailure(ctx context.Context, err error) *apiError {
	if ctx.Err() != nil || errors.Is(err, context.DeadlineExceeded) {
		return fail(CodeDBTimeout)
	}
	return fail(codeForDB(dbsource.KindOf(err)))
}

// columnDetail is one column of PathTableColumns. The platform reads column_name, is_pii
// and pdp_category; the other keys are metadata (labels and counts, never values).
type columnDetail struct {
	ColumnName  string        `json:"column_name"`
	DataType    string        `json:"data_type"`
	IsPII       bool          `json:"is_pii"`
	IsPDP       bool          `json:"is_pdp"`
	PDPCategory *string       `json:"pdp_category"`
	Type        *string       `json:"type"`
	PIICategory *string       `json:"pii_category"`
	Confidence  float64       `json:"confidence"`
	Detection   string        `json:"detection"`
	Content     *contentStats `json:"content,omitempty"`
}

// contentStats summarizes local sampling of a column: counts only.
type contentStats struct {
	Sampled         int    `json:"sampled"`
	Matching        int    `json:"matching"`
	ProtectionState string `json:"protection_state"`
}

type analysisSummary struct {
	TotalColumns   int    `json:"total_columns"`
	PIIColumns     int    `json:"pii_columns"`
	PDPColumns     int    `json:"pdp_columns"`
	OmittedColumns int    `json:"omitted_columns"`
	Sampled        bool   `json:"sampled"`
	SamplingError  string `json:"sampling_error,omitempty"`
}

type columnsResponse struct {
	Status          string          `json:"status"`
	Table           string          `json:"table"`
	AnalysisSummary analysisSummary `json:"analysis_summary"`
	ColumnDetails   []columnDetail  `json:"column_details"`
}

func (s *Server) tableColumns(ctx context.Context, req *v1Request, ev *audit.Event) (any, *apiError) {
	r, aerr := s.resolve(req, ev)
	if aerr != nil {
		return nil, aerr
	}
	conn, done, aerr := s.open(ctx, r)
	if aerr != nil {
		return nil, aerr
	}
	defer done()
	table, found, err := conn.FindTable(ctx, req.TableName, req.SchemaName)
	if err != nil {
		s.log.Warn("table lookup failed", "source", sourceID(r), "error", dbErrMessage(err))
		return nil, s.dbFailure(ctx, err)
	}
	if !found {
		return nil, fail(CodeTableNotFound)
	}
	opts := scan.DBOptions{
		Sampling: r.sampling.On(), Rows: r.sampling.Rows, MaxColumns: s.cfg.Server.Limits.MaxColumns,
		Thresholds: detect.Thresholds{MinMatches: r.sampling.MinMatches, Ratio: r.sampling.Ratio},
	}
	a, err := scan.AnalyzeTable(ctx, conn, table, opts)
	if err != nil {
		s.log.Warn("column analysis failed", "source", sourceID(r), "error", dbErrMessage(err))
		return nil, s.dbFailure(ctx, err)
	}
	resp := columnsResponse{Status: "success", Table: req.TableName, ColumnDetails: make([]columnDetail, 0, len(a.Columns))}
	for _, c := range a.Columns {
		resp.ColumnDetails = append(resp.ColumnDetails, detailOf(c))
	}
	pii, pdp := a.PIIColumns()
	resp.AnalysisSummary = analysisSummary{TotalColumns: len(a.Columns), PIIColumns: pii, PDPColumns: pdp,
		OmittedColumns: a.Omitted, Sampled: a.Sampled, SamplingError: a.SamplingError}
	ev.Tables, ev.Columns, ev.PIIColumns, ev.Sampled = 1, len(a.Columns), pii, a.Sampled
	return resp, nil
}

func strPtr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func detailOf(c scan.ColumnAnalysis) columnDetail {
	f := c.Finding
	d := columnDetail{ColumnName: c.Name, DataType: c.DataType, IsPII: f.IsPII, IsPDP: f.IsPII && f.PDP != "",
		Confidence: f.Confidence, Detection: f.Source}
	if f.IsPII {
		d.PDPCategory = strPtr(f.PDP)
		d.Type = strPtr(string(f.Category))
		if info, ok := detect.Lookup(f.Category); ok {
			d.PIICategory = strPtr(info.Group)
		}
	}
	if f.Content != nil {
		d.Content = &contentStats{Sampled: f.Content.NonEmpty, ProtectionState: f.Content.Protection}
		if f.Content.Category != "" {
			d.Content.Matching = f.Content.Matches[f.Content.Category]
		}
	}
	return d
}
