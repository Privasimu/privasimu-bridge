// Package agent is mode B: an outbound-only agent. It never listens on a port; it polls
// the platform for jobs over HTTPS and posts results. The platform can only name a source
// or a file root defined in the local configuration, by id; it can never send a host, a
// path, a credential or a query. Results carry names, types, categories, counts and
// confidence only.
//
// This file is the wire contract ("agent protocol 1"). docs/DESIGN.md describes the same
// contract for the platform side; keep both in step.
package agent

import "time"

// ProtocolVersion is sent in the X-Bridge-Protocol header of every request.
const ProtocolVersion = 1

// APIPrefix is the path of the agent API below the platform URL.
const APIPrefix = "/api/bridge-agent/v1"

// Paths of the agent API (relative to APIPrefix).
const (
	PathEnroll      = "/enroll"
	PathPoll        = "/poll"
	PathSources     = "/sources"
	PathTokenRotate = "/token/rotate"
	// Job paths are /jobs/{job_id}/progress, /parts, /complete and /fail.
	pathJobs = "/jobs/"
)

// Job types.
const (
	JobTestSource   = "test_source"
	JobScanDatabase = "scan_database"
	JobScanFiles    = "scan_files"
)

// Error codes the platform returns in {"error": {"code": ...}}.
const (
	ErrInvalidRequest      = "invalid_request"
	ErrUnauthenticated     = "unauthenticated"
	ErrAgentRevoked        = "agent_revoked"
	ErrEnrollmentInvalid   = "enrollment_invalid"
	ErrJobNotFound         = "job_not_found"
	ErrLeaseExpired        = "lease_expired"
	ErrPartConflict        = "part_conflict"
	ErrPartsIncomplete     = "parts_incomplete"
	ErrPayloadTooLarge     = "payload_too_large"
	ErrProtocolUnsupported = "protocol_unsupported"
	ErrRateLimited         = "rate_limited"
	ErrMaintenance         = "maintenance"
	ErrServer              = "server_error"
)

// Failure codes the agent reports in a fail request (error_code).
const (
	FailUnsupportedJob   = "unsupported_job"
	FailJobNotAllowed    = "job_not_allowed"
	FailSourceNotFound   = "source_not_found"
	FailSourceInvalid    = "source_invalid"
	FailSecretMissing    = "secret_missing"
	FailDatabase         = "database_error"
	FailFileRoot         = "file_root_error"
	FailTimeout          = "timeout"
	FailCanceled         = "canceled"
	FailResultTooLarge   = "result_too_large"
	FailInternal         = "internal_error"
	FailScanAlreadyRuns  = "scan_running"
	FailInvalidOptions   = "invalid_options"
	FailDatabasePrefix   = "database_" // + dbsource kind: database_auth, database_unreachable, ...
	FailFilesRootMissing = "file_root_missing"
)

// ErrorBody is the error envelope of the platform.
type ErrorBody struct {
	Error struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

// AgentInfo describes the agent at enrollment and on every poll.
type AgentInfo struct {
	Version      string   `json:"version"`
	Protocol     int      `json:"protocol"`
	OS           string   `json:"os"`
	Arch         string   `json:"arch"`
	Capabilities []string `json:"capabilities"`
}

// EnrollRequest exchanges a one-time enrollment token for the agent's credentials.
type EnrollRequest struct {
	EnrollmentToken string    `json:"enrollment_token"`
	Agent           AgentInfo `json:"agent"`
}

// EnrollResponse is returned once; the agent token is never shown again.
type EnrollResponse struct {
	AgentID             string `json:"agent_id"`
	AgentToken          string `json:"agent_token"`
	Organization        Org    `json:"organization"`
	PollIntervalSeconds int    `json:"poll_interval_seconds"`
}

// Org names the tenant the agent belongs to.
type Org struct {
	Name string `json:"name"`
}

// PollRequest is the heartbeat and the request for work.
type PollRequest struct {
	AgentInfo
	SourcesDigest string   `json:"sources_digest"`
	RunningJobs   []string `json:"running_jobs"`
	MaxJobs       int      `json:"max_jobs"`
}

// PollResponse carries jobs (possibly none) and when to poll next.
type PollResponse struct {
	Jobs                   []Job     `json:"jobs"`
	NextPollSeconds        int       `json:"next_poll_seconds"`
	InventoryRequested     bool      `json:"inventory_requested"`
	TokenRotationRequested bool      `json:"token_rotation_requested"`
	ServerTime             time.Time `json:"server_time"`
}

// Job is one unit of work. Options only narrow what the local configuration allows.
type Job struct {
	JobID        string     `json:"job_id"`
	Type         string     `json:"type"`
	SourceID     string     `json:"source_id"`
	LeaseToken   string     `json:"lease_token"`
	LeaseSeconds int        `json:"lease_seconds"`
	Attempt      int        `json:"attempt"`
	CreatedAt    time.Time  `json:"created_at"`
	Options      JobOptions `json:"options"`
}

// JobOptions tune a job. Every field is optional.
type JobOptions struct {
	// Schema narrows a database scan to one schema (must be allowed locally).
	Schema string `json:"schema,omitempty"`
	// MaxTables and MaxColumns lower the local limits (500 and 1000 by default).
	MaxTables  int `json:"max_tables,omitempty"`
	MaxColumns int `json:"max_columns,omitempty"`
	// Sampling false turns local sampling off for this job; true or absent leaves the
	// local setting, which the platform cannot override.
	Sampling *bool `json:"sampling,omitempty"`
	// DeadlineSeconds lowers the job deadline.
	DeadlineSeconds int `json:"deadline_seconds,omitempty"`
	// Refresh asks a file scan to run now; otherwise a stored report younger than
	// MaxAgeSeconds is sent.
	Refresh       bool `json:"refresh,omitempty"`
	MaxAgeSeconds int  `json:"max_age_seconds,omitempty"`
}

// Source is one entry of the inventory the agent reports. It names what the agent may
// scan; it never carries a host, a path or a credential.
type Source struct {
	ID           string   `json:"id"`
	Kind         string   `json:"kind"` // database | files
	Engine       string   `json:"engine"`
	Label        string   `json:"label"`
	Description  string   `json:"description,omitempty"`
	Capabilities []string `json:"capabilities"`
}

// SourcesRequest replaces the agent's inventory on the platform.
type SourcesRequest struct {
	SourcesDigest string   `json:"sources_digest"`
	Sources       []Source `json:"sources"`
}

// SourcesResponse acknowledges the inventory.
type SourcesResponse struct {
	Accepted int `json:"accepted"`
}

// ProgressRequest renews the lease of a running job.
type ProgressRequest struct {
	Progress int    `json:"progress"`
	Stage    string `json:"stage"`
	Done     int    `json:"done"`
	Total    int    `json:"total"`
}

// ProgressResponse may ask the agent to stop.
type ProgressResponse struct {
	LeaseSeconds    int  `json:"lease_seconds"`
	CancelRequested bool `json:"cancel_requested"`
}

// Part kinds.
const (
	PartTables = "tables"
	PartFiles  = "files"
)

// PartRequest uploads one slice of a result. Parts are numbered from 0; sending the
// same part again is accepted as long as its content is the same.
type PartRequest struct {
	Seq   int    `json:"seq"`
	Kind  string `json:"kind"`
	Items []any  `json:"items"`
}

// PartResponse acknowledges a part.
type PartResponse struct {
	Seq      int  `json:"seq"`
	Received bool `json:"received"`
}

// CompleteRequest finishes a job; Parts is the number of parts uploaded.
type CompleteRequest struct {
	Parts  int `json:"parts"`
	Result any `json:"result"`
}

// FailRequest finishes a job with an error code; there is never a free-text message,
// because driver messages can quote values or internal names.
type FailRequest struct {
	ErrorKind string `json:"error_kind"`
	ErrorCode string `json:"error_code"`
	Retryable bool   `json:"retryable"`
	Stage     string `json:"stage"`
}

// StatusResponse acknowledges complete and fail.
type StatusResponse struct {
	Status string `json:"status"`
}

// RotateResponse carries the new agent token; the old one stays valid for
// PreviousValidSeconds so a lost response cannot lock the agent out.
type RotateResponse struct {
	AgentToken           string `json:"agent_token"`
	PreviousValidSeconds int    `json:"previous_valid_seconds"`
}

// TestResult is the result of test_source; it has the shape of the platform's connection
// test response.
type TestResult struct {
	Success       bool    `json:"success"`
	LatencyMS     int64   `json:"latency_ms"`
	ServerVersion *string `json:"server_version"`
	TablesFound   *int    `json:"tables_found"`
	SSLEnabled    *bool   `json:"ssl_enabled"`
}

// DatabaseResult is the result of scan_database; the tables are in the parts.
type DatabaseResult struct {
	Engine        string         `json:"engine"`
	ServerVersion string         `json:"server_version,omitempty"`
	SSLEnabled    *bool          `json:"ssl_enabled"`
	TablesTotal   int            `json:"tables_total"`
	TablesFailed  []TableFailure `json:"tables_failed"`
	Truncated     bool           `json:"truncated"`
	Sampling      bool           `json:"sampling"`
	DurationMS    int64          `json:"duration_ms"`
	BridgeVersion string         `json:"bridge_version"`
}

// TableFailure is a table that could not be analyzed.
type TableFailure struct {
	Name      string `json:"name"`
	ErrorKind string `json:"error_kind"`
}

// TableItem is one table in a "tables" part.
type TableItem struct {
	Name           string       `json:"name"`
	Schema         string       `json:"schema,omitempty"`
	RowEstimate    *int64       `json:"row_estimate"`
	OmittedColumns int          `json:"omitted_columns"`
	Sampled        bool         `json:"sampled"`
	SamplingError  string       `json:"sampling_error,omitempty"`
	Columns        []ColumnItem `json:"columns"`
}

// ColumnItem is one column of a table item: metadata and the finding, never a value.
type ColumnItem struct {
	Name            string        `json:"name"`
	DataType        string        `json:"data_type"`
	Nullable        *bool         `json:"nullable"`
	PII             bool          `json:"pii"`
	Category        string        `json:"category,omitempty"`
	PDPCategory     string        `json:"pdp_category,omitempty"`
	Confidence      float64       `json:"confidence"`
	Detection       string        `json:"detection"`
	Shadow          bool          `json:"shadow"`
	ProtectionState string        `json:"protection_state,omitempty"`
	Content         *ContentCount `json:"content,omitempty"`
}

// ContentCount summarizes sampling of a column.
type ContentCount struct {
	Sampled  int            `json:"sampled"`
	Matching int            `json:"matching"`
	Matches  map[string]int `json:"matches,omitempty"`
}
