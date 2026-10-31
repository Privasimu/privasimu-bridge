package server

import (
	"encoding/json"
	"net/http"

	"github.com/privasimu/bridge/internal/dbsource"
	"github.com/privasimu/bridge/internal/i18n"
)

// Error codes of mode A responses. The platform (contract v1) only looks at the HTTP
// status: 401/403 become "auth", 5xx become "bridge_unavailable" (retried), any other
// non-2xx becomes "bridge_rejected" (not retried). The code and message are for the
// operator and the local audit log.
const (
	CodeInvalidRequest     = "invalid_request"
	CodeUnsupportedDBType  = "unsupported_db_type"
	CodeUnsupportedVersion = "unsupported_contract_version"
	CodeUnauthorized       = "unauthorized"
	CodeClientNotAllowed   = "client_not_allowed"
	CodeLockedOut          = "locked_out"
	CodeRateLimited        = "rate_limited"
	CodeTooLarge           = "payload_too_large"
	CodeMediaType          = "unsupported_media_type"
	CodeMethod             = "method_not_allowed"
	CodeNotFound           = "not_found"
	CodeSourceNotAllowed   = "source_not_allowed"
	CodeSchemaNotAllowed   = "schema_not_allowed"
	CodeTableNotFound      = "table_not_found"
	CodeDBAuth             = "database_auth_failed"
	CodeDBPermission       = "database_permission_denied"
	CodeDBNotFound         = "database_not_found"
	CodeDBTLS              = "database_tls_failed"
	CodeDBUnreachable      = "database_unreachable"
	CodeDBTimeout          = "database_timeout"
	CodeDBError            = "database_error"
	CodeBusy               = "busy"
	CodeInternal           = "internal_error"
	CodeRootNotFound       = "root_not_found"
	CodeReportNotReady     = "report_not_ready"
)

// statusOf maps a code to its HTTP status. Database failures that a retry cannot fix
// (credentials, permissions, names) are 422 so the platform does not retry them and
// cannot lock a database account; network and timeout failures are 502/504 so it does.
var statusOf = map[string]int{
	CodeInvalidRequest:     http.StatusBadRequest,
	CodeUnsupportedDBType:  http.StatusBadRequest,
	CodeUnsupportedVersion: http.StatusBadRequest,
	CodeUnauthorized:       http.StatusUnauthorized,
	CodeClientNotAllowed:   http.StatusForbidden,
	CodeLockedOut:          http.StatusTooManyRequests,
	CodeRateLimited:        http.StatusTooManyRequests,
	CodeTooLarge:           http.StatusRequestEntityTooLarge,
	CodeMediaType:          http.StatusUnsupportedMediaType,
	CodeMethod:             http.StatusMethodNotAllowed,
	CodeNotFound:           http.StatusNotFound,
	CodeSourceNotAllowed:   http.StatusUnprocessableEntity,
	CodeSchemaNotAllowed:   http.StatusUnprocessableEntity,
	CodeTableNotFound:      http.StatusNotFound,
	CodeDBAuth:             http.StatusUnprocessableEntity,
	CodeDBPermission:       http.StatusUnprocessableEntity,
	CodeDBNotFound:         http.StatusUnprocessableEntity,
	CodeDBTLS:              http.StatusUnprocessableEntity,
	CodeDBUnreachable:      http.StatusBadGateway,
	CodeDBTimeout:          http.StatusGatewayTimeout,
	CodeDBError:            http.StatusBadGateway,
	CodeBusy:               http.StatusServiceUnavailable,
	CodeInternal:           http.StatusInternalServerError,
	CodeRootNotFound:       http.StatusNotFound,
	CodeReportNotReady:     http.StatusConflict,
}

// codeForDB maps a database error kind to a response code.
func codeForDB(kind string) string {
	switch kind {
	case dbsource.KindAuth:
		return CodeDBAuth
	case dbsource.KindPermission:
		return CodeDBPermission
	case dbsource.KindNotFound:
		return CodeDBNotFound
	case dbsource.KindTLS:
		return CodeDBTLS
	case dbsource.KindUnreachable:
		return CodeDBUnreachable
	case dbsource.KindTimeout:
		return CodeDBTimeout
	case dbsource.KindBlocked:
		return CodeSourceNotAllowed
	case dbsource.KindConfig:
		return CodeSourceNotAllowed
	case dbsource.KindUnsupported:
		return CodeUnsupportedDBType
	}
	return CodeDBError
}

// apiError is a response error with a code.
type apiError struct {
	code string
}

func (e *apiError) Error() string { return e.code }

func fail(code string) *apiError { return &apiError{code: code} }

type errorBody struct {
	Status  string `json:"status"`
	Code    string `json:"code"`
	Message string `json:"message"`
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	h := w.Header()
	h.Set("Content-Type", "application/json; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, code string) int {
	status, ok := statusOf[code]
	if !ok {
		status = http.StatusInternalServerError
	}
	writeJSON(w, status, errorBody{Status: "error", Code: code, Message: i18n.T("api." + code)})
	return status
}
