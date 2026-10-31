package server

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/netip"
	"regexp"

	"github.com/privasimu/bridge/internal/audit"
	"github.com/privasimu/bridge/internal/files"
)

// Optional file-root endpoints (server.file_endpoints: true). They are an extension of
// contract v1 that the platform does not call yet; see docs/DESIGN.md. A file share is
// scanned by the bridge on its own schedule or on request, and the platform reads the
// latest report: counts per category per file, with hashed ids instead of paths unless the
// root reports relative paths.
const (
	PathFileRoots      = "/ext/v1/file-roots"
	PathFileRootReport = "/ext/v1/file-root-report"
	PathFileRootScan   = "/ext/v1/file-root-scan"
)

const maxPageSize = 500

var rootIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,62}$`)

type fileRequest struct {
	RootID   string `json:"root_id"`
	Page     int    `json:"page"`
	PageSize int    `json:"page_size"`
}

type rootsResponse struct {
	Status string           `json:"status"`
	Roots  []files.RootInfo `json:"roots"`
}

type reportResponse struct {
	Status  string              `json:"status"`
	RootID  string              `json:"root_id"`
	Summary files.Summary       `json:"summary"`
	Page    int                 `json:"page"`
	Pages   int                 `json:"pages"`
	Files   []files.FileFinding `json:"files"`
}

type scanResponse struct {
	Status   string `json:"status"`
	RootID   string `json:"root_id"`
	Scanning bool   `json:"scanning"`
}

func (s *Server) serveFiles(w http.ResponseWriter, r *http.Request, path string, ip netip.Addr, ev *audit.Event) int {
	if aerr := s.authorize(w, r, ip, ev); aerr != nil {
		ev.Code = aerr.code
		return writeError(w, aerr.code)
	}
	var req fileRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, int64(s.cfg.Server.Limits.MaxBodyBytes)))
	if err := dec.Decode(&req); err != nil && !errors.Is(err, io.EOF) {
		ev.Code = CodeInvalidRequest
		return writeError(w, CodeInvalidRequest)
	}
	if path == PathFileRoots {
		writeJSON(w, http.StatusOK, rootsResponse{Status: "success", Roots: s.files.Roots()})
		return http.StatusOK
	}
	if !rootIDPattern.MatchString(req.RootID) {
		ev.Code = CodeInvalidRequest
		return writeError(w, CodeInvalidRequest)
	}
	ev.SourceID = req.RootID
	if _, ok := s.files.Root(req.RootID); !ok {
		ev.Code = CodeRootNotFound
		return writeError(w, CodeRootNotFound)
	}
	if path == PathFileRootScan {
		err := s.files.StartScan(req.RootID)
		if err != nil && !errors.Is(err, files.ErrRunning) {
			ev.Code = CodeInternal
			return writeError(w, CodeInternal)
		}
		writeJSON(w, http.StatusAccepted, scanResponse{Status: "accepted", RootID: req.RootID, Scanning: true})
		return http.StatusAccepted
	}
	rep, err := s.files.Latest(req.RootID)
	if err != nil {
		ev.Code = CodeReportNotReady
		return writeError(w, CodeReportNotReady)
	}
	view := rep.View()
	size := req.PageSize
	if size <= 0 || size > maxPageSize {
		size = maxPageSize
	}
	pages := (len(view.Files) + size - 1) / size
	if pages == 0 {
		pages = 1
	}
	page := req.Page
	if page <= 0 {
		page = 1
	}
	if page > pages {
		ev.Code = CodeInvalidRequest
		return writeError(w, CodeInvalidRequest)
	}
	from := (page - 1) * size
	to := min(len(view.Files), from+size)
	ev.Files = to - from
	writeJSON(w, http.StatusOK, reportResponse{Status: "success", RootID: req.RootID, Summary: view.Summary, Page: page,
		Pages: pages, Files: view.Files[from:to]})
	return http.StatusOK
}
