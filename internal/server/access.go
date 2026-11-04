package server

import (
	"context"
	"errors"

	"github.com/privasimu/bridge/internal/audit"
	"github.com/privasimu/bridge/internal/dbsource"
)

// PathTableAccess answers who can read a table (a proposal like the file endpoints, off
// unless server.access_endpoint): counts and group roles (keyed hashes unless
// access_inventory.role_names is plain), never the names of accounts that can sign in. The
// body is the one of PathTableColumns; only a configured source with access_inventory is
// answered, never request credentials.
const PathTableAccess = "/ext/v1/table-access"

type accessResponse struct {
	Status string          `json:"status"`
	Table  string          `json:"table"`
	Access dbsource.Access `json:"access"`
}

func (s *Server) tableAccess(ctx context.Context, req *v1Request, ev *audit.Event) (any, *apiError) {
	r, aerr := s.resolve(req, ev)
	if aerr != nil {
		return nil, aerr
	}
	if r.source == nil || !r.source.AccessInventory {
		return nil, fail(CodeSourceNotAllowed)
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
	ar, ok := conn.(dbsource.AccessReader)
	if !ok {
		return nil, fail(CodeUnsupportedDBType)
	}
	a, err := ar.TableAccess(ctx, table, s.roleNames)
	if errors.Is(err, dbsource.ErrAccessUnsupported) {
		return nil, fail(CodeUnsupportedDBType)
	}
	if err != nil {
		s.log.Warn("table access failed", "source", sourceID(r), "error", dbErrMessage(err))
		return nil, s.dbFailure(ctx, err)
	}
	if a.Roles == nil {
		a.Roles = []string{}
	}
	ev.Tables = 1
	return accessResponse{Status: "success", Table: req.TableName, Access: a}, nil
}
