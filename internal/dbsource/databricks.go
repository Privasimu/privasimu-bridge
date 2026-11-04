package dbsource

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// dbxConn reads Databricks SQL (Unity Catalog) through the SQL Statement Execution API with
// the standard library; the Go driver links native kernel libraries in its current
// release. Authentication is a personal access token, or OAuth machine-to-machine for a
// service principal (username = its application id, password = its OAuth secret), with
// the token requested on this server. The catalog comes from the catalog's
// information_schema with bound parameters; sampling reads at most rows rows with a row
// limit enforced by the service. Databricks has no read-only session setting: the
// principal should hold only USE CATALOG, USE SCHEMA and BROWSE (names) or SELECT
// (sampling), and CAN USE on the warehouse.
type dbxConn struct {
	t         Target
	client    *http.Client
	base      string
	warehouse string

	mu      sync.Mutex
	token   string
	expires time.Time
}

// dbxWarehouseID takes the id from a warehouse id or its HTTP path.
func dbxWarehouseID(w string) string {
	w = strings.TrimSuffix(strings.TrimSpace(w), "/")
	if i := strings.LastIndex(w, "/"); i >= 0 {
		return w[i+1:]
	}
	return w
}

func openDatabricks(ctx context.Context, t Target) (Conn, error) {
	client, err := cloudClient(t)
	if err != nil {
		return nil, err
	}
	c := &dbxConn{t: t, client: client, base: "https://" + strings.TrimSuffix(strings.ToLower(t.Host), "."),
		warehouse: dbxWarehouseID(t.Warehouse)}
	if t.endpoint != "" {
		c.base = t.endpoint
	}
	if err := c.run(ctx, "SELECT 1", nil, 1, func([]*string) error { return nil }); err != nil {
		client.CloseIdleConnections()
		return nil, wrap("connect", err, true)
	}
	return c, nil
}

// accessToken returns the personal access token, or an OAuth token of the service
// principal renewed five minutes before it expires.
func (c *dbxConn) accessToken(ctx context.Context) (string, error) {
	if c.t.Username == "" {
		return c.t.Password.Reveal(), nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	if c.token != "" && now.Before(c.expires) {
		return c.token, nil
	}
	form := url.Values{"grant_type": {"client_credentials"}, "scope": {"all-apis"}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+"/oidc/v1/token", strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.SetBasicAuth(c.t.Username, c.t.Password.Reveal())
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	var tok struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := cloudDo(c.client, req, "databricks token", &tok, func(e *cloudError, _ []byte) {
		if e.Status == http.StatusBadRequest || e.Status == http.StatusUnauthorized {
			e.Kind = KindAuth
		}
	}); err != nil {
		return "", err
	}
	if tok.AccessToken == "" {
		return "", errors.New("databricks: the token answer has no access token")
	}
	c.token = tok.AccessToken
	c.expires = now.Add(time.Duration(max(tok.ExpiresIn, 600)-300) * time.Second)
	return c.token, nil
}

// dbxStatement is an answer of the Statement Execution API.
type dbxStatement struct {
	StatementID string `json:"statement_id"`
	Status      struct {
		State string `json:"state"`
		Error *struct {
			ErrorCode string `json:"error_code"`
			Message   string `json:"message"`
		} `json:"error"`
	} `json:"status"`
	Result *dbxChunk `json:"result"`
}

// dbxChunk is one chunk of a result.
type dbxChunk struct {
	DataArray             [][]*string `json:"data_array"`
	NextChunkInternalLink string      `json:"next_chunk_internal_link"`
}

// dbxParseError reads {"error_code","message"}.
func dbxParseError(e *cloudError, body []byte) {
	var a struct {
		ErrorCode string `json:"error_code"`
		Message   string `json:"message"`
	}
	if json.Unmarshal(body, &a) == nil {
		e.Code, e.Message = a.ErrorCode, a.Message
	}
	if k := dbxKind(e.Code); k != "" {
		e.Kind = k
	}
}

// dbxKind maps a Databricks error code to a kind ("" when unknown).
func dbxKind(code string) string {
	switch {
	case code == "UNAUTHENTICATED" || code == "INVALID_TOKEN":
		return KindAuth
	case code == "PERMISSION_DENIED" || strings.HasPrefix(code, "INSUFFICIENT_"):
		return KindPermission
	case strings.HasSuffix(code, "NOT_FOUND") || code == "RESOURCE_DOES_NOT_EXIST":
		return KindNotFound
	case code == "DEADLINE_EXCEEDED" || code == "TIMEOUT":
		return KindTimeout
	}
	return ""
}

// dbxWaitTimeout is the source's timeout as the wait_timeout of a statement: whole seconds,
// rounded up, within the 5 to 50 seconds the API accepts.
func dbxWaitTimeout(timeout time.Duration) string {
	s := int((timeout + time.Second - 1) / time.Second)
	return strconv.Itoa(min(max(s, 5), 50)) + "s"
}

// call sends one request of the API.
func (c *dbxConn) call(ctx context.Context, method, path string, body any, out any) error {
	token, err := c.accessToken(ctx)
	if err != nil {
		return err
	}
	var req *http.Request
	if body != nil {
		r, err := jsonBody(body)
		if err != nil {
			return err
		}
		if req, err = http.NewRequestWithContext(ctx, method, c.base+path, r); err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/json")
	} else if req, err = http.NewRequestWithContext(ctx, method, c.base+path, nil); err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "privasimu-bridge")
	return cloudDo(c.client, req, "databricks", out, dbxParseError)
}

// run executes one statement with named parameters (:name) and calls fn for each row.
// rowLimit > 0 makes the service stop after that many rows.
//
// Databricks itself cancels a statement that has not finished within wait_timeout
// (on_wait_timeout CANCEL), so a statement never outlives the source's timeout, even when
// the bridge stops before it could cancel it. With CONTINUE the statement would keep
// running up to the warehouse's statement timeout, two days by default.
func (c *dbxConn) run(ctx context.Context, stmt string, params map[string]string, rowLimit int, fn func([]*string) error) error {
	ctx, cancel := context.WithTimeout(ctx, c.t.Timeout+30*time.Second)
	defer cancel()
	body := map[string]any{"warehouse_id": c.warehouse, "statement": stmt, "catalog": c.t.Database,
		"wait_timeout": dbxWaitTimeout(c.t.Timeout), "on_wait_timeout": "CANCEL", "disposition": "INLINE", "format": "JSON_ARRAY"}
	if rowLimit > 0 {
		body["row_limit"] = rowLimit
	}
	if len(params) > 0 {
		list := make([]map[string]string, 0, len(params))
		for k, v := range params {
			list = append(list, map[string]string{"name": k, "value": v, "type": "STRING"})
		}
		body["parameters"] = list
	}
	var st dbxStatement
	if err := withRetry(ctx, func() error {
		st = dbxStatement{}
		return c.call(ctx, http.MethodPost, "/api/2.0/sql/statements", body, &st)
	}); err != nil {
		return err
	}
	deadline := time.Now().Add(c.t.Timeout)
	for wait := 500 * time.Millisecond; st.Status.State == "PENDING" || st.Status.State == "RUNNING"; wait = min(wait*2, 2*time.Second) {
		if st.StatementID == "" {
			return errors.New("databricks: a running statement has no id")
		}
		if time.Now().After(deadline) {
			c.cancelStatement(st.StatementID)
			return &cloudError{Service: "databricks", Code: "DEADLINE_EXCEEDED", Kind: KindTimeout}
		}
		select {
		case <-ctx.Done():
			c.cancelStatement(st.StatementID)
			return ctx.Err()
		case <-time.After(wait):
		}
		id := st.StatementID
		st = dbxStatement{}
		if err := c.call(ctx, http.MethodGet, "/api/2.0/sql/statements/"+url.PathEscape(id), nil, &st); err != nil {
			return err
		}
		if st.StatementID == "" {
			st.StatementID = id
		}
	}
	if st.Status.State != "SUCCEEDED" {
		e := &cloudError{Service: "databricks", Code: st.Status.State, Kind: KindDatabase}
		if st.Status.State == "CANCELED" {
			// Cancelled at wait_timeout (on_wait_timeout CANCEL): the source's timeout passed.
			e.Kind = KindTimeout
		}
		if st.Status.Error != nil {
			e.Code, e.Message = st.Status.Error.ErrorCode, st.Status.Error.Message
			if k := dbxKind(e.Code); k != "" {
				e.Kind = k
			}
		}
		return e
	}
	chunk := st.Result
	for chunk != nil {
		for _, row := range chunk.DataArray {
			if err := fn(row); err != nil {
				return err
			}
		}
		link := chunk.NextChunkInternalLink
		if link == "" {
			break
		}
		// The link names a chunk of this statement on this workspace, nothing else.
		if !strings.HasPrefix(link, "/api/2.0/sql/statements/"+url.PathEscape(st.StatementID)+"/result/chunks/") {
			return errors.New("databricks: unexpected chunk link")
		}
		next := &dbxChunk{}
		if err := withRetry(ctx, func() error { return c.call(ctx, http.MethodGet, link, nil, next) }); err != nil {
			return err
		}
		chunk = next
	}
	return nil
}

// cancelStatement asks Databricks to stop a statement whose caller has given up.
func (c *dbxConn) cancelStatement(id string) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = c.call(ctx, http.MethodPost, "/api/2.0/sql/statements/"+url.PathEscape(id)+"/cancel", map[string]string{}, nil)
}

func (c *dbxConn) Engine() string                       { return "databricks" }
func (c *dbxConn) ServerVersion(context.Context) string { return "Databricks SQL" }
func (c *dbxConn) DefaultSchema() string                { return "default" }
func (c *dbxConn) TLSInUse() *bool                      { on := true; return &on }

func (c *dbxConn) Close() error {
	c.client.CloseIdleConnections()
	return nil
}

// dbxQuote quotes an identifier with backticks.
func dbxQuote(id string) string { return "`" + strings.ReplaceAll(id, "`", "``") + "`" }

const dbxTables = `SELECT table_schema, table_name FROM information_schema.tables
WHERE table_type IN ('MANAGED', 'EXTERNAL') AND table_schema <> 'information_schema'`

func (c *dbxConn) ListTables(ctx context.Context, schema string) ([]Table, error) {
	schemas, err := listingSchemas(c.t, schema)
	if err != nil {
		return nil, err
	}
	query, params := dbxTables, map[string]string{}
	if len(schemas) > 0 {
		marks := make([]string, len(schemas))
		for i, s := range schemas {
			key := "s" + strconv.Itoa(i)
			marks[i], params[key] = ":"+key, s
		}
		query += " AND table_schema IN (" + strings.Join(marks, ", ") + ")"
	}
	var out []Table
	err = c.run(ctx, query+" ORDER BY 1, 2", params, 0, func(row []*string) error {
		if len(row) >= 2 && row[0] != nil && row[1] != nil && validName(*row[0]) && validName(*row[1]) {
			out = append(out, Table{Schema: *row[0], Name: *row[1], Ref: tableRef("default", *row[0], *row[1], schema)})
		}
		return nil
	})
	if err != nil {
		return nil, wrap("list tables", err, true)
	}
	sortTables(out, "default")
	return out, nil
}

func (c *dbxConn) FindTable(ctx context.Context, ref, schema string) (Table, bool, error) {
	if !validName(ref) {
		return Table{}, false, nil
	}
	for _, cand := range lookupCandidates(c.t, "default", ref, schema) {
		found := false
		err := c.run(ctx, dbxTables+" AND table_schema = :s AND table_name = :n", map[string]string{"s": cand.schema, "n": cand.name}, 1,
			func([]*string) error { found = true; return nil })
		if err != nil {
			return Table{}, false, wrap("find table", err, true)
		}
		if found {
			return Table{Schema: cand.schema, Name: cand.name, Ref: ref}, true, nil
		}
	}
	return Table{}, false, nil
}

// dbxSampleable: text, whole numbers and decimals (read as text).
func dbxSampleable(t string) bool {
	return strings.Contains(t, "string") || strings.HasPrefix(t, "varchar") || strings.HasPrefix(t, "char") ||
		strings.HasPrefix(t, "bigint") || strings.HasPrefix(t, "decimal")
}

func (c *dbxConn) Columns(ctx context.Context, t Table) ([]Column, error) {
	var out []Column
	err := c.run(ctx, `SELECT column_name, full_data_type, is_nullable FROM information_schema.columns
WHERE table_schema = :s AND table_name = :n ORDER BY ordinal_position`, map[string]string{"s": t.Schema, "n": t.Name}, 0,
		func(row []*string) error {
			if len(row) < 3 || row[0] == nil {
				return nil
			}
			typ := ""
			if row[1] != nil {
				typ = strings.ToLower(*row[1])
			}
			nullable := row[2] != nil && strings.EqualFold(*row[2], "YES")
			out = append(out, Column{Name: *row[0], DataType: typ, Nullable: &nullable, Sampleable: dbxSampleable(typ)})
			return nil
		})
	if err != nil {
		return nil, wrap("columns", err, true)
	}
	return out, nil
}

func (c *dbxConn) Sample(ctx context.Context, t Table, cols []Column, rows int, visit func(int, string, bool)) error {
	var idx []int
	var exprs []string
	for i, col := range cols {
		if col.Sampleable && validName(col.Name) {
			idx = append(idx, i)
			exprs = append(exprs, "CAST("+dbxQuote(col.Name)+" AS STRING)")
		}
	}
	if len(idx) == 0 || rows <= 0 {
		return nil
	}
	query := "SELECT " + strings.Join(exprs, ", ") + " FROM " + dbxQuote(c.t.Database) + "." + dbxQuote(t.Schema) + "." +
		dbxQuote(t.Name) + " LIMIT " + strconv.Itoa(rows)
	n := 0
	err := c.run(ctx, query, nil, rows, func(row []*string) error {
		if n >= rows {
			return nil
		}
		n++
		for i := range idx {
			if i < len(row) && row[i] != nil {
				visit(idx[i], *row[i], false)
			} else {
				visit(idx[i], "", true)
			}
		}
		return nil
	})
	return wrap("sample", err, false)
}
