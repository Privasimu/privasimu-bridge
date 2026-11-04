package dbsource

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// bqConn reads Google BigQuery through its REST API with the standard library; the
// official client library would add some 17 MB to the binary. It runs no query job at
// all: the catalog comes from datasets.list, tables.list and tables.get, and sampling from
// tabledata.list, which reads stored rows directly (no query cost). The access token is
// requested with the scope bigquery.readonly, so Google itself refuses anything but reads,
// whatever roles the service account has. The service account key is used on this server
// to sign the token request and never sent.
type bqConn struct {
	t        Target
	client   *http.Client
	api      string // https://bigquery.googleapis.com/bigquery/v2
	tokenURL string
	project  string
	email    string
	keyID    string
	key      *rsa.PrivateKey
	datasets []string // the datasets the listing covers

	mu      sync.Mutex
	token   string
	expires time.Time
}

// The public endpoints of BigQuery and of Google's token service (the token endpoint
// of a key file is ignored, so a key file cannot send the signed assertion elsewhere).
const (
	bqAPI      = "https://bigquery.googleapis.com/bigquery/v2"
	bqTokenURL = "https://oauth2.googleapis.com/token" // #nosec G101 -- an endpoint, not a credential
)

// bqReadonlyScope limits the token to reads.
const bqReadonlyScope = "https://www.googleapis.com/auth/bigquery.readonly"

func openBigQuery(ctx context.Context, t Target) (Conn, error) {
	var sa struct {
		Type         string `json:"type"`
		ClientEmail  string `json:"client_email"`
		PrivateKeyID string `json:"private_key_id"`
		PrivateKey   string `json:"private_key"`
	}
	if err := json.Unmarshal([]byte(t.Credentials.Reveal()), &sa); err != nil || sa.Type != "service_account" || sa.ClientEmail == "" {
		return nil, &Error{Kind: KindConfig, Op: "credentials (a service account key in JSON)", Safe: true}
	}
	key, err := parseRSAKey(sa.PrivateKey, "")
	if err != nil {
		return nil, &Error{Kind: KindConfig, Op: "credentials", Cause: err, Safe: true}
	}
	client, err := cloudClient(t)
	if err != nil {
		return nil, err
	}
	c := &bqConn{t: t, client: client, api: bqAPI, tokenURL: bqTokenURL, project: t.Database, email: sa.ClientEmail,
		keyID: sa.PrivateKeyID, key: key}
	if t.endpoint != "" {
		c.api, c.tokenURL = t.endpoint+"/bigquery/v2", t.endpoint+"/token"
	}
	if err := c.loadDatasets(ctx); err != nil {
		client.CloseIdleConnections()
		return nil, wrap("connect", err, true)
	}
	return c, nil
}

// accessToken returns a token for the read-only scope, renewed five minutes early.
func (c *bqConn) accessToken(ctx context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	if c.token != "" && now.Before(c.expires) {
		return c.token, nil
	}
	assertion, err := signJWT(c.key, map[string]string{"kid": c.keyID}, map[string]any{"iss": c.email, "scope": bqReadonlyScope,
		"aud": c.tokenURL, "iat": now.Unix(), "exp": now.Add(time.Hour).Unix()})
	if err != nil {
		return "", err
	}
	form := url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"}, "assertion": {assertion}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	var tok struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := cloudDo(c.client, req, "bigquery token", &tok, func(e *cloudError, body []byte) {
		var a struct {
			Error       string `json:"error"`
			Description string `json:"error_description"`
		}
		if json.Unmarshal(body, &a) == nil {
			e.Code, e.Message = a.Error, a.Description
		}
		if e.Status == http.StatusBadRequest || e.Status == http.StatusUnauthorized {
			e.Kind = KindAuth // invalid_grant: the key is revoked or the account disabled
		}
	}); err != nil {
		return "", err
	}
	if tok.AccessToken == "" {
		return "", errors.New("bigquery: the token answer has no access token")
	}
	c.token = tok.AccessToken
	c.expires = now.Add(time.Duration(max(tok.ExpiresIn, 600)-300) * time.Second)
	return c.token, nil
}

// bqParseError reads {"error":{"code","message","status"}}.
func bqParseError(e *cloudError, body []byte) {
	var a struct {
		Error struct {
			Message string `json:"message"`
			Status  string `json:"status"`
		} `json:"error"`
	}
	if json.Unmarshal(body, &a) == nil {
		e.Code, e.Message = a.Error.Status, a.Error.Message
	}
}

// get reads one resource of the API.
func (c *bqConn) get(ctx context.Context, path string, query url.Values, out any) error {
	ctx, cancel := context.WithTimeout(ctx, c.t.Timeout)
	defer cancel()
	return withRetry(ctx, func() error {
		token, err := c.accessToken(ctx)
		if err != nil {
			return err
		}
		u := c.api + path
		if len(query) > 0 {
			u += "?" + query.Encode()
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Accept", "application/json")
		req.Header.Set("User-Agent", "privasimu-bridge")
		return cloudDo(c.client, req, "bigquery", out, bqParseError)
	})
}

func (c *bqConn) projectPath() string { return "/projects/" + url.PathEscape(c.project) }

// loadDatasets fixes the datasets a listing covers: the allow-list, or every dataset.
func (c *bqConn) loadDatasets(ctx context.Context) error {
	var all []string
	token := ""
	for {
		q := url.Values{"maxResults": {"1000"}}
		if token != "" {
			q.Set("pageToken", token)
		}
		var page struct {
			Datasets []struct {
				DatasetReference struct {
					DatasetID string `json:"datasetId"`
				} `json:"datasetReference"`
			} `json:"datasets"`
			NextPageToken string `json:"nextPageToken"`
		}
		if err := c.get(ctx, c.projectPath()+"/datasets", q, &page); err != nil {
			return err
		}
		for _, d := range page.Datasets {
			if id := d.DatasetReference.DatasetID; validName(id) && c.t.schemaAllowed(id) {
				all = append(all, id)
			}
		}
		if token = page.NextPageToken; token == "" || len(all) > 10000 {
			break
		}
	}
	sort.Strings(all)
	c.datasets = all
	return nil
}

func (c *bqConn) Engine() string                       { return "bigquery" }
func (c *bqConn) ServerVersion(context.Context) string { return "BigQuery" }
func (c *bqConn) TLSInUse() *bool                      { on := true; return &on }

// DefaultSchema is the dataset whose tables are reported without a prefix: the only one in
// the allow-list, else none (every table is "dataset.table").
func (c *bqConn) DefaultSchema() string {
	if len(c.t.Schemas) == 1 {
		return c.t.Schemas[0]
	}
	return ""
}

func (c *bqConn) Close() error {
	c.client.CloseIdleConnections()
	return nil
}

func (c *bqConn) ListTables(ctx context.Context, schema string) ([]Table, error) {
	datasets, err := listingSchemas(c.t, schema)
	if err != nil {
		return nil, err
	}
	if len(datasets) == 0 {
		datasets = c.datasets
	}
	var out []Table
	for _, ds := range datasets {
		token := ""
		for {
			q := url.Values{"maxResults": {"1000"}}
			if token != "" {
				q.Set("pageToken", token)
			}
			var page struct {
				Tables []struct {
					TableReference struct {
						TableID string `json:"tableId"`
					} `json:"tableReference"`
					Type string `json:"type"`
				} `json:"tables"`
				NextPageToken string `json:"nextPageToken"`
			}
			if err := c.get(ctx, c.projectPath()+"/datasets/"+url.PathEscape(ds)+"/tables", q, &page); err != nil {
				return nil, wrap("list tables", err, true)
			}
			for _, tb := range page.Tables {
				if name := tb.TableReference.TableID; tb.Type == "TABLE" && validName(name) {
					out = append(out, Table{Schema: ds, Name: name, Ref: tableRef(c.DefaultSchema(), ds, name, schema)})
				}
			}
			if token = page.NextPageToken; token == "" || len(out) > 20000 {
				break
			}
		}
	}
	sortTables(out, c.DefaultSchema())
	return out, nil
}

// bqField is a field of a table schema; RECORD fields have sub-fields.
type bqField struct {
	Name   string    `json:"name"`
	Type   string    `json:"type"`
	Mode   string    `json:"mode"`
	Fields []bqField `json:"fields"`
}

type bqTable struct {
	Type    string `json:"type"`
	NumRows string `json:"numRows"`
	Schema  struct {
		Fields []bqField `json:"fields"`
	} `json:"schema"`
}

func (c *bqConn) tablePath(t Table) string {
	return c.projectPath() + "/datasets/" + url.PathEscape(t.Schema) + "/tables/" + url.PathEscape(t.Name)
}

func (c *bqConn) FindTable(ctx context.Context, ref, schema string) (Table, bool, error) {
	if !validName(ref) {
		return Table{}, false, nil
	}
	for _, cand := range lookupCandidates(c.t, c.DefaultSchema(), ref, schema) {
		var tb bqTable
		err := c.get(ctx, c.tablePath(Table{Schema: cand.schema, Name: cand.name}), url.Values{"view": {"BASIC"}}, &tb)
		var ce *cloudError
		if errors.As(err, &ce) && ce.Status == http.StatusNotFound {
			continue
		}
		if err != nil {
			return Table{}, false, wrap("find table", err, true)
		}
		if tb.Type != "TABLE" {
			continue
		}
		t := Table{Schema: cand.schema, Name: cand.name, Ref: ref}
		if n, err := strconv.ParseInt(tb.NumRows, 10, 64); err == nil && n >= 0 {
			t.RowEstimate = &n
		}
		return t, true, nil
	}
	return Table{}, false, nil
}

// bqSampleable: top-level text, whole numbers, numerics and JSON (tabledata.list returns
// them as text); fields inside records are classified by name only.
func bqSampleable(f bqField, nested bool) bool {
	if nested {
		return false
	}
	switch f.Type {
	case "STRING", "INTEGER", "INT64", "NUMERIC", "BIGNUMERIC", "JSON":
		return true
	}
	return false
}

func (c *bqConn) Columns(ctx context.Context, t Table) ([]Column, error) {
	var tb bqTable
	if err := c.get(ctx, c.tablePath(t), nil, &tb); err != nil {
		return nil, wrap("columns", err, true)
	}
	var out []Column
	var walk func(prefix string, fields []bqField, depth int)
	walk = func(prefix string, fields []bqField, depth int) {
		for _, f := range fields {
			name := prefix + f.Name
			if len(f.Fields) > 0 && depth < maxFieldDepth {
				walk(name+".", f.Fields, depth+1)
				continue
			}
			if len(out) >= maxFields {
				return
			}
			typ := strings.ToLower(f.Type)
			if f.Mode == "REPEATED" {
				typ = "array<" + typ + ">"
			}
			nullable := f.Mode != "REQUIRED"
			out = append(out, Column{Name: name, DataType: typ, Nullable: &nullable, Sampleable: bqSampleable(f, prefix != "")})
		}
	}
	walk("", tb.Schema.Fields, 0)
	return out, nil
}

// bqCell is a cell of tabledata.list: a text value, null, or a list of {"v": ...} for a
// repeated field.
type bqCell struct {
	V json.RawMessage `json:"v"`
}

// Sample reads up to rows stored rows of the sampleable top-level fields with
// tabledata.list (no query job); each value of a repeated field is examined on its own.
func (c *bqConn) Sample(ctx context.Context, t Table, cols []Column, rows int, visit func(int, string, bool)) error {
	var idx []int
	var names []string
	for i, col := range cols {
		if col.Sampleable && validName(col.Name) && !strings.Contains(col.Name, ".") {
			idx = append(idx, i)
			names = append(names, col.Name)
		}
	}
	if len(idx) == 0 || rows <= 0 {
		return nil
	}
	var page struct {
		Rows []struct {
			F []bqCell `json:"f"`
		} `json:"rows"`
	}
	q := url.Values{"maxResults": {strconv.Itoa(rows)}, "selectedFields": {strings.Join(names, ",")}}
	if err := c.get(ctx, c.tablePath(t)+"/data", q, &page); err != nil {
		return wrap("sample", err, false)
	}
	for n, row := range page.Rows {
		if n >= rows {
			break
		}
		for i := range idx {
			if i >= len(row.F) {
				visit(idx[i], "", true)
				continue
			}
			visitBQ(row.F[i].V, func(v string, null bool) { visit(idx[i], v, null) })
		}
	}
	return nil
}

// visitBQ passes a cell's text, or each text of a repeated cell (at most 10), to fn.
func visitBQ(raw json.RawMessage, fn func(string, bool)) {
	var s *string
	if json.Unmarshal(raw, &s) == nil {
		if s == nil {
			fn("", true)
		} else {
			fn(*s, false)
		}
		return
	}
	var list []bqCell
	if json.Unmarshal(raw, &list) == nil {
		for i, item := range list {
			if i == 10 {
				break
			}
			var v *string
			if json.Unmarshal(item.V, &v) == nil && v != nil {
				fn(*v, false)
			}
		}
		return
	}
	fn("", true)
}
