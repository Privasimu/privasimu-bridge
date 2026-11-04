package dbsource

import (
	"context"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// sfConn reads Snowflake through its SQL API (REST, version 2) with the standard library;
// the official driver would add some 27 MB to the binary. Authentication is a key pair
// (a JWT signed on this server; the private key never leaves it) or a programmatic access
// token: Snowflake does not take plain passwords over this API, and refuses them for
// service users anyway. The catalog is read with SHOW commands, which need no warehouse;
// sampling needs one. Every statement carries a server-side timeout; the account's role
// should hold only USAGE and REFERENCES (names) or SELECT (sampling), because Snowflake has
// no read-only session setting.
type sfConn struct {
	t       Target
	client  *http.Client
	base    string
	db      string // the database as an SQL identifier
	version string

	tokenType string // KEYPAIR_JWT or PROGRAMMATIC_ACCESS_TOKEN
	pat       string
	key       *rsa.PrivateKey
	iss, sub  string

	mu      sync.Mutex
	jwt     string
	expires time.Time
}

// sfPlain matches identifiers Snowflake stores in upper case when written unquoted.
var sfPlain = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_$]*$`)

// sfObjectName is how the SQL API's database, warehouse and role fields (which are case
// sensitive) and unquoted SQL name an object configured as name: plain names are upper
// case in Snowflake.
func sfObjectName(name string) string {
	if sfPlain.MatchString(name) {
		return strings.ToUpper(name)
	}
	return name
}

// sfIdentifier writes a configured name in SQL: plain names unquoted, others quoted.
func sfIdentifier(name string) string {
	if sfPlain.MatchString(name) {
		return name
	}
	return sfQuote(name)
}

// sfQuote quotes a name exactly as the catalog reports it.
func sfQuote(id string) string { return `"` + strings.ReplaceAll(id, `"`, `""`) + `"` }

// sfAccount returns the account name of the JWT and the API host for a configured host:
// an account identifier ("myorg-myaccount", "myorg.myaccount", a locator "xy12345" or
// "xy12345.ap-southeast-1.aws") or a full host name ending in .snowflakecomputing.com
// (needed for PrivateLink).
func sfAccount(host string) (account, apiHost string) {
	h := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	full := strings.HasSuffix(h, ".snowflakecomputing.com")
	ident := strings.TrimSuffix(h, ".snowflakecomputing.com")
	acct := strings.TrimSuffix(ident, ".privatelink")
	if before, after, found := strings.Cut(acct, "."); found {
		if strings.Contains(after, "-") || strings.Contains(after, ".") {
			acct = before // a locator with its region: the JWT names the locator alone
		} else {
			acct = before + "-" + after // orgname.accountname is orgname-accountname
			ident = acct
		}
	}
	apiHost = ident + ".snowflakecomputing.com"
	if full {
		apiHost = h
	}
	return strings.ToUpper(acct), apiHost
}

func openSnowflake(ctx context.Context, t Target) (Conn, error) {
	client, err := cloudClient(t)
	if err != nil {
		return nil, err
	}
	account, apiHost := sfAccount(t.Host)
	c := &sfConn{t: t, client: client, base: "https://" + apiHost, db: sfIdentifier(t.Database)}
	if t.endpoint != "" {
		c.base = t.endpoint
	}
	if pemText := t.PrivateKey.Reveal(); pemText != "" {
		key, err := parseRSAKey(pemText, t.PrivateKeyPassphrase.Reveal())
		if err != nil {
			return nil, &Error{Kind: KindConfig, Op: "private_key", Cause: err, Safe: true}
		}
		der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
		if err != nil {
			return nil, &Error{Kind: KindConfig, Op: "private_key", Cause: errBadKey, Safe: true}
		}
		sum := sha256.Sum256(der)
		user := strings.ToUpper(t.Username)
		c.key, c.tokenType = key, "KEYPAIR_JWT"
		c.sub = account + "." + user
		c.iss = c.sub + ".SHA256:" + base64.StdEncoding.EncodeToString(sum[:])
	} else {
		c.pat, c.tokenType = t.Password.Reveal(), "PROGRAMMATIC_ACCESS_TOKEN"
	}
	// SHOW needs no warehouse: it checks the login, the role and the database.
	if err := c.run(ctx, "SHOW SCHEMAS IN DATABASE "+c.db+" LIMIT 1", nil, func(map[string]int, []*string) error { return nil }); err != nil {
		client.CloseIdleConnections()
		return nil, wrap("connect", err, true)
	}
	c.version = "Snowflake"
	_ = c.run(ctx, "SELECT CURRENT_VERSION()", nil, func(_ map[string]int, row []*string) error {
		if len(row) > 0 && row[0] != nil {
			c.version = "Snowflake " + *row[0]
		}
		return nil
	})
	return c, nil
}

// token returns the bearer token: a JWT valid for an hour, renewed after 50 minutes, or
// the programmatic access token.
func (c *sfConn) token() (string, error) {
	if c.key == nil {
		return c.pat, nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	if c.jwt != "" && now.Before(c.expires) {
		return c.jwt, nil
	}
	jwt, err := signJWT(c.key, nil, map[string]any{"iss": c.iss, "sub": c.sub, "iat": now.Unix(), "exp": now.Add(time.Hour).Unix()})
	if err != nil {
		return "", err
	}
	c.jwt, c.expires = jwt, now.Add(50*time.Minute)
	return jwt, nil
}

// sfAnswer is an answer of the SQL API.
type sfAnswer struct {
	Code              string `json:"code"`
	Message           string `json:"message"`
	StatementHandle   string `json:"statementHandle"`
	ResultSetMetaData *struct {
		PartitionInfo []struct {
			RowCount int64 `json:"rowCount"`
		} `json:"partitionInfo"`
		RowType []struct {
			Name string `json:"name"`
		} `json:"rowType"`
	} `json:"resultSetMetaData"`
	Data [][]*string `json:"data"`
}

// sfParseError reads an error answer: {"code","message","sqlState"}.
func sfParseError(e *cloudError, body []byte) {
	var a struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	}
	if json.Unmarshal(body, &a) == nil {
		e.Code, e.Message = a.Code, a.Message
	}
	switch e.Code {
	case "390144", "390318", "394304", "390100", "390422":
		e.Kind = KindAuth // JWT invalid, token expired, PAT invalid, login failed
	case "002003", "002043":
		e.Kind = KindNotFound // does not exist or not authorized
	case "003001", "003011":
		e.Kind = KindPermission
	case "000630", "000604":
		e.Kind = KindTimeout // statement timeout, statement canceled
	case "000606":
		e.Kind = KindConfig // no active warehouse
	}
}

// run executes one statement and calls fn for each row with the column indexes by lower-case
// name. A statement still running after the first answer is polled; further partitions are
// fetched one at a time.
func (c *sfConn) run(ctx context.Context, stmt string, binds []string, fn func(map[string]int, []*string) error) error {
	ctx, cancel := context.WithTimeout(ctx, c.t.Timeout+30*time.Second)
	defer cancel()
	body := map[string]any{
		"statement":  stmt,
		"timeout":    max(1, int(c.t.Timeout.Seconds())),
		"database":   sfObjectName(c.t.Database),
		"parameters": map[string]string{"query_tag": "privasimu-bridge"},
	}
	if c.t.Warehouse != "" {
		body["warehouse"] = sfObjectName(c.t.Warehouse)
	}
	if c.t.Role != "" {
		body["role"] = sfObjectName(c.t.Role)
	}
	if len(binds) > 0 {
		b := map[string]map[string]string{}
		for i, v := range binds {
			b[strconv.Itoa(i+1)] = map[string]string{"type": "TEXT", "value": v}
		}
		body["bindings"] = b
	}
	requestID := newRequestID()
	var ans sfAnswer
	err := withRetry(ctx, func() error {
		ans = sfAnswer{}
		u := c.base + "/api/v2/statements?requestId=" + url.QueryEscape(requestID) + "&retry=true"
		return c.call(ctx, http.MethodPost, u, body, &ans)
	})
	if err != nil {
		return err
	}
	for wait := 250 * time.Millisecond; ans.ResultSetMetaData == nil; wait = min(wait*2, 2*time.Second) {
		if ans.StatementHandle == "" {
			return errors.New("snowflake: the answer has neither a result nor a statement handle")
		}
		select {
		case <-ctx.Done():
			c.cancelStatement(ans.StatementHandle)
			return ctx.Err()
		case <-time.After(wait):
		}
		handle := ans.StatementHandle
		ans = sfAnswer{}
		if err := c.call(ctx, http.MethodGet, c.base+"/api/v2/statements/"+url.PathEscape(handle), nil, &ans); err != nil {
			return err
		}
		if ans.StatementHandle == "" {
			ans.StatementHandle = handle
		}
	}
	cols := map[string]int{}
	for i, rt := range ans.ResultSetMetaData.RowType {
		cols[strings.ToLower(rt.Name)] = i
	}
	for _, row := range ans.Data {
		if err := fn(cols, row); err != nil {
			return err
		}
	}
	for p := 1; p < len(ans.ResultSetMetaData.PartitionInfo); p++ {
		var part sfAnswer
		u := c.base + "/api/v2/statements/" + url.PathEscape(ans.StatementHandle) + "?partition=" + strconv.Itoa(p)
		if err := withRetry(ctx, func() error { return c.call(ctx, http.MethodGet, u, nil, &part) }); err != nil {
			return err
		}
		for _, row := range part.Data {
			if err := fn(cols, row); err != nil {
				return err
			}
		}
	}
	return nil
}

// call sends one request of the SQL API.
func (c *sfConn) call(ctx context.Context, method, u string, body any, out any) error {
	token, err := c.token()
	if err != nil {
		return err
	}
	var req *http.Request
	if body != nil {
		r, err := jsonBody(body)
		if err != nil {
			return err
		}
		req, err = http.NewRequestWithContext(ctx, method, u, r)
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/json")
	} else if req, err = http.NewRequestWithContext(ctx, method, u, nil); err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-Snowflake-Authorization-Token-Type", c.tokenType)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "privasimu-bridge")
	return cloudDo(c.client, req, "snowflake", out, sfParseError)
}

// cancelStatement asks Snowflake to stop a statement whose caller has given up.
func (c *sfConn) cancelStatement(handle string) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = c.call(ctx, http.MethodPost, c.base+"/api/v2/statements/"+url.PathEscape(handle)+"/cancel", map[string]string{}, nil)
}

func (c *sfConn) Engine() string                       { return "snowflake" }
func (c *sfConn) ServerVersion(context.Context) string { return c.version }
func (c *sfConn) DefaultSchema() string                { return "PUBLIC" }
func (c *sfConn) TLSInUse() *bool                      { on := true; return &on }

func (c *sfConn) Close() error {
	c.client.CloseIdleConnections()
	return nil
}

// col returns a row's value of a named column.
func col(cols map[string]int, row []*string, name string) (string, bool) {
	i, ok := cols[name]
	if !ok || i >= len(row) || row[i] == nil {
		return "", false
	}
	return *row[i], true
}

// tablesOf reads the rows of SHOW TABLES as tables of the allowed schemas.
func (c *sfConn) tablesOf(cols map[string]int, row []*string, requested string, add func(Table)) {
	schema, ok1 := col(cols, row, "schema_name")
	name, ok2 := col(cols, row, "name")
	if !ok1 || !ok2 || strings.EqualFold(schema, "INFORMATION_SCHEMA") || !validName(schema) || !validName(name) ||
		!c.t.schemaAllowed(schema) || (requested != "" && !strings.EqualFold(schema, requested)) {
		return
	}
	t := Table{Schema: schema, Name: name, Ref: tableRef("PUBLIC", schema, name, requested)}
	if v, ok := col(cols, row, "rows"); ok {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil && n >= 0 {
			t.RowEstimate = &n
		}
	}
	add(t)
}

func (c *sfConn) ListTables(ctx context.Context, schema string) ([]Table, error) {
	if _, err := listingSchemas(c.t, schema); err != nil {
		return nil, err
	}
	var out []Table
	err := c.run(ctx, "SHOW TABLES IN DATABASE "+c.db, nil, func(cols map[string]int, row []*string) error {
		c.tablesOf(cols, row, schema, func(t Table) { out = append(out, t) })
		return nil
	})
	if err != nil {
		return nil, wrap("list tables", err, true)
	}
	sortTables(out, "PUBLIC")
	return out, nil
}

// sfLike writes a name as the string literal of a SHOW ... LIKE pattern. The wildcards _ and
// % stay wildcards (the answer is a superset, filtered by exact name afterwards); quotes and
// backslashes are escaped so the literal cannot end early.
func sfLike(name string) string {
	return "'" + strings.NewReplacer(`\`, `\\`, `'`, `''`).Replace(name) + "'"
}

func (c *sfConn) FindTable(ctx context.Context, ref, schema string) (Table, bool, error) {
	if !validName(ref) {
		return Table{}, false, nil
	}
	for _, cand := range lookupCandidates(c.t, "PUBLIC", ref, schema) {
		var exact, folded *Table
		err := c.run(ctx, "SHOW TABLES LIKE "+sfLike(cand.name)+" IN DATABASE "+c.db, nil, func(cols map[string]int, row []*string) error {
			c.tablesOf(cols, row, "", func(t Table) {
				if !strings.EqualFold(t.Schema, cand.schema) {
					return
				}
				t.Ref = ref
				switch {
				case t.Name == cand.name && exact == nil:
					exact = &t
				case strings.EqualFold(t.Name, cand.name) && folded == nil:
					folded = &t
				}
			})
			return nil
		})
		if err != nil {
			return Table{}, false, wrap("find table", err, true)
		}
		if exact != nil {
			return *exact, true, nil
		}
		if folded != nil {
			return *folded, true, nil
		}
	}
	return Table{}, false, nil
}

// sfType is the data_type JSON of SHOW COLUMNS.
type sfType struct {
	Type      string `json:"type"`
	Length    *int64 `json:"length"`
	Precision *int   `json:"precision"`
	Scale     *int   `json:"scale"`
	Nullable  *bool  `json:"nullable"`
}

// name writes the type like SQL: number(38,0), varchar(16), variant, ...
func (s sfType) name() string {
	switch t := strings.ToLower(s.Type); {
	case t == "fixed" && s.Precision != nil && s.Scale != nil:
		return "number(" + strconv.Itoa(*s.Precision) + "," + strconv.Itoa(*s.Scale) + ")"
	case t == "fixed":
		return "number"
	case t == "text" && s.Length != nil:
		return "varchar(" + strconv.FormatInt(*s.Length, 10) + ")"
	case t == "text":
		return "varchar"
	default:
		return t
	}
}

// sfSampleable: text, whole numbers and semi-structured values (read as JSON text).
func sfSampleable(dataType string) bool {
	switch {
	case strings.HasPrefix(dataType, "varchar"), dataType == "variant", dataType == "object", dataType == "array":
		return true
	case strings.HasPrefix(dataType, "number("):
		return strings.HasSuffix(dataType, ",0)")
	}
	return false
}

func (c *sfConn) tableName(t Table) string {
	return c.db + "." + sfQuote(t.Schema) + "." + sfQuote(t.Name)
}

func (c *sfConn) Columns(ctx context.Context, t Table) ([]Column, error) {
	var out []Column
	err := c.run(ctx, "SHOW COLUMNS IN TABLE "+c.tableName(t), nil, func(cols map[string]int, row []*string) error {
		name, ok := col(cols, row, "column_name")
		if !ok {
			return nil
		}
		var st sfType
		if raw, ok := col(cols, row, "data_type"); ok {
			_ = json.Unmarshal([]byte(raw), &st)
		}
		typ := st.name()
		out = append(out, Column{Name: name, DataType: typ, Nullable: st.Nullable, Sampleable: sfSampleable(typ)})
		return nil
	})
	if err != nil {
		return nil, wrap("columns", err, true)
	}
	return out, nil
}

// Sample reads up to rows rows as text; it needs a warehouse.
func (c *sfConn) Sample(ctx context.Context, t Table, cols []Column, rows int, visit func(int, string, bool)) error {
	var idx []int
	var exprs []string
	for i, col := range cols {
		if col.Sampleable && validName(col.Name) {
			idx = append(idx, i)
			exprs = append(exprs, "TO_VARCHAR("+sfQuote(col.Name)+")")
		}
	}
	if len(idx) == 0 || rows <= 0 {
		return nil
	}
	if c.t.Warehouse == "" {
		return &Error{Kind: KindConfig, Op: "sample (a Snowflake source needs a warehouse to sample)", Safe: true}
	}
	// rows is the local configuration's number (1 to 10000), never the platform's.
	query := "SELECT " + strings.Join(exprs, ", ") + " FROM " + c.tableName(t) + " LIMIT " + strconv.Itoa(rows)
	n := 0
	err := c.run(ctx, query, nil, func(_ map[string]int, row []*string) error {
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
