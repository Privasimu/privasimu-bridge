package dbsource

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/privasimu/bridge/internal/config"
)

// chConn reads ClickHouse over its HTTP interface, with the standard library only (no
// driver to link). Every request is a GET: for a GET the server itself makes the query
// read-only (it raises readonly to 2, which still allows the settings below), so even an
// account that may write cannot write through the bridge. Each request carries settings
// that bound it on the server: max_execution_time at the source's timeout,
// cancel_http_readonly_queries_on_client_close so that a cancelled request stops its
// query, and for sampling max_result_rows. Values from the catalog are bound as query
// parameters ({name:String}), the password travels in a header (never in the URL), and
// environment proxies are not used for database traffic.
type chConn struct {
	t       Target
	base    string
	client  *http.Client
	version string
	tls     *bool
}

// chMaxAnswer bounds one HTTP answer of ClickHouse.
const chMaxAnswer = 64 << 20

// chViews are the table engines that hold no data of their own.
const chViews = `('View', 'MaterializedView', 'LiveView', 'WindowView', 'Dictionary')`

// chError is an error answer of ClickHouse: its exception code and the first line of its
// text (operators see the text only for connection and catalog errors; see Error.Safe).
type chError struct {
	Code   int
	Status int
	Text   string
}

func (e *chError) Error() string {
	return fmt.Sprintf("clickhouse: HTTP %d, code %d: %s", e.Status, e.Code, e.Text)
}

var chCode = regexp.MustCompile(`Code: (\d+)`)

// ClickHouse exception codes the bridge classifies.
const (
	chUnknownTable       = 60
	chUnknownDatabase    = 81
	chTimeoutExceeded    = 159
	chReadonly           = 164
	chUnknownUser        = 192
	chWrongPassword      = 193
	chRequiredPassword   = 194
	chSocketTimeout      = 209
	chDatabaseDenied     = 291
	chQueryCancelled     = 394
	chAccessDenied       = 497
	chAuthenticationFail = 516
)

// classifyClickHouse maps a ClickHouse error to a kind ("" when err is not one).
func classifyClickHouse(err error) string {
	var ch *chError
	if !errors.As(err, &ch) {
		return ""
	}
	switch ch.Code {
	case chAuthenticationFail, chUnknownUser, chWrongPassword, chRequiredPassword:
		return KindAuth
	case chAccessDenied, chReadonly, chDatabaseDenied:
		return KindPermission
	case chUnknownDatabase, chUnknownTable:
		return KindNotFound
	case chTimeoutExceeded, chSocketTimeout, chQueryCancelled:
		return KindTimeout
	}
	switch {
	case ch.Code != 0:
		return KindDatabase
	case ch.Status == http.StatusUnauthorized:
		return KindAuth
	case ch.Status == http.StatusForbidden:
		return KindPermission
	}
	return KindDatabase
}

// quoteClickHouse quotes an identifier with backquotes; a backslash escapes.
func quoteClickHouse(id string) string {
	return "`" + strings.NewReplacer(`\`, `\\`, "`", "\\`").Replace(id) + "`"
}

func openClickHouse(ctx context.Context, t Target) (Conn, error) {
	if t.Port < 1 || t.Port > 65535 {
		return nil, &Error{Kind: KindConfig, Op: "config", Cause: errors.New("port out of range"), Safe: true}
	}
	scheme, tlsOn := "http", false
	transport := &http.Transport{
		Proxy:                 nil,
		MaxConnsPerHost:       t.MaxOpen,
		MaxIdleConnsPerHost:   t.MaxOpen,
		IdleConnTimeout:       time.Minute,
		ResponseHeaderTimeout: t.Timeout + 5*time.Second,
		TLSHandshakeTimeout:   t.Timeout,
	}
	switch t.TLS.Mode {
	case config.DBTLSDisable, "":
	default:
		cfg, err := t.TLS.TLSConfig(t.Host)
		if err != nil {
			return nil, err
		}
		transport.TLSClientConfig = cfg
		scheme, tlsOn = "https", true
	}
	dialer := &net.Dialer{Timeout: t.Timeout, KeepAlive: 30 * time.Second}
	transport.DialContext = dialer.DialContext
	if t.Dial != nil {
		transport.DialContext = t.Dial
	}
	c := &chConn{t: t, base: scheme + "://" + net.JoinHostPort(t.Host, strconv.Itoa(t.Port)) + "/", tls: &tlsOn,
		client: &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		}}}
	var version string
	err := c.rows(ctx, "SELECT version()", nil, nil, func(row []*string) error {
		if len(row) > 0 && row[0] != nil {
			version = *row[0]
		}
		return nil
	})
	if err != nil {
		transport.CloseIdleConnections()
		return nil, wrap("connect", err, true)
	}
	c.version = "ClickHouse " + version
	return c, nil
}

// rows runs a read-only query and calls fn for each row (every value as text or null).
func (c *chConn) rows(ctx context.Context, query string, params, settings map[string]string, fn func([]*string) error) error {
	ctx, cancel := context.WithTimeout(ctx, c.t.Timeout+5*time.Second)
	defer cancel()
	q := url.Values{}
	q.Set("query", query)
	q.Set("database", c.t.Database)
	q.Set("default_format", "JSONCompactEachRow")
	q.Set("max_execution_time", strconv.Itoa(max(1, int(c.t.Timeout.Seconds()))))
	q.Set("cancel_http_readonly_queries_on_client_close", "1")
	// The whole answer is formed before it is sent, so that an error is an HTTP error and
	// not a truncated answer; catalog and sample answers are small.
	q.Set("wait_end_of_query", "1")
	for k, v := range settings {
		q.Set(k, v)
	}
	for k, v := range params {
		q.Set("param_"+k, v)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+"?"+q.Encode(), nil)
	if err != nil {
		return err
	}
	req.Header.Set("X-ClickHouse-User", c.t.Username)
	if p := c.t.Password.Reveal(); p != "" {
		req.Header.Set("X-ClickHouse-Key", p)
	}
	req.Header.Set("User-Agent", "privasimu-bridge")
	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body := io.LimitReader(resp.Body, chMaxAnswer+1)
	if resp.StatusCode != http.StatusOK {
		text, _ := io.ReadAll(io.LimitReader(body, 4096))
		e := &chError{Status: resp.StatusCode, Text: oneLine(string(text))}
		if code, err := strconv.Atoi(resp.Header.Get("X-ClickHouse-Exception-Code")); err == nil {
			e.Code = code
		} else if m := chCode.FindSubmatch(text); m != nil {
			e.Code, _ = strconv.Atoi(string(m[1]))
		}
		return e
	}
	counter := &countingReader{r: body}
	dec := json.NewDecoder(counter)
	for {
		var row []*string
		if err := dec.Decode(&row); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			if counter.n > chMaxAnswer {
				return errors.New("clickhouse: the answer is larger than 64 MiB")
			}
			// Never quote the answer: it can hold values.
			return errors.New("clickhouse: the answer is not JSONCompactEachRow")
		}
		if err := fn(row); err != nil {
			return err
		}
	}
	if counter.n > chMaxAnswer {
		return errors.New("clickhouse: the answer is larger than 64 MiB")
	}
	return nil
}

// countingReader counts the bytes read through it.
type countingReader struct {
	r io.Reader
	n int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

func (c *chConn) Engine() string                       { return "clickhouse" }
func (c *chConn) ServerVersion(context.Context) string { return c.version }
func (c *chConn) DefaultSchema() string                { return c.t.Database }
func (c *chConn) TLSInUse() *bool                      { return c.tls }

func (c *chConn) Close() error {
	c.client.CloseIdleConnections()
	return nil
}

// inList returns "{s0:String}, {s1:String}, ..." and the parameters for a list of names.
func inList(prefix string, names []string, params map[string]string) string {
	parts := make([]string, len(names))
	for i, n := range names {
		key := prefix + strconv.Itoa(i)
		parts[i] = "{" + key + ":String}"
		params[key] = n
	}
	return strings.Join(parts, ", ")
}

const chTables = `SELECT database, name, toString(total_rows) FROM system.tables WHERE is_temporary = 0 AND engine NOT IN ` + chViews

func (c *chConn) ListTables(ctx context.Context, schema string) ([]Table, error) {
	schemas, err := listingSchemas(c.t, schema)
	if err != nil {
		return nil, err
	}
	if len(schemas) == 0 {
		schemas = []string{c.t.Database} // a ClickHouse database is a schema; the configured one
	}
	params := map[string]string{}
	query := chTables + " AND database IN (" + inList("s", schemas, params) + ") ORDER BY database, name"
	var out []Table
	err = c.rows(ctx, query, params, nil, func(row []*string) error {
		if t, ok := c.table(row, schema); ok {
			out = append(out, t)
		}
		return nil
	})
	if err != nil {
		return nil, wrap("list tables", err, true)
	}
	sortTables(out, c.t.Database)
	return out, nil
}

// table reads a (database, name, total_rows) row.
func (c *chConn) table(row []*string, requested string) (Table, bool) {
	if len(row) < 3 || row[0] == nil || row[1] == nil || !validName(*row[0]) || !validName(*row[1]) {
		return Table{}, false
	}
	t := Table{Schema: *row[0], Name: *row[1], Ref: tableRef(c.t.Database, *row[0], *row[1], requested)}
	if row[2] != nil {
		if n, err := strconv.ParseInt(*row[2], 10, 64); err == nil && n >= 0 {
			t.RowEstimate = &n
		}
	}
	return t, true
}

func (c *chConn) FindTable(ctx context.Context, ref, schema string) (Table, bool, error) {
	if !validName(ref) {
		return Table{}, false, nil
	}
	for _, cand := range lookupCandidates(c.t, c.t.Database, ref, schema) {
		params := map[string]string{"s": cand.schema, "n": cand.name}
		var found *Table
		err := c.rows(ctx, chTables+" AND database = {s:String} AND name = {n:String}", params, nil, func(row []*string) error {
			if t, ok := c.table(row, ""); ok && found == nil {
				t.Ref = ref
				found = &t
			}
			return nil
		})
		if err != nil {
			return Table{}, false, wrap("find table", err, true)
		}
		if found != nil {
			return *found, true, nil
		}
	}
	return Table{}, false, nil
}

func (c *chConn) Columns(ctx context.Context, t Table) ([]Column, error) {
	var out []Column
	err := c.rows(ctx, `SELECT name, type, if(position(type, 'Nullable(') > 0, 'YES', 'NO') FROM system.columns
WHERE database = {s:String} AND table = {n:String} ORDER BY position`, map[string]string{"s": t.Schema, "n": t.Name}, nil,
		func(row []*string) error {
			if len(row) < 3 || row[0] == nil || row[1] == nil {
				return nil
			}
			typ := strings.ToLower(*row[1])
			nullable := row[2] != nil && *row[2] == "YES"
			out = append(out, Column{Name: *row[0], DataType: typ, Nullable: &nullable, Sampleable: chSampleable(typ)})
			return nil
		})
	if err != nil {
		return nil, wrap("columns", err, true)
	}
	return out, nil
}

// chSampleable reports whether values of a (lower-case) ClickHouse type are read as text:
// strings, 64-bit and wider integers, decimals and JSON, also inside Nullable,
// LowCardinality and arrays.
func chSampleable(t string) bool {
	for _, w := range []string{"string", "int64", "int128", "int256", "decimal", "json", "object("} {
		if strings.Contains(t, w) {
			return true
		}
	}
	return false
}

// Sample reads up to rows rows as text; errors never carry ClickHouse's text, which can
// quote a value.
func (c *chConn) Sample(ctx context.Context, t Table, cols []Column, rows int, visit func(int, string, bool)) error {
	var idx []int
	var exprs []string
	for i, col := range cols {
		if col.Sampleable && validName(col.Name) {
			idx = append(idx, i)
			exprs = append(exprs, "toString("+quoteClickHouse(col.Name)+")")
		}
	}
	if len(idx) == 0 || rows <= 0 {
		return nil
	}
	query := "SELECT " + strings.Join(exprs, ", ") + " FROM " + quoteClickHouse(t.Schema) + "." + quoteClickHouse(t.Name) +
		" LIMIT {limit:UInt32}"
	settings := map[string]string{"max_result_rows": strconv.Itoa(rows), "result_overflow_mode": "break"}
	n := 0
	err := c.rows(ctx, query, map[string]string{"limit": strconv.Itoa(rows)}, settings, func(row []*string) error {
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
