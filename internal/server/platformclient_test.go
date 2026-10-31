package server

// platformClient re-implements, for tests, what the Privasimu platform does when it calls
// a bridge with contract v1: backend-go internal/dbscan/bridge.go and bridge_types.go, and
// Laravel App\Services\Discovery\Bridge\BridgeClient.php and BridgeSourceTypes.php. The
// rules below are copied from that code: the request body (db_type plus the mapped
// fields), the headers, the status-to-kind mapping, the retry rules, the response checks,
// the 4 MiB cap, the limits (500 tables, 1000 columns) and the concurrency of 4.
//
// The two platform lines send and read the same contract, but not the same bytes; line
// selects which one is replayed:
//   - lineGo: encoding/json body (keys sorted), Go's transport adds Accept-Encoding: gzip,
//     column calls in a sliding window of 4, typed JSON decoding (invalid UTF-8 becomes
//     U+FFFD).
//   - lineLaravel: json_encode body (db_type first, then registry order; "/" and
//     non-ASCII escaped), no Accept-Encoding (decode_content false), column calls in
//     chunks of 4 that each wait for the slowest call (Http::pool over array_chunk),
//     json_decode that rejects a whole response containing invalid UTF-8.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf16"
	"unicode/utf8"
)

const (
	lineGo      = "go"
	lineLaravel = "laravel"
)

// laravelOrder is the order in which BridgeClient.php builds the body: db_type, the
// registry fields (relational fields, then the type's extras) and table_name last.
var laravelOrder = []string{"db_type", "host", "port", "database", "user", "password", "schema_name", "use_ssl",
	"instance_name", "odbc_driver", "trust_server_certificate", "service_name", "sid", "warehouse", "role", "table_name"}

// phpString encodes s the way PHP's json_encode does with default flags: "/" is escaped
// and every non-ASCII character becomes \uXXXX (UTF-16, with surrogate pairs).
func phpString(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch {
		case r == '"':
			b.WriteString(`\"`)
		case r == '\\':
			b.WriteString(`\\`)
		case r == '/':
			b.WriteString(`\/`)
		case r == '\n':
			b.WriteString(`\n`)
		case r == '\r':
			b.WriteString(`\r`)
		case r == '\t':
			b.WriteString(`\t`)
		case r < 0x20:
			fmt.Fprintf(&b, `\u%04x`, r)
		case r < 0x80:
			b.WriteRune(r)
		default:
			for _, u := range utf16.Encode([]rune{r}) {
				fmt.Fprintf(&b, `\u%04x`, u)
			}
		}
	}
	b.WriteByte('"')
	return b.String()
}

// phpBody encodes a request body as Laravel sends it.
func phpBody(body map[string]any) []byte {
	var b strings.Builder
	b.WriteByte('{')
	first := true
	for _, k := range laravelOrder {
		v, ok := body[k]
		if !ok {
			continue
		}
		if !first {
			b.WriteByte(',')
		}
		first = false
		b.WriteString(phpString(k))
		b.WriteByte(':')
		switch t := v.(type) {
		case string:
			b.WriteString(phpString(t))
		case int:
			b.WriteString(strconv.Itoa(t))
		case bool:
			b.WriteString(strconv.FormatBool(t))
		default:
			panic(fmt.Sprintf("unexpected body value %T", v))
		}
	}
	b.WriteByte('}')
	return []byte(b.String())
}

const (
	pcMaxResponse = 4 << 20
	pcMaxTables   = 500
	pcMaxColumns  = 1000
)

// Kinds the platform stores (Go dbscan Kind*, Laravel BridgeClient::KIND_*).
const (
	pcKindConfig      = "config"
	pcKindAuth        = "auth"
	pcKindTLS         = "tls"
	pcKindTimeout     = "timeout"
	pcKindUnavailable = "bridge_unavailable"
	pcKindRejected    = "bridge_rejected"
	pcKindContract    = "bridge_contract"
	pcKindIncomplete  = "bridge_incomplete"
	pcKindLimit       = "limit"
)

type pcField struct {
	from, to, kind string
	required       bool
	group          string
	maxLen         int
	pattern        *regexp.Regexp
	oneOf          []string
}

var (
	pcIdentifier = regexp.MustCompile(`^[A-Za-z0-9_.$@\-]+$`)
	pcHostName   = regexp.MustCompile(`^[A-Za-z0-9._:\-\[\]]+$`)
)

func pcRelational(extra ...pcField) []pcField {
	return append([]pcField{
		{from: "host", to: "host", kind: "string", required: true, maxLen: 255, pattern: pcHostName},
		{from: "port", to: "port", kind: "int"},
		{from: "database", to: "database", kind: "string", required: true, pattern: pcIdentifier},
		{from: "username", to: "user", kind: "string", required: true},
		{from: "password", to: "password", kind: "string", required: true, maxLen: 256},
		{from: "schema", to: "schema_name", kind: "string", pattern: pcIdentifier},
		{from: "use_ssl", to: "use_ssl", kind: "bool"},
	}, extra...)
}

// pcRegistry is the platform's bridge source type registry (postgresql, mysql, mssql,
// oracle; snowflake, db2 and db2i are not served by this bridge).
var pcRegistry = map[string][]pcField{
	"postgresql": pcRelational(),
	"mysql":      pcRelational(),
	"mssql": pcRelational(
		pcField{from: "instance_name", to: "instance_name", kind: "string", pattern: pcIdentifier},
		pcField{from: "odbc_driver", to: "odbc_driver", kind: "string", oneOf: []string{"ODBC Driver 17 for SQL Server", "ODBC Driver 18 for SQL Server"}},
		pcField{from: "trust_server_certificate", to: "trust_server_certificate", kind: "bool"},
	),
	"oracle": pcRelational(
		pcField{from: "service_name", to: "service_name", kind: "string", group: "oracle-target", pattern: pcIdentifier},
		pcField{from: "sid", to: "sid", kind: "string", group: "oracle-target", pattern: pcIdentifier},
	),
	"snowflake": pcRelational(),
	"db2":       pcRelational(),
}

type platformClient struct {
	client      *http.Client
	callTimeout time.Duration
	deadline    time.Duration
	retryDelay  time.Duration
	concurrency int
	line        string
}

// forLine returns a copy of the client that behaves like one platform line. The Laravel
// client gets a transport without automatic compression, so no Accept-Encoding is sent.
func (p *platformClient) forLine(line string) *platformClient {
	c := *p
	c.line = line
	if line == lineLaravel {
		if tr, ok := p.client.Transport.(*http.Transport); ok {
			tr2 := tr.Clone()
			tr2.DisableCompression = true
			hc := *p.client
			hc.Transport = tr2
			c.client = &hc
		}
	}
	return &c
}

type pcFailure struct {
	kind      string
	retryable bool
	status    int
}

func configText(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64)
	case int:
		return strconv.Itoa(t)
	case bool:
		return strconv.FormatBool(t)
	}
	return ""
}

// body builds the request body like settingsFor: only declared fields are sent.
func (p *platformClient) body(sourceType string, cfg map[string]any) (map[string]any, *pcFailure) {
	fields, ok := pcRegistry[sourceType]
	if !ok {
		return nil, &pcFailure{kind: pcKindConfig}
	}
	body := map[string]any{"db_type": sourceType}
	groups, seen := map[string]bool{}, map[string]bool{}
	for _, f := range fields {
		raw := configText(cfg[f.from])
		text := strings.TrimSpace(raw)
		if f.to == "password" {
			text = raw
		}
		if f.group != "" {
			groups[f.group] = true
			if text != "" {
				seen[f.group] = true
			}
		}
		if text == "" {
			if f.required {
				return nil, &pcFailure{kind: pcKindConfig}
			}
			continue
		}
		switch f.kind {
		case "int":
			n, err := strconv.Atoi(text)
			if err != nil || n < 1 || n > 65535 {
				return nil, &pcFailure{kind: pcKindConfig}
			}
			body[f.to] = n
		case "bool":
			body[f.to] = text == "true" || text == "1"
		default:
			max := f.maxLen
			if max == 0 {
				max = 128
			}
			if len(text) > max {
				return nil, &pcFailure{kind: pcKindConfig}
			}
			if len(f.oneOf) > 0 {
				found := false
				for _, o := range f.oneOf {
					found = found || o == text
				}
				if !found {
					return nil, &pcFailure{kind: pcKindConfig}
				}
			} else if f.pattern != nil && !f.pattern.MatchString(text) {
				return nil, &pcFailure{kind: pcKindConfig}
			}
			body[f.to] = text
		}
	}
	for g := range groups {
		if !seen[g] {
			return nil, &pcFailure{kind: pcKindConfig}
		}
	}
	return body, nil
}

func (p *platformClient) post(ctx context.Context, url, apiKey string, body map[string]any, out any) *pcFailure {
	payload, _ := json.Marshal(body)
	if p.line == lineLaravel {
		payload = phpBody(body)
	}
	ctx, cancel := context.WithTimeout(ctx, p.callTimeout)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-API-Key", apiKey)
	req.Header.Set("X-Contract-Version", "1")
	req.Header.Set("User-Agent", "privasimu-nexus-discovery")
	resp, err := p.client.Do(req)
	if err != nil {
		var ne net.Error
		msg := strings.ToLower(err.Error())
		switch {
		case errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &ne) && ne.Timeout()):
			return &pcFailure{kind: pcKindTimeout, retryable: true}
		case strings.Contains(msg, "x509") || strings.Contains(msg, "tls") || strings.Contains(msg, "certificate"):
			return &pcFailure{kind: pcKindTLS}
		}
		return &pcFailure{kind: pcKindUnavailable, retryable: true}
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, pcMaxResponse+1))
	if err != nil {
		return &pcFailure{kind: pcKindUnavailable, retryable: true}
	}
	switch {
	case resp.StatusCode == 401 || resp.StatusCode == 403:
		return &pcFailure{kind: pcKindAuth, status: resp.StatusCode}
	case resp.StatusCode >= 500:
		return &pcFailure{kind: pcKindUnavailable, retryable: true, status: resp.StatusCode}
	case resp.StatusCode < 200 || resp.StatusCode > 299:
		return &pcFailure{kind: pcKindRejected, status: resp.StatusCode}
	}
	if len(data) > pcMaxResponse {
		return &pcFailure{kind: pcKindContract}
	}
	if p.line == lineLaravel && !utf8.Valid(data) {
		return &pcFailure{kind: pcKindContract} // json_decode: JSON_ERROR_UTF8
	}
	if err := json.Unmarshal(data, out); err != nil {
		return &pcFailure{kind: pcKindContract}
	}
	return nil
}

type pcNames struct {
	Status        *string   `json:"status"`
	TablesScanned *int      `json:"tables_scanned"`
	Results       *[]string `json:"results"`
}

type pcColumn struct {
	ColumnName  *string `json:"column_name"`
	IsPII       *bool   `json:"is_pii"`
	PDPCategory *string `json:"pdp_category"`
}

type pcColumns struct {
	Status        *string     `json:"status"`
	Table         *string     `json:"table"`
	ColumnDetails *[]pcColumn `json:"column_details"`
}

func pcValidName(s string, max int) bool {
	if s == "" || len(s) > max {
		return false
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

func (p *platformClient) listTables(ctx context.Context, base, key string, body map[string]any) ([]string, int, *pcFailure) {
	var failure *pcFailure
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return nil, 0, &pcFailure{kind: pcKindTimeout}
			case <-time.After(p.retryDelay * time.Duration(attempt)):
			}
		}
		var resp pcNames
		failure = p.post(ctx, base+"/v1/name-database-tabels", key, body, &resp)
		if failure == nil {
			if resp.Status == nil || *resp.Status != "success" || resp.Results == nil || resp.TablesScanned == nil {
				return nil, 0, &pcFailure{kind: pcKindContract}
			}
			return *resp.Results, *resp.TablesScanned, nil
		}
		if !failure.retryable {
			break
		}
	}
	return nil, 0, failure
}

type pcTestResult struct {
	Success     bool
	TablesFound int
	Kind        string
	Attempts    int
}

// Test is the platform's connection test: one table list.
func (p *platformClient) Test(ctx context.Context, base, key, sourceType string, cfg map[string]any) pcTestResult {
	body, f := p.body(sourceType, cfg)
	if f != nil {
		return pcTestResult{Kind: f.kind}
	}
	names, scanned, f := p.listTables(ctx, base, key, body)
	if f != nil {
		return pcTestResult{Kind: f.kind}
	}
	return pcTestResult{Success: true, TablesFound: max(scanned, len(names))}
}

type pcTable struct {
	Name    string
	Columns []pcColumn
}

type pcFailed struct{ Name, Kind string }

type pcOutcome struct {
	Tables []pcTable
	Failed []pcFailed
	Kind   string
}

// Scan is the platform's scan: the table list, then one column call per table, at most
// four at a time, keeping only column_name, is_pii and pdp_category.
func (p *platformClient) Scan(ctx context.Context, base, key, sourceType string, cfg map[string]any) pcOutcome {
	body, f := p.body(sourceType, cfg)
	if f != nil {
		return pcOutcome{Kind: f.kind}
	}
	ctx, cancel := context.WithTimeout(ctx, p.deadline)
	defer cancel()
	names, reported, f := p.listTables(ctx, base, key, body)
	if f != nil {
		return pcOutcome{Kind: f.kind}
	}
	var out pcOutcome
	if len(names) != reported {
		out.Failed = append(out.Failed, pcFailed{"*", pcKindIncomplete})
	}
	valid := names[:0:0]
	for _, n := range names {
		if pcValidName(n, 255) {
			valid = append(valid, n)
		}
	}
	if len(valid) != len(names) {
		out.Failed = append(out.Failed, pcFailed{"*", pcKindContract})
	}
	names = valid
	if len(names) > pcMaxTables {
		names = names[:pcMaxTables]
		out.Failed = append(out.Failed, pcFailed{"*", pcKindLimit})
	}
	type result struct {
		cols []pcColumn
		f    *pcFailure
	}
	results := make([]result, len(names))
	sem := make(chan struct{}, p.concurrency)
	var wg sync.WaitGroup
	for i, name := range names {
		if p.line == lineLaravel && i > 0 && i%p.concurrency == 0 {
			wg.Wait() // Http::pool over array_chunk: the next chunk starts when this one ends
		}
		sem <- struct{}{}
		wg.Add(1)
		go func(i int, name string) {
			defer wg.Done()
			defer func() { <-sem }()
			b := map[string]any{"table_name": name}
			for k, v := range body {
				b[k] = v
			}
			var resp pcColumns
			if f := p.post(ctx, base+"/v2/scan-table-columns", key, b, &resp); f != nil {
				results[i] = result{f: f}
				return
			}
			if resp.Status == nil || *resp.Status != "success" || resp.ColumnDetails == nil || resp.Table == nil || *resp.Table != name {
				results[i] = result{f: &pcFailure{kind: pcKindContract}}
				return
			}
			for _, c := range *resp.ColumnDetails {
				if c.ColumnName == nil || c.IsPII == nil || !pcValidName(*c.ColumnName, 255) {
					results[i] = result{f: &pcFailure{kind: pcKindContract}}
					return
				}
				if c.PDPCategory != nil && !pcValidName(*c.PDPCategory, 64) {
					c.PDPCategory = nil
				}
				results[i].cols = append(results[i].cols, c)
			}
		}(i, name)
	}
	wg.Wait()
	for i, r := range results {
		if r.f != nil && r.f.kind == pcKindAuth {
			return pcOutcome{Kind: pcKindAuth}
		}
		if r.f != nil {
			out.Failed = append(out.Failed, pcFailed{names[i], pcKindIncomplete})
			continue
		}
		cols := r.cols
		if len(cols) > pcMaxColumns {
			cols = cols[:pcMaxColumns]
			out.Failed = append(out.Failed, pcFailed{names[i], pcKindLimit})
		}
		out.Tables = append(out.Tables, pcTable{Name: names[i], Columns: cols})
	}
	if len(names) > 0 && len(out.Tables) == 0 {
		return pcOutcome{Kind: pcKindIncomplete}
	}
	return out
}
