package dbsource

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"strings"
	"time"
)

// athenaConn reads the catalog of Amazon Athena (the AWS Glue Data Catalog or another data
// catalog) through Athena's metadata API: ListDatabases, ListTableMetadata and
// GetTableMetadata, signed with AWS Signature Version 4 on this server (the standard
// library only; the AWS SDK would add some 5 MB). It runs no query: every Athena query
// writes its result to an S3 bucket, so the bridge reads names and types only and never
// samples values. The IAM principal needs only the athena:List*/Get*Metadata actions and
// glue:GetDatabase(s)/GetTable(s).
type athenaConn struct {
	t         Target
	client    *http.Client
	base      string
	catalog   string
	databases []string
	now       func() time.Time
}

func openAthena(ctx context.Context, t Target) (Conn, error) {
	client, err := cloudClient(t)
	if err != nil {
		return nil, err
	}
	c := &athenaConn{t: t, client: client, base: "https://athena." + t.Region + ".amazonaws.com", catalog: t.Database, now: time.Now}
	if c.catalog == "" {
		c.catalog = "AwsDataCatalog"
	}
	if t.endpoint != "" {
		c.base = t.endpoint
	}
	if err := c.loadDatabases(ctx); err != nil {
		client.CloseIdleConnections()
		return nil, wrap("connect", err, true)
	}
	return c, nil
}

// athenaParseError reads {"__type": "...#Code", "Message"|"message"}.
func athenaParseError(e *cloudError, body []byte) {
	var a struct {
		Type     string `json:"__type"`
		Message  string `json:"Message"`
		Message2 string `json:"message"`
	}
	if json.Unmarshal(body, &a) == nil {
		e.Code = a.Type[strings.LastIndex(a.Type, "#")+1:]
		e.Message = a.Message + a.Message2
	}
	switch e.Code {
	case "UnrecognizedClientException", "InvalidSignatureException", "ExpiredTokenException", "InvalidClientTokenId",
		"IncompleteSignature", "MissingAuthenticationToken":
		e.Kind = KindAuth
	case "AccessDeniedException":
		e.Kind = KindPermission
	case "ThrottlingException", "TooManyRequestsException":
		e.Kind = KindUnreachable
	case "MetadataException", "InvalidRequestException":
		if strings.Contains(strings.ToLower(e.Message), "not found") {
			e.Kind = KindNotFound
		}
	}
}

// call sends one signed request of the Athena API.
func (c *athenaConn) call(ctx context.Context, action string, in, out any) error {
	ctx, cancel := context.WithTimeout(ctx, c.t.Timeout)
	defer cancel()
	payload, err := json.Marshal(in)
	if err != nil {
		return err
	}
	return withRetry(ctx, func() error {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+"/", bytes.NewReader(payload))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/x-amz-json-1.1")
		req.Header.Set("X-Amz-Target", "AmazonAthena."+action)
		req.Header.Set("User-Agent", "privasimu-bridge")
		signAWSRequest(req, payload, c.t.Username, c.t.Password.Reveal(), c.t.SessionToken.Reveal(), c.t.Region, "athena", c.now())
		return cloudDo(c.client, req, "athena", out, athenaParseError)
	})
}

// signAWSRequest adds the AWS Signature Version 4 headers to a request whose path is "/"
// and which has no query string.
func signAWSRequest(req *http.Request, payload []byte, accessKey, secretKey, sessionToken, region, service string, now time.Time) {
	amzDate := now.UTC().Format("20060102T150405Z")
	req.Header.Set("X-Amz-Date", amzDate)
	if sessionToken != "" {
		req.Header.Set("X-Amz-Security-Token", sessionToken)
	}
	headers := map[string]string{"host": req.URL.Host}
	for k, v := range req.Header {
		if lk := strings.ToLower(k); lk == "content-type" || strings.HasPrefix(lk, "x-amz-") {
			headers[lk] = strings.Join(v, ",")
		}
	}
	signed, signature := awsSignature(req.Method, req.URL.EscapedPath(), req.URL.RawQuery, headers, payload, secretKey, region, service, amzDate)
	req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential="+accessKey+"/"+amzDate[:8]+"/"+region+"/"+service+
		"/aws4_request, SignedHeaders="+signed+", Signature="+signature)
}

// awsSignature computes the signed header list and the signature of Signature Version 4.
// headers have lower-case names; query is already in canonical form.
func awsSignature(method, path, query string, headers map[string]string, payload []byte, secretKey, region, service, amzDate string) (string, string) {
	if path == "" {
		path = "/"
	}
	names := make([]string, 0, len(headers))
	for k := range headers {
		names = append(names, k)
	}
	sort.Strings(names)
	var canonHeaders strings.Builder
	for _, k := range names {
		canonHeaders.WriteString(k + ":" + strings.Join(strings.Fields(headers[k]), " ") + "\n")
	}
	signed := strings.Join(names, ";")
	payloadHash := sha256.Sum256(payload)
	canonical := method + "\n" + path + "\n" + query + "\n" + canonHeaders.String() + "\n" + signed + "\n" + hex.EncodeToString(payloadHash[:])
	canonicalHash := sha256.Sum256([]byte(canonical))
	scope := amzDate[:8] + "/" + region + "/" + service + "/aws4_request"
	toSign := "AWS4-HMAC-SHA256\n" + amzDate + "\n" + scope + "\n" + hex.EncodeToString(canonicalHash[:])
	key := hmacSHA256([]byte("AWS4"+secretKey), amzDate[:8])
	key = hmacSHA256(key, region)
	key = hmacSHA256(key, service)
	key = hmacSHA256(key, "aws4_request")
	return signed, hex.EncodeToString(hmacSHA256(key, toSign))
}

func hmacSHA256(key []byte, data string) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(data))
	return m.Sum(nil)
}

// loadDatabases fixes the databases a listing covers: the allow-list, or every database of
// the catalog.
func (c *athenaConn) loadDatabases(ctx context.Context) error {
	var all []string
	next := ""
	for {
		in := map[string]any{"CatalogName": c.catalog, "MaxResults": 50}
		if next != "" {
			in["NextToken"] = next
		}
		var out struct {
			DatabaseList []struct {
				Name string `json:"Name"`
			} `json:"DatabaseList"`
			NextToken string `json:"NextToken"`
		}
		if err := c.call(ctx, "ListDatabases", in, &out); err != nil {
			return err
		}
		for _, d := range out.DatabaseList {
			if validName(d.Name) && c.t.schemaAllowed(d.Name) {
				all = append(all, d.Name)
			}
		}
		if next = out.NextToken; next == "" || len(all) > 10000 {
			break
		}
	}
	sort.Strings(all)
	c.databases = all
	return nil
}

func (c *athenaConn) Engine() string                       { return "athena" }
func (c *athenaConn) ServerVersion(context.Context) string { return "Amazon Athena" }
func (c *athenaConn) TLSInUse() *bool                      { on := true; return &on }

// DefaultSchema is the only database of the allow-list, else none.
func (c *athenaConn) DefaultSchema() string {
	if len(c.t.Schemas) == 1 {
		return c.t.Schemas[0]
	}
	return ""
}

func (c *athenaConn) Close() error {
	c.client.CloseIdleConnections()
	return nil
}

// athenaTable is a table of the metadata API.
type athenaTable struct {
	Name          string         `json:"Name"`
	TableType     string         `json:"TableType"`
	Columns       []athenaColumn `json:"Columns"`
	PartitionKeys []athenaColumn `json:"PartitionKeys"`
}

type athenaColumn struct {
	Name string `json:"Name"`
	Type string `json:"Type"`
}

func (c *athenaConn) ListTables(ctx context.Context, schema string) ([]Table, error) {
	databases, err := listingSchemas(c.t, schema)
	if err != nil {
		return nil, err
	}
	if len(databases) == 0 {
		databases = c.databases
	}
	var out []Table
	for _, db := range databases {
		next := ""
		for {
			in := map[string]any{"CatalogName": c.catalog, "DatabaseName": db, "MaxResults": 50}
			if next != "" {
				in["NextToken"] = next
			}
			var page struct {
				TableMetadataList []athenaTable `json:"TableMetadataList"`
				NextToken         string        `json:"NextToken"`
			}
			if err := c.call(ctx, "ListTableMetadata", in, &page); err != nil {
				return nil, wrap("list tables", err, true)
			}
			for _, tb := range page.TableMetadataList {
				if tb.TableType != "VIRTUAL_VIEW" && validName(tb.Name) {
					out = append(out, Table{Schema: db, Name: tb.Name, Ref: tableRef(c.DefaultSchema(), db, tb.Name, schema)})
				}
			}
			if next = page.NextToken; next == "" || len(out) > 20000 {
				break
			}
		}
	}
	sortTables(out, c.DefaultSchema())
	return out, nil
}

func (c *athenaConn) table(ctx context.Context, db, name string) (*athenaTable, error) {
	var out struct {
		TableMetadata athenaTable `json:"TableMetadata"`
	}
	err := c.call(ctx, "GetTableMetadata", map[string]any{"CatalogName": c.catalog, "DatabaseName": db, "TableName": name}, &out)
	if err != nil {
		return nil, err
	}
	return &out.TableMetadata, nil
}

func (c *athenaConn) FindTable(ctx context.Context, ref, schema string) (Table, bool, error) {
	if !validName(ref) {
		return Table{}, false, nil
	}
	for _, cand := range lookupCandidates(c.t, c.DefaultSchema(), ref, schema) {
		tb, err := c.table(ctx, cand.schema, cand.name)
		var ce *cloudError
		if errors.As(err, &ce) && (ce.Kind == KindNotFound || ce.Code == "MetadataException") {
			continue
		}
		if err != nil {
			return Table{}, false, wrap("find table", err, true)
		}
		if tb.TableType == "VIRTUAL_VIEW" {
			continue
		}
		return Table{Schema: cand.schema, Name: cand.name, Ref: ref}, true, nil
	}
	return Table{}, false, nil
}

func (c *athenaConn) Columns(ctx context.Context, t Table) ([]Column, error) {
	tb, err := c.table(ctx, t.Schema, t.Name)
	if err != nil {
		return nil, wrap("columns", err, true)
	}
	out := make([]Column, 0, len(tb.Columns)+len(tb.PartitionKeys))
	for _, col := range append(tb.Columns, tb.PartitionKeys...) {
		out = append(out, Column{Name: col.Name, DataType: strings.ToLower(col.Type)})
	}
	return out, nil
}

// Sample is not supported: an Athena query writes its result to S3.
func (c *athenaConn) Sample(context.Context, Table, []Column, int, func(int, string, bool)) error {
	return &Error{Kind: KindUnsupported, Op: "sample (Athena sources are read from the catalog only)", Safe: true}
}
