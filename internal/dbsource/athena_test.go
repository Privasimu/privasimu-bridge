package dbsource

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/privasimu/bridge/internal/secrets"
)

// TestAWSSignatureMatchesTheReferenceExample checks Signature Version 4 against the worked
// example of the AWS documentation (IAM ListUsers, 30 August 2015).
func TestAWSSignatureMatchesTheReferenceExample(t *testing.T) {
	signed, sig := awsSignature("GET", "/", "Action=ListUsers&Version=2010-05-08", map[string]string{
		"content-type": "application/x-www-form-urlencoded; charset=utf-8",
		"host":         "iam.amazonaws.com",
		"x-amz-date":   "20150830T123600Z",
	}, nil, "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY", "us-east-1", "iam", "20150830T123600Z")
	if signed != "content-type;host;x-amz-date" || sig != "5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7" {
		t.Fatalf("%s %s", signed, sig)
	}
}

// fakeAthena answers the metadata API after checking every request's signature.
type fakeAthena struct {
	t       *testing.T
	secret  string
	actions []string
}

func (f *fakeAthena) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/x-amz-json-1.1")
	payload, _ := io.ReadAll(r.Body)
	auth := r.Header.Get("Authorization")
	headers := map[string]string{"host": r.Host}
	for k, v := range r.Header {
		if lk := strings.ToLower(k); lk == "content-type" || strings.HasPrefix(lk, "x-amz-") {
			headers[lk] = strings.Join(v, ",")
		}
	}
	date := r.Header.Get("X-Amz-Date")
	_, want := awsSignature(r.Method, "/", "", headers, payload, f.secret, "ap-southeast-3", "athena", date)
	if !strings.HasPrefix(auth, "AWS4-HMAC-SHA256 Credential=AKIAPLACEHOLDER00001/"+date[:8]+"/ap-southeast-3/athena/aws4_request") ||
		!strings.HasSuffix(auth, "Signature="+want) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"__type":"InvalidSignatureException","message":"The request signature we calculated does not match."}`))
		return
	}
	var in map[string]any
	_ = json.Unmarshal(payload, &in)
	action := strings.TrimPrefix(r.Header.Get("X-Amz-Target"), "AmazonAthena.")
	f.actions = append(f.actions, action)
	if in["CatalogName"] != "AwsDataCatalog" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	switch action {
	case "ListDatabases":
		_, _ = w.Write([]byte(`{"DatabaseList":[{"Name":"crm"},{"Name":"logs"}]}`))
	case "ListTableMetadata":
		if in["DatabaseName"] == "crm" {
			_, _ = w.Write([]byte(`{"TableMetadataList":[{"Name":"customers","TableType":"EXTERNAL_TABLE","Columns":[{"Name":"nik","Type":"string"}]},` +
				`{"Name":"v_customers","TableType":"VIRTUAL_VIEW"}]}`))
		} else {
			_, _ = w.Write([]byte(`{"TableMetadataList":[]}`))
		}
	case "GetTableMetadata":
		if in["TableName"] != "customers" {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"__type":"MetadataException","Message":"Table not found"}`))
			return
		}
		_, _ = w.Write([]byte(`{"TableMetadata":{"Name":"customers","TableType":"EXTERNAL_TABLE","Columns":[{"Name":"nik","Type":"string"},` +
			`{"Name":"email","Type":"varchar(255)"}],"PartitionKeys":[{"Name":"dt","Type":"string"}]}}`))
	default:
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"__type":"AccessDeniedException","Message":"not allowed"}`))
	}
}

func athenaTarget(srv *httptest.Server, secret string) Target {
	t := cloudTarget(srv, "athena")
	t.Region, t.Username, t.Password = "ap-southeast-3", "AKIAPLACEHOLDER00001", secrets.Value(secret)
	t.Schemas = []string{"crm"}
	return t
}

func TestAthenaReadsTheCatalogOnly(t *testing.T) {
	fake := &fakeAthena{t: t, secret: "placeholder-secret-access-key"}
	srv := httptest.NewTLSServer(fake)
	defer srv.Close()
	ctx := context.Background()
	conn, err := Open(ctx, athenaTarget(srv, fake.secret))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	tables, err := conn.ListTables(ctx, "")
	if err != nil || len(tables) != 1 || tables[0].Ref != "customers" || conn.DefaultSchema() != "crm" {
		t.Fatalf("listing (allowed database, views left out): %+v %v", tables, err)
	}
	tb, ok, err := conn.FindTable(ctx, "customers", "")
	if err != nil || !ok {
		t.Fatalf("find: %v %v", ok, err)
	}
	if _, ok, err := conn.FindTable(ctx, "missing", ""); ok || err != nil {
		t.Fatalf("a missing table: %v %v", ok, err)
	}
	cols, err := conn.Columns(ctx, tb)
	if err != nil || len(cols) != 3 || cols[2].Name != "dt" || cols[1].Sampleable {
		t.Fatalf("columns (partition keys included, nothing sampleable): %+v %v", cols, err)
	}
	if err := conn.Sample(ctx, tb, cols, 10, func(int, string, bool) {}); KindOf(err) != KindUnsupported {
		t.Fatalf("Athena is never sampled: %v", err)
	}
	for _, a := range fake.actions {
		if !strings.HasPrefix(a, "List") && !strings.HasPrefix(a, "Get") {
			t.Fatalf("only metadata actions: %s", a)
		}
	}
	if _, err := Open(ctx, athenaTarget(srv, "wrong-secret")); KindOf(err) != KindAuth {
		t.Fatalf("a wrong secret key: %s (%v)", KindOf(err), err)
	}
}

func TestAthenaSessionTokenIsSigned(t *testing.T) {
	req := httptestRequest()
	signAWSRequest(req, []byte(`{}`), "ASIAPLACEHOLDER00001", "secret", "placeholder-session-token", "ap-southeast-3", "athena",
		time.Date(2026, 11, 4, 1, 2, 3, 0, time.UTC))
	if req.Header.Get("X-Amz-Security-Token") != "placeholder-session-token" ||
		!strings.Contains(req.Header.Get("Authorization"), "SignedHeaders=content-type;host;x-amz-date;x-amz-security-token;x-amz-target") {
		t.Fatalf("%s", req.Header.Get("Authorization"))
	}
}

func httptestRequest() *http.Request {
	req, _ := http.NewRequest(http.MethodPost, "https://athena.ap-southeast-3.amazonaws.com/", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/x-amz-json-1.1")
	req.Header.Set("X-Amz-Target", "AmazonAthena.ListDatabases")
	return req
}
