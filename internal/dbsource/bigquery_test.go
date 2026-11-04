package dbsource

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/privasimu/bridge/internal/secrets"
)

// fakeBigQuery answers the token endpoint and the REST resources the bridge reads.
type fakeBigQuery struct {
	t      *testing.T
	key    *rsa.PublicKey
	aud    string
	mu     sync.Mutex
	scopes []string
	paths  []string
	denied bool
}

func (f *fakeBigQuery) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	f.mu.Lock()
	f.paths = append(f.paths, r.Method+" "+r.URL.RequestURI())
	f.mu.Unlock()
	if r.URL.Path == "/token" {
		_ = r.ParseForm()
		claims, err := verifyJWT(r.PostForm.Get("assertion"), f.key)
		if err != nil || r.PostForm.Get("grant_type") != "urn:ietf:params:oauth:grant-type:jwt-bearer" ||
			claims["iss"] != "bridge@my-project.iam.gserviceaccount.com" || claims["aud"] != f.aud {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"invalid_grant","error_description":"Invalid JWT Signature."}`))
			return
		}
		f.mu.Lock()
		f.scopes = append(f.scopes, claims["scope"].(string))
		f.mu.Unlock()
		_, _ = w.Write([]byte(`{"access_token":"placeholder-access-token","expires_in":3599,"token_type":"Bearer"}`))
		return
	}
	if r.Header.Get("Authorization") != "Bearer placeholder-access-token" {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":{"code":401,"message":"Request had invalid authentication credentials.","status":"UNAUTHENTICATED"}}`))
		return
	}
	if f.denied {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":{"code":403,"message":"Access Denied: Project my-project","status":"PERMISSION_DENIED"}}`))
		return
	}
	base := "/bigquery/v2/projects/my-project"
	q := r.URL.Query()
	switch r.URL.Path {
	case base + "/datasets":
		if q.Get("pageToken") == "" {
			_, _ = w.Write([]byte(`{"datasets":[{"datasetReference":{"datasetId":"crm","projectId":"my-project"}}],"nextPageToken":"p2"}`))
		} else {
			_, _ = w.Write([]byte(`{"datasets":[{"datasetReference":{"datasetId":"hr","projectId":"my-project"}}]}`))
		}
	case base + "/datasets/crm/tables":
		_, _ = w.Write([]byte(`{"tables":[{"tableReference":{"tableId":"customers"},"type":"TABLE"},{"tableReference":{"tableId":"v_customers"},"type":"VIEW"}]}`))
	case base + "/datasets/hr/tables":
		_, _ = w.Write([]byte(`{"tables":[{"tableReference":{"tableId":"employees"},"type":"TABLE"}]}`))
	case base + "/datasets/crm/tables/customers":
		_, _ = w.Write([]byte(`{"type":"TABLE","numRows":"1200","schema":{"fields":[{"name":"id","type":"INTEGER","mode":"REQUIRED"},` +
			`{"name":"nik","type":"STRING","mode":"NULLABLE"},{"name":"contact","type":"RECORD","mode":"NULLABLE","fields":[{"name":"email","type":"STRING"},{"name":"phone","type":"STRING"}]},` +
			`{"name":"tags","type":"STRING","mode":"REPEATED"},{"name":"created","type":"TIMESTAMP","mode":"NULLABLE"}]}}`))
	case base + "/datasets/crm/tables/customers/data":
		if q.Get("selectedFields") != "id,nik,tags" || q.Get("maxResults") != "50" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		_, _ = w.Write([]byte(`{"rows":[{"f":[{"v":"1"},{"v":"3171012303900001"},{"v":[{"v":"0812-3456-7890"},{"v":"vip"}]}]},` +
			`{"f":[{"v":"2"},{"v":null},{"v":[]}]}]}`))
	default:
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"error":{"code":404,"message":"Not found: Table my-project:crm.missing","status":"NOT_FOUND"}}`))
	}
}

func bigQueryTarget(t *testing.T, srv *httptest.Server) Target {
	key := rsaTestKey(t)
	sa, _ := json.Marshal(map[string]string{"type": "service_account", "client_email": "bridge@my-project.iam.gserviceaccount.com",
		"private_key_id": "k1", "private_key": pkcs8PEM(t, key), "token_uri": "https://evil.example/token"})
	target := cloudTarget(srv, "bigquery")
	target.Database, target.Credentials = "my-project", secrets.Value(sa)
	return target
}

func TestBigQueryReadsWithAReadOnlyToken(t *testing.T) {
	fake := &fakeBigQuery{t: t, key: &rsaTestKey(t).PublicKey}
	srv := httptest.NewTLSServer(fake)
	defer srv.Close()
	fake.aud = srv.URL + "/token"
	ctx := context.Background()
	conn, err := Open(ctx, bigQueryTarget(t, srv))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	tables, err := conn.ListTables(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	var refs []string
	for _, tb := range tables {
		refs = append(refs, tb.Ref)
	}
	if strings.Join(refs, ",") != "crm.customers,hr.employees" || conn.DefaultSchema() != "" {
		t.Fatalf("every dataset (two pages), tables only: %v", refs)
	}
	tb, ok, err := conn.FindTable(ctx, "crm.customers", "")
	if err != nil || !ok || *tb.RowEstimate != 1200 {
		t.Fatalf("find: %+v %v %v", tb, ok, err)
	}
	if _, ok, err := conn.FindTable(ctx, "crm.missing", ""); ok || err != nil {
		t.Fatalf("a missing table is not found, not an error: %v %v", ok, err)
	}
	cols, err := conn.Columns(ctx, tb)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, c := range cols {
		names = append(names, c.Name+":"+c.DataType)
	}
	if strings.Join(names, ",") != "id:integer,nik:string,contact.email:string,contact.phone:string,tags:array<string>,created:timestamp" ||
		!cols[0].Sampleable || cols[2].Sampleable || !cols[4].Sampleable || cols[5].Sampleable || *cols[0].Nullable {
		t.Fatalf("columns: %v", names)
	}
	var values []string
	nulls := 0
	if err := conn.Sample(ctx, tb, cols, 50, func(i int, v string, null bool) {
		if null {
			nulls++
			return
		}
		values = append(values, cols[i].Name+"="+v)
	}); err != nil {
		t.Fatal(err)
	}
	if strings.Join(values, ";") != "id=1;nik=3171012303900001;tags=0812-3456-7890;tags=vip;id=2" || nulls != 1 {
		t.Fatalf("sampled %v, %d nulls", values, nulls)
	}
	for _, s := range fake.scopes {
		if s != bqReadonlyScope {
			t.Fatalf("the token must be read-only: %s", s)
		}
	}
	for _, p := range fake.paths {
		if !strings.HasPrefix(p, "GET /bigquery/v2/") && p != "POST /token" {
			t.Fatalf("only reads (and the token request): %s", p)
		}
	}
}

func TestBigQueryErrors(t *testing.T) {
	fake := &fakeBigQuery{t: t, key: &rsaTestKey(t).PublicKey, aud: "https://no-such-audience/token"}
	srv := httptest.NewTLSServer(fake)
	defer srv.Close()
	if _, err := Open(context.Background(), bigQueryTarget(t, srv)); KindOf(err) != KindAuth {
		t.Fatalf("a refused key: %s (%v)", KindOf(err), err)
	}
	fake.aud = srv.URL + "/token"
	fake.denied = true
	if _, err := Open(context.Background(), bigQueryTarget(t, srv)); KindOf(err) != KindPermission {
		t.Fatalf("no access to the project: %s (%v)", KindOf(err), err)
	}
	target := bigQueryTarget(t, srv)
	target.Credentials = `{"type":"authorized_user"}`
	if _, err := Open(context.Background(), target); KindOf(err) != KindConfig {
		t.Fatalf("not a service account key: %v", err)
	}
}
