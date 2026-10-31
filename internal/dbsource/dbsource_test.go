package dbsource

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-sql-driver/mysql"
	"github.com/jackc/pgx/v5/pgconn"
	mssql "github.com/microsoft/go-mssqldb"
	"go.mongodb.org/mongo-driver/v2/bson"

	"github.com/privasimu/bridge/internal/config"
	"github.com/privasimu/bridge/internal/netguard"
	"github.com/privasimu/bridge/internal/secrets"
)

func TestQuotingCannotBreakOutOfAnIdentifier(t *testing.T) {
	cases := []struct {
		d    dialect
		in   string
		want string
	}{
		{pgDialect{}, `a"b`, `"a""b"`},
		{pgDialect{}, `x"; DROP TABLE t; --`, `"x""; DROP TABLE t; --"`},
		{oraDialect{}, `A"B`, `"A""B"`},
		{myDialect{}, "a`b", "`a``b`"},
		{msDialect{}, "a]b", "[a]]b]"},
		{msDialect{}, "x]; DROP TABLE t; --", "[x]]; DROP TABLE t; --]"},
	}
	for _, c := range cases {
		if got := c.d.quote(c.in); got != c.want {
			t.Errorf("%s quote(%q) = %q, want %q", c.d.engine(), c.in, got, c.want)
		}
	}
}

func TestSampleableTypes(t *testing.T) {
	yes := map[dialect][]string{
		pgDialect{}:  {"character varying(255)", "text", "jsonb", "bigint", "numeric(16,0)", "character(16)", "citext"},
		myDialect{}:  {"varchar(255)", "longtext", "json", "bigint(20) unsigned", "decimal(16,0)", "char(16)"},
		msDialect{}:  {"nvarchar", "varchar", "ntext", "bigint", "decimal", "char"},
		oraDialect{}: {"varchar2", "nvarchar2", "clob", "number", "char"},
	}
	no := map[dialect][]string{
		pgDialect{}:  {"bytea", "uuid", "integer", "boolean", "timestamp with time zone", "text[]", "double precision"},
		myDialect{}:  {"blob", "varbinary(16)", "int(11)", "datetime", "tinyint(1)", "double"},
		msDialect{}:  {"varbinary", "uniqueidentifier", "int", "datetime2", "bit", "float", "image"},
		oraDialect{}: {"blob", "raw", "date", "timestamp(6)", "binary_double"},
	}
	for d, list := range yes {
		for _, typ := range list {
			if !d.sampleable(typ) {
				t.Errorf("%s: %s should be sampleable", d.engine(), typ)
			}
		}
	}
	for d, list := range no {
		for _, typ := range list {
			if d.sampleable(typ) {
				t.Errorf("%s: %s should not be sampleable", d.engine(), typ)
			}
		}
	}
}

func TestSampleQueriesBindTheRowLimit(t *testing.T) {
	for _, d := range []dialect{pgDialect{}, myDialect{}, msDialect{}, oraDialect{}} {
		q, args := d.sampleQuery(`T`, []string{"A"}, 50)
		if len(args) != 1 || args[0] != 50 || strings.Contains(q, "50") {
			t.Errorf("%s: the row limit must be a bind parameter: %q %v", d.engine(), q, args)
		}
		q, args = d.columnsQuery("s'; --", "t")
		if strings.Contains(q, "s'; --") || len(args) != 2 {
			t.Errorf("%s: catalog lookups must bind names: %q", d.engine(), q)
		}
	}
}

func TestClassifyDriverErrors(t *testing.T) {
	cases := map[string]error{
		KindAuth:        &pgconn.PgError{Code: "28P01"},
		KindNotFound:    &pgconn.PgError{Code: "3D000"},
		KindPermission:  &pgconn.PgError{Code: "42501"},
		KindTimeout:     &pgconn.PgError{Code: "57014"},
		KindUnreachable: &pgconn.PgError{Code: "08006"},
	}
	for want, err := range cases {
		if got := classify(err); got != want {
			t.Errorf("pg %v = %s, want %s", err, got, want)
		}
	}
	for num, want := range map[uint16]string{1045: KindAuth, 1044: KindPermission, 1049: KindNotFound, 1142: KindPermission} {
		if got := classify(&mysql.MySQLError{Number: num}); got != want {
			t.Errorf("mysql %d = %s, want %s", num, got, want)
		}
	}
	for num, want := range map[int32]string{18456: KindAuth, 4060: KindNotFound, 229: KindPermission} {
		if got := classify(fmt.Errorf("wrapped: %w", mssql.Error{Number: num})); got != want {
			t.Errorf("mssql %d = %s, want %s", num, got, want)
		}
	}
	for msg, want := range map[string]string{
		"ORA-01017: invalid username/password; logon denied":         KindAuth,
		"ORA-12514: TNS:listener does not currently know of service": KindNotFound,
		"ORA-01031: insufficient privileges":                         KindPermission,
		"ORA-12170: TNS:Connect timeout occurred":                    KindUnreachable,
	} {
		if got := classify(errors.New(msg)); got != want {
			t.Errorf("%q = %s, want %s", msg, got, want)
		}
	}
	if got := classify(&net.OpError{Op: "dial", Err: errors.New("connection refused")}); got != KindUnreachable {
		t.Errorf("dial error = %s", got)
	}
	if got := classify(fmt.Errorf("x: %w", context.DeadlineExceeded)); got != KindTimeout {
		t.Errorf("deadline = %s", got)
	}
	if got := classify(fmt.Errorf("x: %w", netguard.ErrBlocked)); got != KindBlocked {
		t.Errorf("blocked = %s", got)
	}
}

func TestErrorMessagesHideUnsafeCauses(t *testing.T) {
	cause := errors.New(`invalid input syntax for type integer: "3171012303900001"`)
	e := &Error{Kind: KindDatabase, Op: "sample", Cause: cause, Safe: false}
	if strings.Contains(e.Message(), "3171") || strings.Contains(e.Error(), "3171") {
		t.Fatalf("a sampling error must not show its cause: %q", e.Message())
	}
	safe := &Error{Kind: KindAuth, Op: "connect", Cause: errors.New("password authentication failed for user \"ro\""), Safe: true}
	if !strings.Contains(safe.Message(), "password authentication failed") {
		t.Fatalf("a connection error should explain itself locally: %q", safe.Message())
	}
}

func TestTLSConfigModes(t *testing.T) {
	if c, err := (TLSSettings{Mode: config.DBTLSDisable}).TLSConfig("db"); err != nil || c != nil {
		t.Fatalf("disable: %v %v", c, err)
	}
	c, err := (TLSSettings{Mode: config.DBTLSRequire}).TLSConfig("db.internal")
	if err != nil || !c.InsecureSkipVerify || c.MinVersion != tls.VersionTLS12 {
		t.Fatalf("require: %+v %v", c, err)
	}
	c, err = (TLSSettings{Mode: config.DBTLSVerifyFull}).TLSConfig("db.internal")
	if err != nil || c.InsecureSkipVerify || c.ServerName != "db.internal" || c.RootCAs == nil {
		t.Fatalf("verify-full: %+v %v", c, err)
	}
	c, err = (TLSSettings{Mode: config.DBTLSVerifyCA}).TLSConfig("db.internal")
	if err != nil || c.VerifyConnection == nil {
		t.Fatalf("verify-ca must verify the chain itself: %+v %v", c, err)
	}
	if _, err := (TLSSettings{Mode: config.DBTLSVerifyFull, CAFile: "/nonexistent/ca.pem"}).TLSConfig("x"); KindOf(err) != KindConfig {
		t.Fatalf("missing CA file: %v", err)
	}
	if _, err := (TLSSettings{Mode: "sometimes"}).TLSConfig("x"); KindOf(err) != KindConfig {
		t.Fatalf("unknown mode: %v", err)
	}
}

func TestOpenRefusesUnknownEngines(t *testing.T) {
	if _, err := Open(context.Background(), Target{Engine: "db2"}); KindOf(err) != KindUnsupported {
		t.Fatalf("%v", err)
	}
}

func TestOpenThroughTheGuardNeverDials(t *testing.T) {
	g, _ := netguard.New([]string{"10.0.0.0/8"})
	var dialed atomic.Int32
	g.Dialer = &net.Dialer{Timeout: time.Second}
	dial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		dialed.Add(1)
		return g.Dial(ctx, network, addr)
	}
	for _, engine := range []string{"postgresql", "mysql", "mssql", "oracle"} {
		t.Run(engine, func(t *testing.T) {
			_, err := Open(context.Background(), Target{Engine: engine, Host: "169.254.169.254", Port: 1234, Database: "d",
				Username: "u", Password: secrets.Value("p"), Timeout: 2 * time.Second, Dial: dial})
			if k := KindOf(err); k != KindBlocked {
				t.Fatalf("metadata address must be blocked before any connection, got %s (%v)", k, err)
			}
		})
	}
}

type countingConn struct {
	closed atomic.Bool
}

func (c *countingConn) Engine() string                       { return "postgresql" }
func (c *countingConn) ServerVersion(context.Context) string { return "" }
func (c *countingConn) DefaultSchema() string                { return "public" }
func (c *countingConn) ListTables(context.Context, string) ([]Table, error) {
	return nil, nil
}
func (c *countingConn) FindTable(context.Context, string, string) (Table, bool, error) {
	return Table{}, false, nil
}
func (c *countingConn) Columns(context.Context, Table) ([]Column, error) { return nil, nil }
func (c *countingConn) Sample(context.Context, Table, []Column, int, func(int, string, bool)) error {
	return nil
}
func (c *countingConn) TLSInUse() *bool { return nil }
func (c *countingConn) Close() error    { c.closed.Store(true); return nil }

func TestPoolSharesOneConnectionPerTarget(t *testing.T) {
	p := NewPool(4, time.Minute)
	var opens atomic.Int32
	p.Open = func(ctx context.Context, t Target) (Conn, error) {
		opens.Add(1)
		time.Sleep(20 * time.Millisecond)
		return &countingConn{}, nil
	}
	target := Target{Engine: "postgresql", Host: "db", Port: 5432, Database: "d", Username: "u", Password: "p"}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, release, err := p.Get(context.Background(), target)
			if err != nil {
				t.Error(err)
				return
			}
			release()
		}()
	}
	wg.Wait()
	if opens.Load() != 1 {
		t.Fatalf("opens = %d, want 1", opens.Load())
	}
	other := target
	other.Password = "different"
	if Key(other) == Key(target) {
		t.Fatal("a different password must use a different session")
	}
}

func TestPoolRemembersFailedLogins(t *testing.T) {
	p := NewPool(4, time.Minute)
	var opens atomic.Int32
	p.Open = func(ctx context.Context, t Target) (Conn, error) {
		opens.Add(1)
		return nil, &Error{Kind: KindAuth, Op: "connect", Safe: true}
	}
	target := Target{Engine: "postgresql", Host: "db", Username: "u", Password: "wrong"}
	for i := 0; i < 5; i++ {
		if _, _, err := p.Get(context.Background(), target); KindOf(err) != KindAuth {
			t.Fatalf("%v", err)
		}
	}
	if opens.Load() != 1 {
		t.Fatalf("a failed login must be remembered so retries cannot lock the account; opens = %d", opens.Load())
	}
	now := time.Now().Add(2 * time.Minute)
	p.now = func() time.Time { return now }
	_, _, _ = p.Get(context.Background(), target)
	if opens.Load() != 2 {
		t.Fatalf("the failure is forgotten after the hold time; opens = %d", opens.Load())
	}
}

func TestPoolEvictsIdleConnections(t *testing.T) {
	p := NewPool(1, time.Minute)
	conns := []*countingConn{}
	var mu sync.Mutex
	p.Open = func(ctx context.Context, t Target) (Conn, error) {
		c := &countingConn{}
		mu.Lock()
		conns = append(conns, c)
		mu.Unlock()
		return c, nil
	}
	for i := 0; i < 3; i++ {
		_, release, err := p.Get(context.Background(), Target{Engine: "postgresql", Host: fmt.Sprint("db", i)})
		if err != nil {
			t.Fatal(err)
		}
		release()
	}
	if p.Len() > 2 {
		t.Fatalf("pool holds %d connections", p.Len())
	}
	later := time.Now().Add(10 * time.Minute)
	p.now = func() time.Time { return later }
	p.Sweep()
	if p.Len() != 0 {
		t.Fatalf("idle connections must be closed, %d left", p.Len())
	}
}

func TestMongoFlattenReportsDottedPaths(t *testing.T) {
	raw, err := bson.Marshal(bson.D{
		{Key: "_id", Value: 1},
		{Key: "profile", Value: bson.D{{Key: "nik", Value: "3171012303900001"}, {Key: "address", Value: bson.D{{Key: "city", Value: "Jakarta"}}}}},
		{Key: "phones", Value: bson.A{"081234567890", "081298765432"}},
		{Key: "contacts", Value: bson.A{bson.D{{Key: "email", Value: "a@example.co.id"}}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]int{}
	flatten("", raw, 0, func(path string, v bson.RawValue) { seen[path]++ })
	for path, n := range map[string]int{"_id": 1, "profile.nik": 1, "profile.address.city": 1, "phones": 2, "contacts.email": 1} {
		if seen[path] != n {
			t.Errorf("%s seen %d times, want %d (all %v)", path, seen[path], n, seen)
		}
	}
}
