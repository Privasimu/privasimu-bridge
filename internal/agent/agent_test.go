package agent

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/privasimu/bridge/internal/config"
	"github.com/privasimu/bridge/internal/dbsource"
	"github.com/privasimu/bridge/internal/files"
	"github.com/privasimu/bridge/internal/secrets"
	"github.com/privasimu/bridge/internal/testutil/fakedb"
)

// Synthetic values; the tests check that none of them reaches the platform.
var sampleValues = []string{"3171012303900001", "0812-3456-7890", "budi.contoh@example.co.id", "Budi Contoh", "nasabah prioritas"}

const localPassword = "local-placeholder-password"

type env struct {
	t        *testing.T
	fp       *fakePlatform
	cfg      *config.Config
	resolver *secrets.Resolver
	client   *Client
	db       *fakedb.DB
	files    *files.Service
	share    string
}

func newEnv(t *testing.T, mutate func(*config.Config)) *env {
	t.Helper()
	fp := newFakePlatform(t)
	dir := t.TempDir()
	share := t.TempDir()
	if err := os.WriteFile(filepath.Join(share, "Budi Contoh - KTP.txt"), []byte("NIK 3171012303900001\nHP 0812-3456-7890\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	yaml := `
agent:
  platform_url: ` + strconv.Quote(fp.srv.URL) + `
  poll_min: 1s
  poll_max: 5s
sources:
  - id: core-banking
    label: Core banking
    engine: postgresql
    host: 10.10.1.20
    database: corebank
    username: privasimu_ro
    password: "secret:corebank_pg"
    sampling: {enabled: true, rows: 20}
files:
  roots:
    - id: hr-share
      label: HR share
      path: ` + strconv.Quote(share) + `
`
	cfg, err := config.Parse([]byte(yaml))
	if err != nil {
		t.Fatal(err)
	}
	cfg.SetPath(filepath.Join(dir, "bridge.yaml"))
	if mutate != nil {
		mutate(cfg)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	if err := cfg.ValidateAgent(); err != nil {
		t.Fatal(err)
	}
	if err := secrets.CreateKeyFile(cfg.Resolve(cfg.Secrets.KeyFile)); err != nil {
		t.Fatal(err)
	}
	resolver := secrets.NewResolver(cfg)
	store, err := resolver.Store()
	if err != nil {
		t.Fatal(err)
	}
	_ = store.Set("corebank_pg", localPassword)
	if err := store.Save(); err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(fp.srv.Certificate())
	client, err := NewClient(ClientOptions{PlatformURL: fp.srv.URL, RootCAs: pool})
	if err != nil {
		t.Fatal(err)
	}
	fs, err := files.NewService(cfg, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	db := &fakedb.DB{Engine: "postgresql", Version: "PostgreSQL 16.4"}
	users := fakedb.Table{Schema: "public", Name: "users", Columns: []dbsource.Column{fakedb.Int("id"), fakedb.Text("nik"), fakedb.Text("kontak"), fakedb.Text("nama_lengkap"), fakedb.Text("email"), fakedb.Text("catatan")}}
	for i := 0; i < 10; i++ {
		users.Rows = append(users.Rows, map[string]string{"nik": sampleValues[0], "kontak": sampleValues[1], "email": sampleValues[2],
			"nama_lengkap": sampleValues[3], "catatan": sampleValues[4]})
	}
	db.Tables = []fakedb.Table{users}
	for i := 0; i < 450; i++ { // enough tables to need several parts
		db.Tables = append(db.Tables, fakedb.Table{Schema: "public", Name: "z_" + strconv.Itoa(1000+i), Columns: []dbsource.Column{fakedb.Int("id"), fakedb.Text("keterangan")}})
	}
	return &env{t: t, fp: fp, cfg: cfg, resolver: resolver, client: client, db: db, files: fs, share: share}
}

func (e *env) enroll() {
	e.t.Helper()
	if _, err := Enroll(context.Background(), e.cfg, e.resolver, e.client, "pvbe_placeholder-enrollment"); err != nil {
		e.t.Fatal(err)
	}
}

func (e *env) agent() *Agent {
	e.t.Helper()
	a, err := New(Deps{Config: e.cfg, Client: e.client, Resolver: e.resolver, Files: e.files, Log: testLogger(),
		Open: e.db.Opener()})
	if err != nil {
		e.t.Fatal(err)
	}
	a.sleep = func(ctx context.Context, d time.Duration) bool { return sleepCtx(ctx, 20*time.Millisecond) }
	return a
}

// run starts the agent until cond holds (or the timeout passes) and stops it.
func (e *env) run(a *Agent, timeout time.Duration, cond func() bool) bool {
	e.t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = a.Run(ctx); close(done) }()
	deadline := time.Now().Add(timeout)
	ok := false
	for time.Now().Before(deadline) {
		if cond() {
			ok = true
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	cancel()
	<-done
	return ok
}

func (e *env) finished(id string) func() bool {
	return func() bool {
		j := e.fp.job(id)
		e.fp.mu.Lock()
		defer e.fp.mu.Unlock()
		return j != nil && (j.completed != nil || j.failed != nil)
	}
}

func TestEnrollmentStoresTheTokenAndTheID(t *testing.T) {
	e := newEnv(t, nil)
	if _, err := Enroll(context.Background(), e.cfg, e.resolver, e.client, "pvbe_wrong"); codeOf(err) != ErrEnrollmentInvalid {
		t.Fatalf("a wrong enrollment token: %v", err)
	}
	e.enroll()
	st, err := LoadState(e.cfg.Resolve(e.cfg.StateDir))
	if err != nil || st.AgentID != e.fp.agentID {
		t.Fatalf("%+v %v", st, err)
	}
	tok, err := e.resolver.Resolve("secret:agent_token")
	if err != nil || tok.Reveal() != "pvba_placeholder-token-1" {
		t.Fatal("the agent token must be stored in the encrypted store")
	}
	raw, _ := os.ReadFile(e.cfg.Resolve(e.cfg.Secrets.File))
	if bytes.Contains(raw, []byte("pvba_")) {
		t.Fatal("the token must not be readable in the store file")
	}
	if _, err := Enroll(context.Background(), e.cfg, e.resolver, e.client, "pvbe_placeholder-enrollment"); err == nil {
		t.Fatal("an enrollment token is single-use")
	}
}

func TestInventoryNamesSourcesWithoutAddressesOrPaths(t *testing.T) {
	e := newEnv(t, nil)
	e.enroll()
	a := e.agent()
	if !e.run(a, 5*time.Second, func() bool {
		e.fp.mu.Lock()
		defer e.fp.mu.Unlock()
		return e.fp.sources != nil
	}) {
		t.Fatal("no inventory was sent")
	}
	if len(e.fp.sources.Sources) != 2 || e.fp.sources.Sources[0].ID != "core-banking" || e.fp.sources.Sources[1].Kind != "files" {
		t.Fatalf("%+v", e.fp.sources)
	}
	body := e.fp.allBodies()
	for _, leak := range []string{"10.10.1.20", "corebank", "privasimu_ro", localPassword, e.share, filepath.ToSlash(e.share)} {
		if bytes.Contains(body, []byte(leak)) {
			t.Fatalf("a request carries %q", leak)
		}
	}
	if !e.fp.protocolHeaderSeen {
		t.Fatal("X-Bridge-Protocol is missing")
	}
}

func TestTestSourceJob(t *testing.T) {
	e := newEnv(t, nil)
	e.enroll()
	e.fp.enqueue(Job{JobID: "job-test", Type: JobTestSource, SourceID: "core-banking"})
	e.fp.enqueue(Job{JobID: "job-test-files", Type: JobTestSource, SourceID: "hr-share"})
	a := e.agent()
	if !e.run(a, 5*time.Second, func() bool { return e.finished("job-test")() && e.finished("job-test-files")() }) {
		t.Fatal("jobs did not finish")
	}
	j := e.fp.job("job-test")
	raw, _ := json.Marshal(j.completed.Result)
	var r TestResult
	_ = json.Unmarshal(raw, &r)
	if !r.Success || r.TablesFound == nil || *r.TablesFound != 451 || r.ServerVersion == nil {
		t.Fatalf("%s", raw)
	}
	if got := e.db.LastTarget(); got.Password.Reveal() != localPassword || got.Host != "10.10.1.20" {
		t.Fatal("the job must use the local source settings")
	}
	if f := e.fp.job("job-test-files"); f.completed == nil {
		t.Fatalf("file root test: %+v", f.failed)
	}
}

func TestScanDatabaseJobSendsFindingsInParts(t *testing.T) {
	e := newEnv(t, nil)
	e.enroll()
	e.fp.failPartsOnce = true // the first part upload hits a 503 and is retried
	e.fp.enqueue(Job{JobID: "job-db", Type: JobScanDatabase, SourceID: "core-banking", Options: JobOptions{MaxTables: 450}})
	a := e.agent()
	if !e.run(a, 20*time.Second, e.finished("job-db")) {
		t.Fatal("job did not finish")
	}
	j := e.fp.job("job-db")
	if j.completed == nil {
		t.Fatalf("failed: %+v", j.failed)
	}
	if j.completed.Parts < 2 || len(j.parts) != j.completed.Parts {
		t.Fatalf("parts = %d (received %d)", j.completed.Parts, len(j.parts))
	}
	raw, _ := json.Marshal(j.completed.Result)
	var res DatabaseResult
	_ = json.Unmarshal(raw, &res)
	if res.TablesTotal != 451 || !res.Truncated || !res.Sampling || res.Engine != "postgresql" {
		t.Fatalf("%s", raw)
	}
	items := e.fp.items("job-db")
	if len(items) != 450 {
		t.Fatalf("items = %d, want the 450 the job asked for", len(items))
	}
	var users TableItem
	for _, it := range items {
		var ti TableItem
		_ = json.Unmarshal(it, &ti)
		if ti.Name == "users" {
			users = ti
		}
	}
	cols := map[string]ColumnItem{}
	for _, c := range users.Columns {
		cols[c.Name] = c
	}
	if c := cols["kontak"]; !c.PII || c.Category != "phone" || !c.Shadow || c.Content == nil || c.Content.Matching != 10 {
		t.Fatalf("kontak: %+v", c)
	}
	if c := cols["nik"]; c.PDPCategory != "spesifik" || c.ProtectionState != "plaintext" {
		t.Fatalf("nik: %+v", c)
	}
	body := e.fp.allBodies()
	for _, v := range append(sampleValues, localPassword, "10.10.1.20") {
		if bytes.Contains(body, []byte(v)) {
			t.Fatalf("a value or setting reached the platform: %q", v)
		}
	}
}

func TestSamplingCanOnlyBeNarrowedByThePlatform(t *testing.T) {
	e := newEnv(t, func(c *config.Config) { c.Sources[0].Sampling = nil })
	e.enroll()
	on := true
	e.fp.enqueue(Job{JobID: "job-db", Type: JobScanDatabase, SourceID: "core-banking", Options: JobOptions{Sampling: &on, MaxTables: 1}})
	a := e.agent()
	if !e.run(a, 10*time.Second, e.finished("job-db")) {
		t.Fatal("job did not finish")
	}
	if e.db.Sampled != 0 {
		t.Fatal("the platform cannot turn sampling on when the local configuration has it off")
	}
}

func TestScanFilesJobSendsHashedFindings(t *testing.T) {
	e := newEnv(t, nil)
	e.enroll()
	e.fp.enqueue(Job{JobID: "job-files", Type: JobScanFiles, SourceID: "hr-share", Options: JobOptions{Refresh: true}})
	a := e.agent()
	if !e.run(a, 20*time.Second, e.finished("job-files")) {
		t.Fatal("job did not finish")
	}
	j := e.fp.job("job-files")
	if j.completed == nil {
		t.Fatalf("failed: %+v", j.failed)
	}
	items := e.fp.items("job-files")
	if len(items) != 1 {
		t.Fatalf("items = %d", len(items))
	}
	var f files.FileFinding
	_ = json.Unmarshal(items[0], &f)
	if !strings.HasPrefix(f.ID, "f_") || f.Path != "" || f.Categories["nik"] != 1 || f.Categories["phone"] != 1 {
		t.Fatalf("%+v", f)
	}
	body := e.fp.allBodies()
	for _, v := range append(sampleValues, "KTP", e.share, filepath.ToSlash(e.share)) {
		if bytes.Contains(body, []byte(v)) {
			t.Fatalf("file content or a path reached the platform: %q", v)
		}
	}
}

func TestJobsTheAgentRefuses(t *testing.T) {
	e := newEnv(t, func(c *config.Config) { c.Agent.AllowedJobs = []string{config.JobTestSource} })
	e.enroll()
	jobs := map[string]Job{
		"j-type":    {JobID: "j-type", Type: "run_sql", SourceID: "core-banking"},
		"j-allowed": {JobID: "j-allowed", Type: JobScanDatabase, SourceID: "core-banking"},
		"j-source":  {JobID: "j-source", Type: JobTestSource, SourceID: "../../etc"},
	}
	want := map[string]string{"j-type": FailUnsupportedJob, "j-allowed": FailJobNotAllowed, "j-source": FailSourceNotFound}
	for _, j := range jobs {
		e.fp.enqueue(j)
	}
	a := e.agent()
	a.cfg.Agent.MaxParallelJobs = 3
	if !e.run(a, 10*time.Second, func() bool {
		return e.finished("j-type")() && e.finished("j-allowed")() && e.finished("j-source")()
	}) {
		t.Fatal("jobs did not finish")
	}
	for id, code := range want {
		j := e.fp.job(id)
		if j.failed == nil || j.failed.ErrorCode != code || j.failed.Retryable {
			t.Errorf("%s: %+v, want %s", id, j.failed, code)
		}
	}
	if len(e.db.Opened) != 0 {
		t.Fatal("no database may be opened for a refused job")
	}
}

func TestDatabaseFailuresAreReportedAsCodes(t *testing.T) {
	e := newEnv(t, nil)
	e.enroll()
	e.db.Fail = map[string]error{"open": &dbsource.Error{Kind: dbsource.KindAuth, Op: "connect",
		Cause: errors.New("password authentication failed for user privasimu_ro"), Safe: true}}
	e.fp.enqueue(Job{JobID: "j", Type: JobScanDatabase, SourceID: "core-banking"})
	a := e.agent()
	if !e.run(a, 10*time.Second, e.finished("j")) {
		t.Fatal("job did not finish")
	}
	j := e.fp.job("j")
	if j.failed == nil || j.failed.ErrorCode != "database_auth" || j.failed.ErrorKind != "auth" || j.failed.Retryable {
		t.Fatalf("%+v", j.failed)
	}
	if bytes.Contains(e.fp.allBodies(), []byte("privasimu_ro")) {
		t.Fatal("driver messages never reach the platform")
	}
}

func TestLostLeaseAbandonsTheJob(t *testing.T) {
	e := newEnv(t, nil)
	e.enroll()
	e.db.Delay = 100 * time.Millisecond // the scan takes seconds
	e.fp.expireLeases = true
	e.fp.enqueue(Job{JobID: "j", Type: JobScanDatabase, SourceID: "core-banking", LeaseSeconds: 1})
	a := e.agent()
	a.minRenew = 50 * time.Millisecond
	// The agent abandons the job once the platform refuses a renewal: the job leaves the
	// running set although the scan would take much longer.
	gone := e.run(a, 8*time.Second, func() bool {
		j := e.fp.job("j")
		e.fp.mu.Lock()
		calls := j.progressCalls
		e.fp.mu.Unlock()
		a.mu.Lock()
		_, running := a.running["j"]
		a.mu.Unlock()
		return calls > 0 && !running
	})
	if !gone {
		t.Fatal("the job was not abandoned after the lease was withdrawn")
	}
	j := e.fp.job("j")
	if j.completed != nil || j.failed != nil {
		t.Fatal("a job whose lease was withdrawn must not report anything")
	}
}

func TestRevokedAgentBacksOff(t *testing.T) {
	e := newEnv(t, nil)
	e.enroll()
	e.fp.revoked = true
	a := e.agent()
	calls := 0
	a.sleep = func(ctx context.Context, d time.Duration) bool {
		calls++
		if d < e.cfg.Agent.PollMax.D() {
			t.Errorf("a revoked agent must wait the longest interval, waited %v", d)
		}
		return calls < 3 && sleepCtx(ctx, time.Millisecond)
	}
	_ = a.Run(context.Background())
	st, err := LoadStatus(e.cfg.Resolve(e.cfg.StateDir))
	if err != nil || st.LastError != ErrAgentRevoked || st.ConsecutiveFailures < 2 {
		t.Fatalf("%+v %v", st, err)
	}
}

func TestTokenRotation(t *testing.T) {
	e := newEnv(t, nil)
	e.enroll()
	e.fp.rotateRequested = true
	a := e.agent()
	if !e.run(a, 5*time.Second, func() bool {
		v, err := e.resolver.Resolve("secret:agent_token")
		return err == nil && v.Reveal() == "pvba_placeholder-token-2"
	}) {
		t.Fatal("the rotated token was not stored")
	}
	if a.client.bearer() != "pvba_placeholder-token-2" {
		t.Fatal("the client must use the new token")
	}
}

func TestClientRefusesRedirectsAndPlainHTTP(t *testing.T) {
	if _, err := NewClient(ClientOptions{PlatformURL: "http://app.privasimu.example"}); err == nil {
		t.Fatal("plain http must be refused")
	}
	if _, err := NewClient(ClientOptions{PlatformURL: "https://app.privasimu.example", ProxyURL: "socks5://proxy:1080"}); err == nil {
		t.Fatal("only http(s) proxies are supported")
	}
}

func testLogger() *slog.Logger {
	if os.Getenv("BRIDGE_TEST_LOG") != "" {
		return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
	}
	return slog.New(slog.DiscardHandler)
}
