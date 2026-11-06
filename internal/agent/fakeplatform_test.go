package agent

// fakePlatform implements the platform side of agent protocol 1 in memory, following
// docs/AGENT-PROTOCOL.md and what both platform lines (Laravel and Go) implement, so the
// agent is tested against the same rules:
//
//   - the field rules of section 5: a request either line refuses is 400 invalid_request
//     here too, and every test fails when the agent sent one (see newFakePlatform);
//   - token rotation: the current token becomes the previous one, valid 600 seconds, and
//     a poll authenticated with the previous token answers token_rotation_requested: true
//     (the agent lost the answer of its last rotation);
//   - revocation keeps the token hashes, so a revoked agent gets 401 agent_revoked, and
//     the organisation check after authentication answers 403 forbidden;
//   - revision 3: with features set, the poll answer lists platform_features and the
//     inventory accepts kind packages; without (an older platform) the answer has no such
//     key and an inventory with kind packages is refused as a whole. Parts must have the
//     kind of their job type, package items and results follow section 6.7.
//
// It records every request body to check that nothing but metadata leaves the agent.

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unicode/utf8"
)

type fakeJob struct {
	job       Job
	parts     map[int][]byte
	completed *CompleteRequest
	failed    *FailRequest
	progress  []ProgressRequest
	// progressCalls counts renewals, including refused ones.
	progressCalls int
}

type fakePlatform struct {
	t   *testing.T
	srv *httptest.Server

	mu          sync.Mutex
	enrollToken string
	agentToken  string
	prevToken   string
	prevUntil   time.Time
	// issued numbers the agent tokens: pvba_placeholder-token-1 at enrollment, then -2, -3
	// for each rotation.
	issued  int
	agentID string
	queue   []Job
	jobs    map[string]*fakeJob
	sources *SourcesRequest
	bodies  [][]byte
	polls   int
	// pollTokens counts polls by the agent token that authenticated them.
	pollTokens map[string]int
	// previousPolls counts polls authenticated with the previous token.
	previousPolls int
	rotations     int
	// dropRotateAnswers loses that many rotation answers: the rotation is stored, then the
	// connection is closed without an answer.
	dropRotateAnswers int
	revoked           bool
	// forbidden makes the organisation check after authentication refuse the agent.
	forbidden          bool
	inventoryRequested bool
	failPartsOnce      bool
	partFailures       int
	expireLeases       bool
	cancelJobs         bool
	rotateRequested    bool
	protocolHeaderSeen bool
	refusedAuth        int
	// features is the platform_features list of poll answers; nil = an older platform that
	// sends no such key and refuses inventory entries of kind packages.
	features []string
	// invalid counts requests answered 400 invalid_request.
	invalid atomic.Int32
}

func newFakePlatform(t *testing.T) *fakePlatform {
	f := &fakePlatform{t: t, enrollToken: "pvbe_placeholder-enrollment", agentID: "9b2f6c1e-0000-4000-8000-000000000001",
		jobs: map[string]*fakeJob{}, pollTokens: map[string]int{}}
	f.srv = httptest.NewUnstartedServer(http.HandlerFunc(f.handle))
	f.srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	f.srv.StartTLS()
	t.Cleanup(f.srv.Close)
	// Every test also checks that the agent never sent a request the platforms refuse.
	t.Cleanup(func() {
		if n := f.invalid.Load(); n > 0 {
			t.Errorf("the platform answered %d request(s) of the agent with 400 invalid_request", n)
		}
	})
	return f
}

func (f *fakePlatform) enqueue(j Job) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if j.LeaseToken == "" {
		j.LeaseToken = "pvbl_" + j.JobID
	}
	if j.LeaseSeconds == 0 {
		j.LeaseSeconds = 30
	}
	j.Attempt, j.CreatedAt = 1, time.Now().UTC()
	f.queue = append(f.queue, j)
	f.jobs[j.JobID] = &fakeJob{job: j, parts: map[int][]byte{}}
}

// release expires a job's lease and leases the job again under a new lease token, as the
// platforms do when no renewal reached them for the lease time: attempt 2, parts dropped.
func (f *fakePlatform) release(id string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	j := f.jobs[id]
	j.job.LeaseToken += "-2"
	j.job.Attempt++
	j.parts = map[int][]byte{}
	f.queue = append(f.queue, j.job)
}

func (f *fakePlatform) job(id string) *fakeJob {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.jobs[id]
}

// issue returns the next agent token; f.mu is held.
func (f *fakePlatform) issue() string {
	f.issued++
	return "pvba_placeholder-token-" + strconv.Itoa(f.issued)
}

// protocolError is the normative status and message of one error code.
type protocolError struct {
	Status  int
	Message string
}

// protocolErrors is docs/agent-protocol/errors.json: the normative status and message of
// every error code, shared with the platform implementations. TestMain loads it (not a
// package initialiser, which would also run when the test binary acts as a fake tool in
// another working directory).
var protocolErrors map[string]protocolError

func loadProtocolErrors() map[string]protocolError {
	raw, err := os.ReadFile(filepath.Join("..", "..", "docs", "agent-protocol", "errors.json"))
	if err != nil {
		panic(err)
	}
	var doc struct {
		Errors []struct {
			Code    string `json:"code"`
			Status  int    `json:"status"`
			Message string `json:"message"`
		} `json:"errors"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		panic(err)
	}
	out := map[string]protocolError{}
	for _, e := range doc.Errors {
		out[e.Code] = protocolError{e.Status, e.Message}
	}
	return out
}

// canonical encodes a response the way docs/AGENT-PROTOCOL.md requires: compact, keys in
// declaration order, no HTML escaping, no trailing newline.
func canonical(v any) []byte {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		panic(err)
	}
	return bytes.TrimSuffix(b.Bytes(), []byte{'\n'})
}

func headers(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store, private")
	w.Header().Set("X-Bridge-Protocol", "1")
}

func apiErr(w http.ResponseWriter, status int, code string) {
	e, ok := protocolErrors[code]
	if !ok || e.Status != status {
		panic("the fake platform used an error that is not in errors.json: " + code)
	}
	headers(w)
	w.WriteHeader(status)
	var body ErrorBody
	body.Error.Code, body.Error.Message = code, e.Message
	_, _ = w.Write(canonical(body))
}

// refuse answers with an error code at the status errors.json gives it.
func (f *fakePlatform) refuse(w http.ResponseWriter, code string) {
	if code == ErrInvalidRequest {
		f.invalid.Add(1)
	}
	apiErr(w, protocolErrors[code].Status, code)
}

func reply(w http.ResponseWriter, status int, v any) {
	headers(w)
	w.WriteHeader(status)
	_, _ = w.Write(canonical(v))
}

func (f *fakePlatform) handle(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(io.LimitReader(r.Body, 2<<20))
	f.mu.Lock()
	f.bodies = append(f.bodies, body)
	if r.Header.Get("X-Bridge-Protocol") == "1" {
		f.protocolHeaderSeen = true
	}
	f.mu.Unlock()
	path := strings.TrimPrefix(r.URL.Path, APIPrefix)
	// Check order of docs/AGENT-PROTOCOL.md section 4: protocol header, content type,
	// authentication (with the organisation check), then the body and the resource.
	if r.Header.Get("X-Bridge-Protocol") != "1" {
		apiErr(w, 426, ErrProtocolUnsupported)
		return
	}
	if r.Header.Get("Content-Type") != "application/json" {
		apiErr(w, 415, ErrUnsupportedMediaType)
		return
	}
	if path == PathEnroll && r.Method == http.MethodPost {
		f.enroll(w, body)
		return
	}
	auth := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	f.mu.Lock()
	current := auth != "" && auth == f.agentToken
	previous := !current && auth != "" && auth == f.prevToken && time.Now().Before(f.prevUntil)
	code := ""
	switch {
	case !current && !previous:
		code = ErrUnauthenticated
	case f.revoked:
		// Revocation keeps the token hashes, so a revoked agent learns why.
		code = ErrAgentRevoked
	case f.forbidden:
		code = ErrForbidden
	}
	if code != "" {
		f.refusedAuth++
	}
	f.mu.Unlock()
	if code != "" {
		f.refuse(w, code)
		return
	}
	switch {
	case path == PathPoll && r.Method == http.MethodPost:
		f.poll(w, body, auth, previous)
	case path == PathSources && r.Method == http.MethodPut:
		f.putSources(w, body)
	case path == PathTokenRotate && r.Method == http.MethodPost:
		f.rotate(w, body)
	case strings.HasPrefix(path, pathJobs):
		f.jobAction(w, r, strings.TrimPrefix(path, pathJobs), body)
	default:
		apiErr(w, 404, ErrNotFound)
	}
}

func (f *fakePlatform) enroll(w http.ResponseWriter, body []byte) {
	m, ok := object(body)
	tok, _ := m["enrollment_token"].(string)
	f.mu.Lock()
	valid := ok && tok != "" && tok == f.enrollToken
	f.mu.Unlock()
	if !valid {
		f.refuse(w, ErrEnrollmentInvalid)
		return
	}
	info, _ := m["agent"].(map[string]any)
	if code := agentInfoError(info); code != "" {
		f.refuse(w, code)
		return
	}
	f.mu.Lock()
	f.enrollToken = "" // single use
	f.agentToken = f.issue()
	resp := EnrollResponse{AgentID: f.agentID, AgentToken: f.agentToken, Organization: Org{Name: "PT Contoh"}, PollIntervalSeconds: 1}
	f.mu.Unlock()
	reply(w, 201, resp)
}

func (f *fakePlatform) poll(w http.ResponseWriter, body []byte, token string, previous bool) {
	m, ok := object(body)
	if !ok {
		f.refuse(w, ErrInvalidRequest)
		return
	}
	if code := agentInfoError(m); code != "" {
		f.refuse(w, code)
		return
	}
	digest, isString := m["sources_digest"].(string)
	// running_jobs echoes job ids of this fake, which the tests keep short instead of
	// UUIDs, so only the shape of the list is checked.
	if !isString || (digest != "" && !reDigest.MatchString(digest)) ||
		!stringList(m["running_jobs"], 50, func(string) bool { return true }) || !integer(m["max_jobs"], 0, 10) {
		f.refuse(w, ErrInvalidRequest)
		return
	}
	maxJobs, _ := m["max_jobs"].(json.Number).Int64()
	f.mu.Lock()
	f.polls++
	f.pollTokens[token]++
	if previous {
		f.previousPolls++
	}
	n := min(int(maxJobs), 4, len(f.queue))
	jobs := append([]Job{}, f.queue[:n]...)
	f.queue = f.queue[n:]
	inv := f.inventoryRequested || f.sources == nil || f.sources.SourcesDigest != digest
	// As both platform lines: also while the agent still uses its previous token, because
	// then the answer of its last rotation was lost.
	rot := f.rotateRequested || previous
	features := f.features
	f.mu.Unlock()
	if features == nil {
		// An older platform: the answer of revision 2, without platform_features.
		reply(w, 200, struct {
			Jobs                   []Job     `json:"jobs"`
			NextPollSeconds        int       `json:"next_poll_seconds"`
			InventoryRequested     bool      `json:"inventory_requested"`
			TokenRotationRequested bool      `json:"token_rotation_requested"`
			ServerTime             time.Time `json:"server_time"`
		}{jobs, 1, inv, rot, time.Now().UTC()})
		return
	}
	reply(w, 200, PollResponse{Jobs: jobs, NextPollSeconds: 1, InventoryRequested: inv, TokenRotationRequested: rot,
		ServerTime: time.Now().UTC(), PlatformFeatures: features})
}

// featureList returns the platform_features of this platform.
func (f *fakePlatform) featureList() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.features...)
}

func (f *fakePlatform) putSources(w http.ResponseWriter, body []byte) {
	m, ok := object(body)
	if !ok || !validInventory(m, f.featureList()) {
		f.refuse(w, ErrInvalidRequest)
		return
	}
	var req SourcesRequest
	_ = json.Unmarshal(body, &req)
	f.mu.Lock()
	f.sources = &req
	f.inventoryRequested = false
	f.mu.Unlock()
	reply(w, 200, SourcesResponse{Accepted: len(req.Sources)})
}

func (f *fakePlatform) rotate(w http.ResponseWriter, body []byte) {
	if _, ok := object(body); !ok {
		f.refuse(w, ErrInvalidRequest)
		return
	}
	f.mu.Lock()
	// As both platform lines: the current token becomes the previous one for 600 seconds,
	// also when this request was authenticated with the previous token.
	f.prevToken, f.prevUntil = f.agentToken, time.Now().Add(600*time.Second)
	f.agentToken = f.issue()
	f.rotateRequested = false
	f.rotations++
	tok := f.agentToken
	drop := f.dropRotateAnswers > 0
	if drop {
		f.dropRotateAnswers--
	}
	f.mu.Unlock()
	if drop {
		// The rotation is stored, but its answer never reaches the agent.
		panic(http.ErrAbortHandler)
	}
	reply(w, 200, RotateResponse{AgentToken: tok, PreviousValidSeconds: 600})
}

func (f *fakePlatform) jobAction(w http.ResponseWriter, r *http.Request, rest string, body []byte) {
	id, action, _ := strings.Cut(rest, "/")
	// Step 8 (the body) comes before step 9 (the job and its lease).
	m, ok := object(body)
	f.mu.Lock()
	jobType := ""
	if j := f.jobs[id]; j != nil {
		jobType = j.job.Type
	}
	f.mu.Unlock()
	if !ok || !validJobBody(action, m) || !validForJob(jobType, action, m) || !f.accessAccepted(action, m) {
		if action == "progress" || action == "parts" || action == "complete" || action == "fail" {
			f.refuse(w, ErrInvalidRequest)
		} else {
			apiErr(w, 404, ErrNotFound)
		}
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	j, ok := f.jobs[id]
	if !ok {
		apiErr(w, 404, ErrJobNotFound)
		return
	}
	if r.Header.Get("X-Lease-Token") != j.job.LeaseToken {
		apiErr(w, 409, ErrLeaseExpired)
		return
	}
	// A finished job answers a repeated complete or fail with the same status (the first
	// response may have been lost); anything else is a withdrawn lease.
	switch {
	case j.completed != nil && action == "complete":
		reply(w, 200, StatusResponse{Status: StatusCompleted})
		return
	case j.failed != nil && action == "fail":
		reply(w, 200, StatusResponse{Status: StatusFailed})
		return
	case j.completed != nil || j.failed != nil:
		apiErr(w, 409, ErrLeaseExpired)
		return
	}
	switch action {
	case "progress":
		j.progressCalls++
		if f.expireLeases {
			apiErr(w, 409, ErrLeaseExpired)
			return
		}
		var req ProgressRequest
		_ = json.Unmarshal(body, &req)
		j.progress = append(j.progress, req)
		reply(w, 200, ProgressResponse{LeaseSeconds: j.job.LeaseSeconds, CancelRequested: f.cancelJobs})
	case "parts":
		if f.failPartsOnce && f.partFailures == 0 {
			f.partFailures++
			apiErr(w, 503, ErrMaintenance)
			return
		}
		var req PartRequest
		_ = json.Unmarshal(body, &req)
		if prev, dup := j.parts[req.Seq]; dup && sha256.Sum256(prev) != sha256.Sum256(body) {
			apiErr(w, 409, ErrPartConflict)
			return
		}
		j.parts[req.Seq] = body
		reply(w, 200, PartResponse{Seq: req.Seq, Received: true})
	case "complete":
		var req CompleteRequest
		_ = json.Unmarshal(body, &req)
		// Exactly the parts 0 … parts-1.
		for seq := range j.parts {
			if seq >= req.Parts {
				apiErr(w, 409, ErrPartsIncomplete)
				return
			}
		}
		for i := 0; i < req.Parts; i++ {
			if _, ok := j.parts[i]; !ok {
				apiErr(w, 409, ErrPartsIncomplete)
				return
			}
		}
		j.completed = &req
		reply(w, 200, StatusResponse{Status: StatusCompleted})
	case "fail":
		var req FailRequest
		_ = json.Unmarshal(body, &req)
		j.failed = &req
		reply(w, 200, StatusResponse{Status: StatusFailed})
	}
}

// ── the field rules of docs/AGENT-PROTOCOL.md section 5, as both platform lines apply them ──

var (
	reWord       = regexp.MustCompile(`^[a-z0-9_]{1,40}$`)
	reErrorCode  = regexp.MustCompile(`^[a-z0-9_]{1,60}$`)
	reID         = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,62}$`)
	reDigest     = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	reCapability = regexp.MustCompile(`^[a-z0-9_:,.-]{1,64}$`)
	reVersion    = regexp.MustCompile(`^[\x20-\x7e]{1,40}$`)
)

var sourceEngines = map[string][]string{
	"database": {"postgresql", "mysql", "mssql", "oracle", "mongodb"},
	"files":    {"filesystem"},
	"packages": {"host", "directory", "image_archive"},
}

// object decodes a request body that must be one JSON object; numbers stay json.Number.
func object(body []byte) (map[string]any, bool) {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	var m map[string]any
	if err := dec.Decode(&m); err != nil || m == nil {
		return nil, false
	}
	return m, true
}

// text is the protocol's text rule: valid UTF-8, min to max characters, no C0 control
// character (U+0000-U+001F) and no DEL (U+007F). C1 characters are allowed.
func text(v any, min, max int) bool {
	s, ok := v.(string)
	if !ok || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	n := utf8.RuneCountInString(s)
	return n >= min && n <= max
}

func word(v any, re *regexp.Regexp) bool {
	s, ok := v.(string)
	return ok && re.MatchString(s)
}

// stringList checks a JSON list (never null) of at most max strings that each pass ok.
func stringList(v any, max int, ok func(string) bool) bool {
	l, isList := v.([]any)
	if !isList || len(l) > max {
		return false
	}
	for _, e := range l {
		if s, isString := e.(string); !isString || !ok(s) {
			return false
		}
	}
	return true
}

// integer checks a JSON integer from min to max.
func integer(v any, min, max int64) bool {
	n, ok := v.(json.Number)
	if !ok {
		return false
	}
	i, err := n.Int64()
	return err == nil && i >= min && i <= max
}

// agentInfoError checks the agent fields of enroll and poll: "" when they are valid.
func agentInfoError(m map[string]any) string {
	if !integer(m["protocol"], 1, 1) {
		return ErrProtocolUnsupported
	}
	if !word(m["version"], reVersion) || !word(m["os"], reWord) || !word(m["arch"], reWord) ||
		!stringList(m["capabilities"], 64, reCapability.MatchString) {
		return ErrInvalidRequest
	}
	return ""
}

// validInventory checks a PUT /sources body (section 5.3). packagesKind is whether the
// platform implements revision 3; an older one refuses the whole inventory on kind packages.
// validInventory checks an inventory as a platform with these platform_features does: kind
// packages only with source_kind:packages (revision 3), and a database engine beyond
// revision 2 only with "source_engine:<engine>" (revision 4).
func validInventory(m map[string]any, features []string) bool {
	sources, isList := m["sources"].([]any)
	if !word(m["sources_digest"], reDigest) || !isList || len(sources) > 200 {
		return false
	}
	seen := map[string]bool{}
	schemaBytes := 0
	for _, e := range sources {
		s, isObject := e.(map[string]any)
		if !isObject {
			return false
		}
		id, _ := s["id"].(string)
		kind, _ := s["kind"].(string)
		engine, _ := s["engine"].(string)
		known := slices.Contains(sourceEngines[kind], engine) ||
			(kind == "database" && slices.Contains(features, FeatureSourceEnginePrefix+engine))
		if !reID.MatchString(id) || seen[id] || !known || !text(s["label"], 1, 128) ||
			(kind == "packages" && !slices.Contains(features, FeatureSourceKindPackages)) {
			return false
		}
		seen[id] = true
		if d := s["description"]; d != nil && !text(d, 0, 512) {
			return false
		}
		if !stringList(s["capabilities"], 16, reCapability.MatchString) {
			return false
		}
		// schemas (revision 5, contract P4-L1): on a database entry, absent or null, or at
		// most 200 names of the label rule (1 to 128 characters); at most 32 768 bytes of
		// names in the whole inventory. Other kinds ignore the key.
		if v := s["schemas"]; v != nil && kind == "database" {
			if !stringList(v, 200, func(n string) bool { return text(n, 1, 128) }) {
				return false
			}
			for _, n := range v.([]any) {
				schemaBytes += len(n.(string))
			}
		}
	}
	return schemaBytes <= 32768
}

// validJobBody checks the body of a job route (sections 5.4 to 5.7).
func validJobBody(action string, m map[string]any) bool {
	switch action {
	case "progress":
		return integer(m["progress"], 0, 100) && word(m["stage"], reWord) &&
			integer(m["done"], 0, 1_000_000_000) && integer(m["total"], 0, 1_000_000_000)
	case "parts":
		kind, _ := m["kind"].(string)
		items, isList := m["items"].([]any)
		return integer(m["seq"], 0, 499) && (kind == PartTables || kind == PartFiles || kind == PartPackages) && isList && len(items) >= 1 && len(items) <= 1000
	case "complete":
		_, isObject := m["result"].(map[string]any)
		return integer(m["parts"], 0, 500) && isObject
	case "fail":
		_, isBool := m["retryable"].(bool)
		// table (revision 5, proposal): optional, the name rule of a tables part item.
		if v, has := m["table"]; has && !tableName(v) {
			return false
		}
		return word(m["error_kind"], reWord) && word(m["error_code"], reErrorCode) && isBool && word(m["stage"], reWord)
	}
	return false
}

// tableName is the name rule of section 6.4: 1 to 255 bytes of valid UTF-8 without a C0
// control character or DEL.
func tableName(v any) bool {
	s, ok := v.(string)
	return ok && len(s) >= 1 && len(s) <= 255 && text(s, 1, 255)
}

// partKinds is the part kind of each job type (section 5.5).
var partKinds = map[string]string{JobScanDatabase: PartTables, JobScanFiles: PartFiles, JobScanPackages: PartPackages}

// validForJob checks what depends on the job type: the part kind, package items and the
// result of scan_packages (section 6.7).
func validForJob(jobType, action string, m map[string]any) bool {
	switch action {
	case "parts":
		if m["kind"] != partKinds[jobType] {
			return false
		}
		if jobType == JobScanPackages {
			for _, it := range m["items"].([]any) {
				if item, ok := it.(map[string]any); !ok || !validPackageItem(item) {
					return false
				}
			}
		}
	case "complete":
		if jobType == JobScanPackages {
			return validPackagesResult(m["result"].(map[string]any))
		}
	}
	return true
}

var (
	reMatchID      = regexp.MustCompile(`^[A-Za-z0-9._:-]{3,64}$`)
	reSHA256       = regexp.MustCompile(`^[0-9a-f]{64}$`)
	ecosystems     = []string{"npm", "Packagist", "Go", "Maven", "PyPI", "NuGet", "RubyGems", "crates.io", "Debian", "Ubuntu", "Alpine", "Red Hat", "Rocky Linux", "AlmaLinux", "other"}
	componentTypes = []string{"library", "os_package", "application", "framework", "container", "firmware", "other"}
	severities     = []string{"critical", "high", "medium", "low", "negligible", "unknown"}
)

func oneOf(v any, list []string) bool {
	s, ok := v.(string)
	return ok && slices.Contains(list, s)
}

// keysExactly checks that an object has exactly the required keys, plus optional ones.
func keysExactly(m map[string]any, required []string, optional ...string) bool {
	for _, k := range required {
		if _, ok := m[k]; !ok {
			return false
		}
	}
	for k := range m {
		if !slices.Contains(required, k) && !slices.Contains(optional, k) {
			return false
		}
	}
	return true
}

// validPackageItem is the item rule of section 6.7.
func validPackageItem(it map[string]any) bool {
	if !keysExactly(it, []string{"name", "version", "ecosystem", "type", "layer", "dependency", "licenses", "matches"}, "ecosystem_release", "purl") ||
		!text(it["name"], 1, 255) || !text(it["version"], 1, 128) || !oneOf(it["ecosystem"], ecosystems) ||
		!oneOf(it["type"], componentTypes) || !oneOf(it["layer"], []string{"os", "runtime", "application"}) ||
		!oneOf(it["dependency"], []string{"direct", "transitive", "unknown"}) ||
		!stringList(it["licenses"], 10, func(s string) bool { return text(s, 1, 64) }) {
		return false
	}
	if r, ok := it["ecosystem_release"]; ok && !text(r, 1, 32) {
		return false
	}
	if p, ok := it["purl"]; ok && !text(p, 1, 512) {
		return false
	}
	matches, ok := it["matches"].([]any)
	if !ok || len(matches) > 200 {
		return false
	}
	for _, x := range matches {
		m, ok := x.(map[string]any)
		if !ok || !keysExactly(m, []string{"id", "aliases", "severity", "cvss", "fix_versions", "matcher"}) ||
			!word(m["id"], reMatchID) || !stringList(m["aliases"], 20, reMatchID.MatchString) || !oneOf(m["severity"], severities) ||
			!stringList(m["fix_versions"], 10, func(s string) bool { return text(s, 1, 128) }) || !oneOf(m["matcher"], []string{"grype", "trivy"}) {
			return false
		}
		cvss, ok := m["cvss"].([]any)
		if !ok {
			return false
		}
		for _, c := range cvss {
			cm, ok := c.(map[string]any)
			if !ok || !keysExactly(cm, []string{"version", "vector", "score_tenths"}) || !text(cm["version"], 3, 3) || !text(cm["vector"], 1, 200) {
				return false
			}
			// score_tenths is an integer from 0 to 100: a float on the wire is refused.
			n, isNumber := cm["score_tenths"].(json.Number)
			if !isNumber || strings.ContainsAny(string(n), ".eE") || !integer(n, 0, 100) {
				return false
			}
		}
	}
	return true
}

// validPackagesResult checks complete.result of scan_packages: exactly the keys of
// section 6.7, nothing more.
func validPackagesResult(r map[string]any) bool {
	if !keysExactly(r, []string{"target_kind", "target_label", "os", "inventory_tool", "inventory_tool_version", "matcher",
		"matcher_version", "matcher_db_built_at", "packages_total", "matches_total", "truncated", "duration_ms", "bridge_version", "sbom_sha256"}) {
		return false
	}
	if !oneOf(r["target_kind"], []string{"host", "directory", "image_archive"}) || !text(r["target_label"], 1, 128) ||
		r["inventory_tool"] != "syft" || !oneOf(r["matcher"], []string{"grype", "trivy", "none"}) ||
		!integer(r["packages_total"], 0, 1<<40) || !integer(r["matches_total"], 0, 1<<40) || !integer(r["duration_ms"], 0, 1<<40) ||
		!word(r["sbom_sha256"], reSHA256) {
		return false
	}
	if _, ok := r["truncated"].(bool); !ok {
		return false
	}
	if r["matcher"] == "none" && (r["matcher_version"] != nil || r["matcher_db_built_at"] != nil) {
		return false
	}
	if o := r["os"]; o != nil {
		om, ok := o.(map[string]any)
		if !ok || !keysExactly(om, []string{"id", "version"}) {
			return false
		}
	}
	return true
}

// allBodies joins every request body received.
func (f *fakePlatform) allBodies() []byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	return bytes.Join(f.bodies, []byte("\n"))
}

// items decodes the items of every part of a job.
func (f *fakePlatform) items(id string) []json.RawMessage {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []json.RawMessage
	j := f.jobs[id]
	for i := 0; i < len(j.parts); i++ {
		var p struct {
			Items []json.RawMessage `json:"items"`
		}
		_ = json.Unmarshal(j.parts[i], &p)
		out = append(out, p.Items...)
	}
	return out
}

// accessAccepted refuses table items with "access" (revision 4, proposal) unless this
// platform listed table_access, and checks the shape when it did: counts, a list of at most
// 20 role names, booleans, nothing else.
func (f *fakePlatform) accessAccepted(action string, m map[string]any) bool {
	if action != "parts" || m["kind"] != PartTables {
		return true
	}
	accepted := slices.Contains(f.featureList(), FeatureTableAccess)
	for _, it := range m["items"].([]any) {
		item, _ := it.(map[string]any)
		raw, has := item["access"]
		if !has {
			continue
		}
		a, isObject := raw.(map[string]any)
		if !accepted || !isObject || !keysExactly(a, []string{"readers", "roles", "roles_total", "admins", "public", "complete"}) ||
			!integer(a["readers"], 0, 1<<31) || !integer(a["roles_total"], 0, 1<<31) || !integer(a["admins"], 0, 1<<31) ||
			!stringList(a["roles"], 20, func(s string) bool { return text(s, 1, 255) }) {
			return false
		}
		if _, ok := a["public"].(bool); !ok {
			return false
		}
		if _, ok := a["complete"].(bool); !ok {
			return false
		}
	}
	return true
}
