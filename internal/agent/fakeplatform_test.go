package agent

// fakePlatform implements the platform side of agent protocol 1 in memory, as specified in
// docs/DESIGN.md, so that the agent can be tested before Laravel and Go implement it. It
// records every request body to check that nothing but metadata leaves the agent.

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
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

	mu                  sync.Mutex
	enrollToken         string
	agentToken          string
	prevToken           string
	agentID             string
	queue               []Job
	jobs                map[string]*fakeJob
	sources             *SourcesRequest
	bodies              [][]byte
	polls               int
	revoked             bool
	inventoryRequested  bool
	failPartsOnce       bool
	partFailures        int
	expireLeases        bool
	cancelJobs          bool
	rotateRequested     bool
	protocolHeaderSeen  bool
	unauthorizedPolling int
}

func newFakePlatform(t *testing.T) *fakePlatform {
	f := &fakePlatform{t: t, enrollToken: "pvbe_placeholder-enrollment", agentID: "9b2f6c1e-0000-4000-8000-000000000001",
		jobs: map[string]*fakeJob{}}
	f.srv = httptest.NewUnstartedServer(http.HandlerFunc(f.handle))
	f.srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	f.srv.StartTLS()
	t.Cleanup(f.srv.Close)
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

func (f *fakePlatform) job(id string) *fakeJob {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.jobs[id]
}

func apiErr(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(`{"error":{"code":"` + code + `","message":"x"}}`))
}

func reply(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
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
	if path == PathEnroll && r.Method == http.MethodPost {
		var req EnrollRequest
		_ = json.Unmarshal(body, &req)
		f.mu.Lock()
		defer f.mu.Unlock()
		if req.EnrollmentToken == "" || req.EnrollmentToken != f.enrollToken || req.Agent.Protocol != 1 {
			apiErr(w, 401, ErrEnrollmentInvalid)
			return
		}
		f.enrollToken = "" // single use
		f.agentToken = "pvba_placeholder-token-1"
		reply(w, 201, EnrollResponse{AgentID: f.agentID, AgentToken: f.agentToken, Organization: Org{Name: "PT Contoh"}, PollIntervalSeconds: 1})
		return
	}
	f.mu.Lock()
	auth := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	okToken := auth != "" && (auth == f.agentToken || auth == f.prevToken)
	revoked := f.revoked
	f.mu.Unlock()
	if !okToken || revoked {
		f.mu.Lock()
		f.unauthorizedPolling++
		f.mu.Unlock()
		code := ErrUnauthenticated
		if revoked {
			code = ErrAgentRevoked
		}
		apiErr(w, 401, code)
		return
	}
	switch {
	case path == PathPoll && r.Method == http.MethodPost:
		var req PollRequest
		if json.Unmarshal(body, &req) != nil {
			apiErr(w, 400, ErrInvalidRequest)
			return
		}
		f.mu.Lock()
		f.polls++
		n := min(req.MaxJobs, len(f.queue))
		jobs := append([]Job(nil), f.queue[:n]...)
		f.queue = f.queue[n:]
		inv := f.inventoryRequested || f.sources == nil || f.sources.SourcesDigest != req.SourcesDigest
		rot := f.rotateRequested
		f.rotateRequested = false
		f.mu.Unlock()
		reply(w, 200, PollResponse{Jobs: jobs, NextPollSeconds: 1, InventoryRequested: inv, TokenRotationRequested: rot, ServerTime: time.Now().UTC()})
	case path == PathSources && r.Method == http.MethodPut:
		var req SourcesRequest
		if json.Unmarshal(body, &req) != nil {
			apiErr(w, 400, ErrInvalidRequest)
			return
		}
		f.mu.Lock()
		f.sources = &req
		f.inventoryRequested = false
		f.mu.Unlock()
		reply(w, 200, SourcesResponse{Accepted: len(req.Sources)})
	case path == PathTokenRotate && r.Method == http.MethodPost:
		f.mu.Lock()
		f.prevToken, f.agentToken = f.agentToken, "pvba_placeholder-token-2"
		tok := f.agentToken
		f.mu.Unlock()
		reply(w, 200, RotateResponse{AgentToken: tok, PreviousValidSeconds: 600})
	case strings.HasPrefix(path, pathJobs):
		f.jobAction(w, r, strings.TrimPrefix(path, pathJobs), body)
	default:
		apiErr(w, 404, "not_found")
	}
}

func (f *fakePlatform) jobAction(w http.ResponseWriter, r *http.Request, rest string, body []byte) {
	id, action, _ := strings.Cut(rest, "/")
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
	if j.completed != nil || j.failed != nil {
		if action == "complete" || action == "fail" {
			reply(w, 200, StatusResponse{Status: "already_finished"})
			return
		}
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
		if json.Unmarshal(body, &req) != nil || len(body) > 1<<20 {
			apiErr(w, 400, ErrInvalidRequest)
			return
		}
		if prev, dup := j.parts[req.Seq]; dup && sha256.Sum256(prev) != sha256.Sum256(body) {
			apiErr(w, 409, ErrPartConflict)
			return
		}
		j.parts[req.Seq] = body
		reply(w, 200, PartResponse{Seq: req.Seq, Received: true})
	case "complete":
		var req CompleteRequest
		_ = json.Unmarshal(body, &req)
		for i := 0; i < req.Parts; i++ {
			if _, ok := j.parts[i]; !ok {
				apiErr(w, 409, ErrPartsIncomplete)
				return
			}
		}
		j.completed = &req
		reply(w, 200, StatusResponse{Status: "completed"})
	case "fail":
		var req FailRequest
		_ = json.Unmarshal(body, &req)
		j.failed = &req
		reply(w, 200, StatusResponse{Status: "failed"})
	default:
		apiErr(w, 404, "not_found")
	}
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
