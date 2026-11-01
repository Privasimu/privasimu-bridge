package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"math/rand/v2"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/privasimu/bridge/internal/audit"
	"github.com/privasimu/bridge/internal/buildinfo"
	"github.com/privasimu/bridge/internal/config"
	"github.com/privasimu/bridge/internal/dbsource"
	"github.com/privasimu/bridge/internal/files"
	"github.com/privasimu/bridge/internal/secrets"
)

// Deps are the collaborators of the agent.
type Deps struct {
	Config   *config.Config
	Client   *Client
	Resolver *secrets.Resolver
	Files    *files.Service
	Audit    *audit.Logger
	Log      *slog.Logger
	// Open connects to a database; tests replace it.
	Open func(ctx context.Context, t dbsource.Target) (dbsource.Conn, error)
}

// Agent polls the platform and runs jobs.
type Agent struct {
	cfg      *config.Config
	client   *Client
	resolver *secrets.Resolver
	files    *files.Service
	audit    *audit.Logger
	log      *slog.Logger
	open     func(ctx context.Context, t dbsource.Target) (dbsource.Conn, error)
	stateDir string
	agentID  string

	mu      sync.Mutex
	running map[string]*runningJob
	// releases holds a job the platform leased again while an older run of it was still
	// going here; it starts when that run has ended.
	releases map[string]Job
	failures int
	lastOK   time.Time
	lastErr  string
	jobs     sync.WaitGroup
	// unsaved is a rotated token that is in use but could not be stored yet; it is stored
	// again after every poll until that works, so a restart does not fall back to a token
	// the platform stops accepting 600 seconds after the rotation.
	unsaved string
	// saveToken stores the agent token (StoreToken); tests replace it.
	saveToken func(token string) error
	// sleep waits for d or until ctx ends; tests replace it.
	sleep func(ctx context.Context, d time.Duration) bool
	// minRenew is the shortest interval between lease renewals.
	minRenew time.Duration
}

// State is what enrollment leaves in the state directory.
type State struct {
	AgentID     string    `json:"agent_id"`
	PlatformURL string    `json:"platform_url"`
	EnrolledAt  time.Time `json:"enrolled_at"`
}

// Status is written after every poll for the healthcheck command.
type Status struct {
	AgentID             string    `json:"agent_id"`
	Version             string    `json:"version"`
	LastPollOK          time.Time `json:"last_poll_ok"`
	LastError           string    `json:"last_error,omitempty"`
	ConsecutiveFailures int       `json:"consecutive_failures"`
	RunningJobs         int       `json:"running_jobs"`
	UpdatedAt           time.Time `json:"updated_at"`
}

const (
	stateFile  = "agent.json"
	statusFile = "agent-status.json"
)

// LoadState reads the enrollment state.
func LoadState(stateDir string) (State, error) {
	var s State
	data, err := os.ReadFile(filepath.Join(stateDir, stateFile)) // #nosec G304 -- inside the configured state directory
	if err != nil {
		return s, err
	}
	err = json.Unmarshal(data, &s)
	return s, err
}

// LoadStatus reads the last status written by a running agent.
func LoadStatus(stateDir string) (Status, error) {
	var s Status
	data, err := os.ReadFile(filepath.Join(stateDir, statusFile)) // #nosec G304 -- inside the configured state directory
	if err != nil {
		return s, err
	}
	err = json.Unmarshal(data, &s)
	return s, err
}

// ErrNotEnrolled means the agent has no id or token yet.
var ErrNotEnrolled = errors.New("the agent is not enrolled")

// New builds an enrolled agent.
func New(d Deps) (*Agent, error) {
	a := &Agent{cfg: d.Config, client: d.Client, resolver: d.Resolver, files: d.Files, audit: d.Audit, log: d.Log,
		open: d.Open, stateDir: d.Config.Resolve(d.Config.StateDir), running: map[string]*runningJob{}, releases: map[string]Job{},
		sleep: sleepCtx, minRenew: 5 * time.Second}
	a.saveToken = func(token string) error { return StoreToken(a.cfg, a.resolver, token) }
	if a.log == nil {
		a.log = slog.New(slog.DiscardHandler)
	}
	if a.audit == nil {
		a.audit = audit.Discard()
	}
	if a.open == nil {
		a.open = dbsource.Open
	}
	a.agentID = d.Config.Agent.AgentID
	if a.agentID == "" {
		st, err := LoadState(a.stateDir)
		if err != nil {
			return nil, ErrNotEnrolled
		}
		a.agentID = st.AgentID
	}
	token, err := d.Resolver.Resolve(d.Config.Agent.Token)
	if err != nil {
		return nil, ErrNotEnrolled
	}
	a.client.SetToken(token.Reveal())
	return a, nil
}

func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// Info describes this agent to the platform.
func Info(cfg *config.Config) AgentInfo {
	caps := []string{}
	for _, j := range cfg.Agent.AllowedJobs {
		caps = append(caps, "job:"+j)
	}
	for _, e := range config.Engines {
		caps = append(caps, "engine:"+e)
	}
	caps = append(caps, "files:txt,csv,json,docx,xlsx,pdf")
	return AgentInfo{Version: wireVersion(buildinfo.Version), Protocol: ProtocolVersion, OS: runtime.GOOS, Arch: runtime.GOARCH, Capabilities: caps}
}

// wireVersion returns the version as the platforms accept it, 1 to 40 printable ASCII
// characters: a version set at build time (-ldflags -X) could be anything, and an invalid
// one would make every enroll and poll a 400.
func wireVersion(v string) string {
	b := make([]byte, 0, 40)
	for i := 0; i < len(v) && len(b) < 40; i++ {
		if c := v[i]; c >= 0x20 && c <= 0x7e {
			b = append(b, c)
		}
	}
	if len(b) == 0 {
		return "unknown"
	}
	return string(b)
}

// Inventory lists what the agent may scan: database sources and usable file roots. The
// list is never null: both platform lines refuse "sources": null.
func Inventory(cfg *config.Config, fs *files.Service) ([]Source, string) {
	out := []Source{}
	for i := range cfg.Sources {
		src := &cfg.Sources[i]
		caps := []string{}
		if cfg.SamplingFor(src).On() {
			caps = append(caps, "sampling")
		}
		out = append(out, Source{ID: src.ID, Kind: "database", Engine: src.Engine, Label: labelOf(src.Label, src.ID), Description: src.Description, Capabilities: caps})
	}
	if fs != nil {
		for _, r := range fs.Describe() {
			caps := []string{"path_mode:" + r.PathMode}
			if r.ContentScan {
				caps = append(caps, "content_scan")
			}
			root, _ := cfg.Root(r.ID)
			desc := ""
			if root != nil {
				desc = root.Description
			}
			out = append(out, Source{ID: r.ID, Kind: "files", Engine: "filesystem", Label: labelOf(r.Label, r.ID), Description: desc, Capabilities: caps})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	raw, _ := json.Marshal(out)
	sum := sha256.Sum256(raw)
	return out, "sha256:" + hex.EncodeToString(sum[:])
}

// labelOf returns the label the platform requires (1 to 128 characters): the configured
// one, or the id when there is none. The configuration already defaults it; this keeps an
// inventory built from any other configuration valid too.
func labelOf(label, id string) string {
	if strings.TrimSpace(label) == "" {
		return id
	}
	return label
}

// Run polls until ctx ends. Errors are retried with backoff; Run only returns when ctx
// ends, after running jobs have stopped.
func (a *Agent) Run(ctx context.Context) error {
	a.log.Info("bridge agent started", "agent_id", a.agentID, "version", buildinfo.Version, "jobs", a.cfg.Agent.AllowedJobs)
	minPoll, maxPoll := a.cfg.Agent.PollMin.D(), a.cfg.Agent.PollMax.D()
	backoff := minPoll
	inventorySent := false
	for {
		wait, ok := a.pollOnce(ctx, &inventorySent)
		if ok {
			backoff = minPoll
		} else {
			if wait == 0 {
				wait = backoff
			}
			backoff = min(backoff*2, maxPoll)
		}
		wait = min(max(wait, minPoll), maxPoll)
		// Jitter so that agents do not poll in step; not a security value.
		wait += time.Duration(rand.Int64N(int64(wait)/10 + 1)) // #nosec G404
		if !a.sleep(ctx, wait) {
			break
		}
	}
	a.jobs.Wait()
	a.log.Info("bridge agent stopped")
	return nil
}

// pollOnce sends one poll and starts the jobs it returns. It reports how long to wait
// before the next poll (0 = use backoff) and whether the poll succeeded.
func (a *Agent) pollOnce(ctx context.Context, inventorySent *bool) (time.Duration, bool) {
	sources, digest := Inventory(a.cfg, a.files)
	a.mu.Lock()
	running := make([]string, 0, len(a.running))
	for id := range a.running {
		running = append(running, id)
	}
	a.mu.Unlock()
	sort.Strings(running)
	// The protocol accepts max_jobs 0 to 10; a larger value would make every poll a 400.
	free := min(max(a.cfg.Agent.MaxParallelJobs-len(running), 0), maxJobsPerPoll)
	pctx, cancel := context.WithTimeout(ctx, requestTimeout)
	resp, err := a.client.Poll(pctx, PollRequest{AgentInfo: Info(a.cfg), SourcesDigest: digest, RunningJobs: running, MaxJobs: free})
	cancel()
	if err != nil {
		if ctx.Err() != nil {
			return 0, false
		}
		return a.pollFailed(err), false
	}
	a.mu.Lock()
	a.failures, a.lastOK, a.lastErr = 0, time.Now().UTC(), ""
	unsaved := a.unsaved
	a.mu.Unlock()
	if unsaved != "" {
		a.storeToken(unsaved)
	}
	if resp.InventoryRequested || !*inventorySent {
		ictx, cancel := context.WithTimeout(ctx, requestTimeout)
		if err := a.client.PutSources(ictx, SourcesRequest{SourcesDigest: digest, Sources: sources}); err != nil {
			a.log.Warn("inventory could not be sent", "error", err.Error())
		} else {
			*inventorySent = true
		}
		cancel()
	}
	if resp.TokenRotationRequested {
		a.rotate(ctx)
	}
	for _, job := range resp.Jobs {
		a.start(ctx, job)
	}
	a.writeStatus()
	return time.Duration(resp.NextPollSeconds) * time.Second, true
}

func (a *Agent) pollFailed(err error) time.Duration {
	code := codeOf(err)
	if code == "" {
		code = "network"
	}
	a.mu.Lock()
	a.failures++
	a.lastErr = code
	n := a.failures
	a.mu.Unlock()
	a.writeStatus()
	var ae *APIError
	if errors.As(err, &ae) {
		switch {
		case ae.Status == 401 || ae.Status == 403:
			// Refusals that waiting does not fix: poll at the longest interval and say why
			// now and then (every 12th refusal, about an hour at the default poll_max).
			if n == 1 || n%12 == 0 {
				a.log.Error(refusalMessage(ae), "code", ae.Code)
			}
			return a.cfg.Agent.PollMax.D()
		case ae.Code == ErrProtocolUnsupported || ae.Status == 426:
			a.log.Error("the platform does not support this agent version; upgrade the bridge", "code", ae.Code)
			return a.cfg.Agent.PollMax.D()
		case ae.RetryAfter > 0:
			return ae.RetryAfter
		}
	}
	if n == 1 || n%10 == 0 {
		a.log.Warn("poll failed", "code", code, "consecutive_failures", n)
	}
	return 0
}

// maxJobsPerPoll is the largest max_jobs the protocol accepts in a poll.
const maxJobsPerPoll = 10

// refusalMessage explains a 401 or 403 answer to a poll to the operator.
func refusalMessage(ae *APIError) string {
	switch {
	case ae.Code == ErrAgentRevoked:
		return "this agent was revoked on the platform; create or renew an agent there and enroll again with: privasimu-bridge agent enroll"
	case ae.Status == 403:
		return "the platform refuses this agent because its organisation is not active (archived, deleted or frozen); ask the tenant admin"
	}
	return "the platform does not accept the agent token; enroll again with: privasimu-bridge agent enroll"
}

// rotate asks for a new agent token, uses it at once and stores it. When the answer is lost
// the agent keeps its current token; the platform still accepts it for 600 seconds as the
// previous token and asks for a rotation again in the next poll answer, so the agent simply
// rotates again (both platform lines answer token_rotation_requested: true while the
// previous token is in use).
func (a *Agent) rotate(ctx context.Context) {
	rctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	resp, err := a.client.Rotate(rctx)
	if err != nil {
		a.log.Warn("token rotation failed; the platform asks again in the next poll answer", "error", err.Error())
		return
	}
	a.client.SetToken(resp.AgentToken)
	a.audit.Log(audit.Event{Event: "token_rotated", Mode: "agent", AgentID: a.agentID, Outcome: audit.OK})
	a.storeToken(resp.AgentToken)
}

// storeToken saves a token that is already in use. When that fails the token is kept as
// unsaved and pollOnce tries again after every poll: the stored token stops working 600
// seconds after the rotation, and a restart would read it.
func (a *Agent) storeToken(token string) {
	err := a.saveToken(token)
	a.mu.Lock()
	first := a.unsaved != token
	if err != nil {
		a.unsaved = token
	} else {
		a.unsaved = ""
	}
	a.mu.Unlock()
	switch {
	case err != nil && first:
		a.log.Error("the new agent token could not be stored; retrying after every poll (until then, a restart more than 10 minutes after the rotation needs a new enrollment)", "error", err.Error())
	case err == nil && first:
		a.log.Info("agent token rotated")
	case err == nil:
		a.log.Info("the rotated agent token is stored now")
	}
}

// StoreToken saves the agent token in the encrypted store named by agent.token.
func StoreToken(cfg *config.Config, r *secrets.Resolver, token string) error {
	kind, name, ok := cfg.Agent.Token.Parse()
	if !ok || kind != config.RefSecret {
		return errors.New("agent.token must be a secret:NAME reference to store the token")
	}
	store, err := r.Store()
	if err != nil {
		return err
	}
	if err := store.Set(name, token); err != nil {
		return err
	}
	return store.Save()
}

func (a *Agent) writeStatus() {
	a.mu.Lock()
	st := Status{AgentID: a.agentID, Version: buildinfo.Version, LastPollOK: a.lastOK, LastError: a.lastErr,
		ConsecutiveFailures: a.failures, RunningJobs: len(a.running), UpdatedAt: time.Now().UTC()}
	a.mu.Unlock()
	raw, _ := json.MarshalIndent(st, "", "  ")
	_ = secrets.WriteFileAtomic(filepath.Join(a.stateDir, statusFile), raw, 0o600)
}

// Enroll exchanges an enrollment token for the agent's id and token, stores the token in
// the encrypted store and the id in the state directory.
func Enroll(ctx context.Context, cfg *config.Config, r *secrets.Resolver, c *Client, enrollmentToken string) (EnrollResponse, error) {
	if kind, _, ok := cfg.Agent.Token.Parse(); !ok || kind != config.RefSecret {
		return EnrollResponse{}, errors.New("agent.token must be a secret:NAME reference before enrolling")
	}
	if _, err := r.Store(); err != nil {
		return EnrollResponse{}, err
	}
	resp, err := c.Enroll(ctx, EnrollRequest{EnrollmentToken: enrollmentToken, Agent: Info(cfg)})
	if err != nil {
		return resp, err
	}
	if err := StoreToken(cfg, r, resp.AgentToken); err != nil {
		return resp, err
	}
	st := State{AgentID: resp.AgentID, PlatformURL: cfg.Agent.PlatformURL, EnrolledAt: time.Now().UTC()}
	raw, _ := json.MarshalIndent(st, "", "  ")
	if err := secrets.WriteFileAtomic(filepath.Join(cfg.Resolve(cfg.StateDir), stateFile), raw, 0o600); err != nil {
		return resp, err
	}
	return resp, nil
}
