package cli

// Item B-5 of the 6 November 2026 staging report: init writes a configuration for the mode
// the operator chose, and check names what stands between the agent and the platform.

import (
	"encoding/pem"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/privasimu/bridge/internal/config"
	"github.com/privasimu/bridge/internal/i18n"
)

// fakePlatformAddress starts a TLS server answering the agent API probe with h, and writes
// its certificate as a CA file.
func fakePlatformAddress(t *testing.T, h http.HandlerFunc) (srv *httptest.Server, caFile string) {
	t.Helper()
	srv = httptest.NewUnstartedServer(h)
	srv.Config.ErrorLog = log.New(io.Discard, "", 0) // refused handshakes are the point of some cases
	srv.StartTLS()
	t.Cleanup(srv.Close)
	caFile = filepath.Join(t.TempDir(), "platform-ca.pem")
	data := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	if err := os.WriteFile(caFile, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return srv, caFile
}

// agentAPI answers like both platform lines on the agent prefix: 405 with the envelope.
func agentAPI(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Bridge-Protocol", "1")
	w.Header().Set("Allow", "POST")
	w.WriteHeader(http.StatusMethodNotAllowed)
	_, _ = io.WriteString(w, `{"error":{"code":"method_not_allowed","message":"This method is not allowed here."}}`)
}

func modeBConfig(t *testing.T, platformURL, caFile string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "bridge.yaml")
	yaml := "agent:\n  platform_url: " + strconv.Quote(platformURL) + "\n  ca_file: " + strconv.Quote(caFile) + "\n"
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestInitModeBWritesAnAgentConfiguration(t *testing.T) {
	t.Cleanup(func() { i18n.Set(i18n.EN) })
	srv, caFile := fakePlatformAddress(t, agentAPI)
	dir := filepath.Join(t.TempDir(), "conf")
	cfgPath := filepath.Join(dir, "bridge.yaml")
	r := run(t, "", "--config", cfgPath, "init", "--mode", "b", "--platform-url", srv.URL)
	if r.code != 0 {
		t.Fatalf("init: %d %s", r.code, r.stderr)
	}
	if keyPattern.MatchString(r.stdout) || !strings.Contains(r.stdout, "agent enroll") || !strings.Contains(r.stdout, "mode B") {
		t.Fatalf("mode B prints no API key and points at enrollment:\n%s", r.stdout)
	}
	if _, err := os.Stat(filepath.Join(dir, "tls")); !os.IsNotExist(err) {
		t.Fatal("mode B needs no certificate folder")
	}
	data, _ := os.ReadFile(cfgPath)
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatalf("%v\n%s", err, data)
	}
	if cfg.Agent.PlatformURL != srv.URL || len(cfg.Server.APIKeys) != 0 || cfg.Agent.MaxParallelJobs != 1 {
		t.Fatalf("agent %+v, %d API keys", cfg.Agent, len(cfg.Server.APIKeys))
	}
	if err := cfg.ValidateAgent(); err != nil {
		t.Fatal(err)
	}
	// check does not ask for a certificate in mode B, and reaches the agent API.
	yaml := strings.Replace(string(data), "ca_file: \"\"", "ca_file: "+strconv.Quote(caFile), 1)
	if err := os.WriteFile(cfgPath, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	r = run(t, "", "--config", cfgPath, "check")
	if r.code != 0 || strings.Contains(r.stdout, "TLS certificate:") ||
		!strings.Contains(r.stdout, "[OK]   mode B: the bridge agent API answers at "+srv.URL+"/api/bridge-agent/v1/poll") {
		t.Fatalf("check: %d\n%s\n%s", r.code, r.stdout, r.stderr)
	}
}

func TestInitChoosesTheMode(t *testing.T) {
	t.Cleanup(func() { i18n.Set(i18n.EN) })
	modeOf := func(t *testing.T, stdin string, args ...string) (*config.Config, result) {
		t.Helper()
		cfgPath := filepath.Join(t.TempDir(), "conf", "bridge.yaml")
		r := run(t, stdin, append([]string{"--config", cfgPath, "init"}, args...)...)
		if r.code != 0 {
			return nil, r
		}
		cfg, err := config.Load(cfgPath)
		if err != nil {
			t.Fatal(err)
		}
		return cfg, r
	}
	// A platform address alone means mode B; a public address means mode A, as before.
	if cfg, r := modeOf(t, "", "--platform-url", "https://privasimu.example.co.id"); cfg == nil || len(cfg.Server.APIKeys) != 0 {
		t.Fatalf("--platform-url alone must write mode B: %+v", r)
	}
	if cfg, r := modeOf(t, "", "--public-url", "https://bridge.example.co.id:8443"); cfg == nil || len(cfg.Server.APIKeys) != 1 {
		t.Fatalf("--public-url must write mode A: %+v", r)
	}
	if cfg, r := modeOf(t, "", "--mode", "agent"); cfg == nil || len(cfg.Server.APIKeys) != 0 || cfg.Agent.PlatformURL != "" ||
		!strings.Contains(r.stdout, "agent.platform_url in") {
		t.Fatalf("--mode agent writes mode B and asks for the platform address: %+v", r)
	}
	if _, r := modeOf(t, "", "--mode", "c"); r.code != 2 || !strings.Contains(r.stderr, `"c"`) {
		t.Fatalf("an unknown mode is a usage error: %+v", r)
	}
	// Without a flag, init asks on a terminal, and keeps mode A elsewhere (scripts).
	if cfg, _ := modeOf(t, ""); cfg == nil || len(cfg.Server.APIKeys) != 1 {
		t.Fatal("without a terminal init keeps writing mode A")
	}
	saved := isTerminal
	isTerminal = func(io.Reader) bool { return true }
	t.Cleanup(func() { isTerminal = saved })
	cfg, r := modeOf(t, "x\nb\nhttps://privasimu.example.co.id\n")
	if cfg == nil || len(cfg.Server.APIKeys) != 0 || cfg.Agent.PlatformURL != "https://privasimu.example.co.id" ||
		strings.Count(r.stdout, "Mode? A =") != 2 {
		t.Fatalf("the answer b (after an unknown one) writes mode B with the address given: %+v", r)
	}
	if cfg, _ := modeOf(t, "\n"); cfg == nil || len(cfg.Server.APIKeys) != 1 {
		t.Fatal("an empty answer keeps mode A")
	}
}

// TestCheckNamesWhatStandsInFrontOfThePlatform: TLS problems name the fix (agent.ca_file, the
// host name), HTTP Basic Auth in front of the platform is recognised, and so are a redirect,
// a refusal by something else, and an address without the agent API.
func TestCheckNamesWhatStandsInFrontOfThePlatform(t *testing.T) {
	answer := func(status int, headers ...string) http.HandlerFunc {
		return func(w http.ResponseWriter, _ *http.Request) {
			for i := 0; i+1 < len(headers); i += 2 {
				w.Header().Set(headers[i], headers[i+1])
			}
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(status)
			_, _ = io.WriteString(w, "<html>no</html>")
		}
	}
	cases := []struct {
		name    string
		handler http.HandlerFunc
		host    func(srv *httptest.Server) string // the platform URL (default the server URL)
		noCA    bool
		want    string
		code    int
	}{
		{name: "basic auth", handler: answer(401, "WWW-Authenticate", `Basic realm="Privasimu staging"`),
			want: `asks for HTTP Basic Auth (realm "Privasimu staging")`, code: 1},
		{name: "redirect", handler: answer(302, "Location", "https://login.example.co.id/"),
			want: "redirect to https://login.example.co.id/", code: 1},
		{name: "no agent API", handler: answer(404), want: "no bridge agent API at", code: 1},
		{name: "refused in front", handler: answer(403), want: "refused", code: 1},
		{name: "unknown CA", handler: agentAPI, noCA: true, want: "put that CA's PEM file in agent.ca_file", code: 1},
		{name: "host name", handler: agentAPI, host: func(srv *httptest.Server) string {
			return strings.Replace(srv.URL, "127.0.0.1", "localhost", 1)
		}, want: "certificate of localhost is not valid for that name (it is valid for: example.com", code: 1},
		{name: "agent API", handler: agentAPI, want: "[OK]   mode B: the bridge agent API answers", code: 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			srv, caFile := fakePlatformAddress(t, c.handler)
			u := srv.URL
			if c.host != nil {
				u = c.host(srv)
			}
			if c.noCA {
				caFile = ""
			}
			r := run(t, "", "--config", modeBConfig(t, u, caFile), "check")
			if r.code != c.code || !strings.Contains(r.stdout, c.want) {
				t.Fatalf("code %d, want %d; output lacks %q:\n%s%s", r.code, c.code, c.want, r.stdout, r.stderr)
			}
		})
	}
	// A CA file that holds no certificate is named before connecting.
	empty := filepath.Join(t.TempDir(), "empty.pem")
	_ = os.WriteFile(empty, []byte("not a certificate"), 0o600)
	if r := run(t, "", "--config", modeBConfig(t, "https://127.0.0.1:1", empty), "check"); r.code != 1 ||
		!strings.Contains(r.stdout, "holds no PEM certificate") {
		t.Fatalf("%+v", r)
	}
}
