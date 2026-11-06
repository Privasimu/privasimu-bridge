package agent

import (
	"context"
	"crypto/x509"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestBasicAuthInFrontOfThePlatformIsNamed: a web server in front of the platform that asks
// for HTTP Basic Auth answers 401 without the protocol envelope. That is not a refused agent
// token, and the agent says so instead of asking for a new enrollment (B-5).
func TestBasicAuthInFrontOfThePlatformIsNamed(t *testing.T) {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("WWW-Authenticate", "Basic realm=\"stag\ting\", charset=\"UTF-8\"") // a tab is dropped when shown
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(w, "<html>401 Authorization Required</html>")
	}))
	srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	srv.StartTLS()
	t.Cleanup(srv.Close)
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	c, err := NewClient(ClientOptions{PlatformURL: srv.URL, RootCAs: pool})
	if err != nil {
		t.Fatal(err)
	}
	c.SetToken("pvba_placeholder-token")
	_, err = c.Poll(context.Background(), PollRequest{AgentInfo: AgentInfo{Version: "test", Protocol: 1, OS: "linux", Arch: "amd64",
		Capabilities: []string{}}, RunningJobs: []string{}})
	var ae *APIError
	if !errors.As(err, &ae) || ae.Status != 401 || ae.Code != ErrHTTPBasicAuth {
		t.Fatalf("err = %v", err)
	}
	if msg := refusalMessage(ae); !strings.Contains(msg, "HTTP Basic Auth") || strings.Contains(msg, "enroll again") {
		t.Fatalf("message = %q", msg)
	}
	probe, err := c.Probe(context.Background())
	if err != nil || !probe.BasicAuth || probe.Realm != "staging" || probe.FromPlatform() {
		t.Fatalf("probe %+v, %v", probe, err)
	}
	// The platform's own 401 keeps its code: a refused token is still a refused token.
	if got := refusalMessage(&APIError{Status: 401, Code: ErrUnauthenticated}); !strings.Contains(got, "enroll again") {
		t.Fatal(got)
	}
}
