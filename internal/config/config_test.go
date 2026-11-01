package config

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

func abs(p string) string {
	if runtime.GOOS == "windows" {
		return `C:\data\` + p
	}
	return "/data/" + p
}

const validYAML = `
language: id
server:
  listen: "0.0.0.0:8443"
  tls: {mode: file, cert_file: tls/cert.pem, key_file: tls/key.pem}
  api_keys:
    - {id: k_1, hash: "sha256:0000000000000000000000000000000000000000000000000000000000000000"}
sources:
  - id: core-banking
    engine: postgresql
    host: 10.10.1.20
    database: corebank
    username: privasimu_ro
    password: "secret:corebank_pg"
    schemas: [public, cif]
  - id: crm
    engine: mariadb
    host: crm.internal
    database: crm
    username: ro
    password: "env:CRM_PASSWORD"
`

func TestParseAppliesDefaultsAndValidates(t *testing.T) {
	c, err := Parse([]byte(validYAML))
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	if err := c.ValidateServer(); err != nil {
		t.Fatal(err)
	}
	pg, _ := c.Source("core-banking")
	my, _ := c.Source("crm")
	if pg.Port != 5432 || pg.TLS.Mode != DBTLSPrefer || my.Engine != "mysql" || my.Port != 3306 {
		t.Fatalf("defaults: %+v %+v", pg, my)
	}
	if c.Server.Credentials != CredentialsLocal || c.Files.ReportPaths != PathsHashed || c.SamplingFor(pg).On() {
		t.Fatalf("safe defaults expected: %+v", c.Server)
	}
	if c.Server.Limits.RequestTimeout.D().Seconds() != 25 {
		t.Fatalf("request timeout = %v", c.Server.Limits.RequestTimeout.D())
	}
}

func TestUnknownKeysAreRejected(t *testing.T) {
	if _, err := Parse([]byte("server:\n  lisen: \":8443\"\n")); err == nil {
		t.Fatal("a misspelled key must be an error")
	}
}

func TestPlainPasswordsAreRefused(t *testing.T) {
	c, err := Parse([]byte(strings.Replace(validYAML, `"secret:corebank_pg"`, `"Sup3rSecret!"`, 1)))
	if err != nil {
		t.Fatal(err)
	}
	err = c.Validate()
	if err == nil || !strings.Contains(err.Error(), "sources[0].password") {
		t.Fatalf("a literal password must be refused, got %v", err)
	}
	if strings.Contains(err.Error(), "Sup3rSecret") {
		t.Fatal("the error must not echo the password")
	}
}

func TestValidationFindsEveryProblem(t *testing.T) {
	bad := `
language: fr
sources:
  - id: Core Banking
    engine: db9
  - id: dup
    engine: postgresql
    host: "bad host!"
    port: 70000
    database: "x;drop"
    username: ro
    password: "secret:x"
    tls: {mode: maybe}
files:
  report_paths: everything
  roots:
    - id: dup
      path: relative/path
`
	c, err := Parse([]byte(bad))
	if err != nil {
		t.Fatal(err)
	}
	err = c.Validate()
	ve, ok := err.(*ValidationError)
	if !ok {
		t.Fatalf("got %v", err)
	}
	joined := strings.Join(ve.Problems, "\n")
	for _, want := range []string{"language", "sources[0].id", "sources[0].engine", "sources[1].host", "sources[1].port",
		"sources[1].database", "sources[1].tls.mode", "files.report_paths", "files.roots[0].path", `"dup"`} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing problem about %s in:\n%s", want, joined)
		}
	}
}

func TestServerValidation(t *testing.T) {
	c, _ := Parse([]byte(validYAML))
	c.Server.TLS.Mode = TLSModeProxy
	if err := c.ValidateServer(); err == nil {
		t.Fatal("proxy mode must listen on loopback")
	}
	c.Server.Listen = "127.0.0.1:8080"
	if err := c.ValidateServer(); err != nil {
		t.Fatal(err)
	}
	c.Server.Credentials = CredentialsRequest
	if err := c.ValidateServer(); err == nil {
		t.Fatal("request credentials need allowed_targets")
	}
	c.Server.AllowedTargets = []string{"10.10.0.0/16", "db.internal.example"}
	if err := c.ValidateServer(); err != nil {
		t.Fatal(err)
	}
	c.Server.APIKeys[0].Disabled = true
	if err := c.ValidateServer(); err == nil {
		t.Fatal("at least one active key is required")
	}
}

func TestAgentValidation(t *testing.T) {
	c, _ := Parse([]byte(validYAML))
	if err := c.ValidateAgent(); err == nil {
		t.Fatal("platform_url is required")
	}
	c.Agent.PlatformURL = "https://app.privasimu.example"
	if err := c.ValidateAgent(); err != nil {
		t.Fatal(err)
	}
	c.Agent.AgentID = "not an id!"
	if err := c.ValidateAgent(); err == nil {
		t.Fatal("an agent_id override must look like an id")
	}
	c.Agent.AgentID = "0b7c5d0e-8f8a-4d6e-9d55-3f1d2a6b7c8d"
	if err := c.ValidateAgent(); err != nil {
		t.Fatal(err)
	}
	c.Agent.PlatformURL = "http://app.privasimu.example"
	if err := c.ValidateAgent(); err == nil {
		t.Fatal("plain http must be refused")
	}
	c.Agent.PlatformURL = "https://app.privasimu.example"
	c.Agent.Token = "hunter2"
	if err := c.ValidateAgent(); err == nil {
		t.Fatal("a literal token must be refused")
	}
}

func TestSecretRefs(t *testing.T) {
	for ref, ok := range map[SecretRef]bool{"secret:pg": true, "env:PG_PASS": true, "file:/run/secrets/pg": true,
		"secret:": false, "hunter2": false, "vault:x": false, "": false} {
		if _, _, got := ref.Parse(); got != ok {
			t.Errorf("%q: %v, want %v", ref, got, ok)
		}
	}
}

func TestByteSizeAndDuration(t *testing.T) {
	for in, want := range map[string]int64{"50MiB": 50 << 20, "8MB": 8 << 20, "512KiB": 512 << 10, "1024": 1024, "1GiB": 1 << 30} {
		got, err := ParseByteSize(in)
		if err != nil || got != want {
			t.Errorf("%s = %d %v", in, got, err)
		}
	}
	c, err := Parse([]byte("server:\n  limits:\n    request_timeout: 3\n    lockout: 2m\n"))
	if err != nil {
		t.Fatal(err)
	}
	if c.Server.Limits.RequestTimeout.D().Seconds() != 3 || c.Server.Limits.Lockout.D().Minutes() != 2 {
		t.Fatalf("%+v", c.Server.Limits)
	}
}

func TestRenderedTemplateIsValid(t *testing.T) {
	for _, lang := range []string{"en", "id"} {
		out, err := Render(TemplateData{Language: lang, Listen: "0.0.0.0:8443", PublicURL: "https://bridge.example.co.id:8443",
			KeyID: "k_1", KeyHash: "sha256:" + strings.Repeat("ab", 32), Created: "2026-10-31",
			CertFile: abs(`tls\cert.pem`), KeyFile: abs(`tls\key.pem`), StateDir: abs("state"),
			SecretsFile: "secrets.enc", SecretsKey: "secrets.key", AuditFile: "logs/audit.jsonl"})
		if err != nil {
			t.Fatal(err)
		}
		c, err := Parse(out)
		if err != nil {
			t.Fatalf("%s: %v\n%s", lang, err, out)
		}
		if err := c.Validate(); err != nil {
			t.Fatalf("%s: %v", lang, err)
		}
		if err := c.ValidateServer(); err != nil {
			t.Fatalf("%s: %v", lang, err)
		}
		if c.Server.TLS.CertFile != abs(`tls\cert.pem`) {
			t.Fatalf("path quoting: %q", c.Server.TLS.CertFile)
		}
	}
}

func TestLoadResolvesRelativePaths(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "bridge.yaml")
	if err := os.WriteFile(p, []byte(validYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if got := c.Resolve(c.Server.TLS.CertFile); got != filepath.Join(dir, "tls", "cert.pem") {
		t.Fatalf("resolved %q", got)
	}
	if _, err := Load(filepath.Join(dir, "missing.yaml")); err == nil {
		t.Fatal("a missing file must be an error")
	}
}

func TestLabelsDefaultToTheID(t *testing.T) {
	c, err := Parse([]byte("sources:\n  - id: crm\n    engine: mysql\n    host: h\n    database: d\n    username: u\n    password: \"env:X\"\nfiles:\n  roots:\n    - id: hr-share\n      path: " + strconv.Quote(abs("share")) + "\n"))
	if err != nil {
		t.Fatal(err)
	}
	if c.Sources[0].Label != "crm" || c.Files.Roots[0].Label != "hr-share" {
		t.Fatalf("labels: %q %q", c.Sources[0].Label, c.Files.Roots[0].Label)
	}
}

func TestLabelRuleMatchesTheAgentProtocol(t *testing.T) {
	cases := map[string]bool{
		strings.Repeat("é", 128): true,  // 128 characters, 256 bytes
		strings.Repeat("é", 129): false, // 129 characters
		"Inti \u0085 bank":       true,  // C1 characters are allowed
		"Inti \u0001 bank":       false, // C0 control
		"Inti \u007f bank":       false, // DEL
	}
	for label, ok := range cases {
		if got := validText(label, 1, 128); got != ok {
			t.Errorf("validText(%q) = %v, want %v", label, got, ok)
		}
	}
	if validText("", 1, 128) || !validText("", 0, 512) {
		t.Fatal("an empty label is refused, an empty description is fine")
	}
}

func TestAgentBoundsFollowThePlatform(t *testing.T) {
	base := func() *Config {
		c, _ := Parse([]byte("agent:\n  platform_url: \"https://app.privasimu.example\"\n"))
		return c
	}
	if err := base().ValidateAgent(); err != nil {
		t.Fatalf("defaults (5s, 5m, 1 job) must be valid: %v", err)
	}
	// The end-to-end tests of both platform lines run the agent with 1s and 2s.
	fast := base()
	fast.Agent.PollMin, fast.Agent.PollMax, fast.Agent.MaxParallelJobs = Duration(time.Second), Duration(2*time.Second), 10
	if err := fast.ValidateAgent(); err != nil {
		t.Fatalf("1s, 2s and 10 jobs must be valid: %v", err)
	}
	for name, mutate := range map[string]func(*Config){
		"poll_min below 1s":       func(c *Config) { c.Agent.PollMin = Duration(500 * time.Millisecond) },
		"poll_max above 5m":       func(c *Config) { c.Agent.PollMax = Duration(10 * time.Minute) },
		"more than 10 parallel":   func(c *Config) { c.Agent.MaxParallelJobs = 11 },
		"poll_min above poll_max": func(c *Config) { c.Agent.PollMin, c.Agent.PollMax = Duration(time.Minute), Duration(30*time.Second) },
	} {
		c := base()
		mutate(c)
		if err := c.ValidateAgent(); err == nil {
			t.Errorf("%s must be refused", name)
		}
	}
}

func TestInventorySizeIsBounded(t *testing.T) {
	var b strings.Builder
	b.WriteString("sources:\n")
	for i := 0; i <= MaxInventory; i++ {
		fmt.Fprintf(&b, "  - {id: s%d, engine: postgresql, host: h, database: d, username: u, password: \"env:X\"}\n", i)
	}
	c, err := Parse([]byte(b.String()))
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "201") {
		t.Fatalf("201 inventory entries must be refused: %v", err)
	}
}
