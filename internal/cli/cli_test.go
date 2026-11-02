package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/privasimu/bridge/internal/config"
	"github.com/privasimu/bridge/internal/i18n"
)

type result struct {
	code           int
	stdout, stderr string
}

func run(t *testing.T, stdin string, args ...string) result {
	t.Helper()
	var out, errb bytes.Buffer
	code := Main(args, strings.NewReader(stdin), &out, &errb)
	return result{code, out.String(), errb.String()}
}

var keyPattern = regexp.MustCompile(`pvbk_[A-Za-z0-9_-]{43}`)

func TestInitKeySecretAndCheck(t *testing.T) {
	t.Cleanup(func() { i18n.Set(i18n.EN) })
	dir := filepath.Join(t.TempDir(), "conf")
	cfgPath := filepath.Join(dir, "bridge.yaml")
	r := run(t, "", "--config", cfgPath, "init", "--listen", "127.0.0.1:18443")
	if r.code != 0 {
		t.Fatalf("init: %d %s", r.code, r.stderr)
	}
	key := keyPattern.FindString(r.stdout)
	if key == "" {
		t.Fatalf("init must print the API key once: %s", r.stdout)
	}
	data, _ := os.ReadFile(cfgPath)
	if bytes.Contains(data, []byte(key)) {
		t.Fatal("the configuration must hold the hash, not the key")
	}
	if r := run(t, "", "--config", cfgPath, "init"); r.code == 0 {
		t.Fatal("init must not overwrite an existing configuration without --force")
	}
	if r := run(t, "placeholder-secret\n", "--config", cfgPath, "secret", "set", "crm_password"); r.code != 0 {
		t.Fatalf("secret set: %s", r.stderr)
	}
	r = run(t, "", "--config", cfgPath, "secret", "list")
	if strings.TrimSpace(r.stdout) != "crm_password" || strings.Contains(r.stdout, "placeholder-secret") {
		t.Fatalf("secret list must show names only: %q", r.stdout)
	}
	if r := run(t, "", "--config", cfgPath, "key", "create"); r.code != 0 || keyPattern.FindString(r.stdout) == "" {
		t.Fatalf("key create: %d %s %s", r.code, r.stdout, r.stderr)
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Server.APIKeys) != 2 {
		t.Fatalf("keys = %d", len(cfg.Server.APIKeys))
	}
	if r := run(t, "", "--config", cfgPath, "key", "revoke", cfg.Server.APIKeys[0].ID); r.code != 0 {
		t.Fatalf("revoke: %s", r.stderr)
	}
	cfg, _ = config.Load(cfgPath)
	if !cfg.Server.APIKeys[0].Disabled || cfg.Server.APIKeys[1].Disabled {
		t.Fatalf("%+v", cfg.Server.APIKeys)
	}
	// check fails without a certificate, and says so in Indonesian on request.
	r = run(t, "", "--config", cfgPath, "--lang", "id", "check")
	if r.code != 1 || !strings.Contains(r.stdout, "sertifikat TLS") {
		t.Fatalf("check: %d\n%s\n%s", r.code, r.stdout, r.stderr)
	}
}

func TestUsageAndVersion(t *testing.T) {
	if r := run(t, "", "version"); r.code != 0 || !strings.Contains(r.stdout, "contract 1") {
		t.Fatalf("%+v", r)
	}
	if r := run(t, "", "nonsense"); r.code != 2 || !strings.Contains(r.stderr, "nonsense") {
		t.Fatalf("%+v", r)
	}
	if r := run(t, "", "--lang", "id", "help"); r.code != 0 || !strings.Contains(r.stderr, "Perintah:") {
		t.Fatalf("%+v", r)
	}
	if r := run(t, "", "--config", filepath.Join(t.TempDir(), "missing.yaml"), "check"); r.code != 1 || !strings.Contains(r.stdout+r.stderr, "init") {
		t.Fatalf("a missing configuration must point at init: %+v", r)
	}
}

func TestPlainPasswordInConfigIsRefused(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "bridge.yaml")
	yaml := "sources:\n  - id: db\n    engine: postgresql\n    host: 10.0.0.5\n    database: app\n    username: ro\n    password: \"Sup3r-placeholder\"\n"
	if err := os.WriteFile(cfgPath, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	r := run(t, "", "--config", cfgPath, "check")
	if r.code != 1 || !strings.Contains(r.stdout, "secret:NAME") || strings.Contains(r.stdout+r.stderr, "Sup3r") {
		t.Fatalf("%+v", r)
	}
}

// TestCheckVerifiesPackageScanners: check reports a pinned tool whose checksum differs, a
// missing tool, a target that cannot be read, and that scan_packages is not allowed.
func TestCheckVerifiesPackageScanners(t *testing.T) {
	dir := t.TempDir()
	tool := filepath.Join(dir, "syft")
	if err := os.WriteFile(tool, []byte("not the pinned build"), 0o755); err != nil {
		t.Fatal(err)
	}
	app := filepath.Join(dir, "app")
	_ = os.MkdirAll(app, 0o755)
	zero := strings.Repeat("0", 64)
	yaml := "packages:\n  targets:\n" +
		"    - {id: app, kind: directory, path: " + quoteYAML(app) + "}\n" +
		"    - {id: gone, kind: directory, path: " + quoteYAML(filepath.Join(dir, "gone")) + "}\n" +
		"  tools:\n    syft: {path: " + quoteYAML(tool) + ", sha256: " + zero + "}\n" +
		"    grype: {path: " + quoteYAML(filepath.Join(dir, "grype")) + ", sha256: " + zero + "}\n"
	cfgPath := filepath.Join(dir, "bridge.yaml")
	if err := os.WriteFile(cfgPath, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	r := run(t, "", "--config", cfgPath, "check")
	for _, want := range []string{"scan_packages", "package scanner syft", "does not match the sha256", "package scanner grype",
		"missing or not a regular file", "packages target app: directory", "packages target gone"} {
		if !strings.Contains(r.stdout, want) {
			t.Errorf("check output lacks %q:\n%s", want, r.stdout)
		}
	}
	if r.code != 1 {
		t.Fatalf("check must fail: %d", r.code)
	}
}

func quoteYAML(s string) string { return strconv.Quote(s) }
