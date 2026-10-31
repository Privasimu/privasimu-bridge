package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"

	"github.com/privasimu/bridge/internal/apikey"
	"github.com/privasimu/bridge/internal/config"
	"github.com/privasimu/bridge/internal/i18n"
	"github.com/privasimu/bridge/internal/secrets"
)

// cmdInit creates bridge.yaml, the secret store key and the first API key.
func (a *app) cmdInit(args []string) error {
	fs := newFlags("init")
	dir := fs.String("dir", "", "")
	listen := fs.String("listen", "0.0.0.0:8443", "")
	publicURL := fs.String("public-url", "", "")
	platformURL := fs.String("platform-url", "", "")
	force := fs.Bool("force", false, "")
	if err := parseFlags(a, fs, args, "cli.init.usage"); err != nil {
		return err
	}
	if *dir == "" {
		if a.configPath != config.DefaultPath() {
			*dir = filepath.Dir(a.configPath)
		} else {
			*dir = config.DefaultDir()
		}
	}
	abs, err := filepath.Abs(*dir)
	if err != nil {
		return err
	}
	cfgPath := filepath.Join(abs, "bridge.yaml")
	if _, err := os.Stat(cfgPath); err == nil && !*force {
		return errors.New(i18n.T("cli.init.exists", cfgPath))
	}
	stateDir := config.DefaultStateDir(abs)
	logDir := config.DefaultLogDir(abs)
	secretsFile := filepath.Join(abs, "secrets.enc")
	if runtime.GOOS != "windows" && abs == "/etc/privasimu-bridge" {
		// The service writes the store when the agent token rotates; /etc stays read-only.
		secretsFile = filepath.Join(stateDir, "secrets.enc")
	}
	for _, d := range []string{abs, filepath.Join(abs, "tls"), stateDir, logDir} {
		if err := os.MkdirAll(d, 0o750); err != nil {
			return err
		}
	}
	keyFile := filepath.Join(abs, "secrets.key")
	if _, err := os.Stat(keyFile); errors.Is(err, os.ErrNotExist) {
		if err := secrets.CreateKeyFile(keyFile); err != nil {
			return err
		}
		a.printf("cli.init.created", keyFile)
	} else {
		a.printf("cli.init.kept_key", keyFile)
	}
	key, id, hash, err := apikey.Generate()
	if err != nil {
		return err
	}
	lang := string(i18n.Current())
	data, err := config.Render(config.TemplateData{
		Language: lang, Listen: *listen, PublicURL: *publicURL, KeyID: id, KeyHash: hash,
		Created: time.Now().UTC().Format("2006-01-02"), CertFile: filepath.Join(abs, "tls", "fullchain.pem"),
		KeyFile: filepath.Join(abs, "tls", "privkey.pem"), PlatformURL: *platformURL, StateDir: stateDir,
		SecretsFile: secretsFile, SecretsKey: keyFile, AuditFile: filepath.Join(logDir, "audit.jsonl"),
	})
	if err != nil {
		return err
	}
	if err := secrets.WriteFileAtomic(cfgPath, data, 0o640); err != nil {
		return err
	}
	a.printf("cli.init.created", cfgPath)
	if runtime.GOOS == "windows" && filepath.Clean(abs) == filepath.Clean(config.DefaultDir()) {
		// Only the system location is locked down: a directory under a user profile
		// (an evaluation) must stay usable by that user.
		a.restrictWindowsACL(abs)
	}
	a.printf("cli.init.key_once")
	fmt.Fprintf(a.stdout, "\n    %s\n\n", key)
	a.printf("cli.init.next", cfgPath)
	return nil
}

// restrictWindowsACL leaves the data directory to Administrators and SYSTEM only; the
// service account is granted access when the service is installed.
func (a *app) restrictWindowsACL(dir string) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "icacls", dir, "/inheritance:r", "/grant:r",
		"*S-1-5-32-544:(OI)(CI)F", "*S-1-5-18:(OI)(CI)F") // #nosec G204 -- fixed command
	if out, err := cmd.CombinedOutput(); err != nil {
		a.printf("cli.init.acl_failed", dir, string(out))
		return
	}
	a.printf("cli.init.acl_done", dir)
}
