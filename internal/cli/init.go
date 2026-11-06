package cli

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/privasimu/bridge/internal/apikey"
	"github.com/privasimu/bridge/internal/config"
	"github.com/privasimu/bridge/internal/i18n"
	"github.com/privasimu/bridge/internal/secrets"
)

// cmdInit creates bridge.yaml and the secret store key: for mode A also the first API key,
// for mode B a configuration with the agent filled in and no server.
func (a *app) cmdInit(args []string) error {
	fs := newFlags("init")
	dir := fs.String("dir", "", "")
	mode := fs.String("mode", "", "")
	listen := fs.String("listen", "0.0.0.0:8443", "")
	publicURL := fs.String("public-url", "", "")
	platformURL := fs.String("platform-url", "", "")
	stateFlag := fs.String("state-dir", "", "")
	logFlag := fs.String("log-dir", "", "")
	force := fs.Bool("force", false, "")
	if err := parseFlags(a, fs, args, "cli.init.usage"); err != nil {
		return err
	}
	modeB, err := a.initMode(*mode, *publicURL, platformURL)
	if err != nil {
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
	if *stateFlag != "" {
		if stateDir, err = filepath.Abs(*stateFlag); err != nil {
			return err
		}
	}
	logDir := config.DefaultLogDir(abs)
	if *logFlag != "" {
		if logDir, err = filepath.Abs(*logFlag); err != nil {
			return err
		}
	}
	// The store lives in the state folder: the service writes it when the agent token
	// rotates, while the configuration folder stays read-only for the service account.
	// Its key stays next to the configuration.
	secretsFile := filepath.Join(stateDir, "secrets.enc")
	dirs := []string{abs, stateDir, logDir}
	if !modeB {
		dirs = append(dirs, filepath.Join(abs, "tls"))
	}
	for _, d := range dirs {
		if err := os.MkdirAll(d, 0o750); err != nil {
			return notWritable(d, err)
		}
	}
	keyFile := filepath.Join(abs, "secrets.key")
	if _, err := os.Stat(keyFile); errors.Is(err, os.ErrNotExist) {
		if err := secrets.CreateKeyFile(keyFile); err != nil {
			return notWritable(keyFile, err)
		}
		a.printf("cli.init.created", keyFile)
	} else {
		a.printf("cli.init.kept_key", keyFile)
	}
	td := config.TemplateData{
		Language: string(i18n.Current()), ModeB: modeB, Listen: *listen, PublicURL: *publicURL,
		Created: time.Now().UTC().Format("2006-01-02"), CertFile: filepath.Join(abs, "tls", "fullchain.pem"),
		KeyFile: filepath.Join(abs, "tls", "privkey.pem"), PlatformURL: *platformURL, StateDir: stateDir,
		SecretsFile: secretsFile, SecretsKey: keyFile, AuditFile: filepath.Join(logDir, "audit.jsonl"),
	}
	var key string
	if !modeB {
		if key, td.KeyID, td.KeyHash, err = apikey.Generate(); err != nil {
			return err
		}
	}
	data, err := config.Render(td)
	if err != nil {
		return err
	}
	if err := secrets.WriteFileAtomic(cfgPath, data, 0o640); err != nil {
		return notWritable(cfgPath, err)
	}
	a.printf("cli.init.created", cfgPath)
	if runtime.GOOS == "windows" && filepath.Clean(abs) == filepath.Clean(config.DefaultDir()) {
		// Only the system location is locked down: a directory under a user profile
		// (an evaluation) must stay usable by that user.
		a.restrictWindowsACL(abs)
	}
	if modeB {
		if *platformURL == "" {
			a.printf("cli.init.platform_url_empty", cfgPath)
		}
		a.printf("cli.init.next_b", cfgPath)
		return nil
	}
	a.printf("cli.init.key_once")
	fmt.Fprintf(a.stdout, "\n    %s\n\n", key)
	a.printf("cli.init.next", cfgPath)
	return nil
}

// notWritable explains a write that the operating system refused: in a container the
// state volume or the configuration folder is often owned by root, while the bridge runs as
// the user 65532.
func notWritable(path string, err error) error {
	if errors.Is(err, os.ErrPermission) {
		return errors.New(i18n.T("cli.init.not_writable", path, err.Error()))
	}
	return err
}

// initMode decides whether init writes a mode B configuration: --mode a or b (also serve or
// agent) when given; else a --platform-url without --public-url means B, a --public-url A;
// else init asks on a terminal, and writes mode A otherwise (as before --mode existed). An
// answer of B may also give the platform address.
func (a *app) initMode(mode, publicURL string, platformURL *string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "a", "serve":
		return false, nil
	case "b", "agent":
		return true, nil
	case "":
	default:
		fmt.Fprintln(a.stderr, i18n.T("cli.init.bad_mode", mode))
		fmt.Fprintln(a.stderr, i18n.T("cli.init.usage"))
		return false, errUsage
	}
	switch {
	case *platformURL != "" && publicURL == "":
		return true, nil
	case publicURL != "" || !isTerminal(a.stdin):
		return false, nil
	}
	in := bufio.NewReader(a.stdin)
	for {
		fmt.Fprint(a.stdout, i18n.T("cli.init.ask_mode")+" ")
		line, err := in.ReadString('\n')
		switch strings.ToLower(strings.TrimSpace(line)) {
		case "", "a":
			return false, nil
		case "b":
			if *platformURL == "" {
				fmt.Fprint(a.stdout, i18n.T("cli.init.ask_platform_url")+" ")
				addr, _ := in.ReadString('\n')
				*platformURL = strings.TrimSpace(addr)
			}
			return true, nil
		}
		if err != nil {
			return false, nil
		}
	}
}

// isTerminal reports whether r is an interactive terminal; tests replace it.
var isTerminal = func(r io.Reader) bool {
	f, ok := r.(*os.File)
	if !ok {
		return false
	}
	st, err := f.Stat()
	return err == nil && st.Mode()&os.ModeCharDevice != 0
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
