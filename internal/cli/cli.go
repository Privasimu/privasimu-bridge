// Package cli is the command line of privasimu-bridge. Every message an operator reads
// is available in English and Indonesian (--lang id, PRIVASIMU_BRIDGE_LANG or the
// configuration's language).
package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/privasimu/bridge/internal/audit"
	"github.com/privasimu/bridge/internal/config"
	"github.com/privasimu/bridge/internal/i18n"
	"github.com/privasimu/bridge/internal/secrets"
)

// app holds what every command needs.
type app struct {
	stdout, stderr io.Writer
	stdin          io.Reader
	configPath     string
	lang           string
}

type command struct {
	name    string
	summary string // i18n key
	run     func(a *app, args []string) error
}

func commands() []command {
	return []command{
		{"init", "cli.cmd.init", (*app).cmdInit},
		{"check", "cli.cmd.check", (*app).cmdCheck},
		{"serve", "cli.cmd.serve", (*app).cmdServe},
		{"agent", "cli.cmd.agent", (*app).cmdAgent},
		{"service", "cli.cmd.service", (*app).cmdService},
		{"key", "cli.cmd.key", (*app).cmdKey},
		{"secret", "cli.cmd.secret", (*app).cmdSecret},
		{"files", "cli.cmd.files", (*app).cmdFiles},
		{"healthcheck", "cli.cmd.healthcheck", (*app).cmdHealthcheck},
		{"version", "cli.cmd.version", (*app).cmdVersion},
	}
}

// errUsage marks a usage error (exit status 2).
var errUsage = errors.New("usage")

// Main runs the command line and returns the exit status.
func Main(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	a := &app{stdin: stdin, stdout: stdout, stderr: stderr}
	fs := flag.NewFlagSet("privasimu-bridge", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.StringVar(&a.configPath, "config", config.DefaultPath(), "")
	fs.StringVar(&a.lang, "lang", "", "")
	help := fs.Bool("help", false, "")
	if err := fs.Parse(args); err != nil {
		i18n.Set(i18n.Detect(a.lang, ""))
		fmt.Fprintln(stderr, err)
		a.usage()
		return 2
	}
	i18n.Set(i18n.Detect(a.lang, a.peekLanguage()))
	rest := fs.Args()
	if *help || len(rest) == 0 || rest[0] == "help" {
		a.usage()
		if *help || (len(rest) > 0 && rest[0] == "help") {
			return 0
		}
		return 2
	}
	for _, c := range commands() {
		if c.name == rest[0] {
			err := c.run(a, rest[1:])
			switch {
			case err == nil:
				return 0
			case errors.Is(err, errUsage):
				return 2
			default:
				fmt.Fprintln(stderr, i18n.T("cli.error"), err)
				return 1
			}
		}
	}
	fmt.Fprintln(stderr, i18n.T("cli.unknown_command", rest[0]))
	a.usage()
	return 2
}

// peekLanguage reads the language of the configuration file without validating it.
func (a *app) peekLanguage() string {
	data, err := os.ReadFile(a.configPath)
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(line), "language:"); ok {
			return strings.Trim(strings.TrimSpace(v), `"'`)
		}
	}
	return ""
}

func (a *app) usage() {
	fmt.Fprintln(a.stderr, i18n.T("cli.usage"))
	for _, c := range commands() {
		fmt.Fprintf(a.stderr, "  %-12s %s\n", c.name, i18n.T(c.summary))
	}
	fmt.Fprintln(a.stderr, i18n.T("cli.usage_flags"))
}

func (a *app) printf(key string, args ...any) { fmt.Fprintln(a.stdout, i18n.T(key, args...)) }

// load reads and validates the configuration.
func (a *app) load() (*config.Config, error) {
	cfg, err := config.Load(a.configPath)
	if err != nil {
		if errors.Is(err, config.ErrNotFound) {
			return nil, errors.New(i18n.T("cli.no_config", a.configPath))
		}
		return nil, err
	}
	return cfg, nil
}

// logger builds the operational log: JSON lines to the configured file or stderr.
func (a *app) logger(cfg *config.Config, service bool) (*slog.Logger, func(), error) {
	level := slog.LevelInfo
	switch strings.ToLower(cfg.Log.Level) {
	case "debug":
		level = slog.LevelDebug
	case "warn", "warning":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	}
	var w io.Writer = a.stderr
	closeFn := func() {}
	path := cfg.Log.File
	if path == "" && service {
		path = filepath.Join(filepath.Dir(cfg.Resolve(cfg.Audit.File)), "bridge.log")
	}
	if path != "" {
		path = cfg.Resolve(path)
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			return nil, nil, err
		}
		// Readable by the group so that a log shipper in the service group can read it.
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o640) // #nosec G302 G304 -- configured log path
		if err != nil {
			return nil, nil, err
		}
		w, closeFn = f, func() { _ = f.Close() }
	}
	return slog.New(slog.NewJSONHandler(w, &slog.HandlerOptions{Level: level})), closeFn, nil
}

func (a *app) auditLog(cfg *config.Config) (*audit.Logger, error) {
	return audit.Open(cfg.Resolve(cfg.Audit.File), cfg.Audit.MaxSizeMB, cfg.Audit.MaxFiles)
}

func (a *app) resolver(cfg *config.Config) *secrets.Resolver { return secrets.NewResolver(cfg) }

// signalContext ends on Ctrl+C or SIGTERM.
func signalContext() (context.Context, context.CancelFunc) {
	return signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
}

// subcommand splits "key create ..." into the action and its arguments.
func (a *app) subcommand(args []string, usageKey string, actions ...string) (string, []string, error) {
	if len(args) == 0 {
		fmt.Fprintln(a.stderr, i18n.T(usageKey))
		return "", nil, errUsage
	}
	for _, x := range actions {
		if args[0] == x {
			return x, args[1:], nil
		}
	}
	fmt.Fprintln(a.stderr, i18n.T(usageKey))
	return "", nil, errUsage
}

func newFlags(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	return fs
}

func parseFlags(a *app, fs *flag.FlagSet, args []string, usageKey string) error {
	if err := fs.Parse(args); err != nil {
		fmt.Fprintln(a.stderr, err)
		fmt.Fprintln(a.stderr, i18n.T(usageKey))
		return errUsage
	}
	return nil
}
