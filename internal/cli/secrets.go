package cli

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/term"

	"github.com/privasimu/bridge/internal/i18n"
	"github.com/privasimu/bridge/internal/secrets"
)

// cmdSecret manages the encrypted secret store. Values are read from the terminal
// without echo (or from standard input in scripts) and are never printed.
func (a *app) cmdSecret(args []string) error {
	action, rest, err := a.subcommand(args, "cli.secret.usage", "set", "list", "delete")
	if err != nil {
		return err
	}
	cfg, err := a.load()
	if err != nil {
		return err
	}
	store, err := secrets.NewResolver(cfg).Store()
	if err != nil {
		if errors.Is(err, secrets.ErrNoKey) {
			return errors.New(i18n.T("cli.secret.no_key", cfg.Resolve(cfg.Secrets.KeyFile)))
		}
		return err
	}
	switch action {
	case "list":
		for _, n := range store.Names() {
			fmt.Fprintln(a.stdout, n)
		}
		return nil
	case "delete":
		if len(rest) != 1 {
			fmt.Fprintln(a.stderr, i18n.T("cli.secret.usage"))
			return errUsage
		}
		if !store.Delete(rest[0]) {
			return errors.New(i18n.T("cli.secret.not_found", rest[0]))
		}
		if err := store.Save(); err != nil {
			return err
		}
		a.printf("cli.secret.deleted", rest[0])
		return nil
	default:
		if len(rest) != 1 || !secrets.ValidName(rest[0]) {
			fmt.Fprintln(a.stderr, i18n.T("cli.secret.usage"))
			return errUsage
		}
		value, err := a.readSecret()
		if err != nil {
			return err
		}
		if err := store.Set(rest[0], value); err != nil {
			return err
		}
		if err := store.Save(); err != nil {
			return err
		}
		a.printf("cli.secret.stored", rest[0], rest[0])
		return nil
	}
}

// readSecret reads a value twice without echo from a terminal, or once from a pipe.
func (a *app) readSecret() (string, error) {
	if f, ok := a.stdin.(*os.File); ok && term.IsTerminal(int(f.Fd())) {
		fmt.Fprint(a.stderr, i18n.T("cli.secret.prompt"))
		first, err := term.ReadPassword(int(f.Fd()))
		fmt.Fprintln(a.stderr)
		if err != nil {
			return "", err
		}
		fmt.Fprint(a.stderr, i18n.T("cli.secret.again"))
		second, err := term.ReadPassword(int(f.Fd()))
		fmt.Fprintln(a.stderr)
		if err != nil {
			return "", err
		}
		if string(first) != string(second) {
			return "", errors.New(i18n.T("cli.secret.mismatch"))
		}
		if len(first) == 0 {
			return "", errors.New(i18n.T("cli.secret.empty"))
		}
		return string(first), nil
	}
	data, err := io.ReadAll(io.LimitReader(bufio.NewReader(a.stdin), 64<<10))
	if err != nil {
		return "", err
	}
	v := strings.TrimRight(string(data), "\r\n")
	if v == "" {
		return "", errors.New(i18n.T("cli.secret.empty"))
	}
	return v, nil
}
