//go:build linux

package service

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"time"
)

const unitDir = "/etc/systemd/system"

func run(ctx context.Context, out io.Writer, name string, args ...string) error {
	fmt.Fprintf(out, "  $ %s %s\n", name, joinArgs(args))
	cmd := exec.CommandContext(ctx, name, args...) // #nosec G204 -- fixed commands with checked arguments
	cmd.Stdout, cmd.Stderr = out, out
	return cmd.Run()
}

func joinArgs(args []string) string {
	out := ""
	for i, a := range args {
		if i > 0 {
			out += " "
		}
		out += quoteArg(a)
	}
	return out
}

// Install creates the service user, fixes the ownership of the bridge's directories,
// writes the unit and enables it. dryRun only prints the unit.
func Install(s Spec, out io.Writer, dryRun bool) error {
	if err := s.Validate(); err != nil {
		return err
	}
	if s.Account == "" {
		s.Account = "privasimu-bridge"
	}
	unit, err := Unit(s)
	if err != nil {
		return err
	}
	path := filepath.Join(unitDir, s.Name+".service")
	if dryRun {
		fmt.Fprintf(out, "# %s\n%s", path, unit)
		return nil
	}
	if os.Geteuid() != 0 {
		return errors.New("run this command as root (sudo)")
	}
	if _, err := exec.LookPath("systemctl"); err != nil {
		return ErrUnsupported
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if _, err := user.Lookup(s.Account); err != nil {
		if err := run(ctx, out, "useradd", "--system", "--no-create-home", "--home-dir", "/nonexistent",
			"--shell", "/usr/sbin/nologin", s.Account); err != nil {
			return fmt.Errorf("create the service user: %w", err)
		}
	}
	for _, d := range s.ReadWritePaths {
		if err := os.MkdirAll(d, 0o750); err != nil {
			return err
		}
		if err := run(ctx, out, "chown", "-R", s.Account+":"+s.Account, d); err != nil {
			return err
		}
		if err := run(ctx, out, "chmod", "-R", "u+rwX,g-w,o-rwx", d); err != nil {
			return err
		}
	}
	confDir := filepath.Dir(s.ConfigPath)
	if err := run(ctx, out, "chown", "-R", "root:"+s.Account, confDir); err != nil {
		return err
	}
	if err := run(ctx, out, "chmod", "-R", "u+rwX,g+rX,g-w,o-rwx", confDir); err != nil {
		return err
	}
	if err := os.WriteFile(path, []byte(unit), 0o644); err != nil {
		return err
	}
	fmt.Fprintf(out, "  wrote %s\n", path)
	if err := run(ctx, out, "systemctl", "daemon-reload"); err != nil {
		return err
	}
	return run(ctx, out, "systemctl", "enable", "--now", s.Name+".service")
}

// Uninstall stops, disables and removes the unit. The user and the data are kept.
func Uninstall(name string, out io.Writer) error {
	if os.Geteuid() != 0 {
		return errors.New("run this command as root (sudo)")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	_ = run(ctx, out, "systemctl", "disable", "--now", name+".service")
	path := filepath.Join(unitDir, name+".service")
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	fmt.Fprintf(out, "  removed %s\n", path)
	return run(ctx, out, "systemctl", "daemon-reload")
}

// RunIfService runs fn under the Windows service manager; elsewhere it reports false.
func RunIfService(string, func(context.Context) error) (bool, error) { return false, nil }
