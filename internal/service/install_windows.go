//go:build windows

package service

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"time"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

// wellKnown maps service account names to their SIDs, which icacls accepts in any
// Windows display language.
var wellKnown = map[string]string{
	`nt authority\localservice`:    "*S-1-5-19",
	`nt authority\local service`:   "*S-1-5-19",
	`nt authority\networkservice`:  "*S-1-5-20",
	`nt authority\network service`: "*S-1-5-20",
	"localsystem":                  "*S-1-5-18",
	`nt authority\system`:          "*S-1-5-18",
}

func principal(account string) string {
	if sid, ok := wellKnown[strings.ToLower(account)]; ok {
		return sid
	}
	return account
}

func icacls(ctx context.Context, out io.Writer, args ...string) error {
	fmt.Fprintf(out, "  > icacls %s\n", strings.Join(args, " "))
	cmd := exec.CommandContext(ctx, "icacls", args...) // #nosec G204 -- fixed command, checked paths
	cmd.Stdout, cmd.Stderr = io.Discard, out
	return cmd.Run()
}

// Install registers the Windows service (automatic, delayed start, restart on failure)
// and gives the service account read access to the configuration and write access to
// the state and log directories. dryRun only prints what would be done.
func Install(s Spec, out io.Writer, dryRun bool) error {
	if err := s.Validate(); err != nil {
		return err
	}
	if s.Account == "" {
		s.Account = `NT AUTHORITY\LocalService`
	}
	args := []string{"--config", s.ConfigPath, s.Mode}
	fmt.Fprintf(out, "  service %s: %s %s (account %s)\n", s.Name, quoteArg(s.Executable), joinQuoted(args), s.Account)
	if dryRun {
		return nil
	}
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect to the service manager (run as Administrator): %w", err)
	}
	defer m.Disconnect()
	if existing, err := m.OpenService(s.Name); err == nil {
		_ = existing.Close()
		return fmt.Errorf("service %s already exists; uninstall it first", s.Name)
	}
	cfg := mgr.Config{
		DisplayName:      "Privasimu Bridge (" + s.Mode + ")",
		Description:      s.Description(),
		StartType:        mgr.StartAutomatic,
		DelayedAutoStart: true,
		ServiceStartName: s.Account,
	}
	svcHandle, err := m.CreateService(s.Name, s.Executable, cfg, args...)
	if err != nil {
		return fmt.Errorf("create the service: %w", err)
	}
	defer svcHandle.Close()
	actions := []mgr.RecoveryAction{
		{Type: mgr.ServiceRestart, Delay: 10 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 30 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 60 * time.Second},
	}
	if err := svcHandle.SetRecoveryActions(actions, 86400); err != nil {
		fmt.Fprintf(out, "  warning: recovery actions not set: %v\n", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	who := principal(s.Account)
	for _, d := range s.ReadOnlyPaths {
		if err := icacls(ctx, out, d, "/grant", who+":(OI)(CI)RX"); err != nil {
			fmt.Fprintf(out, "  warning: could not grant read access to %s: %v\n", d, err)
		}
	}
	for _, d := range s.ReadWritePaths {
		if err := icacls(ctx, out, d, "/grant", who+":(OI)(CI)M"); err != nil {
			fmt.Fprintf(out, "  warning: could not grant write access to %s: %v\n", d, err)
		}
	}
	if err := svcHandle.Start(); err != nil {
		return fmt.Errorf("the service was created but did not start: %w", err)
	}
	fmt.Fprintf(out, "  service %s installed and started\n", s.Name)
	return nil
}

func joinQuoted(args []string) string {
	out := make([]string, len(args))
	for i, a := range args {
		out[i] = quoteArg(a)
	}
	return strings.Join(out, " ")
}

// Uninstall stops and deletes the service. Data and configuration are kept.
func Uninstall(name string, out io.Writer) error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect to the service manager (run as Administrator): %w", err)
	}
	defer m.Disconnect()
	s, err := m.OpenService(name)
	if err != nil {
		return fmt.Errorf("service %s not found: %w", name, err)
	}
	defer s.Close()
	if status, err := s.Control(svc.Stop); err == nil {
		deadline := time.Now().Add(30 * time.Second)
		for status.State != svc.Stopped && time.Now().Before(deadline) {
			time.Sleep(500 * time.Millisecond)
			if status, err = s.Query(); err != nil {
				break
			}
		}
	}
	if err := s.Delete(); err != nil {
		return err
	}
	fmt.Fprintf(out, "  service %s removed\n", name)
	return nil
}

// RunIfService runs fn under the service control manager when the process was started
// by it, and reports whether it did.
func RunIfService(name string, fn func(context.Context) error) (bool, error) {
	isService, err := svc.IsWindowsService()
	if err != nil || !isService {
		return false, nil
	}
	h := &handler{run: fn}
	if err := svc.Run(name, h); err != nil {
		return true, err
	}
	return true, h.err
}

type handler struct {
	run func(context.Context) error
	err error
}

// Execute is called by the service control manager.
func (h *handler) Execute(_ []string, requests <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	status <- svc.Status{State: svc.StartPending}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- h.run(ctx) }()
	status <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	for {
		select {
		case err := <-done:
			h.err = err
			if err != nil && !errors.Is(err, context.Canceled) {
				return true, 1
			}
			return false, 0
		case c := <-requests:
			switch c.Cmd {
			case svc.Interrogate:
				status <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				status <- svc.Status{State: svc.StopPending}
				cancel()
				select {
				case h.err = <-done:
				case <-time.After(25 * time.Second):
				}
				return false, 0
			}
		}
	}
}
