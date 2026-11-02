package cli

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/privasimu/bridge/internal/agent"
	"github.com/privasimu/bridge/internal/buildinfo"
	"github.com/privasimu/bridge/internal/config"
	"github.com/privasimu/bridge/internal/files"
	"github.com/privasimu/bridge/internal/i18n"
	"github.com/privasimu/bridge/internal/service"
)

func (a *app) cmdVersion([]string) error {
	fmt.Fprintf(a.stdout, "privasimu-bridge %s (%s, %s) contract %s, agent protocol %d\n", buildinfo.Version,
		buildinfo.Revision(), buildinfo.Platform(), buildinfo.ContractVersion, buildinfo.AgentProtocol)
	return nil
}

// cmdFiles scans file roots locally and maps file ids back to paths.
func (a *app) cmdFiles(args []string) error {
	action, rest, err := a.subcommand(args, "cli.files.usage", "list", "scan", "locate")
	if err != nil {
		return err
	}
	cfg, err := a.load()
	if err != nil {
		return err
	}
	auditLog, err := a.auditLog(cfg)
	if err != nil {
		return err
	}
	defer auditLog.Close()
	svc, err := files.NewService(cfg, nil, auditLog)
	if err != nil {
		return err
	}
	for id, e := range svc.Invalid {
		fmt.Fprintln(a.stderr, i18n.T("cli.check.root_failed", id, e.Error()))
	}
	switch action {
	case "list":
		for _, r := range svc.Roots() {
			last := i18n.T("cli.files.never")
			if r.LastScan != nil {
				last = i18n.T("cli.files.last", r.LastScan.ScannedAt.Format(time.RFC3339), r.LastScan.FilesScanned, r.LastScan.FilesWithPII)
			}
			fmt.Fprintf(a.stdout, "%-20s %-30s %s\n", r.ID, r.Label, last)
		}
		return nil
	case "scan":
		if len(rest) != 1 {
			fmt.Fprintln(a.stderr, i18n.T("cli.files.usage"))
			return errUsage
		}
		ctx, stop := signalContext()
		defer stop()
		started := time.Now()
		rep, err := svc.ScanNow(ctx, rest[0], func(seen, scanned int) {
			if scanned%500 == 0 && scanned > 0 {
				fmt.Fprintln(a.stderr, i18n.T("cli.files.progress", scanned, seen))
			}
		})
		if err != nil {
			return err
		}
		a.printf("cli.files.summary", rep.RootID, rep.FilesSeen, rep.FilesScanned, rep.FilesWithPII, time.Since(started).Round(time.Second))
		cats := make([]string, 0, len(rep.Totals))
		for c, n := range rep.Totals {
			cats = append(cats, fmt.Sprintf("%s=%d", c, n))
		}
		sort.Strings(cats)
		if len(cats) > 0 {
			fmt.Fprintln(a.stdout, "  "+strings.Join(cats, "  "))
		}
		if len(rep.Skipped) > 0 {
			skipped := make([]string, 0, len(rep.Skipped))
			for k, n := range rep.Skipped {
				skipped = append(skipped, fmt.Sprintf("%s=%d", k, n))
			}
			sort.Strings(skipped)
			a.printf("cli.files.skipped", strings.Join(skipped, "  "))
		}
		a.printf("cli.files.report", filepath.Join(cfg.Resolve(cfg.StateDir), "reports", rep.RootID+".json"))
		return nil
	default:
		if len(rest) != 2 {
			fmt.Fprintln(a.stderr, i18n.T("cli.files.usage"))
			return errUsage
		}
		rep, err := svc.Latest(rest[0])
		if err != nil {
			return err
		}
		for _, f := range rep.Files {
			if f.ID == rest[1] {
				root, _ := svc.Root(rest[0])
				fmt.Fprintln(a.stdout, filepath.Join(root.Path, filepath.FromSlash(f.Path)))
				return nil
			}
		}
		return errors.New(i18n.T("cli.files.id_not_found", rest[1]))
	}
}

// cmdService installs or removes the Windows service or systemd unit.
func (a *app) cmdService(args []string) error {
	action, rest, err := a.subcommand(args, "cli.service.usage", "install", "uninstall")
	if err != nil {
		return err
	}
	fs := newFlags("service " + action)
	mode := fs.String("mode", "serve", "")
	name := fs.String("name", "", "")
	account := fs.String("account", "", "")
	dryRun := fs.Bool("dry-run", false, "")
	if err := parseFlags(a, fs, rest, "cli.service.usage"); err != nil {
		return err
	}
	if *name == "" {
		*name = service.DefaultName(*mode)
	}
	if action == "uninstall" {
		return service.Uninstall(*name, a.stdout)
	}
	cfg, err := a.load()
	if err != nil {
		return err
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	if exe, err = filepath.EvalSymlinks(exe); err != nil {
		return err
	}
	spec := service.Spec{Name: *name, Mode: *mode, Executable: exe, ConfigPath: cfg.Path(), Account: *account,
		ReadWritePaths: []string{cfg.Resolve(cfg.StateDir), filepath.Dir(cfg.Resolve(cfg.Audit.File))},
		ReadOnlyPaths:  []string{cfg.Dir()}}
	if store := filepath.Dir(cfg.Resolve(cfg.Secrets.File)); store != cfg.Dir() {
		spec.ReadWritePaths = append(spec.ReadWritePaths, store)
	}
	for _, r := range cfg.Files.Roots {
		spec.ReadOnlyPaths = append(spec.ReadOnlyPaths, r.Path)
	}
	// Package targets are read-only like file roots. A host target at "/" needs no entry:
	// the unit already makes the whole system read-only (ProtectSystem=strict).
	for _, t := range cfg.Packages.Targets {
		if p := filepath.Clean(t.Path); filepath.Dir(p) != p {
			spec.ReadOnlyPaths = append(spec.ReadOnlyPaths, p)
		}
	}
	if _, port, err := net.SplitHostPort(cfg.Server.Listen); err == nil && *mode == "serve" {
		if p, _ := strconv.Atoi(port); p > 0 && p < 1024 {
			spec.BindPrivileged = true
		}
	}
	if *mode == "serve" {
		if err := cfg.ValidateServer(); err != nil {
			return err
		}
	} else if err := cfg.ValidateAgent(); err != nil {
		return err
	}
	return service.Install(spec, a.stdout, *dryRun)
}

// cmdHealthcheck exits 0 when the running bridge is healthy: mode A answers /healthz on
// its own address, mode B polled the platform recently. Used by Docker HEALTHCHECK.
func (a *app) cmdHealthcheck(args []string) error {
	fs := newFlags("healthcheck")
	mode := fs.String("mode", "serve", "")
	if err := parseFlags(a, fs, args, "cli.health.usage"); err != nil {
		return err
	}
	cfg, err := a.load()
	if err != nil {
		return err
	}
	if *mode == "agent" {
		st, err := agent.LoadStatus(cfg.Resolve(cfg.StateDir))
		if err != nil {
			return errors.New(i18n.T("cli.health.no_status"))
		}
		limit := 3*cfg.Agent.PollMax.D() + time.Minute
		if time.Since(st.LastPollOK) > limit {
			return errors.New(i18n.T("cli.health.stale", st.LastError))
		}
		a.printf("cli.health.ok")
		return nil
	}
	_, port, err := net.SplitHostPort(cfg.Server.Listen)
	if err != nil {
		return err
	}
	scheme := "https"
	if cfg.Server.TLS.Mode == config.TLSModeProxy {
		scheme = "http"
	}
	// The check talks to this host's own listener over loopback, so the certificate
	// (issued for the public name) is not verified here.
	client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}, // #nosec G402 -- loopback health probe
		Proxy:           nil,
	}}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, scheme+"://127.0.0.1:"+port+cfg.Server.BasePath+"/healthz", nil)
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	var body struct {
		Status string `json:"status"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&body)
	if resp.StatusCode != http.StatusOK || body.Status != "ok" {
		return errors.New(i18n.T("cli.health.bad", resp.StatusCode))
	}
	a.printf("cli.health.ok")
	return nil
}
