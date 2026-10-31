package cli

import (
	"bufio"
	"context"
	"errors"
	"os"
	"strings"
	"time"

	"github.com/privasimu/bridge/internal/agent"
	"github.com/privasimu/bridge/internal/config"
	"github.com/privasimu/bridge/internal/dbsource"
	"github.com/privasimu/bridge/internal/files"
	"github.com/privasimu/bridge/internal/i18n"
	"github.com/privasimu/bridge/internal/secrets"
	"github.com/privasimu/bridge/internal/server"
	"github.com/privasimu/bridge/internal/service"
)

// runner starts a long-running mode under the service manager or in the foreground;
// asService tells fn that there is no console (logs then go to a file).
func (a *app) runner(name string, fn func(ctx context.Context, asService bool) error) error {
	if handled, err := service.RunIfService(name, func(ctx context.Context) error { return fn(ctx, true) }); handled {
		return err
	}
	ctx, stop := signalContext()
	defer stop()
	return fn(ctx, false)
}

// cmdServe runs mode A.
func (a *app) cmdServe(args []string) error {
	fs := newFlags("serve")
	name := fs.String("service-name", service.DefaultName("serve"), "")
	if err := parseFlags(a, fs, args, "cli.serve.usage"); err != nil {
		return err
	}
	cfg, err := a.load()
	if err != nil {
		return err
	}
	if err := cfg.ValidateServer(); err != nil {
		return err
	}
	return a.runner(*name, func(ctx context.Context, asService bool) error {
		log, closeLog, err := a.logger(cfg, asService)
		if err != nil {
			return err
		}
		defer closeLog()
		auditLog, err := a.auditLog(cfg)
		if err != nil {
			return err
		}
		defer auditLog.Close()
		var fsvc *files.Service
		if cfg.Server.FileEndpoints {
			if fsvc, err = files.NewService(cfg, log, auditLog); err != nil {
				return err
			}
		}
		srv, err := server.New(server.Deps{Config: cfg, Resolver: secrets.NewResolver(cfg),
			Pool: dbsource.NewPool(32, 5*time.Minute), Audit: auditLog, Log: log, Files: fsvc})
		if err != nil {
			return err
		}
		return srv.Run(ctx)
	})
}

// cmdAgent runs mode B, or enrolls it ("agent enroll").
func (a *app) cmdAgent(args []string) error {
	if len(args) > 0 && args[0] == "enroll" {
		return a.cmdEnroll(args[1:])
	}
	fs := newFlags("agent")
	name := fs.String("service-name", service.DefaultName("agent"), "")
	if err := parseFlags(a, fs, args, "cli.agent.usage"); err != nil {
		return err
	}
	cfg, err := a.load()
	if err != nil {
		return err
	}
	if err := cfg.ValidateAgent(); err != nil {
		return err
	}
	return a.runner(*name, func(ctx context.Context, asService bool) error {
		log, closeLog, err := a.logger(cfg, asService)
		if err != nil {
			return err
		}
		defer closeLog()
		auditLog, err := a.auditLog(cfg)
		if err != nil {
			return err
		}
		defer auditLog.Close()
		client, err := a.platformClient(cfg)
		if err != nil {
			return err
		}
		fsvc, err := files.NewService(cfg, log, auditLog)
		if err != nil {
			return err
		}
		ag, err := agent.New(agent.Deps{Config: cfg, Client: client, Resolver: secrets.NewResolver(cfg), Files: fsvc,
			Audit: auditLog, Log: log})
		if err != nil {
			if errors.Is(err, agent.ErrNotEnrolled) {
				return errors.New(i18n.T("cli.agent.not_enrolled"))
			}
			return err
		}
		return ag.Run(ctx)
	})
}

func (a *app) platformClient(cfg *config.Config) (*agent.Client, error) {
	opts := agent.ClientOptions{PlatformURL: cfg.Agent.PlatformURL, CAFile: cfg.Resolve(cfg.Agent.CAFile), ProxyURL: cfg.Agent.ProxyURL}
	if cfg.Agent.ProxyAuth.IsSet() {
		v, err := secrets.NewResolver(cfg).Resolve(cfg.Agent.ProxyAuth)
		if err != nil {
			return nil, err
		}
		opts.ProxyAuth = v.Reveal()
	}
	return agent.NewClient(opts)
}

// cmdEnroll exchanges a one-time enrollment token from the Privasimu console. The token
// is read from --token, PRIVASIMU_BRIDGE_ENROLL_TOKEN or standard input.
func (a *app) cmdEnroll(args []string) error {
	fs := newFlags("agent enroll")
	token := fs.String("token", "", "")
	if err := parseFlags(a, fs, args, "cli.enroll.usage"); err != nil {
		return err
	}
	cfg, err := a.load()
	if err != nil {
		return err
	}
	if err := cfg.ValidateAgent(); err != nil {
		return err
	}
	if *token == "" {
		*token = os.Getenv("PRIVASIMU_BRIDGE_ENROLL_TOKEN")
	}
	if *token == "" {
		a.printf("cli.enroll.prompt")
		line, _ := bufio.NewReader(a.stdin).ReadString('\n')
		*token = strings.TrimSpace(line)
	}
	if *token == "" {
		return errors.New(i18n.T("cli.enroll.no_token"))
	}
	client, err := a.platformClient(cfg)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	resp, err := agent.Enroll(ctx, cfg, secrets.NewResolver(cfg), client, *token)
	if err != nil {
		return errors.New(i18n.T("cli.enroll.failed", err.Error()))
	}
	a.printf("cli.enroll.done", resp.AgentID, resp.Organization.Name)
	return nil
}
