package cli

import (
	"fmt"

	"github.com/privasimu/bridge/internal/config"
	"github.com/privasimu/bridge/internal/dbsource"
	"github.com/privasimu/bridge/internal/i18n"
	"github.com/privasimu/bridge/internal/secrets"
)

// cmdAccess prints, on this server only, the ids under which the access inventory reports
// group roles (access_inventory.role_names: hashed), so that a role id shown in Privasimu
// can be matched to a role name here, like "files locate" does for file ids.
func (a *app) cmdAccess(args []string) error {
	_, names, err := a.subcommand(args, "cli.access.usage", "role-id")
	if err != nil {
		return err
	}
	if len(names) == 0 {
		fmt.Fprintln(a.stderr, i18n.T("cli.access.usage"))
		return errUsage
	}
	cfg, err := a.load()
	if err != nil {
		return err
	}
	if cfg.AccessInventory.RoleNames == config.RoleNamesPlain {
		a.printf("cli.access.plain")
		return nil
	}
	key, err := secrets.LoadOrCreateIDKey(cfg.Resolve(cfg.StateDir))
	if err != nil {
		return err
	}
	ids := dbsource.HashedRoleNames(key)
	for _, name := range names {
		fmt.Fprintf(a.stdout, "%s  %s\n", ids.Name(name), name)
	}
	return nil
}
