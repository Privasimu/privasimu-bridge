package agent

import (
	"bytes"
	"encoding/json"
	"slices"
	"testing"
	"time"

	"github.com/privasimu/bridge/internal/config"
	"github.com/privasimu/bridge/internal/dbsource"
	"github.com/privasimu/bridge/internal/secrets"
)

// TestAccessIsSentOnlyToAPlatformThatStoresIt: the access inventory (revision 4, proposal)
// travels in the table items only when the platform listed table_access and the source has
// access_inventory; it holds counts and group roles, the roles as keyed hashes unless the
// operator chose plain names, never an account name.
func TestAccessIsSentOnlyToAPlatformThatStoresIt(t *testing.T) {
	for _, c := range []struct {
		accepted  bool
		roleNames string
	}{{false, config.RoleNamesHashed}, {true, config.RoleNamesHashed}, {true, config.RoleNamesPlain}} {
		e := newEnv(t, func(cfg *config.Config) {
			cfg.Sources[0].AccessInventory = true
			cfg.AccessInventory.RoleNames = c.roleNames
		})
		e.db.Access = map[string]dbsource.Access{"users": {Readers: 4, Roles: []string{"crm_reader"}, RolesTotal: 1, Admins: 1, Complete: true}}
		if c.accepted {
			e.fp.setFeatures([]string{FeatureTableAccess})
		}
		e.enroll()
		e.fp.enqueue(Job{JobID: "job-db", Type: JobScanDatabase, SourceID: "core-banking", Options: JobOptions{MaxTables: 5}})
		a := e.agent()
		if !e.run(a, 20*time.Second, e.finished("job-db")) || e.fp.job("job-db").completed == nil {
			t.Fatalf("%+v: the job did not complete: %+v", c, e.fp.job("job-db").failed)
		}
		var users TableItem
		for _, it := range e.fp.items("job-db") {
			var ti TableItem
			_ = json.Unmarshal(it, &ti)
			if ti.Name == "users" {
				users = ti
			}
			if ti.Name != "users" && ti.Access != nil {
				t.Fatalf("a table without personal data has no access entry: %s", ti.Name)
			}
		}
		if c.accepted != (users.Access != nil) {
			t.Fatalf("%+v: access %+v", c, users.Access)
		}
		inventory, _ := json.Marshal(e.fp.sources)
		if c.accepted != bytes.Contains(inventory, []byte(`"access"`)) {
			t.Fatalf("%+v: the access capability: %s", c, inventory)
		}
		if !c.accepted {
			continue
		}
		want := "crm_reader"
		if c.roleNames == config.RoleNamesHashed {
			key, err := secrets.LoadOrCreateIDKey(e.cfg.Resolve(e.cfg.StateDir))
			if err != nil {
				t.Fatal(err)
			}
			want = dbsource.HashedRoleNames(key).Name("crm_reader")
			if bytes.Contains(e.fp.allBodies(), []byte("crm_reader")) {
				t.Fatal("a role name left the bridge although role_names is hashed")
			}
		}
		if users.Access.Readers != 4 || !slices.Equal(users.Access.Roles, []string{want}) || users.Access.RolesTotal != 1 || !users.Access.Complete {
			t.Fatalf("%+v: %+v, want role %s", c, users.Access, want)
		}
	}
}
