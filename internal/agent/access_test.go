package agent

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/privasimu/bridge/internal/config"
	"github.com/privasimu/bridge/internal/dbsource"
)

// TestAccessIsSentOnlyToAPlatformThatStoresIt: the access inventory (revision 4, proposal)
// travels in the table items only when the platform listed table_access and the source has
// access_inventory; it holds counts and role names, never an account name.
func TestAccessIsSentOnlyToAPlatformThatStoresIt(t *testing.T) {
	for _, accepted := range []bool{false, true} {
		e := newEnv(t, func(c *config.Config) { c.Sources[0].AccessInventory = true })
		e.db.Access = map[string]dbsource.Access{"users": {Readers: 4, Roles: []string{"crm_reader"}, RolesTotal: 1, Admins: 1, Complete: true}}
		if accepted {
			e.fp.setFeatures([]string{FeatureTableAccess})
		}
		e.enroll()
		e.fp.enqueue(Job{JobID: "job-db", Type: JobScanDatabase, SourceID: "core-banking", Options: JobOptions{MaxTables: 5}})
		a := e.agent()
		if !e.run(a, 20*time.Second, e.finished("job-db")) || e.fp.job("job-db").completed == nil {
			t.Fatalf("accepted=%v: the job did not complete: %+v", accepted, e.fp.job("job-db").failed)
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
		if accepted != (users.Access != nil) {
			t.Fatalf("accepted=%v: access %+v", accepted, users.Access)
		}
		if accepted && (users.Access.Readers != 4 || users.Access.Roles[0] != "crm_reader" || !users.Access.Complete) {
			t.Fatalf("%+v", users.Access)
		}
		inventory, _ := json.Marshal(e.fp.sources)
		if accepted != bytes.Contains(inventory, []byte(`"access"`)) {
			t.Fatalf("accepted=%v: the access capability: %s", accepted, inventory)
		}
	}
}
