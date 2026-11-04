//go:build integration

package dbsource

// The access inventory against real servers, with the roles of
// testdata/integration/access_<engine>.sql: a group role with a member, a login account
// with a direct grant, a group without members, and administrators.

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/privasimu/bridge/internal/config"
	"github.com/privasimu/bridge/internal/secrets"
	"github.com/privasimu/bridge/internal/testutil/itenv"
)

func accessOf(t *testing.T, s itenv.Settings, user, password string) Access {
	t.Helper()
	port := s.Port
	if port == 0 {
		port = config.DefaultPort(s.Engine)
	}
	tlsMode := s.TLS
	if tlsMode == "" {
		tlsMode = config.DBTLSPrefer
	}
	conn, err := Open(context.Background(), Target{Engine: s.Engine, Host: s.Host, Port: port, Database: s.Database, Username: user,
		Password: secrets.Value(password), Timeout: 20 * time.Second, TLS: TLSSettings{Mode: tlsMode, CAFile: s.CAFile, ServerName: s.ServerName}})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer conn.Close()
	tbl, ok, err := conn.FindTable(context.Background(), "customers", "")
	if err != nil || !ok {
		t.Fatalf("customers: %v %v", ok, err)
	}
	a, err := conn.(AccessReader).TableAccess(context.Background(), tbl)
	if err != nil {
		t.Fatalf("access: %v", err)
	}
	raw, _ := json.Marshal(a)
	for _, account := range []string{"analyst1", "app_user", "bridge_ro", "postgres", "root", s.User} {
		if strings.Contains(string(raw), account) {
			t.Fatalf("an account name left the bridge: %s", raw)
		}
	}
	t.Logf("%s as %s: %s", s.Engine, strings.Repeat("*", len(user)), raw)
	return a
}

func TestTableAccess(t *testing.T) {
	t.Run("postgresql", func(t *testing.T) {
		s, ok := itenv.Lookup("postgresql")
		if !ok {
			t.Skip("BRIDGE_IT_POSTGRESQL_HOST is not set")
		}
		a := accessOf(t, s, s.User, s.Password)
		// bridge_ro, analyst1 (through crm_reader), app_user and the superuser.
		if !a.Complete || a.Readers < 4 || a.Admins < 1 || a.Public || !slices.Equal(a.Roles, []string{"crm_reader"}) {
			t.Fatalf("%+v", a)
		}
	})
	t.Run("mysql", func(t *testing.T) {
		s, ok := itenv.Lookup("mysql")
		if !ok {
			t.Skip("BRIDGE_IT_MYSQL_HOST is not set")
		}
		// The read-only account sees only its own grants: the answer says it is incomplete.
		if a := accessOf(t, s, s.User, s.Password); a.Complete {
			t.Fatalf("without the grant tables the answer must be incomplete: %+v", a)
		}
		if s.AccessUser == "" {
			t.Skip("BRIDGE_IT_MYSQL_ACCESS_USER is not set")
		}
		a := accessOf(t, s, s.AccessUser, s.AccessPassword)
		// root accounts (global SELECT), the schema readers and analyst1 through crm_reader.
		if !a.Complete || a.Readers < 4 || a.Admins < 1 || a.Public || !slices.Equal(a.Roles, []string{"crm_reader"}) {
			t.Fatalf("%+v", a)
		}
	})
}
