//go:build integration

package dbsource

// The access inventory against real servers, with the roles of
// testdata/integration/access_<engine>.sql (MySQL 8: access_mysql8.sql): a group role with a
// member, a login account with a direct grant, a group without members, administrators,
// and the ways a person's name could pass for a role name: a PostgreSQL login turned
// NOLOGIN and granted to a successor, a MySQL 8 account granted to another account.

import (
	"bytes"
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

// accountsThatSignIn are the fixtures' accounts that can sign in: never in any answer.
var accountsThatSignIn = []string{"analyst1", "app_user", "bridge_ro", "postgres", "root", "successor1", "budi.santoso", "intern1"}

// accessOf reads the access inventory of customers with each naming, checks that no
// account that can sign in is named, and that hashed answers name no role either. It
// returns the plain answer and the server version.
func accessOf(t *testing.T, s itenv.Settings, user, password string) (Access, string) {
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
	hashedNames := HashedRoleNames(bytes.Repeat([]byte{7}, 32))
	var plain, hashed Access
	for _, names := range []RoleNaming{PlainRoleNames(), hashedNames} {
		a, err := conn.(AccessReader).TableAccess(context.Background(), tbl, names)
		if err != nil {
			t.Fatalf("access: %v", err)
		}
		raw, _ := json.Marshal(a)
		for _, account := range append(slices.Clone(accountsThatSignIn), s.User) {
			if strings.Contains(string(raw), account) {
				t.Fatalf("an account name left the bridge: %s", raw)
			}
		}
		t.Logf("%s as %s: %s", s.Engine, strings.Repeat("*", len(user)), raw)
		if names.plain {
			plain = a
		} else {
			hashed = a
		}
	}
	for _, role := range plain.Roles {
		if strings.Contains(strings.Join(hashed.Roles, ","), role) {
			t.Fatalf("a role name left the bridge with role_names: hashed: %v", hashed.Roles)
		}
	}
	if want, _ := hashedNames.Names(plain.Roles); !slices.Equal(hashed.Roles, want) || hashed.Readers != plain.Readers {
		t.Fatalf("hashed %+v, plain %+v", hashed, plain)
	}
	return plain, conn.ServerVersion(context.Background())
}

func TestTableAccess(t *testing.T) {
	t.Run("postgresql", func(t *testing.T) {
		s, ok := itenv.Lookup("postgresql")
		if !ok {
			t.Skip("BRIDGE_IT_POSTGRESQL_HOST is not set")
		}
		a, _ := accessOf(t, s, s.User, s.Password)
		// bridge_ro, analyst1 (through crm_reader), app_user, successor1 (through
		// budi_santoso) and the superuser; budi_santoso is a group role now.
		if !a.Complete || a.Readers < 5 || a.Admins < 1 || a.Public || !slices.Equal(a.Roles, []string{"budi_santoso", "crm_reader"}) {
			t.Fatalf("%+v", a)
		}
	})
	t.Run("mysql", func(t *testing.T) {
		s, ok := itenv.Lookup("mysql")
		if !ok {
			t.Skip("BRIDGE_IT_MYSQL_HOST is not set")
		}
		// The read-only account sees only its own grants: the answer says it is incomplete.
		if a, _ := accessOf(t, s, s.User, s.Password); a.Complete {
			t.Fatalf("without the grant tables the answer must be incomplete: %+v", a)
		}
		if s.AccessUser == "" {
			t.Skip("BRIDGE_IT_MYSQL_ACCESS_USER is not set")
		}
		a, version := accessOf(t, s, s.AccessUser, s.AccessPassword)
		// MariaDB: root accounts (global SELECT), the schema readers and analyst1 through
		// crm_reader. MySQL 8 also budi.santoso and intern1, to whom budi.santoso is granted:
		// both can sign in, so neither is a role.
		least := 4
		if !strings.Contains(strings.ToLower(version), "mariadb") {
			least = 5
		}
		if !a.Complete || a.Readers < least || a.Admins < 1 || a.Public || !slices.Equal(a.Roles, []string{"crm_reader"}) {
			t.Fatalf("%s: %+v", version, a)
		}
	})
}
