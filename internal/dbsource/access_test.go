package dbsource

// The access inventory on the rows the catalog and grant tables return, through a driver
// that answers each query with canned rows. MySQL 8 is not among the integration servers
// here, so its role graph (an account granted to another account, locked roles) is covered
// by these fixtures; testdata/integration/access_*.sql are the same cases for real servers.

import (
	"bytes"
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-sql-driver/mysql"

	"github.com/privasimu/bridge/internal/config"
)

// grantAnswer is the answer to every query that contains its key.
type grantAnswer struct {
	cols []string
	rows [][]driver.Value
	err  error
}

// grantsDB is a database/sql connector whose queries are answered from answers, by the
// first key (in keys order) the query contains.
type grantsDB struct {
	keys    []string
	answers map[string]grantAnswer
	mu      sync.Mutex
	queries []string
}

func newGrantsDB(answers map[string]grantAnswer) (*sql.DB, *grantsDB) {
	g := &grantsDB{answers: answers}
	for k := range answers {
		g.keys = append(g.keys, k)
	}
	slices.Sort(g.keys)
	return sql.OpenDB(g), g
}

func (g *grantsDB) Connect(context.Context) (driver.Conn, error) { return &grantsConn{g}, nil }
func (g *grantsDB) Driver() driver.Driver                        { return grantsDriver{} }

type grantsDriver struct{}

func (grantsDriver) Open(string) (driver.Conn, error) { return nil, errors.New("not used") }

type grantsConn struct{ g *grantsDB }

func (c *grantsConn) Prepare(string) (driver.Stmt, error) { return nil, errors.New("not used") }
func (c *grantsConn) Close() error                        { return nil }
func (c *grantsConn) Begin() (driver.Tx, error)           { return nil, errors.New("not used") }

func (c *grantsConn) QueryContext(_ context.Context, query string, _ []driver.NamedValue) (driver.Rows, error) {
	c.g.mu.Lock()
	c.g.queries = append(c.g.queries, query)
	c.g.mu.Unlock()
	for _, k := range c.g.keys {
		if strings.Contains(query, k) {
			a := c.g.answers[k]
			if a.err != nil {
				return nil, a.err
			}
			return &grantRows{cols: a.cols, rows: a.rows}, nil
		}
	}
	return nil, fmt.Errorf("unexpected query %q", query)
}

type grantRows struct {
	cols []string
	rows [][]driver.Value
	next int
}

func (r *grantRows) Columns() []string { return r.cols }
func (r *grantRows) Close() error      { return nil }
func (r *grantRows) Next(dest []driver.Value) error {
	if r.next >= len(r.rows) {
		return io.EOF
	}
	copy(dest, r.rows[r.next])
	r.next++
	return nil
}

// textRows turns rows of strings into driver rows.
func textRows(rows ...[]string) [][]driver.Value {
	out := make([][]driver.Value, 0, len(rows))
	for _, r := range rows {
		v := make([]driver.Value, len(r))
		for i, s := range r {
			v[i] = s
		}
		out = append(out, v)
	}
	return out
}

var (
	testIDKey  = bytes.Repeat([]byte{7}, 32)
	roleIDForm = regexp.MustCompile(`^r_[0-9a-f]{16}$`)
	customers  = Table{Schema: "crm", Name: "customers", Ref: "customers"}
)

// accessWith runs the inventory of customers on db with each naming: hashed (the default)
// and plain. No name in personNames may appear in either answer.
func accessWith(t *testing.T, d dialect, version string, db *sql.DB, personNames []string) (hashed, plain Access) {
	t.Helper()
	conn := &sqlConn{d: d, db: db, version: version, t: Target{Timeout: 5 * time.Second}}
	for i, naming := range []RoleNaming{HashedRoleNames(testIDKey), PlainRoleNames()} {
		a, err := conn.TableAccess(context.Background(), customers, naming)
		if err != nil {
			t.Fatalf("access: %v", err)
		}
		raw, _ := json.Marshal(a)
		for _, name := range personNames {
			if bytes.Contains(raw, []byte(name)) {
				t.Fatalf("the name of an account that can sign in left the bridge: %s", raw)
			}
		}
		if i == 0 {
			hashed = a
		} else {
			plain = a
		}
	}
	for _, id := range hashed.Roles {
		if !roleIDForm.MatchString(id) {
			t.Fatalf("hashed role %q", id)
		}
	}
	if hashed.Readers != plain.Readers || hashed.RolesTotal != plain.RolesTotal || hashed.Admins != plain.Admins {
		t.Fatalf("the naming changes only the names: %+v %+v", hashed, plain)
	}
	return hashed, plain
}

func hashedIDs(names ...string) []string {
	n := HashedRoleNames(testIDKey)
	out := make([]string, 0, len(names))
	for _, name := range names {
		out = append(out, n.Name(name))
	}
	slices.Sort(out)
	return out
}

var myUserCols = []string{"User", "Host", "Select_priv", "Super_priv", "account_locked"}

// mysql8Grants is a MySQL 8 server: roles are locked accounts (CREATE ROLE), and a
// person's account is granted to another account like a role.
func mysql8Grants() map[string]grantAnswer {
	return map[string]grantAnswer{
		"FROM mysql.user": {cols: myUserCols, rows: textRows(
			[]string{"root", "localhost", "Y", "Y", "N"},
			[]string{"crm_reader", "%", "N", "N", "Y"},   // CREATE ROLE crm_reader
			[]string{"ex.employee", "%", "N", "N", "Y"},  // a person's locked account, granted to a successor
			[]string{"old_group", "%", "N", "N", "Y"},    // locked, with a grant but no member
			[]string{"budi.santoso", "%", "N", "N", "N"}, // a person who signs in
			[]string{"intern1", "%", "N", "N", "N"},
			[]string{"analyst1", "%", "N", "N", "N"},
			[]string{"successor", "%", "N", "N", "N"},
			[]string{"app", "%", "N", "N", "N"},
			[]string{"mysql.infoschema", "localhost", "Y", "N", "Y"}, // locked system account with global SELECT
			[]string{"mysql.session", "localhost", "N", "Y", "Y"},
		)},
		"FROM mysql.role_edges": {cols: []string{"FROM_USER", "FROM_HOST", "TO_USER", "TO_HOST"}, rows: textRows(
			[]string{"crm_reader", "%", "analyst1", "%"},
			[]string{"budi.santoso", "%", "intern1", "%"}, // GRANT 'budi.santoso'@'%' TO 'intern1'@'%'
			[]string{"ex.employee", "%", "successor", "%"},
		)},
		"FROM mysql.db": {cols: []string{"User", "Host"}, rows: textRows([]string{"app", "%"})},
		"FROM mysql.tables_priv": {cols: []string{"User", "Host"}, rows: textRows(
			[]string{"crm_reader", "%"}, []string{"budi.santoso", "%"}, []string{"old_group", "%"}, []string{"ex.employee", "%"},
		)},
	}
}

func TestMySQL8AccountsThatSignInAreNeverNamed(t *testing.T) {
	db, g := newGrantsDB(mysql8Grants())
	hashed, plain := accessWith(t, myDialect{}, "8.4.3", db, []string{"budi.santoso", "intern1", "analyst1", "successor", "app", "root"})
	// root (global SELECT), app (schema), budi.santoso (direct), intern1 (through
	// budi.santoso), analyst1 (through crm_reader), successor (through ex.employee); the
	// locked accounts without members (old_group, mysql.infoschema) cannot sign in.
	if plain.Readers != 6 || plain.Admins != 1 || plain.Public || !plain.Complete {
		t.Fatalf("%+v", plain)
	}
	if !slices.Equal(plain.Roles, []string{"crm_reader", "ex.employee"}) || plain.RolesTotal != 2 {
		t.Fatalf("plain: only locked accounts with members are roles: %+v", plain)
	}
	if !slices.Equal(hashed.Roles, hashedIDs("crm_reader", "ex.employee")) || hashed.RolesTotal != 2 {
		t.Fatalf("hashed: %+v", hashed)
	}
	var users string
	for _, q := range g.queries {
		if strings.Contains(q, "FROM mysql.user") {
			users = q
		}
	}
	if !strings.Contains(users, "account_locked") || strings.Contains(users, "authentication_string") {
		t.Fatalf("MySQL reads account_locked and never the password hash: %q", users)
	}
}

func TestMySQL8GrantTablesNotReadable(t *testing.T) {
	// The account may read the role edges and its own table grants, not mysql.user: whether
	// an account can sign in is unknown, so no account is named and the answer is incomplete.
	answers := mysql8Grants()
	answers["FROM mysql.user"] = grantAnswer{err: &mysql.MySQLError{Number: 1143, Message: "SELECT command denied for column 'account_locked'"}}
	answers["FROM mysql.db"] = grantAnswer{err: &mysql.MySQLError{Number: 1142, Message: "SELECT command denied"}}
	db, _ := newGrantsDB(answers)
	_, plain := accessWith(t, myDialect{}, "8.0.36", db, []string{"budi.santoso", "intern1", "analyst1", "successor", "crm_reader", "ex.employee"})
	// crm_reader, budi.santoso, old_group and ex.employee (table grants) and the accounts they
	// are granted to (analyst1, intern1, successor), all counted, none named.
	if plain.Complete || plain.Readers != 7 || len(plain.Roles) != 0 || plain.RolesTotal != 0 || plain.Admins != 0 {
		t.Fatalf("%+v", plain)
	}
}

func TestMySQL57HasNoRoleEdges(t *testing.T) {
	answers := mysql8Grants()
	answers["FROM mysql.role_edges"] = grantAnswer{err: &mysql.MySQLError{Number: 1146, Message: "Table 'mysql.role_edges' doesn't exist"}}
	db, _ := newGrantsDB(answers)
	_, plain := accessWith(t, myDialect{}, "5.7.44", db, []string{"budi.santoso", "app", "root"})
	// root, app and budi.santoso; without role edges the locked accounts are no one's role.
	if !plain.Complete || plain.Readers != 3 || plain.RolesTotal != 0 {
		t.Fatalf("%+v", plain)
	}
}

func TestMariaDBRolesAndPublic(t *testing.T) {
	cols := []string{"User", "Host", "Select_priv", "Super_priv", "is_role"}
	answers := map[string]grantAnswer{
		"FROM mysql.user": {cols: cols, rows: textRows(
			[]string{"root", "localhost", "Y", "Y", "N"},
			[]string{"crm_reader", "", "N", "N", "Y"},
			[]string{"analyst1", "%", "N", "N", "N"},
			[]string{"app", "%", "N", "N", "N"},
		)},
		// CREATE ROLE grants the role to its creator too.
		"FROM mysql.roles_mapping": {cols: []string{"Role", "", "User", "Host"}, rows: textRows(
			[]string{"crm_reader", "", "analyst1", "%"}, []string{"crm_reader", "", "root", "localhost"},
		)},
		"FROM mysql.db":          {cols: []string{"User", "Host"}, rows: textRows([]string{"app", "%"})},
		"FROM mysql.tables_priv": {cols: []string{"User", "Host"}, rows: textRows([]string{"crm_reader", ""})},
	}
	db, _ := newGrantsDB(answers)
	hashed, plain := accessWith(t, myDialect{}, "11.8.9-MariaDB", db, []string{"analyst1", "app", "root"})
	if plain.Readers != 3 || plain.Admins != 1 || plain.Public || !plain.Complete || !slices.Equal(plain.Roles, []string{"crm_reader"}) {
		t.Fatalf("%+v", plain)
	}
	if !slices.Equal(hashed.Roles, hashedIDs("crm_reader")) {
		t.Fatalf("%+v", hashed)
	}
	// GRANT SELECT ON crm.customers TO PUBLIC (MariaDB 10.11+): every account reads it.
	answers["FROM mysql.tables_priv"] = grantAnswer{cols: []string{"User", "Host"}, rows: textRows([]string{"PUBLIC", ""})}
	db, _ = newGrantsDB(answers)
	_, plain = accessWith(t, myDialect{}, "11.8.9-MariaDB", db, []string{"analyst1", "app", "root"})
	if !plain.Public || plain.Readers != 3 || len(plain.Roles) != 0 {
		t.Fatalf("PUBLIC: %+v", plain)
	}
}

func TestPostgreSQLNoLoginPersonIsHashedByDefault(t *testing.T) {
	// ALTER ROLE budi NOLOGIN; GRANT budi TO successor: budi is a group role now, and its
	// name is a person's. Roles that can sign in are never named.
	answers := map[string]grantAnswer{
		"pg_namespace": {cols: []string{"oid"}, rows: [][]driver.Value{{int64(16384)}}},
		"aclexplode":   {cols: []string{"exists"}, rows: [][]driver.Value{{false}}},
		"pg_auth_members": {cols: []string{"rolname", "rolcanlogin", "rolsuper", "exists"}, rows: [][]driver.Value{
			{"postgres", true, true, false},
			{"bridge_ro", true, false, false},
			{"app_user", true, false, false},
			{"analyst1", true, false, false},
			{"successor", true, false, false},
			{"lead_analyst", true, false, true}, // a login role others are granted to: still not named
			{"crm_reader", false, false, true},
			{"budi", false, false, true},
			{"empty_group", false, false, false},
		}},
	}
	db, _ := newGrantsDB(answers)
	hashed, plain := accessWith(t, pgDialect{}, "PostgreSQL 16.6", db, []string{"analyst1", "app_user", "successor", "lead_analyst", "bridge_ro"})
	if plain.Readers != 6 || plain.Admins != 1 || plain.Public || !plain.Complete || !slices.Equal(plain.Roles, []string{"budi", "crm_reader"}) {
		t.Fatalf("plain: %+v", plain)
	}
	raw, _ := json.Marshal(hashed)
	if bytes.Contains(raw, []byte("budi")) || bytes.Contains(raw, []byte("crm_reader")) || !slices.Equal(hashed.Roles, hashedIDs("budi", "crm_reader")) {
		t.Fatalf("hashed by default: %s", raw)
	}
}

func TestRoleNaming(t *testing.T) {
	h := HashedRoleNames(testIDKey)
	if h.Name("crm_reader") != h.Name("crm_reader") || h.Name("crm_reader") == h.Name("crm_writer") {
		t.Fatal("an id is stable for a name and differs between names")
	}
	if other := HashedRoleNames(bytes.Repeat([]byte{8}, 32)); other.Name("crm_reader") == h.Name("crm_reader") {
		t.Fatal("another install has other ids")
	}
	if HashedRoleNames([]byte("short")).Name("crm_reader") != "" {
		t.Fatal("a short key names nothing")
	}
	var many []string
	for i := range 30 {
		many = append(many, fmt.Sprintf("group_%02d", i))
	}
	many = append(many, "group_00", "bad\x01name")
	for _, c := range []struct {
		naming RoleNaming
		listed int
	}{{h, MaxAccessRoles}, {PlainRoleNames(), MaxAccessRoles}, {RoleNaming{}, 0}} {
		names, total := c.naming.Names(many)
		if total != 31 || len(names) != c.listed || !slices.IsSorted(names) {
			t.Fatalf("%+v: %d %q", c.naming, total, names)
		}
		if slices.Contains(names, "bad\x01name") {
			t.Fatal("a name the platform cannot store is not listed")
		}
	}
	if names, _ := (RoleNaming{}).Names([]string{"crm_reader"}); names == nil {
		t.Fatal("the zero value reports an empty list, not null")
	}
}

func TestRoleNamingFor(t *testing.T) {
	dir := t.TempDir()
	cfg, err := config.Parse([]byte("sources:\n  - {id: crm, engine: postgresql, host: h, database: d, username: u, password: \"secret:p\", access_inventory: true}\n"))
	if err != nil {
		t.Fatal(err)
	}
	cfg.SetPath(dir + "/bridge.yaml")
	if cfg.AccessInventory.RoleNames != config.RoleNamesHashed {
		t.Fatalf("the default is hashed: %q", cfg.AccessInventory.RoleNames)
	}
	first, err := RoleNamingFor(cfg)
	if err != nil {
		t.Fatal(err)
	}
	again, _ := RoleNamingFor(cfg)
	if id := first.Name("crm_reader"); !roleIDForm.MatchString(id) || again.Name("crm_reader") != id {
		t.Fatalf("hashed with the install key, stable within the install: %q", id)
	}
	cfg.AccessInventory.RoleNames = config.RoleNamesPlain
	if plain, _ := RoleNamingFor(cfg); plain.Name("crm_reader") != "crm_reader" {
		t.Fatal("plain is the operator's explicit choice")
	}
	cfg.Sources[0].AccessInventory = false
	if none, _ := RoleNamingFor(cfg); none.Name("crm_reader") != "" {
		t.Fatal("without access_inventory nothing is named")
	}
}
