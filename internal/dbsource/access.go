package dbsource

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"sort"
	"strings"

	"github.com/go-sql-driver/mysql"

	"github.com/privasimu/bridge/internal/config"
	"github.com/privasimu/bridge/internal/secrets"
)

// Access tells who can read a table, as counts and group roles only: the names of accounts
// that can sign in (which are often people's names) never leave the bridge, and group roles
// leave as keyed hashes unless the operator chose plain names (RoleNaming).
type Access struct {
	// Readers counts the accounts that can sign in and read the table: directly, through a
	// role, through PUBLIC, or as administrators.
	Readers int `json:"readers"`
	// Roles are the group roles (roles that cannot sign in) with read access that have at
	// least one member, as the RoleNaming reports them, sorted, at most MaxAccessRoles;
	// RolesTotal counts them all.
	Roles      []string `json:"roles"`
	RolesTotal int      `json:"roles_total"`
	// Admins counts the accounts that can read every table (superusers, global SELECT).
	Admins int `json:"admins"`
	// Public is true when every account can read the table.
	Public bool `json:"public"`
	// Complete is false when the bridge's account could not see every grant (the install
	// guide lists what it needs per engine).
	Complete bool `json:"complete"`
}

// MaxAccessRoles bounds the role names of one table.
const MaxAccessRoles = 20

// ErrAccessUnsupported means the engine has no access inventory in the bridge.
var ErrAccessUnsupported = errors.New("the access inventory is not available for this engine")

// AccessReader is a connection that can tell who may read a table.
type AccessReader interface {
	// TableAccess reads who can read t; names decides what is reported for each group role.
	TableAccess(ctx context.Context, t Table, names RoleNaming) (Access, error)
}

// accessDialect is a SQL dialect with an access inventory. It returns the counts and the
// group roles as the database names them; TableAccess turns those into what is reported.
type accessDialect interface {
	tableAccess(ctx context.Context, db *sql.DB, version string, t Table) (Access, []string, error)
}

// TableAccess reads who can read a table, for engines whose dialect supports it.
func (c *sqlConn) TableAccess(ctx context.Context, t Table, names RoleNaming) (Access, error) {
	ad, ok := c.d.(accessDialect)
	if !ok {
		return Access{}, ErrAccessUnsupported
	}
	qctx, cancel := c.ctx(ctx)
	defer cancel()
	a, roles, err := ad.tableAccess(qctx, c.db, c.version, t)
	if err != nil {
		return Access{}, wrap("table access", err, true)
	}
	a.Roles, a.RolesTotal = names.Names(roles)
	return a, nil
}

// RoleNaming decides what the access inventory reports for a group role. The zero value
// reports no name at all, only the count, so a caller that sets nothing sends no name.
type RoleNaming struct {
	plain bool
	key   []byte
}

// roleKeyContext separates the key of role ids from the other uses of the install's id key.
const roleKeyContext = "privasimu-bridge access_inventory role_names v1"

// HashedRoleNames reports each group role as "r_" and 16 hexadecimal digits: an
// HMAC-SHA256 of its name under a key derived from the install's id key
// (secrets.LoadOrCreateIDKey). The same name keeps its id within one install; without the
// key an id cannot be turned back into a name (access_inventory.role_names: hashed, the
// default). A key shorter than 16 bytes names nothing.
func HashedRoleNames(idKey []byte) RoleNaming {
	if len(idKey) < 16 {
		return RoleNaming{}
	}
	m := hmac.New(sha256.New, idKey)
	m.Write([]byte(roleKeyContext))
	return RoleNaming{key: m.Sum(nil)}
}

// PlainRoleNames reports the role names as they are (access_inventory.role_names: plain,
// an explicit choice of the operator).
func PlainRoleNames() RoleNaming { return RoleNaming{plain: true} }

// RoleNamingFor returns the naming that access_inventory.role_names sets, reading (or
// creating) the install's id key for hashed names. Without a source with access_inventory
// there is nothing to name and no key is read.
func RoleNamingFor(cfg *config.Config) (RoleNaming, error) {
	switch {
	case !cfg.UsesAccessInventory():
		return RoleNaming{}, nil
	case cfg.AccessInventory.RoleNames == config.RoleNamesPlain:
		return PlainRoleNames(), nil
	}
	key, err := secrets.LoadOrCreateIDKey(cfg.Resolve(cfg.StateDir))
	if err != nil {
		return RoleNaming{}, err
	}
	return HashedRoleNames(key), nil
}

// Name returns what is reported for one role: its id, its name (plain), or "" when no name
// is reported (the zero value, or a plain name the platform cannot store).
func (n RoleNaming) Name(role string) string {
	switch {
	case n.key != nil:
		m := hmac.New(sha256.New, n.key)
		m.Write([]byte(role))
		return "r_" + hex.EncodeToString(m.Sum(nil)[:8])
	case n.plain && validName(role):
		return role
	}
	return ""
}

// Names returns what is reported for the group roles a table has, sorted and at most
// MaxAccessRoles, and how many roles there are.
func (n RoleNaming) Names(roles []string) ([]string, int) {
	distinct := map[string]bool{}
	reported := map[string]bool{}
	for _, r := range roles {
		distinct[r] = true
		if name := n.Name(r); name != "" {
			reported[name] = true
		}
	}
	out := make([]string, 0, len(reported))
	for name := range reported {
		out = append(out, name)
	}
	sort.Strings(out)
	if len(out) > MaxAccessRoles {
		out = out[:MaxAccessRoles]
	}
	return out, len(distinct)
}

// PostgreSQL: has_table_privilege decides for every role, with role membership, PUBLIC and
// superusers included; pg_roles is readable by every account, so the answer is complete.
const pgAccessRoles = `SELECT r.rolname, r.rolcanlogin, r.rolsuper,
  EXISTS (SELECT 1 FROM pg_catalog.pg_auth_members m WHERE m.roleid = r.oid)
FROM pg_catalog.pg_roles r
WHERE pg_catalog.has_table_privilege(r.oid, $1::oid, 'SELECT')`

const pgAccessPublic = `SELECT EXISTS (SELECT 1 FROM pg_catalog.pg_class c,
  LATERAL pg_catalog.aclexplode(COALESCE(c.relacl, pg_catalog.acldefault('r', c.relowner))) a
  WHERE c.oid = $1::oid AND a.grantee = 0 AND a.privilege_type = 'SELECT')`

const pgTableOID = `SELECT c.oid FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
WHERE n.nspname = $1 AND c.relname = $2`

// tableAccess counts the roles that can read the table. A role that can sign in
// (rolcanlogin) is a reader, an administrator when it is a superuser, and is never named,
// even when other roles are granted to it. A role that cannot sign in reads nothing itself:
// it is returned as a group role when it has members, and left out otherwise (it grants
// nothing to anyone). Such a role can still carry a person's name (ALTER ROLE budi NOLOGIN;
// GRANT budi TO successor), which is why role names leave as keyed hashes by default.
func (pgDialect) tableAccess(ctx context.Context, db *sql.DB, _ string, t Table) (Access, []string, error) {
	var oid int64
	if err := db.QueryRowContext(ctx, pgTableOID, t.Schema, t.Name).Scan(&oid); err != nil {
		return Access{}, nil, err
	}
	a := Access{Complete: true}
	if err := db.QueryRowContext(ctx, pgAccessPublic, oid).Scan(&a.Public); err != nil {
		return Access{}, nil, err
	}
	rows, err := db.QueryContext(ctx, pgAccessRoles, oid)
	if err != nil {
		return Access{}, nil, err
	}
	defer rows.Close()
	var roles []string
	for rows.Next() {
		var name string
		var login, super, members bool
		if err := rows.Scan(&name, &login, &super, &members); err != nil {
			return Access{}, nil, err
		}
		switch {
		case login:
			a.Readers++
			if super {
				a.Admins++
			}
		case members:
			roles = append(roles, name)
		}
	}
	if err := rows.Err(); err != nil {
		return Access{}, nil, err
	}
	return a, roles, nil
}

// MySQL and MariaDB keep grants in the mysql schema, which a read-only account cannot see
// through information_schema (it shows only the account's own grants). With SELECT on
// mysql.db, mysql.tables_priv and the role mapping, and a column grant on mysql.user that
// leaves out the password hash (install guide), the answer is complete; without them it is
// what was readable, marked incomplete.
//
// Only an account that cannot sign in may be named. On MariaDB that is a role (is_role).
// MySQL 8 has no such flag: CREATE ROLE makes a locked account, and any account, also one a
// person signs in with, can be granted to another like a role (GRANT 'budi'@'%' TO
// 'intern1'@'%'). So on MySQL an account is a role only when it is locked
// (account_locked); an account that can sign in, or whose row could not be read, is
// counted as a reader and never named.

// myKey is an account or role: user and host.
type myKey struct{ user, host string }

// myPublic is MariaDB's PUBLIC (10.11+): what is granted to it, every account has.
var myPublic = myKey{user: "PUBLIC"}

// myAccount is what mysql.user says about an account.
type myAccount struct {
	// noLogin: the account cannot sign in (a MariaDB role, a locked MySQL account).
	noLogin       bool
	global, super bool
}

// myGrants is what the grant tables say about one table.
type myGrants struct {
	mariadb, complete bool
	accounts          map[myKey]*myAccount
	// members[role] are the accounts and roles a role is granted to.
	members map[myKey][]myKey
	// grantees have SELECT on the table: everywhere, on its schema, or on the table.
	grantees map[myKey]bool
}

// MySQL errors that mean a grant table (or a column of it) may not be read: the answer is
// then incomplete. errNoSuchTable: mysql.role_edges does not exist before MySQL 8, which has
// no roles.
const (
	errTableAccessDenied  = 1142
	errColumnAccessDenied = 1143
	errDBAccessDenied     = 1044
	errNoSuchTable        = 1146
)

func (myDialect) tableAccess(ctx context.Context, db *sql.DB, version string, t Table) (Access, []string, error) {
	g := &myGrants{mariadb: strings.Contains(strings.ToLower(version), "mariadb"), complete: true,
		accounts: map[myKey]*myAccount{}, members: map[myKey][]myKey{}, grantees: map[myKey]bool{}}
	// skip reports whether a failed query leaves the answer incomplete instead of failing
	// it: a grant table, or a column of it, the account may not read. With absent, a
	// missing table has no rows (mysql.role_edges before MySQL 8, which has no roles).
	skip := func(err error, absent bool) bool {
		var me *mysql.MySQLError
		if !errors.As(err, &me) {
			return false
		}
		switch me.Number {
		case errTableAccessDenied, errColumnAccessDenied, errDBAccessDenied:
			g.complete = false
			return true
		case errNoSuchTable:
			return absent
		}
		return false
	}
	userQuery := "SELECT User, Host, Select_priv, Super_priv, account_locked FROM mysql.user"
	if g.mariadb {
		userQuery = "SELECT User, Host, Select_priv, Super_priv, is_role FROM mysql.user"
	}
	if err := eachRow(ctx, db, userQuery, nil, func(v []string) {
		a := g.account(v[0], v[1])
		a.global, a.super, a.noLogin = v[2] == "Y", v[3] == "Y", v[4] == "Y"
	}); err != nil && !skip(err, false) {
		return Access{}, nil, err
	}
	edges := "SELECT FROM_USER, FROM_HOST, TO_USER, TO_HOST FROM mysql.role_edges"
	if g.mariadb {
		edges = "SELECT Role, '', User, Host FROM mysql.roles_mapping"
	}
	if err := eachRow(ctx, db, edges, nil, func(v []string) {
		if r := g.account(v[0], v[1]); g.mariadb {
			r.noLogin = true // a MariaDB role mapping only ever names a role; on MySQL the lock decides
		}
		role := myKey{v[0], v[1]}
		g.members[role] = append(g.members[role], myKey{v[2], v[3]})
		g.account(v[2], v[3])
	}); err != nil && !skip(err, true) {
		return Access{}, nil, err
	}
	for k, a := range g.accounts {
		if a.global {
			g.grantees[k] = true
		}
	}
	add := func(v []string) { g.grantees[myKey{v[0], v[1]}] = true; g.account(v[0], v[1]) }
	if err := eachRow(ctx, db, "SELECT User, Host FROM mysql.db WHERE Select_priv = 'Y' AND ? LIKE Db", []any{t.Schema}, add); err != nil && !skip(err, false) {
		return Access{}, nil, err
	}
	if err := eachRow(ctx, db, "SELECT User, Host FROM mysql.tables_priv WHERE Db = ? AND Table_name = ? AND FIND_IN_SET('Select', Table_priv) > 0",
		[]any{t.Schema, t.Name}, add); err != nil && !skip(err, false) {
		return Access{}, nil, err
	}
	a, roles := g.access()
	return a, roles, nil
}

// account returns the entry of an account, adding one (able to sign in, as far as is
// known) for an account seen only in a grant.
func (g *myGrants) account(user, host string) *myAccount {
	k := myKey{user, host}
	if g.accounts[k] == nil {
		g.accounts[k] = &myAccount{}
	}
	return g.accounts[k]
}

// access follows the grants: the grantees, and everyone a role passes them to, also
// through other roles. Accounts that can sign in are counted; roles are returned by name
// when they have members.
func (g *myGrants) access() (Access, []string) {
	readers := map[myKey]bool{}
	roles := map[string]bool{}
	public := false
	seen := map[myKey]bool{}
	stack := make([]myKey, 0, len(g.grantees))
	for k := range g.grantees {
		stack = append(stack, k)
	}
	for len(stack) > 0 {
		k := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if seen[k] {
			continue
		}
		seen[k] = true
		a := g.accounts[k]
		switch {
		case g.mariadb && k == myPublic:
			public = true
			continue
		case a != nil && a.noLogin:
			if len(g.members[k]) > 0 {
				roles[k.user] = true
			}
		default:
			readers[k] = true
		}
		stack = append(stack, g.members[k]...)
	}
	out := Access{Readers: len(readers), Public: public, Complete: g.complete}
	for k := range readers {
		if a := g.accounts[k]; a != nil && (a.super || a.global) {
			out.Admins++
		}
	}
	if public {
		// Every account can read the table: count all that can sign in.
		n := 0
		for k, a := range g.accounts {
			if !a.noLogin && k != myPublic {
				n++
			}
		}
		out.Readers = max(out.Readers, n)
	}
	names := make([]string, 0, len(roles))
	for r := range roles {
		names = append(names, r)
	}
	return out, names
}

// eachRow runs a query and passes each row as text.
func eachRow(ctx context.Context, db *sql.DB, query string, args []any, fn func([]string)) error {
	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return err
	}
	defer rows.Close()
	cols, err := rows.Columns()
	if err != nil {
		return err
	}
	vals := make([]sql.NullString, len(cols))
	ptrs := make([]any, len(cols))
	for i := range vals {
		ptrs[i] = &vals[i]
	}
	for rows.Next() {
		if err := rows.Scan(ptrs...); err != nil {
			return err
		}
		v := make([]string, len(cols))
		for i := range vals {
			v[i] = vals[i].String
		}
		fn(v)
	}
	return rows.Err()
}
