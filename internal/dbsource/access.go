package dbsource

import (
	"context"
	"database/sql"
	"errors"
	"sort"
	"strings"

	"github.com/go-sql-driver/mysql"
)

// Access tells who can read a table, as counts and role names only: the names of login
// accounts (which are often people's names) never leave the bridge.
type Access struct {
	// Readers counts the login accounts that can read the table: directly, through a role,
	// through PUBLIC, or as administrators.
	Readers int `json:"readers"`
	// Roles names the group roles (not login accounts) with read access that have at least
	// one member, sorted, at most MaxAccessRoles; RolesTotal counts them all.
	Roles      []string `json:"roles"`
	RolesTotal int      `json:"roles_total"`
	// Admins counts the login accounts that can read every table (superusers, global
	// SELECT).
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
	TableAccess(ctx context.Context, t Table) (Access, error)
}

// accessDialect is a SQL dialect with an access inventory.
type accessDialect interface {
	tableAccess(ctx context.Context, db *sql.DB, version string, t Table) (Access, error)
}

// TableAccess reads who can read a table, for engines whose dialect supports it.
func (c *sqlConn) TableAccess(ctx context.Context, t Table) (Access, error) {
	ad, ok := c.d.(accessDialect)
	if !ok {
		return Access{}, ErrAccessUnsupported
	}
	qctx, cancel := c.ctx(ctx)
	defer cancel()
	a, err := ad.tableAccess(qctx, c.db, c.version, t)
	if err != nil {
		return Access{}, wrap("table access", err, true)
	}
	return a, nil
}

// roleList sorts and bounds role names.
func roleList(names map[string]bool) ([]string, int) {
	out := make([]string, 0, len(names))
	for n := range names {
		if validName(n) {
			out = append(out, n)
		}
	}
	sort.Strings(out)
	total := len(out)
	if len(out) > MaxAccessRoles {
		out = out[:MaxAccessRoles]
	}
	return out, total
}

// PostgreSQL: has_table_privilege decides for every role, with role membership, PUBLIC and
// superusers included; pg_roles is readable by every account, so the answer is complete.
// Group roles without members grant nothing to anyone and are left out.
const pgAccessRoles = `SELECT r.rolname, r.rolcanlogin, r.rolsuper,
  EXISTS (SELECT 1 FROM pg_catalog.pg_auth_members m WHERE m.roleid = r.oid)
FROM pg_catalog.pg_roles r
WHERE pg_catalog.has_table_privilege(r.oid, $1::oid, 'SELECT')`

const pgAccessPublic = `SELECT EXISTS (SELECT 1 FROM pg_catalog.pg_class c,
  LATERAL pg_catalog.aclexplode(COALESCE(c.relacl, pg_catalog.acldefault('r', c.relowner))) a
  WHERE c.oid = $1::oid AND a.grantee = 0 AND a.privilege_type = 'SELECT')`

func (pgDialect) tableAccess(ctx context.Context, db *sql.DB, _ string, t Table) (Access, error) {
	var oid int64
	err := db.QueryRowContext(ctx, `SELECT c.oid FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
WHERE n.nspname = $1 AND c.relname = $2`, t.Schema, t.Name).Scan(&oid)
	if err != nil {
		return Access{}, err
	}
	a := Access{Complete: true}
	if err := db.QueryRowContext(ctx, pgAccessPublic, oid).Scan(&a.Public); err != nil {
		return Access{}, err
	}
	rows, err := db.QueryContext(ctx, pgAccessRoles, oid)
	if err != nil {
		return Access{}, err
	}
	defer rows.Close()
	roles := map[string]bool{}
	for rows.Next() {
		var name string
		var login, super, members bool
		if err := rows.Scan(&name, &login, &super, &members); err != nil {
			return Access{}, err
		}
		switch {
		case login:
			a.Readers++
			if super {
				a.Admins++
			}
		case members:
			roles[name] = true
		}
	}
	if err := rows.Err(); err != nil {
		return Access{}, err
	}
	a.Roles, a.RolesTotal = roleList(roles)
	return a, nil
}

// MySQL and MariaDB keep grants in the mysql schema, which a read-only account cannot see
// through information_schema (it shows only the account's own grants). With SELECT on
// mysql.db, mysql.tables_priv and the role mapping, and a column grant on mysql.user that
// leaves out the password hash (install guide), the answer is complete; without them it is
// what was readable, marked incomplete.
type myAccount struct {
	role, global, super bool
}

func (myDialect) tableAccess(ctx context.Context, db *sql.DB, version string, t Table) (Access, error) {
	mariadb := strings.Contains(strings.ToLower(version), "mariadb")
	complete := true
	denied := func(err error) bool {
		var me *mysql.MySQLError
		if errors.As(err, &me) && (me.Number == 1142 || me.Number == 1143 || me.Number == 1044) {
			complete = false
			return true
		}
		return false
	}
	accounts := map[string]*myAccount{}
	account := func(user, host string) *myAccount {
		k := user + "@" + host
		if accounts[k] == nil {
			accounts[k] = &myAccount{}
		}
		return accounts[k]
	}
	userQuery := "SELECT User, Host, Select_priv, Super_priv, 'N' FROM mysql.user"
	if mariadb {
		userQuery = "SELECT User, Host, Select_priv, Super_priv, is_role FROM mysql.user"
	}
	if err := eachRow(ctx, db, userQuery, nil, func(v []string) {
		a := account(v[0], v[1])
		a.global, a.super, a.role = v[2] == "Y", v[3] == "Y", v[4] == "Y"
	}); err != nil && !denied(err) {
		return Access{}, err
	}
	// members[role] are the accounts and roles a role is granted to.
	members := map[string][]string{}
	edges, edgeArgs := "SELECT FROM_USER, FROM_HOST, TO_USER, TO_HOST FROM mysql.role_edges", []any(nil)
	if mariadb {
		edges = "SELECT Role, '', User, Host FROM mysql.roles_mapping"
	}
	if err := eachRow(ctx, db, edges, edgeArgs, func(v []string) {
		account(v[0], v[1]).role = true
		members[v[0]+"@"+v[1]] = append(members[v[0]+"@"+v[1]], v[2]+"@"+v[3])
		account(v[2], v[3])
	}); err != nil && !denied(err) {
		return Access{}, err
	}
	// The grantees with SELECT on the table: everywhere, on its schema, on the table.
	grantees := map[string]bool{}
	for k, a := range accounts {
		if a.global {
			grantees[k] = true
		}
	}
	add := func(v []string) { grantees[v[0]+"@"+v[1]] = true; account(v[0], v[1]) }
	if err := eachRow(ctx, db, "SELECT User, Host FROM mysql.db WHERE Select_priv = 'Y' AND ? LIKE Db", []any{t.Schema}, add); err != nil && !denied(err) {
		return Access{}, err
	}
	if err := eachRow(ctx, db, "SELECT User, Host FROM mysql.tables_priv WHERE Db = ? AND Table_name = ? AND FIND_IN_SET('Select', Table_priv) > 0",
		[]any{t.Schema, t.Name}, add); err != nil && !denied(err) {
		return Access{}, err
	}
	// Roles pass their grants to their members, also through other roles.
	readers := map[string]bool{}
	roles := map[string]bool{}
	public := false
	var visit func(k string, depth int)
	visit = func(k string, depth int) {
		a := accounts[k]
		if a != nil && a.role {
			user := k[:strings.LastIndex(k, "@")]
			if user == "PUBLIC" {
				public = true
			} else if len(members[k]) > 0 {
				roles[user] = true
			}
			if depth < 5 {
				for _, m := range members[k] {
					visit(m, depth+1)
				}
			}
			return
		}
		readers[k] = true
	}
	for k := range grantees {
		visit(k, 0)
	}
	out := Access{Readers: len(readers), Public: public, Complete: complete}
	for k := range readers {
		if a := accounts[k]; a != nil && (a.super || a.global) {
			out.Admins++
		}
	}
	if public {
		// Every account can read the table: count them all.
		n := 0
		for _, a := range accounts {
			if !a.role {
				n++
			}
		}
		out.Readers = max(out.Readers, n)
	}
	out.Roles, out.RolesTotal = roleList(roles)
	return out, nil
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
