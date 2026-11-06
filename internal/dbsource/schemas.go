package dbsource

import (
	"context"
	"database/sql"
	"errors"
	"sort"
)

// SchemaLister lists the schemas a source's account can see, names only (contract P-4): the
// choice a platform offers per source. Oracle reports the owners of at least one table the
// account can read, without Oracle-maintained accounts; PostgreSQL and Redshift the schemas
// with USAGE; MySQL and MariaDB the databases; SQL Server the user schemas. System schemas
// are left out. The list is not narrowed by the target's allow-list: the caller applies the
// local configuration.
type SchemaLister interface {
	ListSchemas(ctx context.Context) ([]string, error)
}

// ErrSchemasUnsupported is returned by engines that have no schema list.
var ErrSchemasUnsupported = errors.New("the engine has no schema list")

// HasSchemas reports whether an engine organises tables in schemas that a scan can be
// narrowed to (every engine but MongoDB, whose database is the only level).
func HasSchemas(engine string) bool { return engine != "mongodb" }

// ListsSchemas reports whether the bridge reads a schema list for an engine: the SQL
// engines. ClickHouse and the cloud warehouses can be narrowed by schema but report no
// list yet.
func ListsSchemas(engine string) bool {
	switch engine {
	case "postgresql", "mysql", "mariadb", "mssql", "oracle", "redshift":
		return true
	}
	return false
}

// schemaQuerier is the optional part of a dialect that lists schemas.
type schemaQuerier interface {
	schemasQuery() string
}

func (pgDialect) schemasQuery() string {
	// Names starting with pg_ are reserved for system schemas.
	return `SELECT n.nspname FROM pg_catalog.pg_namespace n
WHERE n.nspname <> 'information_schema' AND n.nspname NOT LIKE 'pg\_%'
  AND has_schema_privilege(n.oid, 'USAGE') ORDER BY 1`
}

func (rsDialect) schemasQuery() string {
	return `SELECT n.nspname FROM pg_catalog.pg_namespace n
WHERE n.nspname NOT IN ` + rsSystemSchemas + ` AND n.nspname NOT LIKE 'pg\_%'
  AND has_schema_privilege(n.nspname, 'USAGE') ORDER BY 1`
}

func (myDialect) schemasQuery() string {
	// information_schema.schemata shows only the databases the account has a privilege on.
	return `SELECT schema_name FROM information_schema.schemata
WHERE schema_name NOT IN ('mysql', 'information_schema', 'performance_schema', 'sys') ORDER BY 1`
}

func (msDialect) schemasQuery() string {
	// guest (2), INFORMATION_SCHEMA (3) and sys (4) are system schemas; the schemas of the
	// fixed database roles start at 16384.
	return `SELECT name FROM sys.schemas WHERE schema_id NOT IN (2, 3, 4) AND schema_id < 16384 ORDER BY name`
}

func (oraDialect) schemasQuery() string {
	// An Oracle schema is its owner. all_tables shows the tables the account can read.
	return `SELECT owner FROM all_tables
WHERE dropped = 'NO' AND nested = 'NO' AND secondary = 'N'
  AND owner IN (SELECT username FROM all_users WHERE oracle_maintained = 'N')
GROUP BY owner ORDER BY owner`
}

// ListSchemas lists the schemas of the database (SchemaLister). Names the platform could not
// store are left out.
func (c *sqlConn) ListSchemas(ctx context.Context) ([]string, error) {
	sq, ok := c.d.(schemaQuerier)
	if !ok {
		return nil, ErrSchemasUnsupported
	}
	qctx, cancel := c.ctx(ctx)
	defer cancel()
	rows, err := c.db.QueryContext(qctx, sq.schemasQuery())
	if err != nil {
		return nil, wrap("list schemas", err, true)
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var s sql.NullString
		if err := rows.Scan(&s); err != nil {
			return nil, wrap("list schemas", err, true)
		}
		if s.Valid && validName(s.String) {
			out = append(out, s.String)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, wrap("list schemas", err, true)
	}
	sort.Strings(out)
	return out, nil
}
