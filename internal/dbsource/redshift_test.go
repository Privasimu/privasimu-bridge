package dbsource

import (
	"strings"
	"testing"
)

func TestRedshiftCatalogQueries(t *testing.T) {
	d := rsDialect{}
	q, args := d.tablesQuery([]string{"public", "fin"})
	// Redshift has no arrays: a schema allow-list is an IN list of bind parameters.
	if strings.Contains(q, "ANY(") || !strings.Contains(q, "IN ($1, $2)") || len(args) != 2 {
		t.Fatalf("%s %v", q, args)
	}
	q, args = d.tablesQuery(nil)
	for _, s := range []string{"pg_catalog", "information_schema", "pg_internal", "pg_automv"} {
		if !strings.Contains(q, "'"+s+"'") {
			t.Errorf("%s must be left out of a listing: %s", s, q)
		}
	}
	if len(args) != 0 || strings.Contains(q, "pg_inherits") || strings.Contains(q, "relkind IN") {
		t.Fatalf("%s", q)
	}
	q, args = d.sampleQuery(`"public"."users"`, []string{d.selectExpr(Column{Name: `a"b`})}, 50)
	if q != `SELECT CAST("a""b" AS VARCHAR(65535)) FROM "public"."users" LIMIT $1` || len(args) != 1 || args[0] != 50 {
		t.Fatalf("%s %v", q, args)
	}
	for typ, ok := range map[string]bool{"character varying(256)": true, "character(10)": true, "bigint": true, "numeric(18,0)": true,
		"integer": false, "super": false, "timestamp without time zone": false, "boolean": false} {
		if d.sampleable(typ) != ok {
			t.Errorf("sampleable(%s) != %v", typ, ok)
		}
	}
}

func TestRedshiftVersionLabel(t *testing.T) {
	v := "PostgreSQL 8.0.2 on i686-pc-linux-gnu, compiled by GCC gcc (GCC) 3.4.2 20041017 (Red Hat 3.4.2-6.fc3), Redshift 1.0.77467"
	if got := redshiftVersion.FindString(v); got != "Redshift 1.0.77467" {
		t.Fatalf("%q", got)
	}
}
