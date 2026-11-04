// Package itenv reads the settings of the database integration tests (go test -tags
// integration) from environment variables, so that every package's integration tests
// use the same variables:
//
//	BRIDGE_IT_<ENGINE>_HOST       required; the engine's tests are skipped without it
//	BRIDGE_IT_<ENGINE>_PORT       default: the engine's port
//	BRIDGE_IT_<ENGINE>_DB         database (MySQL: the schema; Oracle: the service name)
//	BRIDGE_IT_<ENGINE>_USER       the read-only account of the bridge
//	BRIDGE_IT_<ENGINE>_PASSWORD   its password
//	BRIDGE_IT_<ENGINE>_SCHEMA     optional: narrows the listing
//	BRIDGE_IT_<ENGINE>_TLS        disable | prefer | require | verify-ca | verify-full
//	BRIDGE_IT_<ENGINE>_CA_FILE    CA certificate (PEM) for verify-ca and verify-full
//	BRIDGE_IT_<ENGINE>_SERVER_NAME  the name in the server certificate, when not the host
//	BRIDGE_IT_<ENGINE>_SERVICE    Oracle service name
//	BRIDGE_IT_<ENGINE>_WRITER_USER, _WRITER_PASSWORD
//	                              optional: an account that may write, to show that the
//	                              bridge's sessions stay read-only even then
//
// <ENGINE> is POSTGRESQL, MYSQL (MySQL and MariaDB), MSSQL, ORACLE or MONGODB. The
// fixtures in internal/dbsource/testdata/integration create the table "customers" with
// the synthetic values in FixtureValues.
package itenv

import (
	"os"
	"strconv"
	"strings"
)

// Settings are the connection settings of one engine.
type Settings struct {
	Engine     string
	Host       string
	Port       int
	Database   string
	User       string
	Password   string
	Schema     string
	TLS        string
	CAFile     string
	ServerName string
	Service    string
	// WriterUser and WriterPassword name an account with write privileges (optional).
	WriterUser     string
	WriterPassword string
}

// Lookup returns the settings of an engine and whether its host is set.
func Lookup(engine string) (Settings, bool) {
	prefix := "BRIDGE_IT_" + strings.ToUpper(engine) + "_"
	get := func(k string) string { return os.Getenv(prefix + k) }
	s := Settings{Engine: engine, Host: get("HOST"), Database: get("DB"), User: get("USER"), Password: get("PASSWORD"),
		Schema: get("SCHEMA"), TLS: get("TLS"), CAFile: get("CA_FILE"), ServerName: get("SERVER_NAME"),
		Service: get("SERVICE"), WriterUser: get("WRITER_USER"), WriterPassword: get("WRITER_PASSWORD")}
	s.Port, _ = strconv.Atoi(get("PORT"))
	return s, s.Host != ""
}

// PasswordEnv is the name of the variable holding an engine's password, for a
// configuration that refers to it as env:NAME.
func PasswordEnv(engine string) string {
	return "BRIDGE_IT_" + strings.ToUpper(engine) + "_PASSWORD"
}

// FixtureValues are the synthetic values the fixtures store. A test that sends anything
// to the platform checks that none of them appears in what was sent.
var FixtureValues = []string{
	"3171012303900001", "3171016303900002", "3273011505850003", "3578014107920004", "5171012001880005",
	"budi.contoh@example.co.id", "sari.contoh@example.co.id", "andi.contoh@example.co.id",
	"dewi.contoh@example.co.id", "eko.contoh@example.co.id",
	"0812-3456-7890", "0813-1111-2222", "0857-2222-3333", "0821-4444-5555", "0811-6666-7777",
	"setelah jam 5",
}
