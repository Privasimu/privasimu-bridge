package dbsource

import (
	"errors"
	"strings"

	"github.com/go-sql-driver/mysql"
	"github.com/jackc/pgx/v5/pgconn"
	mssql "github.com/microsoft/go-mssqldb"
	"go.mongodb.org/mongo-driver/v2/mongo"
)

// classifyDriver maps errors of the database drivers to a kind ("" when unknown).
func classifyDriver(err error) string {
	if k := classifyClickHouse(err); k != "" {
		return k
	}
	var ce *cloudError
	if errors.As(err, &ce) && ce.Kind != "" {
		return ce.Kind
	}
	var pg *pgconn.PgError
	if errors.As(err, &pg) {
		switch {
		case pg.Code == "28P01" || pg.Code == "28000":
			return KindAuth
		case pg.Code == "3D000" || pg.Code == "42P01" || pg.Code == "3F000":
			return KindNotFound
		case pg.Code == "42501":
			return KindPermission
		case pg.Code == "57014" || pg.Code == "55P03":
			return KindTimeout
		case strings.HasPrefix(pg.Code, "08"):
			return KindUnreachable
		}
		return KindDatabase
	}
	var my *mysql.MySQLError
	if errors.As(err, &my) {
		switch my.Number {
		case 1045, 1698:
			return KindAuth
		case 1044, 1142, 1143, 1227:
			return KindPermission
		case 1049, 1146:
			return KindNotFound
		case 3024, 1969:
			return KindTimeout
		}
		return KindDatabase
	}
	var ms mssql.Error
	if errors.As(err, &ms) {
		switch ms.Number {
		case 18456, 18452:
			return KindAuth
		case 229, 230, 297, 916, 262:
			return KindPermission
		case 4060, 208, 911:
			return KindNotFound
		case 1222:
			return KindTimeout
		}
		return KindDatabase
	}
	var mc mongo.CommandError
	if errors.As(err, &mc) {
		switch mc.Code {
		case 18:
			return KindAuth
		case 13:
			return KindPermission
		case 50:
			return KindTimeout
		}
		return KindDatabase
	}
	msg := err.Error()
	switch {
	case strings.Contains(msg, "ORA-01017") || strings.Contains(msg, "ORA-28000") || strings.Contains(msg, "ORA-01005"):
		return KindAuth
	case strings.Contains(msg, "ORA-12514") || strings.Contains(msg, "ORA-12505") || strings.Contains(msg, "ORA-00942"):
		return KindNotFound
	case strings.Contains(msg, "ORA-01031") || strings.Contains(msg, "ORA-01045"):
		return KindPermission
	case strings.Contains(msg, "ORA-12170") || strings.Contains(msg, "ORA-12541") || strings.Contains(msg, "ORA-12543"):
		return KindUnreachable
	case strings.Contains(msg, "ORA-01013"):
		return KindTimeout
	case strings.Contains(msg, "server selection") || strings.Contains(msg, "no reachable servers"):
		return KindUnreachable
	case strings.Contains(strings.ToLower(msg), "auth error") || strings.Contains(msg, "AuthenticationFailed"):
		return KindAuth
	}
	return ""
}
