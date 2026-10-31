# Third-party modules

The `privasimu-bridge` binary links the modules below (from `go version -m`, release
0.1.0-dev, 2026-10-31). Each module keeps its own licence; the licence texts are in the
module sources (`go mod download`, then the `LICENSE` file of each module).

| Module | Version | Licence | Used for |
|---|---|---|---|
| github.com/jackc/pgx/v5 | v5.11.0 | MIT | PostgreSQL driver |
| github.com/jackc/pgpassfile | v1.0.0 | MIT | pgx dependency |
| github.com/jackc/pgservicefile | v0.0.0-20240606120523 | MIT | pgx dependency |
| github.com/jackc/puddle/v2 | v2.2.2 | MIT | pgx dependency |
| github.com/go-sql-driver/mysql | v1.10.1 | MPL-2.0 | MySQL / MariaDB driver |
| filippo.io/edwards25519 | v1.2.0 | BSD-3-Clause | MySQL driver dependency |
| github.com/microsoft/go-mssqldb | v1.11.2 | BSD-3-Clause | SQL Server driver |
| github.com/golang-sql/civil | v0.0.0-20220223132316 | Apache-2.0 | SQL Server driver dependency |
| github.com/golang-sql/sqlexp | v0.1.0 | BSD-3-Clause | SQL Server driver dependency |
| github.com/google/uuid | v1.6.0 | BSD-3-Clause | SQL Server driver dependency |
| github.com/shopspring/decimal | v1.4.0 | MIT | SQL Server driver dependency |
| github.com/sijms/go-ora/v2 | v2.9.0 | MIT | Oracle driver (pure Go, no Instant Client) |
| go.mongodb.org/mongo-driver/v2 | v2.9.2 | Apache-2.0 | MongoDB driver |
| github.com/klauspost/compress | v1.19.2 | BSD-3-Clause | MongoDB driver dependency |
| github.com/xdg-go/scram | v1.2.0 | Apache-2.0 | MongoDB driver dependency |
| github.com/xdg-go/stringprep | v1.0.4 | Apache-2.0 | MongoDB driver dependency |
| github.com/youmark/pkcs8 | v0.0.0-20240726163527 | MIT | MongoDB driver dependency |
| github.com/digitorus/pdf | v0.3.0 | BSD-3-Clause | PDF text extraction |
| go.yaml.in/yaml/v3 | v3.0.5 | MIT and Apache-2.0 | configuration file |
| golang.org/x/crypto | v0.58.0 | BSD-3-Clause | driver dependency |
| golang.org/x/sync | v0.24.0 | BSD-3-Clause | driver dependency |
| golang.org/x/sys | v0.49.0 | BSD-3-Clause | Windows service, DPAPI |
| golang.org/x/term | v0.47.0 | BSD-3-Clause | password prompt without echo |
| golang.org/x/text | v0.43.0 | BSD-3-Clause | driver dependency |

All are permissive licences except **MPL-2.0** for the MySQL driver. MPL-2.0 is a
file-level copyleft: the bridge uses the driver unmodified, so the obligation is to keep
the driver's own source files available under MPL-2.0 (they are public at
https://github.com/go-sql-driver/mysql). If the driver is ever modified, the modified
files must be published under MPL-2.0. No module source is copied into this repository;
modules are fetched by `go mod download` and checked against `go.sum`.

Security status at the same date: `govulncheck ./...` reports no vulnerability reachable
from the code. It lists one module-level advisory, GO-2026-5932 (the unmaintained
`golang.org/x/crypto/openpgp` package), which has no fix and is not imported by the
bridge or its dependencies' code paths.
