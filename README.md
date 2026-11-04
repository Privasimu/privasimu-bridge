# Privasimu Bridge

Privasimu Bridge lets **Privasimu Data Discovery** inventory personal data in databases and
file shares **inside a client's network** without the data leaving it. It is one static
binary that runs on a server next to the data, reads database catalogs and files there,
detects personal data there, and reports only **names, types, personal-data categories,
counts and confidence**. Values, samples and file content never leave.

- **Mode A** (works today): Privasimu calls the bridge over HTTPS with the existing
  bridge contract (contract v1). No change to Privasimu is needed.
- **Mode B** (agent and both platform lines): the bridge polls Privasimu for jobs and
  posts results, so the client opens **no inbound port**.

Databases: PostgreSQL, MySQL and MariaDB, Microsoft SQL Server, Oracle, MongoDB, and in mode B
from agent protocol revision 4 Amazon Redshift, ClickHouse, Snowflake (also mode A), Google
BigQuery, Databricks SQL and Amazon Athena (catalog only) (pure-Go drivers; ClickHouse and the
cloud warehouses over their HTTP APIs with the standard library; no Oracle Instant Client or
ODBC). Files: TXT, CSV, JSON and other text, DOCX,
XLSX, PDF text. Software (mode B, opt-in): installed packages of a host, a directory or a
local container image archive, with Syft, matched against vulnerability data with Grype or
Trivy, for the security posture per RoPA; only package names, versions, licences and
vulnerability ids leave. Indonesian identifiers are validated locally (NIK, KK, NPWP, BPJS,
+62/08 phone numbers, payment cards with Luhn, and more). Optionally, long text also goes to
your own language-model service on the bridge server or your network (names, addresses,
health and the like in free text); only its counts are used. Optionally, the bridge also
reports who can read each table with personal data (PostgreSQL, MySQL, MariaDB): counts and
group role names, never account names.

## Works with both Privasimu Nexus lines (Laravel and Go)

Privasimu Nexus has two backend lines that stay in sync: the **Laravel line**
(priva-back, api-privasimu-nexus) and the **Go line** (go-api-privasimu-nexus). The
**same bridge binary works with both**:

- In mode A both lines use the identical contract v1: Laravel
  `App\Services\Discovery\Bridge\BridgeClient` and Go `internal/dbscan/bridge.go` call
  `/v1/name-database-tabels` and `/v2/scan-table-columns` with the same headers
  (`X-API-Key`, `X-Contract-Version: 1`) and the same field mapping (`BridgeSourceTypes`).
  The test suite replays both clients, including the bytes where they differ (JSON
  encoding, compression, concurrency); see [docs/DESIGN.md](docs/DESIGN.md) section 2.2.
- Mode B is specified once, in [docs/AGENT-PROTOCOL.md](docs/AGENT-PROTOCOL.md), and both
  platforms implement it byte-identically; the Laravel line verified it end to end with
  this binary.

**Why a Go binary and not PHP**: the bridge runs on the client's server. As one static
file it needs no PHP, Composer, web server, PHP-FPM or database extensions (`oci8` with
Instant Client, `sqlsrv` with the ODBC driver, ...); its Oracle and SQL Server drivers
are pure Go. The same binary runs as a Windows service, a systemd unit or a container.

## Verify the download

Releases are signed (see [docs/RELEASE-SIGNING.md](docs/RELEASE-SIGNING.md)): `SHA256SUMS`
with minisign, the container images with cosign. With the release files and the public
keys from [`release-keys/`](release-keys/) in one folder:

```sh
minisign -Vm SHA256SUMS -x SHA256SUMS.sig -p minisign.pub   # signature of the checksums
sha256sum -c SHA256SUMS --ignore-missing                    # checksums of the binaries
cosign verify --key cosign.pub privasimu-bridge:<version>-scan   # an image
```

(`scripts/release/verify.sh <folder>` runs the first two.) The release keys have not been
generated yet: `release-keys/` holds clearly marked placeholders until the owner publishes
the real public keys, and the scripts refuse to sign or verify with a placeholder.

## Quick start (mode A)

```sh
privasimu-bridge init --public-url https://bridge.example.co.id:8443   # prints the API key once
privasimu-bridge secret set corebank_pg                                 # database password, no echo
# put the TLS certificate in tls/, add sources to bridge.yaml (see examples/)
privasimu-bridge check
privasimu-bridge service install --mode serve
```

In Privasimu Data Discovery add a system of the same database type, open **Bridge
service (optional)** and enter the bridge address and the API key. Full guides:

- [docs/INSTALL.en.md](docs/INSTALL.en.md) (English)
- [docs/INSTALL.id.md](docs/INSTALL.id.md) (Bahasa Indonesia)

## Security in short

- Only the endpoints that return names and findings exist; endpoints that return rows,
  samples or file content do not.
- Database passwords stay on the bridge by default ("local credentials"): Privasimu can
  only scan sources listed in the bridge's own configuration.
- The configuration holds no secret: passwords are references to an encrypted store
  (AES-256-GCM; DPAPI on Windows), environment variables or files. API keys are stored as
  SHA-256 hashes and compared in constant time; lockout and rate limits apply.
- TLS 1.2+ (HTTP/1.1 only), client IP allow-list before the TLS handshake.
- Databases are read in read-only sessions with timeouts and bounded concurrency.
- File shares: only allow-listed roots; links and junctions that leave a root are
  refused (`os.Root`); PDFs are parsed in a separate process with a timeout.
- A JSON-lines audit log records every request and job without any value.

Details and the threat model: [docs/DESIGN.md](docs/DESIGN.md).

## Repository

| Path | Content |
|---|---|
| `cmd/privasimu-bridge` | the binary |
| `internal/` | detection, database access, file scanning, mode A server, mode B agent, CLI |
| `docs/DESIGN.md` | architecture, threat model, both modes, platform work list, comparison checklist |
| `docs/AGENT-PROTOCOL.md`, `docs/agent-protocol/errors.json` | the mode B platform contract (revision 3: package scans) |
| `docs/RELEASE-SIGNING.md`, `release-keys/`, `scripts/release/` | release signing (minisign, cosign) and verification |
| `docs/INSTALL.en.md`, `docs/INSTALL.id.md` | installation tutorials |
| `examples/bridge.example.yaml` | every configuration option, commented |
| `deploy/` | systemd unit, Docker Compose, nginx examples |
| `Dockerfile`, `Dockerfile.scan`, `Makefile` | container images (default, and `-scan` with pinned Syft and Grype), release builds |
| `THIRD_PARTY_NOTICES.md` | linked modules and licences |

## Development

Requires Go 1.26.10.

```sh
go test ./...                    # unit, contract, security and fake-platform tests
go vet ./... && GOOS=linux go vet ./...
govulncheck ./...
make dist VERSION=0.1.0          # static builds for linux/amd64, linux/arm64, windows/amd64
make integration                 # needs the BRIDGE_IT_* variables of internal/testutil/itenv
```

The command line speaks English and Indonesian (`--lang id` or
`PRIVASIMU_BRIDGE_LANG=id`).

## Status

0.1.0-dev. Mode A is complete and tested against both platform clients. Mode B and file
scanning are implemented in both platform lines (agent protocol revision 2; see
[docs/DESIGN.md](docs/DESIGN.md) section 12 for the frontend work). Package scans
(`scan_packages`, agent protocol revision 3) are implemented in the agent and tested with
fake scanners; the platform side is in progress in both lines. The database integration
tests ran against PostgreSQL 16.6 and MariaDB 11.8.9 (catalog, sampling, read-only and
time-limited sessions, error kinds, both modes end to end); MySQL 8, SQL Server, Oracle and
MongoDB have not been run against live servers yet.
