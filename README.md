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

Databases: PostgreSQL, MySQL and MariaDB, Microsoft SQL Server, Oracle, MongoDB (pure-Go
drivers; no Oracle Instant Client or ODBC). Files: TXT, CSV, JSON and other text, DOCX,
XLSX, PDF text. Indonesian identifiers are validated locally (NIK, KK, NPWP, BPJS,
+62/08 phone numbers, payment cards with Luhn, and more).

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
| `docs/AGENT-PROTOCOL.md`, `docs/agent-protocol/errors.json` | the mode B platform contract |
| `docs/INSTALL.en.md`, `docs/INSTALL.id.md` | installation tutorials |
| `examples/bridge.example.yaml` | every configuration option, commented |
| `deploy/` | systemd unit, Docker Compose, nginx examples |
| `Dockerfile`, `Makefile` | container image, release builds |
| `THIRD_PARTY_NOTICES.md` | linked modules and licences |

## Development

Requires Go 1.26.10.

```sh
go test ./...                    # unit, contract, security and fake-platform tests
go vet ./... && GOOS=linux go vet ./...
govulncheck ./...
make dist VERSION=0.1.0          # static builds for linux/amd64, linux/arm64, windows/amd64
go test -tags integration ./internal/dbsource/   # needs BRIDGE_IT_* database variables
```

The command line speaks English and Indonesian (`--lang id` or
`PRIVASIMU_BRIDGE_LANG=id`).

## Status

0.1.0-dev. Mode A is complete and tested against both platform clients. Mode B and file
scanning are implemented in both platform lines (agent protocol revision 2; see
[docs/DESIGN.md](docs/DESIGN.md) section 12 for the frontend work). Database integration
tests have not been run against live databases yet.
