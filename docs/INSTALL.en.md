# Installing Privasimu Bridge

This guide installs the bridge on a server inside your network and connects it to
Privasimu Data Discovery. It covers Windows Server and Linux, the TLS certificate, the
firewall, read-only database accounts, sources and file shares, the connection in
Privasimu, and troubleshooting.

Indonesian version: [INSTALL.id.md](INSTALL.id.md). Design and security details:
[DESIGN.md](DESIGN.md).

## 0. Before you start

**Which mode?**

| | Mode A (every Privasimu version) | Mode B (agent; Privasimu with bridge agents) |
|---|---|---|
| Direction | Privasimu → bridge (HTTPS, inbound to your network) | bridge → Privasimu (HTTPS, outbound only) |
| Firewall | open one TCP port to Privasimu's IP addresses only | no inbound port |
| Certificate | a certificate Privasimu trusts | none on the bridge |
| What it scans | databases | databases and file shares |

Mode A works with every current Privasimu version. Mode B needs a Privasimu version with
bridge agents (both lines, from November 2026) and is the way to scan file shares.
Sections 1 to 10 describe mode A; section 11 describes mode B.

**You need**

- A server (virtual is fine) in the network that can reach your databases: Windows Server
  2016 or later, or Linux x86-64/arm64 (Ubuntu 20.04+, Debian 11+, RHEL/Rocky/Alma 8+).
  2 vCPU and 2 GB RAM are enough; 1 GB disk for logs and reports.
- Administrator (Windows) or root/sudo (Linux) on that server.
- For mode A with Privasimu SaaS: a DNS name for the bridge (for example
  `bridge.example.co.id`) that Privasimu can reach, and the outgoing IP addresses of
  Privasimu (ask Privasimu support).
- For each database: a read-only account (section 6).

**Works with both Privasimu Nexus lines.** Privasimu runs on a Laravel backend or a Go
backend. Both call the bridge with the same contract (contract v1: the same paths,
headers `X-API-Key` and `X-Contract-Version: 1`, and the same fields), so this guide is
the same for both. In mode B both lines implement the same agent protocol, so the agent
setup is the same too. The only difference that matters during installation is how the
Privasimu server trusts an internal certificate (section 4.2). The bridge is a single Go
program, so your server needs no PHP, web server, database extensions, Oracle Instant
Client or ODBC driver.

## 1. Install the program

The release has one file per platform: `privasimu-bridge-<version>-linux-amd64`,
`...-linux-arm64`, `...-windows-amd64.exe`, `SHA256SUMS` and `SHA256SUMS.sig`.

**Verify the download first.** `SHA256SUMS` is signed with minisign
(<https://jedisct1.github.io/minisign/>); the public key is `release-keys/minisign.pub` in
the bridge repository and is also published with every release. Compare its key line with
the one below before you trust it:

```text
Release public key (minisign): NOT PUBLISHED YET. The release keys have not been
generated; until the owner publishes them here, releases are unsigned and only the
checksums below can be checked.
```

```sh
minisign -Vm SHA256SUMS -x SHA256SUMS.sig -p minisign.pub   # must print "Signature and comment signature verified"
```

### Linux

```sh
minisign -Vm SHA256SUMS -x SHA256SUMS.sig -p minisign.pub   # signature (see above)
sha256sum -c SHA256SUMS --ignore-missing                # checksums
sudo install -m 0755 privasimu-bridge-0.1.0-linux-amd64 /usr/local/bin/privasimu-bridge
privasimu-bridge version
```

### Windows (PowerShell as Administrator)

```powershell
minisign.exe -Vm SHA256SUMS -x SHA256SUMS.sig -p minisign.pub              # signature (see above)
Get-FileHash .\privasimu-bridge-0.1.0-windows-amd64.exe -Algorithm SHA256   # compare with SHA256SUMS
New-Item -ItemType Directory -Force "C:\Program Files\PrivasimuBridge" | Out-Null
Copy-Item .\privasimu-bridge-0.1.0-windows-amd64.exe "C:\Program Files\PrivasimuBridge\privasimu-bridge.exe"
& "C:\Program Files\PrivasimuBridge\privasimu-bridge.exe" version
```

Add `C:\Program Files\PrivasimuBridge` to the system `PATH`, or call the program with its
full path in the commands below.

### Docker

See `deploy/docker/docker-compose.yml`. The image runs as a non-root user with a
read-only file system; mount the configuration at `/etc/privasimu-bridge` and a volume at
`/var/lib/privasimu-bridge`. Run `init` once with
`--dir /etc/privasimu-bridge --state-dir /var/lib/privasimu-bridge --log-dir /var/lib/privasimu-bridge/logs`.
For package scans (section 11.1) use `privasimu-bridge:<version>-scan`, which adds pinned
Syft and Grype. Images are signed with cosign; verify before you run one:
`cosign verify --key cosign.pub privasimu-bridge:<version>-scan` (`cosign.pub` from
`release-keys/` of the bridge repository).

Every command prints English by default; add `--lang id` (or set
`PRIVASIMU_BRIDGE_LANG=id`) for Indonesian.

## 2. Create the configuration

```sh
# Linux
sudo privasimu-bridge init --public-url https://bridge.example.co.id:8443
# Windows (Administrator)
privasimu-bridge init --public-url https://bridge.example.co.id:8443
```

`init` creates:

| File | Linux | Windows |
|---|---|---|
| configuration | `/etc/privasimu-bridge/bridge.yaml` | `C:\ProgramData\PrivasimuBridge\bridge.yaml` |
| key of the secret store | `/etc/privasimu-bridge/secrets.key` | `C:\ProgramData\PrivasimuBridge\secrets.key` (sealed with DPAPI) |
| encrypted secret store | `/var/lib/privasimu-bridge/secrets.enc` | `C:\ProgramData\PrivasimuBridge\state\secrets.enc` |
| certificate folder | `/etc/privasimu-bridge/tls/` | `C:\ProgramData\PrivasimuBridge\tls\` |
| audit log | `/var/log/privasimu-bridge/audit.jsonl` | `C:\ProgramData\PrivasimuBridge\logs\audit.jsonl` |

It also prints an **API key** (`pvbk_…`) **once**. Copy it to your password manager now:
only its hash is stored, it cannot be shown again (you can create a new one with
`privasimu-bridge key create`). On Windows the folder is restricted to Administrators and
SYSTEM.

Options: `--listen` (default `0.0.0.0:8443`), `--dir`, `--state-dir`, `--log-dir`,
`--platform-url` (mode B), `--force` (rewrite the configuration; the store key is kept).

## 3. Firewall (mode A)

Open the bridge port (8443 by default) **only** to Privasimu's outgoing IP addresses.

Linux with ufw:
```sh
sudo ufw allow from 203.0.113.10 to any port 8443 proto tcp
```
Linux with firewalld:
```sh
sudo firewall-cmd --permanent --new-zone=privasimu
sudo firewall-cmd --permanent --zone=privasimu --add-source=203.0.113.10/32
sudo firewall-cmd --permanent --zone=privasimu --add-port=8443/tcp
sudo firewall-cmd --reload
```
Windows:
```powershell
New-NetFirewallRule -DisplayName "Privasimu Bridge" -Direction Inbound -Protocol TCP `
  -LocalPort 8443 -RemoteAddress 203.0.113.10 -Action Allow
```

Do the same on the perimeter firewall or NAT. Then set the same addresses in
`bridge.yaml`; the bridge closes other connections before the TLS handshake:

```yaml
server:
  allowed_clients: [203.0.113.10/32]
```

**Privasimu SaaS and private addresses.** Privasimu's host policy refuses a bridge address
that resolves to a private IP (10.x, 172.16-31.x, 192.168.x) unless a Privasimu platform
administrator adds your private range for your organization (Platform Admin → Tenants →
**Bridge allowlist**). The usual setup is a public DNS name for the bridge with the
firewall rule above. A Privasimu installed inside your network (on-premise) may reach
private addresses directly. Loopback (127.0.0.1) is never allowed.

## 4. TLS certificate

Privasimu verifies the bridge's certificate with its trust store and never skips the
check. A self-signed certificate does not work. The certificate must be valid for the
host name in the bridge address you enter in Privasimu.

Put the certificate with its intermediates (leaf first) and the private key here:

| | Certificate | Key |
|---|---|---|
| Linux | `/etc/privasimu-bridge/tls/fullchain.pem` | `/etc/privasimu-bridge/tls/privkey.pem` |
| Windows | `C:\ProgramData\PrivasimuBridge\tls\fullchain.pem` | `C:\ProgramData\PrivasimuBridge\tls\privkey.pem` |

(or change `server.tls.cert_file` and `key_file`). The bridge reloads the files within a
minute after they change; no restart is needed after a renewal.

### 4.1 A public certificate (Privasimu SaaS)

Linux with certbot (the DNS challenge needs no open port 80):
```sh
sudo certbot certonly --manual --preferred-challenges dns -d bridge.example.co.id
```
Copy the files on every renewal with a deploy hook,
`/etc/letsencrypt/renewal-hooks/deploy/privasimu-bridge.sh`:
```sh
#!/bin/sh
install -m 0640 -o root -g privasimu-bridge /etc/letsencrypt/live/bridge.example.co.id/fullchain.pem /etc/privasimu-bridge/tls/fullchain.pem
install -m 0640 -o root -g privasimu-bridge /etc/letsencrypt/live/bridge.example.co.id/privkey.pem /etc/privasimu-bridge/tls/privkey.pem
```
Windows with win-acme: choose the PEM file store and the folder
`C:\ProgramData\PrivasimuBridge\tls`; point `cert_file` at the chain file
(`…-chain.pem`) and `key_file` at the key file (`…-key.pem`). A certificate from a
commercial CA works the same way (PEM, chain included).

### 4.2 A certificate from your internal CA (Privasimu on-premise)

Issue a server certificate whose Subject Alternative Name holds the bridge's DNS name.
Then make the **Privasimu server** trust your CA, depending on the line it runs:

- **Go line**: add the CA to the operating system store and restart the backend.
  Debian/Ubuntu: `sudo cp corp-root-ca.crt /usr/local/share/ca-certificates/ && sudo update-ca-certificates`.
  RHEL family: `sudo cp corp-root-ca.crt /etc/pki/ca-trust/source/anchors/ && sudo update-ca-trust`.
  In a container: add the CA to the image or mount a bundle and set `SSL_CERT_FILE`.
- **Laravel line**: PHP uses curl's CA bundle. Add the CA to the system store as above,
  check that `curl.cainfo` / `openssl.cafile` in `php.ini` are empty or point to a bundle
  that includes your CA (`php -r 'print_r(openssl_get_cert_locations());'`), then
  restart PHP-FPM **and the queue workers** (`php artisan queue:restart`): scans run in
  the queue.

Check from the Privasimu server, without `-k`:
```sh
curl -sS https://bridge.example.co.id:8443/healthz      # {"status":"ok"}
```

### 4.3 Behind a reverse proxy

If nginx (or another proxy) already terminates TLS on the bridge server, set:
```yaml
server:
  listen: "127.0.0.1:8080"
  tls: {mode: proxy}
  trusted_proxies: [127.0.0.1/32]
```
An nginx example is in `deploy/nginx-bridge.conf` (TLS, client allow-list,
`X-Forwarded-For`). In proxy mode the bridge refuses to listen on anything but loopback.

## 5. Check the base installation

```sh
sudo privasimu-bridge check          # Windows: privasimu-bridge check
```
Each line is `[OK]`, `[WARN]` or `[FAIL]`. At this point you should see the configuration,
the secret store and the certificate. Fix every `[FAIL]` before you continue.

## 6. Read-only database accounts

Use a dedicated account per database that can read the catalog and, if you enable
sampling, read rows. Never use an administrator account. Replace names in angle brackets.

**PostgreSQL**
```sql
CREATE ROLE privasimu_ro LOGIN PASSWORD '<strong password>';
ALTER ROLE privasimu_ro SET default_transaction_read_only = on;
GRANT CONNECT ON DATABASE corebank TO privasimu_ro;
GRANT USAGE ON SCHEMA public TO privasimu_ro;
-- Names only: the catalog is readable without more. For local sampling also:
GRANT SELECT ON ALL TABLES IN SCHEMA public TO privasimu_ro;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO privasimu_ro;
-- PostgreSQL 14+: GRANT pg_read_all_data TO privasimu_ro;  (every schema)
```
Allow the bridge server in `pg_hba.conf` (`hostssl corebank privasimu_ro <bridge-ip>/32 scram-sha-256`).

**MySQL / MariaDB** (tables are only visible in the catalog to accounts with a privilege on them)
```sql
CREATE USER 'privasimu_ro'@'<bridge-ip>' IDENTIFIED BY '<strong password>';
GRANT SELECT, SHOW VIEW ON crm.* TO 'privasimu_ro'@'<bridge-ip>';
```
Every session of the bridge is read-only (`SET SESSION TRANSACTION READ ONLY`), so even an
account with more rights cannot write through it, and the server itself stops a statement
after the source's `timeout` (`max_execution_time` on MySQL 5.7.8+, `max_statement_time`
on MariaDB 10.1+); a query waits at most 5 seconds behind a metadata lock
(`lock_wait_timeout`).

**Microsoft SQL Server**
```sql
CREATE LOGIN privasimu_ro WITH PASSWORD = '<strong password>', CHECK_POLICY = ON;
USE HRIS;
CREATE USER privasimu_ro FOR LOGIN privasimu_ro;
GRANT VIEW DEFINITION TO privasimu_ro;              -- names and types
ALTER ROLE db_datareader ADD MEMBER privasimu_ro;   -- only for local sampling
```
The bridge connects with `ApplicationIntent=ReadOnly` (a readable secondary is used in an
availability group) and samples with `READ UNCOMMITTED`, so it never blocks your
transactions.

**Oracle** (12c or later; `READ` does not lock rows)
```sql
CREATE USER privasimu_ro IDENTIFIED BY "<strong password>";
GRANT CREATE SESSION TO privasimu_ro;
-- names and sampling of the FIN schema:
BEGIN
  FOR t IN (SELECT table_name FROM all_tables WHERE owner = 'FIN') LOOP
    EXECUTE IMMEDIATE 'GRANT READ ON FIN."' || t.table_name || '" TO privasimu_ro';
  END LOOP;
END;
/
```
Set `schemas: [FIN]` on the source (an Oracle schema is the owner).

**MongoDB**
```js
use app
db.createUser({ user: "privasimu_ro", pwd: passwordPrompt(), roles: [ { role: "read", db: "app" } ] })
```
MongoDB has no schema catalog: the bridge reads up to 100 documents per collection on the
bridge server to learn field names. It examines the values only when sampling is on.

**Amazon Redshift** (provisioned or Serverless; port 5439)
```sql
CREATE USER privasimu_ro PASSWORD '<strong password>';
-- Names only: the catalog is readable without more. For local sampling also:
GRANT USAGE ON SCHEMA public TO privasimu_ro;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO privasimu_ro;
```
Redshift has no read-only session setting: give this account no other privilege. The
bridge sets `statement_timeout` for every session (the source's `timeout`) and samples
inside `BEGIN READ ONLY` transactions. Use `tls: {mode: verify-full}`; the Amazon
certificate authorities are in the system trust store. Redshift reports no row counts.

**ClickHouse** (HTTP interface: port 8123, or 8443 with TLS)
```sql
CREATE USER privasimu_ro IDENTIFIED WITH sha256_password BY '<strong password>' HOST IP '<bridge-ip>';
GRANT SHOW TABLES, SHOW COLUMNS ON crm.* TO privasimu_ro;   -- names and types
GRANT SELECT ON crm.* TO privasimu_ro;                       -- only for local sampling
```
The bridge sends only `GET` requests, which ClickHouse itself makes read-only, with a
server-side time limit (`max_execution_time`, the source's `timeout`) and, for sampling,
a row limit. Do not give this user a profile with `readonly = 1`: it forbids those limits
(`readonly = 2`, or no setting, is right). In ClickHouse a database is a schema: the source's
`database` is listed, or the databases in `schemas`. Use the HTTPS port with
`tls: {mode: verify-full}` wherever ClickHouse has a certificate.

Redshift and ClickHouse sources are offered to Privasimu in mode B once Privasimu accepts
these engines (agent protocol revision 4); until then the agent logs that it withholds
them, and `check` tests them.

## 7. Store the passwords and define the sources

Store each password in the encrypted store (the value is not shown while you type):

```sh
sudo privasimu-bridge secret set corebank_pg
sudo privasimu-bridge secret list          # names only
```

Then add the sources to `bridge.yaml` (every option is explained in
`examples/bridge.example.yaml`):

```yaml
sources:
  - id: core-banking
    label: "Core banking"
    engine: postgresql          # postgresql | mysql | mariadb | mssql | oracle | mongodb | redshift | clickhouse
    host: 10.10.1.20
    database: corebank
    username: privasimu_ro
    password: "secret:corebank_pg"
    schemas: [public]           # optional
    tls:
      mode: verify-full         # disable | prefer | require | verify-ca | verify-full
      ca_file: tls/db-ca.pem
    sampling: {enabled: false}  # true = read up to 100 values per column on this server
    match:
      host: corebank            # what you will type as "Host" in Privasimu
```

- **Credentials stay on the bridge** (`server.credentials: local`, the default). Privasimu
  can only scan these sources. It finds one by database type, host and database name; the
  password typed in Privasimu is ignored.
- `match.host` lets you type an alias such as `corebank` in Privasimu instead of the real
  address, so the address never leaves your network.
- `label` is the name Privasimu shows for the source in mode B (1 to 128 characters,
  without control characters). Without a label, the `id` is shown.
- Instead of `secret:NAME` you can use `env:NAME` (an environment variable) or
  `file:/path` (a Docker secret or systemd credential). A plain password in the file is
  refused.
- **Sampling** is off by default. When on, values are read and examined on the bridge
  server and only counts and categories are sent; it finds personal data in columns with
  neutral names (for example a `notes` column full of phone numbers).

Test:
```sh
sudo privasimu-bridge check
# [OK]   source core-banking: PostgreSQL 16.4, 120 tables, TLS on, sampling off (names only)
```

## 8. File shares (mode B and local reports)

File roots are scanned with mode B or locally with the command line. Only the folders
you list can be read (at most 200 sources and file roots together):

```yaml
files:
  report_paths: hashed          # hashed: files named by a keyed hash; relative: by their path
  roots:
    - id: hr-share
      label: "HR file share"
      path: /srv/shares/hr      # Windows: "D:/Shares/HR"
      exclude: ["arsip/**"]
      refresh_interval: 24h     # rescan in the background
```

- Give the service account read access: Linux
  `sudo setfacl -R -m u:privasimu-bridge:rX /srv/shares/hr` (and default ACLs for new
  files); Windows: NTFS read permission for the service account. A share on another
  server needs a domain account or gMSA as the service account (section 9).
- Links and junctions that point outside a root are never followed.
- Without `label`, Privasimu shows the root's `id`.
- Scan and look up a file locally:
  ```sh
  sudo privasimu-bridge files scan hr-share
  sudo privasimu-bridge files locate hr-share f_2207cae0c743e650
  ```
  The local report (with real paths) stays in the state folder.

## 9. Run as a service

**Linux** (systemd):
```sh
sudo privasimu-bridge service install --mode serve
systemctl status privasimu-bridge
journalctl -u privasimu-bridge -f
```
This creates the `privasimu-bridge` system user, gives it read access to the
configuration and write access to `/var/lib/privasimu-bridge` and
`/var/log/privasimu-bridge`, and installs a sandboxed unit. Preview the unit with
`--dry-run`. Port numbers below 1024 are allowed through `CAP_NET_BIND_SERVICE` only.

**Windows** (PowerShell as Administrator):
```powershell
privasimu-bridge service install --mode serve
Get-Service privasimu-bridge
```
The service runs as `NT AUTHORITY\LocalService` with automatic (delayed) start and
restarts after a failure. Logs: `C:\ProgramData\PrivasimuBridge\logs\bridge.log`. To read
a network share, use a domain account or a group managed service account:
`--account "CORP\svc-privasimu$"`.

Remove with `privasimu-bridge service uninstall` (configuration and data are kept).

## 10. Connect the bridge in Privasimu Data Discovery (mode A)

1. Open **Data Discovery** and click **Add System**.
2. Choose the **Data source type** of the database: PostgreSQL, MySQL, Microsoft SQL
   Server or Oracle. (These are the types Privasimu can send to a bridge. MongoDB through
   the bridge needs mode B, and so do Redshift and ClickHouse.)
3. Under **Credentials & connection** fill the standard fields:
   - **Host**: the source's `match.host` (for example `corebank`), or its `host` when you
     set no alias;
   - **Port**: the database port (not used to match);
   - **Database**: the source's `database` (Oracle: also fill **Service name** or **SID**,
     which Privasimu requires);
   - **Username**: the read-only account name, for your reference;
   - **Password**: any text, for example `stored-on-the-bridge`. With local credentials the
     bridge ignores it.
4. Open **Bridge service (optional)**:
   - **Service address (https)**: the bridge address, for example
     `https://bridge.example.co.id:8443` (the same as `server.public_url`);
   - **Service API key**: the `pvbk_…` key from `init` or `key create`;
   - under **Connection fields sent to the bridge service**, **Schema** narrows the scan
     to one schema (it must be allowed in `schemas`). **Use SSL**, **Instance name**,
     **ODBC driver** and **Trust server certificate** only matter with
     `credentials: request`.
5. Save, then click **Test Connection**. Success shows the number of tables.
6. Click **Standard Scan**. Results appear under **Column Classification**: column names,
   personal-data categories and the UU PDP category. Types, row counts and values are not
   sent by contract v1.

Privasimu retries the table list up to three times, scans at most 500 tables and 1000
columns per table, and gives a scan 120 seconds. For large databases set a **Schema** or
`schemas` per source.

## 11. Mode B: outbound agent

Mode B needs a Privasimu version with bridge agents. The Laravel and Go lines implement
the same agent protocol ([AGENT-PROTOCOL.md](AGENT-PROTOCOL.md)), so these steps are the
same for both.

1. In Privasimu Data Discovery create a bridge agent and copy its enrollment token
   (`pvbe_…`, shown once, valid 24 hours). Creating, renaming, rotating, revoking and
   deleting agents is reserved for a tenant admin, a DPO, or a user whose Data Discovery
   access is set explicitly to `ubah` in Menu Preferences (for the user's division or for
   the user personally). Other users with Data Discovery access can see the agents and
   link systems to their sources.
2. On the bridge server set `agent.platform_url` in `bridge.yaml` (and `agent.proxy_url` /
   `agent.proxy_auth: "secret:proxy_auth"` when the server reaches the internet through a
   proxy; `agent.ca_file` for an on-premise Privasimu with an internal certificate).
3. Enroll and install:
   ```sh
   sudo privasimu-bridge agent enroll --token pvbe_…
   sudo privasimu-bridge check
   sudo privasimu-bridge service install --mode agent
   ```
4. In Privasimu link systems to the agent's sources (databases and file roots). Each
   source appears with its `label`, or its `id` when it has none.

The agent opens no port; allow outbound HTTPS to Privasimu only.

- **Limits**: at most 200 sources and file roots together, `agent.max_parallel_jobs` 1 to
  10 and `agent.poll_max` at most 5 minutes; `check` refuses other values.
- **Token rotation**: after an admin rotates the token in Privasimu, the agent takes a new
  token on its next poll and keeps it in the encrypted store. If the answer is lost on the
  way, Privasimu asks again on the next poll and the agent rotates again; its old token
  keeps working for 10 minutes. Only when two answers in a row are lost must the agent be
  enrolled again.
- **Revocation**: a revoked agent stops its running jobs and logs "this agent was
  revoked". To reconnect, create a new agent in Privasimu and enroll with its token.

### 11.1 Package scans (security posture)

The job `scan_packages` lists the software installed on a system and the vulnerabilities
known for it, for the security posture per RoPA in Privasimu. It is **off** until you
allow it, and Privasimu shows it only to organisations with that module.

1. **Install the scanners yourself.** Syft (inventory) and Grype or Trivy (matching) from
   their official releases, or use the image `privasimu-bridge:<version>-scan`, which has
   Syft and Grype at `/opt/privasimu-bridge/tools/` (their SHA-256 values are in
   `/opt/privasimu-bridge/tools/SHA256SUMS`). The bridge never downloads a tool.
   ```sh
   sudo install -o root -g root -m 0755 syft grype /opt/privasimu-bridge/tools/
   sha256sum /opt/privasimu-bridge/tools/syft /opt/privasimu-bridge/tools/grype
   ```
2. **Configure** targets and tools in `bridge.yaml` (every option is in
   `examples/bridge.example.yaml`), and add `scan_packages` to `agent.allowed_jobs`:
   ```yaml
   agent:
     allowed_jobs: [test_source, scan_database, scan_files, scan_packages]
   packages:
     targets:
       - id: web-01
         label: "Web 01"
         kind: host                 # host | directory | image_archive
         path: /
         refresh_interval: 24h
     tools:
       syft:  {path: /opt/privasimu-bridge/tools/syft,  sha256: "<sha256 of syft>"}
       matcher: grype
       grype: {path: /opt/privasimu-bridge/tools/grype, sha256: "<sha256 of grype>"}
   ```
   - `host` reads an installed system (OS packages from the dpkg, rpm or apk database, and
     language packages it finds); `/proc`, `/sys`, `/dev`, `/run` and the bridge's own
     folders are never read. The service account reads only what it may read: OS package
     databases are world-readable, application folders may need read access
     (`setfacl -R -m u:privasimu-bridge:rX /srv/app`).
   - `directory` reads one application or deployment folder.
   - `image_archive` reads a container image saved as a file (`docker save -o app.tar
     app:1.4.2`, or an OCI archive); the bridge uses no Docker socket and pulls nothing.
3. **Vulnerability database.** The matcher needs its own database, kept inside
   `state_dir`. Either let Grype download it (`db_auto_update: true`; outbound HTTPS to
   Anchore's database host, or to a mirror in your network with `db_update_url`), or
   keep updates off and update it yourself, for example
   `sudo -u privasimu-bridge env GRYPE_DB_CACHE_DIR=/var/lib/privasimu-bridge/grype-db /opt/privasimu-bridge/tools/grype db update`
   on a schedule (or `grype db import <file>` on an air-gapped server). A database older
   than `db_max_age` (default 120h) is refused; the job then fails with
   `matcher_db_unavailable`. Trivy: `cache_dir`, `db_repository` (mirror) and
   `skip_db_update` work the same way.
4. **Check and restart**: `sudo privasimu-bridge check` verifies each tool against its
   SHA-256, the database and each target; then restart the agent service. In Privasimu,
   open **Security Posture → Inventory**, add an asset linked to the agent's packages target
   and click **Scan now**.

How it runs: the tools are checked against their SHA-256 before every run, started without
a shell with fixed arguments and an empty environment, at the lowest CPU and I/O priority,
with a 30-minute timeout (`packages.timeout`) and a 256 MiB output limit. One package scan
runs at a time. Only package names, versions, licences and vulnerability ids are sent;
paths, files and the SBOM stay on the server. Failures appear in Privasimu as codes:
`tool_missing`, `tool_checksum_mismatch` (fix the path or the `sha256`), `tool_failed`,
`tool_timeout`, `matcher_db_unavailable` (update the database), `target_unreadable`
(path or permissions). The systemd unit made by `service install` adds every target
outside `/` as a read-only path.

## 12. Troubleshooting

First run `privasimu-bridge check`, then look at the bridge log and the audit log
(`audit.jsonl`: one line per request with `endpoint`, `status`, `code`, never a value).

What Privasimu shows (`error_kind`) and what to do:

| Kind | Message in Privasimu | Cause and fix |
|---|---|---|
| `config` | "URL dan kunci API jembatan wajib diisi." / "Isian … wajib diisi untuk sumber ini." / "URL jembatan harus memakai https." | A field is missing or invalid in the Privasimu form. Fill the bridge address (https) and API key and the required database fields. |
| `blocked` | "Host jembatan tidak diizinkan. Hubungi admin platform bila ini jaringan internal klien." | The bridge address resolves to a private, loopback or reserved IP. Use a public DNS name (SaaS) or ask a Privasimu platform administrator to add your range to the **Bridge allowlist**. |
| `unreachable` | "Layanan jembatan tidak dapat dijangkau. Periksa URL dan jaringan." | DNS does not resolve, or nothing answers: check the name, the port, the firewall/NAT, and that the service runs (`healthz`). |
| `tls` | "Sertifikat layanan jembatan tidak tepercaya. Pasang sertifikat CA di server Nexus." | The certificate is not trusted, expired, or not valid for the host name (`check` shows this). On the **Laravel line** this also appears when the bridge refuses the connection because the caller is not in `allowed_clients`: look for "connection refused: the address is not in server.allowed_clients" in the bridge log. |
| `timeout` | "Waktu menunggu layanan jembatan habis." / "Pemindaian melebihi batas waktu 120 detik. …" | The database is slow or the catalog is large: narrow with a schema, keep sampling off, check the database latency from the bridge server. |
| `auth` | "Kunci API jembatan ditolak. Periksa kunci API jembatan." | Wrong, revoked or expired API key (`key list`). In proxy mode also a caller outside `allowed_clients` (code `client_not_allowed`). |
| `bridge_rejected` | "Layanan jembatan menolak permintaan (kode N). Periksa isian sumber." | See the code in the audit log. **422**: `source_not_allowed` (no source matches the type, host and database typed in Privasimu: compare with `match`), `schema_not_allowed`, `database_auth_failed` (the bridge's own database password is wrong: `secret set`), `database_permission_denied`, `database_not_found`, `database_tls_failed`. **400**: invalid field or unsupported type (`unsupported_db_type`). **404**: table not found. **429**: rate limited, or locked out after 10 wrong keys (wait 15 minutes). |
| `bridge_unavailable` | "Layanan jembatan sedang bermasalah." / "Layanan jembatan tidak dapat dijangkau." | **502** the database is unreachable from the bridge, **504** it timed out, **503** the bridge is busy, **500** internal error (see the bridge log). On the **Go line** also a connection refused by `allowed_clients`. |
| `bridge_contract` | "Respons layanan jembatan tidak sesuai kontrak." | The address points to something that is not this bridge (a proxy error page, another service). |
| `bridge_incomplete` | (a table marked incomplete) | One table failed or the listing was incomplete; the other tables are kept. Check the audit log for that table. |
| `limit` | (a table or the listing marked) | More than 500 tables or 1000 columns: scan per schema. |

Test the bridge by hand from a machine that is allowed to connect (never put a real key in
scripts or tickets):
```sh
curl -sS https://bridge.example.co.id:8443/healthz
curl -sS https://bridge.example.co.id:8443/v1/name-database-tabels \
  -H "Content-Type: application/json" -H "X-Contract-Version: 1" -H "X-API-Key: $BRIDGE_KEY" \
  -d '{"db_type":"postgresql","host":"corebank","database":"corebank","user":"x","password":"x"}'
```

## 13. Maintenance

- **Rotate the API key**: `key create`, update the key in Privasimu, then
  `key revoke <old id>` and restart the service.
- **Certificate renewal**: replace the files; the bridge reloads them within a minute.
- **Upgrade**: verify the new release (section 1), replace the binary, run `check`,
  restart the service.
- **Package scanners**: after updating Syft, Grype or Trivy, put the new SHA-256 in
  `packages.tools` and run `check`; until then scans fail with `tool_checksum_mismatch`.
- **Backup**: `bridge.yaml`, `secrets.key` and `secrets.enc` together. On Windows the key
  is sealed to the machine: after moving to a new server, store the secrets again with
  `secret set`.
- **Logs**: the audit log rotates at 50 MB and keeps 10 files (`audit:` settings).
