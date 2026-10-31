# Memasang Privasimu Bridge

Panduan ini memasang bridge di server di dalam jaringan Anda dan menghubungkannya ke
Data Discovery Privasimu. Isinya: Windows Server dan Linux, sertifikat TLS, firewall, akun
basis data hanya-baca, sumber dan berbagi berkas, penghubungan di Privasimu, serta
pemecahan masalah.

Versi bahasa Inggris: [INSTALL.en.md](INSTALL.en.md). Rincian desain dan keamanan:
[DESIGN.md](DESIGN.md) (bahasa Inggris).

## 0. Sebelum mulai

**Mode mana?**

| | Mode A (tersedia sekarang) | Mode B (agen; butuh pembaruan Privasimu) |
|---|---|---|
| Arah | Privasimu → bridge (HTTPS, masuk ke jaringan Anda) | bridge → Privasimu (HTTPS, hanya keluar) |
| Firewall | buka satu port TCP hanya untuk IP Privasimu | tidak ada port masuk |
| Sertifikat | sertifikat yang dipercaya Privasimu | tidak perlu di bridge |
| Yang dipindai | basis data | basis data dan berbagi berkas |

Mulailah dengan mode A untuk memindai basis data hari ini. Bagian 1 sampai 10 membahas
mode A; bagian 11 membahas mode B.

**Yang Anda perlukan**

- Satu server (boleh virtual) di jaringan yang dapat menjangkau basis data Anda: Windows
  Server 2016 atau lebih baru, atau Linux x86-64/arm64 (Ubuntu 20.04+, Debian 11+,
  RHEL/Rocky/Alma 8+). 2 vCPU dan RAM 2 GB sudah cukup; ruang disk 1 GB untuk log dan
  laporan.
- Hak Administrator (Windows) atau root/sudo (Linux) di server itu.
- Untuk mode A dengan Privasimu SaaS: nama DNS untuk bridge (misalnya
  `bridge.contoh.co.id`) yang dapat dijangkau Privasimu, dan alamat IP keluar Privasimu
  (tanyakan ke dukungan Privasimu).
- Untuk setiap basis data: akun hanya-baca (bagian 6).

**Bekerja dengan kedua lini Privasimu Nexus.** Privasimu berjalan di backend Laravel atau
backend Go. Keduanya memanggil bridge dengan kontrak yang sama (kontrak v1: path yang
sama, header `X-API-Key` dan `X-Contract-Version: 1`, serta isian yang sama), jadi panduan
ini sama untuk keduanya. Satu-satunya perbedaan yang penting saat pemasangan adalah cara
server Privasimu memercayai sertifikat internal (bagian 4.2). Bridge adalah satu program
Go, sehingga server Anda tidak memerlukan PHP, web server, ekstensi basis data, Oracle
Instant Client, maupun driver ODBC.

## 1. Pasang programnya

Setiap rilis berisi satu berkas per platform: `privasimu-bridge-<versi>-linux-amd64`,
`...-linux-arm64`, `...-windows-amd64.exe`, dan `SHA256SUMS`.

### Linux

```sh
sha256sum -c SHA256SUMS --ignore-missing                # periksa unduhan
sudo install -m 0755 privasimu-bridge-0.1.0-linux-amd64 /usr/local/bin/privasimu-bridge
privasimu-bridge version
```

### Windows (PowerShell sebagai Administrator)

```powershell
Get-FileHash .\privasimu-bridge-0.1.0-windows-amd64.exe -Algorithm SHA256   # cocokkan dengan SHA256SUMS
New-Item -ItemType Directory -Force "C:\Program Files\PrivasimuBridge" | Out-Null
Copy-Item .\privasimu-bridge-0.1.0-windows-amd64.exe "C:\Program Files\PrivasimuBridge\privasimu-bridge.exe"
& "C:\Program Files\PrivasimuBridge\privasimu-bridge.exe" version
```

Tambahkan `C:\Program Files\PrivasimuBridge` ke `PATH` sistem, atau panggil program
dengan path lengkapnya pada perintah-perintah di bawah.

### Docker

Lihat `deploy/docker/docker-compose.yml`. Image berjalan sebagai pengguna non-root dengan
sistem berkas hanya-baca; pasang konfigurasi di `/etc/privasimu-bridge` dan sebuah volume
di `/var/lib/privasimu-bridge`. Jalankan `init` sekali dengan
`--dir /etc/privasimu-bridge --state-dir /var/lib/privasimu-bridge --log-dir /var/lib/privasimu-bridge/logs`.

Pesan program berbahasa Inggris secara bawaan; tambahkan `--lang id` (atau atur
`PRIVASIMU_BRIDGE_LANG=id`) untuk bahasa Indonesia.

## 2. Buat konfigurasi

```sh
# Linux
sudo privasimu-bridge --lang id init --public-url https://bridge.contoh.co.id:8443
# Windows (Administrator)
privasimu-bridge --lang id init --public-url https://bridge.contoh.co.id:8443
```

`init` membuat:

| Berkas | Linux | Windows |
|---|---|---|
| konfigurasi | `/etc/privasimu-bridge/bridge.yaml` | `C:\ProgramData\PrivasimuBridge\bridge.yaml` |
| kunci penyimpanan rahasia | `/etc/privasimu-bridge/secrets.key` | `C:\ProgramData\PrivasimuBridge\secrets.key` (disegel dengan DPAPI) |
| penyimpanan rahasia terenkripsi | `/var/lib/privasimu-bridge/secrets.enc` | `C:\ProgramData\PrivasimuBridge\state\secrets.enc` |
| folder sertifikat | `/etc/privasimu-bridge/tls/` | `C:\ProgramData\PrivasimuBridge\tls\` |
| log audit | `/var/log/privasimu-bridge/audit.jsonl` | `C:\ProgramData\PrivasimuBridge\logs\audit.jsonl` |

`init` juga menampilkan **kunci API** (`pvbk_…`) **satu kali saja**. Salin sekarang ke
pengelola kata sandi Anda: yang disimpan hanya hash-nya, kunci itu tidak dapat
ditampilkan lagi (kunci baru dapat dibuat dengan `privasimu-bridge key create`). Di
Windows folder ini dibatasi untuk Administrators dan SYSTEM.

Opsi: `--listen` (bawaan `0.0.0.0:8443`), `--dir`, `--state-dir`, `--log-dir`,
`--platform-url` (mode B), `--force` (tulis ulang konfigurasi; kunci penyimpanan tetap).

Komentar di `bridge.yaml` mengikuti bahasa perintah (`--lang id` menghasilkan komentar
berbahasa Indonesia).

## 3. Firewall (mode A)

Buka port bridge (bawaan 8443) **hanya** untuk alamat IP keluar Privasimu.

Linux dengan ufw:
```sh
sudo ufw allow from 203.0.113.10 to any port 8443 proto tcp
```
Linux dengan firewalld:
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

Lakukan hal yang sama di firewall perimeter atau NAT. Lalu isi alamat yang sama di
`bridge.yaml`; bridge menutup koneksi lain sebelum jabat tangan TLS:

```yaml
server:
  allowed_clients: [203.0.113.10/32]
```

**Privasimu SaaS dan alamat privat.** Kebijakan host Privasimu menolak alamat bridge yang
mengarah ke IP privat (10.x, 172.16-31.x, 192.168.x), kecuali admin platform Privasimu
menambahkan rentang privat Anda untuk organisasi Anda (Platform Admin → Tenants →
**Allowlist jembatan**). Susunan yang lazim adalah nama DNS publik untuk bridge dengan
aturan firewall di atas. Privasimu yang terpasang di dalam jaringan Anda (on-premise)
boleh menjangkau alamat privat secara langsung. Loopback (127.0.0.1) tidak pernah
diizinkan.

## 4. Sertifikat TLS

Privasimu memverifikasi sertifikat bridge dengan trust store-nya dan tidak pernah
melewatkan pemeriksaan itu. Sertifikat yang ditandatangani sendiri (self-signed) tidak
akan berfungsi. Sertifikat harus berlaku untuk nama host pada alamat bridge yang Anda
isikan di Privasimu.

Taruh sertifikat beserta intermediate-nya (sertifikat server di urutan pertama) dan kunci
privatnya di sini:

| | Sertifikat | Kunci |
|---|---|---|
| Linux | `/etc/privasimu-bridge/tls/fullchain.pem` | `/etc/privasimu-bridge/tls/privkey.pem` |
| Windows | `C:\ProgramData\PrivasimuBridge\tls\fullchain.pem` | `C:\ProgramData\PrivasimuBridge\tls\privkey.pem` |

(atau ubah `server.tls.cert_file` dan `key_file`). Bridge memuat ulang berkas itu dalam
satu menit setelah berubah; tidak perlu restart setelah perpanjangan.

### 4.1 Sertifikat publik (Privasimu SaaS)

Linux dengan certbot (tantangan DNS tidak memerlukan port 80 terbuka):
```sh
sudo certbot certonly --manual --preferred-challenges dns -d bridge.contoh.co.id
```
Salin berkasnya setiap kali diperpanjang dengan deploy hook,
`/etc/letsencrypt/renewal-hooks/deploy/privasimu-bridge.sh`:
```sh
#!/bin/sh
install -m 0640 -o root -g privasimu-bridge /etc/letsencrypt/live/bridge.contoh.co.id/fullchain.pem /etc/privasimu-bridge/tls/fullchain.pem
install -m 0640 -o root -g privasimu-bridge /etc/letsencrypt/live/bridge.contoh.co.id/privkey.pem /etc/privasimu-bridge/tls/privkey.pem
```
Windows dengan win-acme: pilih penyimpanan berkas PEM dan folder
`C:\ProgramData\PrivasimuBridge\tls`; arahkan `cert_file` ke berkas rantai
(`…-chain.pem`) dan `key_file` ke berkas kunci (`…-key.pem`). Sertifikat dari CA komersial
dipakai dengan cara yang sama (PEM, termasuk rantainya).

### 4.2 Sertifikat dari CA internal (Privasimu on-premise)

Terbitkan sertifikat server dengan Subject Alternative Name berisi nama DNS bridge. Lalu
buat **server Privasimu** memercayai CA Anda, sesuai lini yang dijalankannya:

- **Lini Go**: tambahkan CA ke trust store sistem operasi lalu restart backend.
  Debian/Ubuntu: `sudo cp corp-root-ca.crt /usr/local/share/ca-certificates/ && sudo update-ca-certificates`.
  Keluarga RHEL: `sudo cp corp-root-ca.crt /etc/pki/ca-trust/source/anchors/ && sudo update-ca-trust`.
  Di dalam kontainer: tambahkan CA ke image atau pasang bundle dan atur `SSL_CERT_FILE`.
- **Lini Laravel**: PHP memakai bundle CA milik curl. Tambahkan CA ke trust store sistem
  seperti di atas, pastikan `curl.cainfo` / `openssl.cafile` di `php.ini` kosong atau
  menunjuk ke bundle yang memuat CA Anda
  (`php -r 'print_r(openssl_get_cert_locations());'`), lalu restart PHP-FPM **dan worker
  antrean** (`php artisan queue:restart`): pemindaian berjalan di antrean.

Periksa dari server Privasimu, tanpa `-k`:
```sh
curl -sS https://bridge.contoh.co.id:8443/healthz      # {"status":"ok"}
```

### 4.3 Di belakang reverse proxy

Bila nginx (atau proxy lain) sudah menangani TLS di server bridge, atur:
```yaml
server:
  listen: "127.0.0.1:8080"
  tls: {mode: proxy}
  trusted_proxies: [127.0.0.1/32]
```
Contoh nginx ada di `deploy/nginx-bridge.conf` (TLS, daftar IP yang diizinkan,
`X-Forwarded-For`). Dalam mode proxy, bridge menolak mendengarkan di alamat selain
loopback.

## 5. Periksa pemasangan dasar

```sh
sudo privasimu-bridge --lang id check          # Windows: privasimu-bridge --lang id check
```
Setiap baris berupa `[OK]`, `[WARN]` atau `[FAIL]`. Pada tahap ini Anda seharusnya melihat
konfigurasi, penyimpanan rahasia, dan sertifikat. Perbaiki setiap `[FAIL]` sebelum lanjut.

## 6. Akun basis data hanya-baca

Pakai akun khusus per basis data yang dapat membaca katalog dan, bila sampling diaktifkan,
membaca baris. Jangan pakai akun administrator. Ganti nama dalam kurung siku.

**PostgreSQL**
```sql
CREATE ROLE privasimu_ro LOGIN PASSWORD '<kata sandi kuat>';
ALTER ROLE privasimu_ro SET default_transaction_read_only = on;
GRANT CONNECT ON DATABASE corebank TO privasimu_ro;
GRANT USAGE ON SCHEMA public TO privasimu_ro;
-- Hanya nama: katalog sudah dapat dibaca tanpa izin lain. Untuk sampling lokal tambahkan:
GRANT SELECT ON ALL TABLES IN SCHEMA public TO privasimu_ro;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO privasimu_ro;
-- PostgreSQL 14+: GRANT pg_read_all_data TO privasimu_ro;  (semua skema)
```
Izinkan server bridge di `pg_hba.conf` (`hostssl corebank privasimu_ro <ip-bridge>/32 scram-sha-256`).

**MySQL / MariaDB** (tabel hanya terlihat di katalog bagi akun yang punya izin atasnya)
```sql
CREATE USER 'privasimu_ro'@'<ip-bridge>' IDENTIFIED BY '<kata sandi kuat>';
GRANT SELECT, SHOW VIEW ON crm.* TO 'privasimu_ro'@'<ip-bridge>';
```

**Microsoft SQL Server**
```sql
CREATE LOGIN privasimu_ro WITH PASSWORD = '<kata sandi kuat>', CHECK_POLICY = ON;
USE HRIS;
CREATE USER privasimu_ro FOR LOGIN privasimu_ro;
GRANT VIEW DEFINITION TO privasimu_ro;              -- nama dan tipe
ALTER ROLE db_datareader ADD MEMBER privasimu_ro;   -- hanya untuk sampling lokal
```
Bridge terhubung dengan `ApplicationIntent=ReadOnly` (memakai replika yang dapat dibaca
dalam availability group) dan mengambil sampel dengan `READ UNCOMMITTED`, sehingga tidak
pernah menghambat transaksi Anda.

**Oracle** (12c atau lebih baru; izin `READ` tidak mengunci baris)
```sql
CREATE USER privasimu_ro IDENTIFIED BY "<kata sandi kuat>";
GRANT CREATE SESSION TO privasimu_ro;
-- nama dan sampling skema FIN:
BEGIN
  FOR t IN (SELECT table_name FROM all_tables WHERE owner = 'FIN') LOOP
    EXECUTE IMMEDIATE 'GRANT READ ON FIN."' || t.table_name || '" TO privasimu_ro';
  END LOOP;
END;
/
```
Isi `schemas: [FIN]` pada sumbernya (skema Oracle adalah pemilik/owner).

**MongoDB**
```js
use app
db.createUser({ user: "privasimu_ro", pwd: passwordPrompt(), roles: [ { role: "read", db: "app" } ] })
```
MongoDB tidak punya katalog skema: bridge membaca hingga 100 dokumen per koleksi di server
bridge untuk mengetahui nama field. Nilainya hanya diperiksa bila sampling aktif.

## 7. Simpan password dan tentukan sumber

Simpan setiap password di penyimpanan terenkripsi (nilainya tidak tampil saat diketik):

```sh
sudo privasimu-bridge --lang id secret set corebank_pg
sudo privasimu-bridge secret list          # hanya nama
```

Lalu tambahkan sumber ke `bridge.yaml` (setiap opsi dijelaskan di
`examples/bridge.example.yaml`):

```yaml
sources:
  - id: core-banking
    label: "Core banking"
    engine: postgresql          # postgresql | mysql | mariadb | mssql | oracle | mongodb
    host: 10.10.1.20
    database: corebank
    username: privasimu_ro
    password: "secret:corebank_pg"
    schemas: [public]           # opsional
    tls:
      mode: verify-full         # disable | prefer | require | verify-ca | verify-full
      ca_file: tls/db-ca.pem
    sampling: {enabled: false}  # true = baca hingga 100 nilai per kolom di server ini
    match:
      host: corebank            # yang akan Anda ketik sebagai "Host" di Privasimu
```

- **Kredensial tetap di bridge** (`server.credentials: local`, bawaan). Privasimu hanya
  dapat memindai sumber-sumber ini. Bridge mencocokkan sumber dari jenis basis data, host,
  dan nama basis data; password yang diketik di Privasimu diabaikan.
- `match.host` memungkinkan Anda mengetik alias seperti `corebank` di Privasimu alih-alih
  alamat sebenarnya, sehingga alamat itu tidak pernah keluar dari jaringan Anda.
- Selain `secret:NAMA`, Anda dapat memakai `env:NAMA` (variabel lingkungan) atau
  `file:/path` (Docker secret atau systemd credential). Password polos di berkas ditolak.
- **Sampling** mati secara bawaan. Bila aktif, nilai dibaca dan diperiksa di server bridge
  dan hanya jumlah serta kategori yang dikirim; sampling menemukan data pribadi di kolom
  bernama netral (misalnya kolom `keterangan` yang penuh nomor telepon).

Uji:
```sh
sudo privasimu-bridge --lang id check
# [OK]   sumber core-banking: PostgreSQL 16.4, 120 tabel, TLS aktif, sampling mati (hanya nama)
```

## 8. Berbagi berkas (mode B dan laporan lokal)

Root berkas dipindai lewat mode B (setelah Privasimu mendukungnya) atau secara lokal
lewat baris perintah. Hanya folder yang Anda daftarkan yang dapat dibaca:

```yaml
files:
  report_paths: hashed          # hashed: berkas dinamai hash berkunci; relative: dengan path-nya
  roots:
    - id: hr-share
      label: "Berbagi berkas SDM"
      path: /srv/shares/hr      # Windows: "D:/Shares/HR"
      exclude: ["arsip/**"]
      refresh_interval: 24h     # pindai ulang di latar belakang
```

- Beri akun layanan izin baca: Linux
  `sudo setfacl -R -m u:privasimu-bridge:rX /srv/shares/hr` (dan ACL bawaan untuk berkas
  baru); Windows: izin baca NTFS untuk akun layanan. Berbagi berkas di server lain
  memerlukan akun domain atau gMSA sebagai akun layanan (bagian 9).
- Tautan (symlink) dan junction yang mengarah ke luar root tidak pernah diikuti.
- Pindai dan cari berkas secara lokal:
  ```sh
  sudo privasimu-bridge --lang id files scan hr-share
  sudo privasimu-bridge files locate hr-share f_2207cae0c743e650
  ```
  Laporan lokal (dengan path sebenarnya) tetap berada di folder state.

## 9. Jalankan sebagai layanan

**Linux** (systemd):
```sh
sudo privasimu-bridge service install --mode serve
systemctl status privasimu-bridge
journalctl -u privasimu-bridge -f
```
Perintah ini membuat pengguna sistem `privasimu-bridge`, memberinya akses baca ke
konfigurasi dan akses tulis ke `/var/lib/privasimu-bridge` serta
`/var/log/privasimu-bridge`, dan memasang unit yang terisolasi (sandbox). Pratinjau unitnya
dengan `--dry-run`. Port di bawah 1024 hanya diizinkan lewat `CAP_NET_BIND_SERVICE`.

**Windows** (PowerShell sebagai Administrator):
```powershell
privasimu-bridge service install --mode serve
Get-Service privasimu-bridge
```
Layanan berjalan sebagai `NT AUTHORITY\LocalService` dengan mulai otomatis (tertunda) dan
dijalankan ulang setelah gagal. Log: `C:\ProgramData\PrivasimuBridge\logs\bridge.log`.
Untuk membaca berbagi berkas di jaringan, pakai akun domain atau group managed service
account: `--account "CORP\svc-privasimu$"`.

Hapus dengan `privasimu-bridge service uninstall` (konfigurasi dan data tetap ada).

## 10. Hubungkan bridge di Data Discovery Privasimu (mode A)

1. Buka **Data Discovery** dan klik **Tambah Sistem**.
2. Pilih **Tipe sumber data** sesuai basis datanya: PostgreSQL, MySQL, Microsoft SQL Server,
   atau Oracle. (Inilah tipe yang dapat dikirim Privasimu ke bridge. MongoDB lewat bridge
   memerlukan mode B.)
3. Di **Kredensial & koneksi** isi isian standar:
   - **Host**: `match.host` sumbernya (misalnya `corebank`), atau `host`-nya bila tidak
     memakai alias;
   - **Port**: port basis data (tidak dipakai untuk pencocokan);
   - **Basis data**: `database` sumbernya (Oracle: isi juga **Service name** atau **SID**,
     yang diwajibkan Privasimu);
   - **Username**: nama akun hanya-baca, sebagai catatan Anda;
   - **Password**: teks apa saja, misalnya `disimpan-di-bridge`. Dengan kredensial lokal,
     bridge mengabaikannya.
4. Buka **Layanan jembatan (opsional)**:
   - **Alamat layanan (https)**: alamat bridge, misalnya
     `https://bridge.contoh.co.id:8443` (sama dengan `server.public_url`);
   - **Kunci API layanan**: kunci `pvbk_…` dari `init` atau `key create`;
   - di bawah **Isian koneksi yang dikirim ke layanan jembatan:**, **Skema** membatasi
     pemindaian ke satu skema (harus diizinkan di `schemas`). **Gunakan SSL**,
     **Nama instance**, **Driver ODBC**, dan **Percayai sertifikat server** hanya berpengaruh
     bila `credentials: request`.
5. Simpan, lalu klik **Uji Koneksi**. Bila berhasil, jumlah tabel ditampilkan.
6. Klik **Pemindaian Standar**. Hasilnya muncul di **Klasifikasi Kolom**: nama kolom,
   kategori data pribadi, dan kategori UU PDP (umum/spesifik). Tipe data, jumlah baris, dan
   nilai tidak dikirim oleh kontrak v1.

Privasimu mencoba ulang daftar tabel hingga tiga kali, memindai paling banyak 500 tabel
dan 1000 kolom per tabel, dan memberi satu pemindaian waktu 120 detik. Untuk basis data
besar, isi **Skema** atau `schemas` per sumber.

## 11. Mode B: agen keluar (setelah Privasimu mendukungnya)

Mode B memerlukan pembaruan Privasimu yang dijelaskan di [AGENT-PROTOCOL.md](AGENT-PROTOCOL.md).
Setelah tersedia:

1. Di Privasimu buat agen bridge; salin token pendaftarannya (`pvbe_…`, berlaku 24 jam).
2. Di server bridge isi `agent.platform_url` di `bridge.yaml` (dan `agent.proxy_url` /
   `agent.proxy_auth: "secret:proxy_auth"` bila server keluar ke internet lewat proxy;
   `agent.ca_file` untuk Privasimu on-premise dengan sertifikat internal).
3. Daftarkan dan pasang:
   ```sh
   sudo privasimu-bridge --lang id agent enroll --token pvbe_…
   sudo privasimu-bridge --lang id check
   sudo privasimu-bridge service install --mode agent
   ```
4. Di Privasimu tautkan sistem ke sumber-sumber agen (basis data dan root berkas).

Agen tidak membuka port; cukup izinkan HTTPS keluar ke Privasimu.

## 12. Pemecahan masalah

Pertama jalankan `privasimu-bridge --lang id check`, lalu lihat log bridge dan log audit
(`audit.jsonl`: satu baris per permintaan berisi `endpoint`, `status`, `code`, tanpa
nilai apa pun).

Yang ditampilkan Privasimu (`error_kind`) dan yang perlu dilakukan:

| Jenis | Pesan di Privasimu | Penyebab dan perbaikan |
|---|---|---|
| `config` | "URL dan kunci API jembatan wajib diisi." / "Isian … wajib diisi untuk sumber ini." / "URL jembatan harus memakai https." | Ada isian yang kosong atau tidak valid di formulir Privasimu. Isi alamat bridge (https), kunci API, dan isian basis data yang wajib. |
| `blocked` | "Host jembatan tidak diizinkan. Hubungi admin platform bila ini jaringan internal klien." | Alamat bridge mengarah ke IP privat, loopback, atau khusus. Pakai nama DNS publik (SaaS) atau minta admin platform Privasimu menambahkan rentang Anda di **Allowlist jembatan**. |
| `unreachable` | "Layanan jembatan tidak dapat dijangkau. Periksa URL dan jaringan." | Nama DNS tidak dapat di-resolve, atau tidak ada yang menjawab: periksa nama, port, firewall/NAT, dan apakah layanan berjalan (`healthz`). |
| `tls` | "Sertifikat layanan jembatan tidak tepercaya. Pasang sertifikat CA di server Nexus." | Sertifikat tidak dipercaya, kedaluwarsa, atau tidak berlaku untuk nama host (`check` menunjukkannya). Di **lini Laravel** pesan ini juga muncul bila bridge menolak koneksi karena pemanggil tidak ada di `allowed_clients`: cari "connection refused: the address is not in server.allowed_clients" di log bridge. |
| `timeout` | "Waktu menunggu layanan jembatan habis." / "Pemindaian melebihi batas waktu 120 detik. …" | Basis data lambat atau katalognya besar: persempit dengan skema, biarkan sampling mati, periksa latensi basis data dari server bridge. |
| `auth` | "Kunci API jembatan ditolak. Periksa kunci API jembatan." | Kunci API salah, dicabut, atau kedaluwarsa (`key list`). Dalam mode proxy juga pemanggil di luar `allowed_clients` (kode `client_not_allowed`). |
| `bridge_rejected` | "Layanan jembatan menolak permintaan (kode N). Periksa isian sumber." | Lihat kodenya di log audit. **422**: `source_not_allowed` (tidak ada sumber yang cocok dengan tipe, host, dan basis data yang diketik di Privasimu: bandingkan dengan `match`), `schema_not_allowed`, `database_auth_failed` (password basis data milik bridge salah: `secret set`), `database_permission_denied`, `database_not_found`, `database_tls_failed`. **400**: isian tidak valid atau tipe tidak didukung (`unsupported_db_type`). **404**: tabel tidak ditemukan. **429**: dibatasi laju, atau terkunci setelah 10 kunci salah (tunggu 15 menit). |
| `bridge_unavailable` | "Layanan jembatan sedang bermasalah." / "Layanan jembatan tidak dapat dijangkau." | **502** basis data tidak terjangkau dari bridge, **504** waktu habis, **503** bridge sibuk, **500** galat internal (lihat log bridge). Di **lini Go** juga koneksi yang ditolak `allowed_clients`. |
| `bridge_contract` | "Respons layanan jembatan tidak sesuai kontrak." | Alamat itu bukan bridge ini (halaman galat proxy, layanan lain). |
| `bridge_incomplete` | (sebuah tabel ditandai tidak lengkap) | Satu tabel gagal atau daftar tabel tidak lengkap; tabel lain tetap tersimpan. Periksa log audit untuk tabel itu. |
| `limit` | (sebuah tabel atau daftar ditandai) | Lebih dari 500 tabel atau 1000 kolom: pindai per skema. |

Uji bridge secara manual dari mesin yang diizinkan terhubung (jangan pernah menaruh kunci
asli di skrip atau tiket):
```sh
curl -sS https://bridge.contoh.co.id:8443/healthz
curl -sS https://bridge.contoh.co.id:8443/v1/name-database-tabels \
  -H "Content-Type: application/json" -H "X-Contract-Version: 1" -H "X-API-Key: $BRIDGE_KEY" \
  -d '{"db_type":"postgresql","host":"corebank","database":"corebank","user":"x","password":"x"}'
```

## 13. Pemeliharaan

- **Ganti kunci API**: `key create`, perbarui kunci di Privasimu, lalu
  `key revoke <id lama>` dan restart layanan.
- **Perpanjangan sertifikat**: ganti berkasnya; bridge memuat ulang dalam satu menit.
- **Pembaruan program**: ganti berkas program, jalankan `check`, restart layanan.
- **Cadangan**: `bridge.yaml`, `secrets.key`, dan `secrets.enc` bersama-sama. Di Windows
  kuncinya disegel ke mesin itu: setelah pindah ke server baru, simpan ulang rahasianya
  dengan `secret set`.
- **Log**: log audit dirotasi pada 50 MB dan menyimpan 10 berkas (pengaturan `audit:`).
