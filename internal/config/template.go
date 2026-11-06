package config

import (
	"bytes"
	"strconv"
	"text/template"

	"github.com/privasimu/bridge/internal/i18n"
)

// TemplateData fills the configuration file written by init.
type TemplateData struct {
	Language string
	// ModeB writes a mode B configuration: the agent section filled in, no server section
	// and no API key. Otherwise the file is for mode A (the server section with the first
	// API key) and keeps an empty agent section for later.
	ModeB       bool
	Listen      string
	PublicURL   string
	KeyID       string
	KeyHash     string
	Created     string
	CertFile    string
	KeyFile     string
	PlatformURL string
	StateDir    string
	SecretsFile string
	SecretsKey  string
	AuditFile   string
}

// comments are the explanatory lines of the generated file, in English and Indonesian.
var comments = map[string][2]string{
	"head": {
		"Privasimu Bridge configuration. No secret is written in this file: passwords are\n# references (secret:NAME, env:NAME or file:PATH) and API keys are stored as hashes.\n# Check it with: privasimu-bridge check",
		"Konfigurasi Privasimu Bridge. Tidak ada rahasia yang ditulis di berkas ini: password\n# berupa rujukan (secret:NAMA, env:NAMA atau file:PATH) dan kunci API disimpan sebagai hash.\n# Periksa dengan: privasimu-bridge check",
	},
	"server": {
		"Mode A: the platform calls this HTTPS server (privasimu-bridge serve).",
		"Mode A: platform memanggil server HTTPS ini (privasimu-bridge serve).",
	},
	"public_url": {
		"Address entered in Privasimu as the bridge address (used by check).",
		"Alamat yang diisikan di Privasimu sebagai alamat layanan (dipakai oleh check).",
	},
	"tls": {
		"file: the bridge serves TLS with a certificate trusted by the platform (a public CA,\n    # or your internal CA installed on the Privasimu server). proxy: a reverse proxy on this\n    # host terminates TLS; listen must then be 127.0.0.1.",
		"file: bridge melayani TLS dengan sertifikat yang dipercaya platform (CA publik, atau CA\n    # internal Anda yang dipasang di server Privasimu). proxy: reverse proxy di host ini yang\n    # menangani TLS; listen wajib 127.0.0.1.",
	},
	"allowed_clients": {
		"Only these addresses may connect (the platform's outgoing IPs). Empty = any.",
		"Hanya alamat ini yang boleh terhubung (IP keluar platform). Kosong = semua.",
	},
	"api_keys": {
		"API keys as SHA-256 hashes. Add one with: privasimu-bridge key create",
		"Kunci API sebagai hash SHA-256. Tambah dengan: privasimu-bridge key create",
	},
	"credentials": {
		"local: only sources listed below can be scanned; the password typed in Privasimu is\n  # ignored. request: the settings Privasimu sends are used, for allowed_targets only.",
		"local: hanya sumber di bawah yang dapat dipindai; password yang diisi di Privasimu\n  # diabaikan. request: isian dari Privasimu dipakai, hanya untuk allowed_targets.",
	},
	"agent": {
		"Mode B: outbound-only agent (privasimu-bridge agent). Fill platform_url, then run\n# privasimu-bridge agent enroll --token <enrollment token>.",
		"Mode B: agen yang hanya keluar (privasimu-bridge agent). Isi platform_url, lalu jalankan\n# privasimu-bridge agent enroll --token <token pendaftaran>.",
	},
	"agent_b": {
		"Mode B: this bridge polls Privasimu over HTTPS and opens no port. platform_url is the\n# address of the Privasimu backend without /api (the install guide in Privasimu shows it).\n# Then run: privasimu-bridge agent enroll --token <enrollment token>",
		"Mode B: bridge ini menghubungi Privasimu lewat HTTPS dan tidak membuka port. platform_url\n# adalah alamat backend Privasimu tanpa /api (panduan pemasangan di Privasimu menampilkannya).\n# Lalu jalankan: privasimu-bridge agent enroll --token <token pendaftaran>",
	},
	"ca_file": {
		"PEM file of the CA that issued Privasimu's certificate, when it is not publicly trusted.",
		"Berkas PEM CA penerbit sertifikat Privasimu, bila CA itu tidak dipercaya publik.",
	},
	"parallel": {
		"Jobs run at the same time (1 to 10). 1 runs them one after another, the lowest load.",
		"Tugas yang berjalan bersamaan (1 sampai 10). 1 menjalankannya satu per satu, beban terendah.",
	},
	"no_server": {
		"Mode A (an HTTPS server Privasimu calls) is not set up in this file: run\n# privasimu-bridge init --mode a in another directory to create such a configuration.",
		"Mode A (server HTTPS yang dipanggil Privasimu) tidak disiapkan di berkas ini: jalankan\n# privasimu-bridge init --mode a di direktori lain untuk membuat konfigurasi seperti itu.",
	},
	"sources": {
		"Databases this bridge may scan. Store each password with:\n#   privasimu-bridge secret set <name>",
		"Basis data yang boleh dipindai bridge ini. Simpan setiap password dengan:\n#   privasimu-bridge secret set <nama>",
	},
	"files": {
		"File-share roots this bridge may scan. Only these directories are ever read; the\n# platform names a root by its id and can never send a path.",
		"Direktori berbagi berkas yang boleh dipindai. Hanya direktori ini yang dibaca; platform\n# menyebut root dengan id-nya dan tidak pernah dapat mengirim path.",
	},
	"report_paths": {
		"hashed: report a keyed hash per file (default). relative: report the path in the root.",
		"hashed: laporkan hash berkunci per berkas (bawaan). relative: laporkan path di dalam root.",
	},
	"packages": {
		"Software inventory and vulnerability matching (job scan_packages; add it to\n# agent.allowed_jobs to allow it). Install Syft and Grype or Trivy yourself and pin each\n# by path and SHA-256 (sha256sum <file>); the bridge never downloads them.",
		"Inventaris perangkat lunak dan pencocokan kerentanan (tugas scan_packages; tambahkan ke\n# agent.allowed_jobs untuk mengizinkannya). Pasang sendiri Syft dan Grype atau Trivy, lalu\n# kunci masing-masing dengan path dan SHA-256 (sha256sum <berkas>); bridge tidak pernah mengunduhnya.",
	},
	"sampling": {
		"Local sampling reads a few values per column ON THIS SERVER to confirm personal data.\n  # Only counts and categories leave; values are never sent, stored or logged.",
		"Sampling lokal membaca beberapa nilai per kolom DI SERVER INI untuk memastikan data\n  # pribadi. Hanya jumlah dan kategori yang keluar; nilai tidak pernah dikirim, disimpan, atau dicatat.",
	},
}

const configTemplate = `# {{c "head"}}

language: {{.Language}}
state_dir: {{q .StateDir}}
{{if .ModeB}}
# {{c "agent_b"}}
agent:
  platform_url: {{q .PlatformURL}}
  token: "secret:agent_token"
  # {{c "ca_file"}}
  ca_file: ""
  allowed_jobs: [test_source, scan_database, scan_files]
  # {{c "parallel"}}
  max_parallel_jobs: 1

# {{c "no_server"}}
{{else}}
# {{c "server"}}
server:
  listen: {{q .Listen}}
  # {{c "public_url"}}
  public_url: {{q .PublicURL}}
  tls:
    # {{c "tls"}}
    mode: file
    cert_file: {{q .CertFile}}
    key_file: {{q .KeyFile}}
    min_version: "1.2"
  # {{c "allowed_clients"}}
  allowed_clients: []
  # {{c "api_keys"}}
  api_keys:
    - id: {{q .KeyID}}
      hash: {{q .KeyHash}}
      created: {{q .Created}}
  # {{c "credentials"}}
  credentials: local
  allowed_targets: []

# {{c "agent"}}
agent:
  platform_url: {{q .PlatformURL}}
  agent_id: ""
  token: "secret:agent_token"
  allowed_jobs: [test_source, scan_database, scan_files]
{{end}}
# {{c "sources"}}
sources: []
#  - id: core-banking
#    label: "Core banking"
#    engine: postgresql        # postgresql | mysql | mariadb | mssql | oracle | mongodb | redshift | clickhouse
#                              # | snowflake | bigquery | databricks | athena (see the install guide)
#    host: 10.10.1.20
#    port: 5432
#    database: corebank
#    username: privasimu_ro
#    password: "secret:corebank_pg"
#    schemas: [public]
#    tls:
#      mode: verify-full       # disable | prefer | require | verify-ca | verify-full
#      ca_file: ""
#    match:
#      host: corebank          # Host typed in Privasimu (default: host)

# {{c "files"}}
files:
  # {{c "report_paths"}}
  report_paths: hashed
  roots: []
#    - id: hr-share
#      label: "HR share"
#      path: "/srv/shares/hr"
#      exclude: ["**/~$*", "**/.git/**"]

# {{c "packages"}}
packages:
  targets: []
#    - id: web-01
#      label: "Web 01"
#      kind: host                # host | directory | image_archive
#      path: /
#      refresh_interval: 24h
#  tools:
#    syft: {path: /opt/privasimu-bridge/tools/syft, sha256: "<sha256>"}
#    matcher: grype            # grype | trivy | none
#    grype: {path: /opt/privasimu-bridge/tools/grype, sha256: "<sha256>"}

detection:
  # {{c "sampling"}}
  sampling:
    enabled: false
    rows: 100

secrets:
  file: {{q .SecretsFile}}
  key_file: {{q .SecretsKey}}

audit:
  file: {{q .AuditFile}}
  max_size_mb: 50
  max_files: 10

log:
  level: info
`

// Render produces the configuration file written by init.
func Render(d TemplateData) ([]byte, error) {
	lang := i18n.Parse(d.Language)
	if d.Language == "" {
		d.Language = string(lang)
	}
	funcs := template.FuncMap{
		"c": func(key string) string {
			pair := comments[key]
			if lang == i18n.ID {
				return pair[1]
			}
			return pair[0]
		},
		"q": strconv.Quote,
	}
	t, err := template.New("config").Funcs(funcs).Parse(configTemplate)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	if err := t.Execute(&buf, d); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
