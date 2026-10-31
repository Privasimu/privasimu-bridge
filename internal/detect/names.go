package detect

import (
	"strings"
	"unicode"
)

// NameMatch is the result of classifying a column or field name.
type NameMatch struct {
	Category   Category
	Confidence float64
}

// Tokens splits a column name into lower-case words: snake_case, kebab-case, camelCase,
// digits, and words written together without a separator when the whole word can be
// split into known words ("noktp" -> "no", "ktp"; "tanggallahir" -> "tanggal", "lahir").
func Tokens(name string) []string {
	var raw []string
	var cur []rune
	flush := func() {
		if len(cur) > 0 {
			raw = append(raw, strings.ToLower(string(cur)))
			cur = cur[:0]
		}
	}
	runes := []rune(name)
	for i, r := range runes {
		switch {
		case unicode.IsLetter(r) || unicode.IsDigit(r):
			if len(cur) > 0 {
				prev := cur[len(cur)-1]
				switch {
				case unicode.IsDigit(r) != unicode.IsDigit(prev):
					flush() // letters and digits are separate words
				case unicode.IsUpper(r) && unicode.IsLower(prev):
					flush() // camelCase boundary
				case unicode.IsUpper(r) && unicode.IsUpper(prev) && i+1 < len(runes) && unicode.IsLower(runes[i+1]):
					flush() // "NIKNumber" -> "NIK", "Number"
				}
			}
			cur = append(cur, r)
		default:
			flush()
		}
	}
	flush()
	out := make([]string, 0, len(raw))
	for _, t := range raw {
		if vocabulary[t] || len(t) < 4 {
			out = append(out, t)
			continue
		}
		if parts := segment(t); parts != nil {
			out = append(out, parts...)
		} else {
			out = append(out, t)
		}
	}
	return out
}

// shortPieces are the only words of fewer than four letters a glued word may be split
// into. Other short words ("sim", "pan", "lat") would make ordinary words such as
// "simpan" (save) look like identifiers.
var shortPieces = map[string]bool{
	"no": true, "nmr": true, "tgl": true, "id": true, "hp": true, "nik": true, "ktp": true, "kk": true,
	"ip": true, "dob": true, "rek": true, "kis": true, "kpj": true, "nip": true, "nim": true, "tax": true,
	"ibu": true, "of": true, "wa": true,
}

// segment splits a word into known words, preferring the fewest pieces; nil when the
// whole word cannot be covered.
func segment(w string) []string {
	n := len(w)
	if n > 48 {
		return nil
	}
	best := make([]int, n+1) // best[i] = fewest pieces covering w[:i]; -1 = impossible
	prev := make([]int, n+1)
	for i := 1; i <= n; i++ {
		best[i] = -1
	}
	for i := 1; i <= n; i++ {
		for j := 0; j < i; j++ {
			piece := w[j:i]
			if best[j] < 0 || len(piece) < 2 || !vocabulary[piece] || (len(piece) < 4 && !shortPieces[piece]) {
				continue
			}
			if best[i] < 0 || best[j]+1 < best[i] {
				best[i] = best[j] + 1
				prev[i] = j
			}
		}
	}
	if best[n] < 2 {
		return nil
	}
	parts := make([]string, best[n])
	for i, k := n, best[n]-1; i > 0; k-- {
		parts[k] = w[prev[i]:i]
		i = prev[i]
	}
	return parts
}

// nameRule matches when any of its phrases appears as consecutive tokens.
type nameRule struct {
	cat     Category
	conf    float64
	phrases [][]string
	// unless lists tokens that veto the rule when present anywhere in the name.
	unless []string
}

func phrases(list ...string) [][]string {
	out := make([][]string, 0, len(list))
	for _, p := range list {
		out = append(out, strings.Fields(p))
	}
	return out
}

// nonPerson are words that make a "name", "photo" or "address" belong to something that
// is not a person (a product, a branch, a server, a table).
var nonPerson = []string{
	"product", "produk", "company", "perusahaan", "cabang", "branch", "bank", "file", "filename", "table", "tabel",
	"host", "hostname", "server", "db", "database", "schema", "column", "kolom", "field", "app", "aplikasi", "device",
	"perangkat", "menu", "role", "group", "grup", "category", "kategori", "item", "barang", "toko", "store", "shop",
	"merchant", "program", "project", "proyek", "event", "acara", "campaign", "kampanye", "city", "kota", "province",
	"provinsi", "department", "departemen", "divisi", "division", "unit", "jabatan", "position", "job", "title",
	"sheet", "tag", "label", "type", "tipe", "jenis", "status", "kode", "code", "sekolah", "school", "universitas",
	"university", "instansi", "institution", "organisasi", "organization", "org", "brand", "merk", "model", "plan",
	"paket", "package", "layanan", "service", "supplier", "pemasok", "queue", "task", "method", "function", "class",
	"module", "modul", "key", "param", "parameter", "variable", "attribute", "atribut", "domain", "region", "wilayah",
	"area", "country", "negara", "currency", "web", "site", "url", "mac", "wallet", "contract", "kontrak", "street",
	"jalan", "building", "gedung", "office", "kantor", "warehouse", "gudang", "bucket", "folder", "directory",
	"index", "view", "report", "laporan", "template", "document", "dokumen", "region", "zone", "cluster", "node",
}

// metaSuffix are last words that make a column describe a value instead of holding it
// ("email_verified_at", "phone_type", "address_id").
var metaSuffix = map[string]bool{
	"verified": true, "verification": true, "verify": true, "type": true, "types": true, "status": true,
	"flag": true, "flags": true, "count": true, "cnt": true, "template": true, "format": true, "enabled": true,
	"disabled": true, "at": true, "on": true, "sent": true, "required": true, "visible": true, "visibility": true,
	"opt": true, "optin": true, "optout": true, "valid": true, "validated": true, "confirmed": true,
	"confirmation": true, "changed": true, "updated": true, "created": true, "id": true, "ids": true, "uuid": true,
	"key": true, "fk": true, "ref": true, "length": true, "len": true, "label": true, "domain": true,
	"provider": true, "prefix": true, "suffix": true, "regex": true, "pattern": true, "policy": true,
	"setting": true, "settings": true, "preference": true, "preferences": true, "config": true, "otp": true,
	"token": true, "version": true, "total": true, "max": true, "min": true, "limit": true,
}

// flagPrefix are first words of boolean and counter columns ("is_email_verified",
// "has_npwp", "jumlah_nasabah").
var flagPrefix = map[string]bool{
	"is": true, "has": true, "can": true, "allow": true, "allowed": true, "show": true, "enable": true,
	"use": true, "should": true, "need": true, "needs": true, "must": true, "jumlah": true, "total": true,
	"count": true,
}

// businessAddress are words that make an address belong to an organization or a machine.
var businessAddress = []string{
	"product", "produk", "company", "perusahaan", "cabang", "branch", "toko", "store", "merchant", "server",
	"host", "web", "site", "url", "mac", "wallet", "contract", "kontrak", "warehouse", "gudang", "office",
	"kantor", "email", "ip",
}

// rules are checked in order; the first match wins. Confidence is a heuristic: a phrase
// that can only mean the category scores high, a short or ambiguous word scores lower.
var rules = []nameRule{
	// Identifiers that look like a national ID word but are not.
	{EmployeeID, 0.8, phrases("nik karyawan", "nik pegawai", "nik employee", "employee nik", "nik staff", "nip",
		"nrp", "employee id", "employee number", "employee no", "emp id", "emp no", "nomor induk pegawai",
		"nomor pegawai", "no pegawai", "id karyawan", "no karyawan", "nomor karyawan", "id pegawai"), nil},
	{StudentID, 0.8, phrases("nisn", "nim", "nomor induk siswa", "nomor induk mahasiswa", "student id", "student number"), nil},
	// Specific personal data (UU PDP Art. 4(2) as classified by the platform).
	{KK, 0.95, phrases("no kk", "nomor kk", "nmr kk", "kartu keluarga", "family card", "kk number"), nil},
	{NIK, 0.95, phrases("nik", "ktp", "ektp", "e ktp", "national id", "id card", "identity number", "identity card",
		"nomor induk kependudukan", "nik ktp"), nil},
	{NIK, 0.7, phrases("nomor identitas", "no identitas", "identitas"), nil},
	{KK, 0.7, phrases("kk"), nil},
	{NPWP, 0.95, phrases("npwp", "tax id", "tax number", "nomor pajak", "nomor pokok wajib pajak", "taxpayer id"), nil},
	{Passport, 0.9, phrases("passport", "paspor"), nil},
	{DrivingLicense, 0.9, phrases("no sim", "nomor sim", "sim number", "driving license", "driver license",
		"driving licence", "driver licence", "surat izin mengemudi", "drivers license"),
		[]string{"card", "kartu", "operator", "provider", "slot"}},
	{BPJSKetenagakerjaan, 0.9, phrases("bpjs ketenagakerjaan", "bpjs tk", "bpjstk", "kpj", "jamsostek"), nil},
	{BPJSKesehatan, 0.9, phrases("bpjs kesehatan", "bpjs", "jkn", "no kis", "nomor kis"), nil},
	{Health, 0.85, phrases("diagnosis", "diagnosa", "diagnose", "medical", "medis", "kesehatan", "penyakit", "disease",
		"illness", "allergy", "alergi", "symptom", "gejala", "rekam medis", "medical record", "blood type",
		"golongan darah", "riwayat penyakit", "disability", "disabilitas", "kehamilan", "pregnancy", "icd"), nil},
	{Health, 0.6, phrases("health"), []string{"check", "service", "server", "endpoint", "url", "probe", "monitor"}},
	{Biometric, 0.9, phrases("fingerprint", "biometric", "biometrik", "retina", "iris", "sidik jari", "face id",
		"face template", "face embedding", "voiceprint", "face encoding"), nil},
	{Genetic, 0.9, phrases("dna", "genetic", "genetik", "genome"), nil},
	{Religion, 0.9, phrases("religion", "agama", "kepercayaan", "faith"), []string{"tingkat", "level", "skor", "score"}},
	{CardNumber, 0.9, phrases("card number", "card no", "card num", "credit card", "debit card", "no kartu",
		"nomor kartu", "kartu kredit", "kartu debit", "cvv", "cvc", "cvv2", "ccnum", "cc number", "cc no", "pan"),
		[]string{"keluarga", "family", "sim", "iccid"}},
	{BankAccount, 0.9, phrases("account number", "account no", "account num", "acct no", "acctno", "bank account",
		"no rek", "no rekening", "nomor rekening", "rekening", "norek", "iban", "accno", "acc no"), nil},
	{Financial, 0.8, phrases("salary", "gaji", "wage", "wages", "upah", "income", "penghasilan", "compensation",
		"kompensasi", "tunjangan", "take home pay", "thp", "credit score", "skor kredit", "slik"), nil},
	{Financial, 0.5, phrases("bonus", "pendapatan"), []string{"point", "points", "poin", "product", "produk"}},
	{CriminalRecord, 0.9, phrases("criminal", "kriminal", "arrest", "conviction", "skck", "catatan kepolisian",
		"pidana", "narapidana"), nil},
	// General personal data.
	{MotherMaidenName, 0.95, phrases("nama ibu", "ibu kandung", "mother maiden", "maiden name", "mother name",
		"mothers maiden name", "nama gadis ibu"), nil},
	{IPAddress, 0.9, phrases("ip address", "ip addr", "ipaddress", "client ip", "remote addr", "remote ip",
		"remote address", "ipv4", "ipv6", "source ip", "src ip", "login ip", "user ip"), nil},
	{IPAddress, 0.7, phrases("ip"), nil},
	{Username, 0.8, phrases("username", "user name", "login id", "user login", "login name"), nil},
	{Username, 0.6, phrases("login"), nil},
	{Username, 0.5, phrases("user id", "userid"), nil},
	{Email, 0.95, phrases("email", "e mail", "surel", "email address", "emailaddress"), nil},
	{Email, 0.6, phrases("mail"), []string{"post", "postal", "pos", "mailing", "server", "host"}},
	{Phone, 0.9, phrases("phone", "telepon", "telp", "tlp", "telephone", "ponsel", "handphone", "no hp", "nomor hp",
		"whatsapp", "msisdn", "cellphone", "cell phone", "phone number", "nomor telepon", "no telp", "hp"),
		[]string{"app", "version", "os", "platform", "device", "model"}},
	{Phone, 0.6, phrases("mobile", "cell", "wa", "fax"), []string{"app", "version", "os", "platform", "device", "model", "banking", "network", "number_of"}},
	{BirthDate, 0.9, phrases("dob", "birthdate", "birth date", "birthday", "date of birth", "tanggal lahir",
		"tgl lahir", "tempat lahir", "birth place", "birthplace", "place of birth", "lahir", "birth", "ttl"), nil},
	{BirthDate, 0.6, phrases("born"), nil},
	{Address, 0.9, phrases("address", "alamat", "addr", "domisili", "kodepos", "kode pos", "zipcode", "zip code",
		"postal code", "postcode", "rt rw"), businessAddress},
	{Address, 0.6, phrases("street", "jalan", "kelurahan", "desa", "kecamatan", "kabupaten", "kota", "zip",
		"postal"), []string{"product", "produk", "company", "perusahaan", "cabang", "branch", "toko", "store",
		"merchant", "server", "warehouse", "gudang", "office", "kantor", "code", "kode", "id", "name", "nama"}},
	{Location, 0.8, phrases("latitude", "longitude", "geolocation", "geo location", "gps", "coordinate",
		"coordinates", "koordinat"), nil},
	{Location, 0.6, phrases("lat", "lng", "lon"), nil},
	{Location, 0.5, phrases("location", "lokasi"), []string{"storage", "file", "server", "warehouse", "gudang",
		"product", "produk", "branch", "cabang", "office", "kantor", "rack", "rak", "bucket", "folder", "url"}},
	{Gender, 0.9, phrases("gender", "sex", "jenis kelamin", "kelamin"), nil},
	{Gender, 0.6, phrases("jk"), nil},
	{MaritalStatus, 0.8, phrases("marital status", "marital", "status perkawinan", "status pernikahan",
		"status kawin", "perkawinan", "pernikahan", "nikah", "menikah"), nil},
	{Nationality, 0.8, phrases("nationality", "kewarganegaraan", "citizenship", "warga negara", "ethnicity"), nil},
	{Nationality, 0.6, phrases("suku"), []string{"bunga", "cadang"}},
	{Photo, 0.8, phrases("photo", "foto", "avatar", "selfie", "profile picture", "profile image", "profile photo",
		"pas foto"), nonPerson},
	{Photo, 0.6, phrases("picture"), nonPerson},
	{VehiclePlate, 0.8, phrases("nopol", "no polisi", "nomor polisi", "plat nomor", "license plate",
		"plate number", "nomor kendaraan", "no kendaraan"), nil},
	{PersonName, 0.9, phrases("full name", "fullname", "first name", "firstname", "last name", "lastname",
		"middle name", "given name", "surname", "nama lengkap", "nama depan", "nama belakang", "nama panggilan",
		"nickname", "display name", "account name", "nama rekening", "card holder", "cardholder", "holder name"), nonPerson},
	{PersonName, 0.7, phrases("name", "nama"), nonPerson},
}

// vocabulary holds every rule word plus common qualifiers, so that a name written without
// separators can be split ("customeremail" -> "customer", "email").
var vocabulary = func() map[string]bool {
	v := map[string]bool{}
	for _, r := range rules {
		for _, p := range r.phrases {
			for _, w := range p {
				v[w] = true
			}
		}
	}
	for _, w := range []string{"no", "nomor", "nmr", "num", "number", "id", "kode", "code", "tgl", "tanggal",
		"nama", "customer", "nasabah", "pelanggan", "user", "member", "anggota", "employee", "karyawan",
		"pegawai", "patient", "pasien", "student", "siswa", "data", "info", "primary", "secondary", "home",
		"rumah", "work", "kerja", "personal", "pribadi", "contact", "kontak", "debitur", "debtor", "owner",
		"pemilik", "ahli", "waris", "wali", "guardian", "ibu", "ayah", "father", "mother", "suami", "istri",
		"spouse", "anak", "child", "date", "of", "place", "tempat", "card", "kartu", "bank", "account", "akun",
		"holder", "pemegang", "address", "addr", "verified", "masked", "hash", "encrypted", "enc", "raw", "old",
		"new", "lama", "baru", "valid", "status", "type", "tipe", "jenis", "is", "has", "last", "first",
		"utama", "darurat", "emergency", "billing", "shipping", "kirim", "pengiriman", "tagihan", "ktp",
		"sim", "line", "office", "kantor", "company", "perusahaan", "product", "produk", "branch", "cabang",
		"file", "table", "log", "at", "on", "by", "to", "from", "count", "total", "max", "min"} {
		v[w] = true
	}
	return v
}()

// ClassifyName reports the personal-data category a column or field name suggests.
func ClassifyName(name string) (NameMatch, bool) {
	tokens := Tokens(name)
	if len(tokens) == 0 || flagPrefix[tokens[0]] {
		return NameMatch{}, false
	}
	present := make(map[string]bool, len(tokens))
	for _, t := range tokens {
		present[t] = true
	}
	for _, r := range rules {
		end, ok := matchPhrases(tokens, r.phrases)
		if !ok {
			continue
		}
		if vetoed(present, r.unless) {
			continue
		}
		// A last word such as "_id" or "_verified_at" describes the value, unless the
		// matched phrase itself ends the name ("national_id", "user_id"). Biometric
		// templates are the data itself ("fingerprint_template").
		if last := tokens[len(tokens)-1]; metaSuffix[last] && end != len(tokens) && r.cat != Biometric {
			continue
		}
		return NameMatch{Category: r.cat, Confidence: r.conf}, true
	}
	return NameMatch{}, false
}

// matchPhrases returns the end index (exclusive) of the first phrase found in tokens.
func matchPhrases(tokens []string, list [][]string) (int, bool) {
	for _, p := range list {
		for i := 0; i+len(p) <= len(tokens); i++ {
			ok := true
			for j, w := range p {
				if tokens[i+j] != w {
					ok = false
					break
				}
			}
			if ok {
				return i + len(p), true
			}
		}
	}
	return 0, false
}

func vetoed(present map[string]bool, unless []string) bool {
	for _, u := range unless {
		if present[u] {
			return true
		}
	}
	return false
}
