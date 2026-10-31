package detect

import (
	"encoding/json"
	"strings"
	"testing"
)

// luhnComplete appends the Luhn check digit to payload. Test identifiers are generated,
// never copied from real people.
func luhnComplete(payload string) string {
	for d := byte('0'); d <= '9'; d++ {
		if Luhn(payload + string(d)) {
			return payload + string(d)
		}
	}
	panic("no check digit")
}

// Synthetic identifiers used across the tests.
var (
	nikMale   = "3171012303900001" // DKI, 23-03-1990
	nikFemale = "3171016303900002" // day 23 + 40
	npwp15    = luhnComplete("01234567") + "012000"
	visa      = "4111111111111111"
	amex      = "378282246310005"
)

func TestValidators(t *testing.T) {
	cases := []struct {
		name string
		fn   func(string) bool
		in   string
		want bool
	}{
		{"nik male", ValidNIK, nikMale, true},
		{"nik female", ValidNIK, nikFemale, true},
		{"nik day 32", ValidNIK, "3171013203900001", false},
		{"nik day 72", ValidNIK, "3171017203900001", false},
		{"nik bad province", ValidNIK, "9971012303900001", false},
		{"nik month 13", ValidNIK, "3171012313900001", false},
		{"nik 31 february", ValidNIK, "3171013102900001", false},
		{"nik zero sequence", ValidNIK, "3171012303900000", false},
		{"nik zero regency", ValidNIK, "3100012303900001", false},
		{"nik all same", ValidNIK, "1111111111111111", false},
		{"nik 15 digits", ValidNIK, "317101230390000", false},
		{"nik letters", ValidNIK, "31710123039000AB", false},
		{"kk", ValidKK, nikMale, true},
		{"kk rejects woman's day", ValidKK, nikFemale, false},
		{"npwp15", ValidNPWP15, npwp15, true},
		{"npwp15 bad check digit", ValidNPWP15, "012345670012000", false},
		{"npwp16 entity", ValidNPWP16, "0" + npwp15, true},
		{"npwp16 not starting with zero", ValidNPWP16, "1" + npwp15, false},
		{"bpjs kesehatan", LooksBPJSKesehatan, "0001234567890", true},
		{"bpjs kesehatan prefix", LooksBPJSKesehatan, "1001234567890", false},
		{"bpjs kesehatan zeros", LooksBPJSKesehatan, "0000000000000", false},
		{"visa", ValidCard, visa, true},
		{"mastercard", ValidCard, "5555555555554444", true},
		{"mastercard 2-series", ValidCard, "2223003122003222", true},
		{"amex", ValidCard, amex, true},
		{"jcb", ValidCard, "3530111333300000", true},
		{"discover", ValidCard, "6011111111111117", true},
		{"card bad luhn", ValidCard, "4111111111111112", false},
		{"card unknown issuer", ValidCard, luhnComplete("999999999999999"), false},
		{"card wrong length for amex", ValidCard, luhnComplete("3782822463100"), false},
		{"passport", LooksPassport, "B1234567", true},
		{"passport two letters", LooksPassport, "XA123456", true},
		{"passport no letters", LooksPassport, "12345678", false},
		{"passport too long", LooksPassport, "B12345678", false},
		{"bank account", LooksBankAccount, "1234567890", true},
		{"bank account short", LooksBankAccount, "123456789", false},
		{"phone mobile", ValidPhone, "081234567890", true},
		{"phone mobile +62", ValidPhone, "+62 812-3456-7890", true},
		{"phone mobile 62", ValidPhone, "6281234567890", true},
		{"phone mobile grouped", ValidPhone, "0812 3456 7890", true},
		{"phone landline paren", ValidPhone, "(021) 5550123", true},
		{"phone landline +62", ValidPhone, "+62 21 5550123", true},
		{"phone landline bare", ValidPhone, "0215550123", false},
		{"phone toll free", ValidPhone, "08001234567", false},
		{"phone other country", ValidPhone, "+65 8123 4567", false},
		{"phone too long", ValidPhone, "08123456789012", false},
		{"email", ValidEmail, "budi.santoso@example.co.id", true},
		{"email plus", ValidEmail, "a+tag@mail.example", true},
		{"email no tld", ValidEmail, "a@b", false},
		{"email short tld", ValidEmail, "a@b.c", false},
		{"email double dot", ValidEmail, "a..b@mail.example", false},
		{"email two ats", ValidEmail, "a@b@mail.example", false},
	}
	for _, c := range cases {
		if got := c.fn(c.in); got != c.want {
			t.Errorf("%s: %q = %v, want %v", c.name, c.in, got, c.want)
		}
	}
}

func TestFormattedNPWPIsAcceptedWithoutCheckDigit(t *testing.T) {
	if !formattedNPWP("01.234.567.0-012.000") {
		t.Fatal("printed NPWP format must be recognized")
	}
	if formattedNPWP("01.234.567.0-012") || formattedNPWP("012.34.567.0-012.000") {
		t.Fatal("wrong grouping must not count as NPWP")
	}
}

func TestClassifyValueUsesContext(t *testing.T) {
	cases := []struct {
		value string
		hints Hints
		want  Category // "" = no match
	}{
		{nikMale, 0, NIK},
		{nikMale, HintKK, KK},
		{nikMale, HintKK | HintNIK, NIK},
		{visa, 0, CardNumber},
		{"4111 1111 1111 1111", 0, CardNumber},
		{"3782 822463 10005", 0, CardNumber},
		{npwp15, 0, NPWP},
		{npwp15, HintNPWP, NPWP},
		{"01.234.567.0-012.000", 0, NPWP},
		{"0" + npwp15, HintNPWP, NPWP},
		{"0001234567890", 0, BPJSKesehatan},
		{"0001234567890", HintBPJSKes, BPJSKesehatan},
		{"12345678901", HintBPJSTK, BPJSKetenagakerjaan},
		{"12345678901", 0, ""},
		{"B1234567", HintPassport, Passport},
		{"B1234567", 0, ""},
		{"1234567890", HintBank, BankAccount},
		{"1234567890", 0, ""},
		{"081234567890", 0, Phone},
		{"081234567890", HintBank, BankAccount},
		{"081234567890", HintBank | HintPhone, Phone},
		{"budi@example.co.id", 0, Email},
		{"12/05/1990", 0, ""},
		{"Rp 1.500.000", 0, ""},
		{"abc", 0, ""},
		{"", 0, ""},
	}
	for _, c := range cases {
		m, ok := ClassifyValue(c.value, c.hints)
		got := Category("")
		if ok {
			got = m.Category
		}
		if got != c.want {
			t.Errorf("ClassifyValue(%q, %b) = %q, want %q", c.value, c.hints, got, c.want)
		}
	}
}

func TestHintsFromWords(t *testing.T) {
	if h := HintsFromWords([]string{"kartu", "keluarga"}); !h.Has(HintKK) || h.Has(HintCard) {
		t.Fatalf("kartu keluarga is the family card: %b", h)
	}
	if h := HintsFromWords([]string{"user", "account"}); h.Has(HintBank) {
		t.Fatalf("a user account is not a bank account: %b", h)
	}
	if h := HintsFromWords([]string{"account", "number"}); !h.Has(HintBank) {
		t.Fatalf("account number names a bank account: %b", h)
	}
	if h := HintsFromWords([]string{"bpjs", "tk"}); !h.Has(HintBPJSTK) || h.Has(HintBPJSKes) {
		t.Fatalf("bpjs tk is the employment programme: %b", h)
	}
}

func TestTokens(t *testing.T) {
	cases := map[string]string{
		"nomor_ktp":         "nomor ktp",
		"NoKTP":             "no ktp",
		"customerEmail":     "customer email",
		"customeremail":     "customer email",
		"TGL_LAHIR":         "tgl lahir",
		"tgllahir":          "tgl lahir",
		"NIKNumber":         "nik number",
		"email2":            "email 2",
		"namaibukandung":    "nama ibu kandung",
		"tanggal_simpan":    "tanggal simpan",
		"company":           "company",
		"address-line-1":    "address line 1",
		"Nomor Rekening":    "nomor rekening",
		"PhoneNumber":       "phone number",
		"simpanan_berjangka": "simpanan berjangka",
	}
	for in, want := range cases {
		if got := strings.Join(Tokens(in), " "); got != want {
			t.Errorf("Tokens(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestClassifyName(t *testing.T) {
	cases := map[string]Category{
		// Identifiers.
		"nik": NIK, "NIK": NIK, "nomor_ktp": NIK, "noktp": NIK, "national_id": NIK, "id_card": NIK,
		"nik_nasabah": NIK, "nomor_identitas": NIK,
		"no_kk": KK, "nomor_kartu_keluarga": KK, "kk": KK,
		"npwp": NPWP, "tax_id": NPWP, "NPWP_Number": NPWP,
		"passport_no": Passport, "no_paspor": Passport,
		"no_sim": DrivingLicense, "driver_license_number": DrivingLicense,
		"no_bpjs": BPJSKesehatan, "bpjs_kesehatan": BPJSKesehatan, "no_kpj": BPJSKetenagakerjaan,
		"bpjs_tk": BPJSKetenagakerjaan,
		"card_number": CardNumber, "cc_no": CardNumber, "nomor_kartu": CardNumber, "cvv": CardNumber, "pan": CardNumber,
		"account_number": BankAccount, "no_rekening": BankAccount, "norek": BankAccount, "iban": BankAccount,
		// Other specific data.
		"diagnosis": Health, "riwayat_penyakit": Health, "golongan_darah": Health,
		"fingerprint_template": Biometric, "agama": Religion, "religion": Religion,
		"gaji_pokok": Financial, "salary": Financial, "skck_number": CriminalRecord,
		// General data.
		"nama_lengkap": PersonName, "first_name": PersonName, "customer_name": PersonName, "nama": PersonName,
		"account_name": PersonName, "display_name": PersonName,
		"nama_ibu_kandung": MotherMaidenName, "mother_maiden_name": MotherMaidenName,
		"email": Email, "customer_email": Email, "EmailAddress": Email,
		"phone": Phone, "no_hp": Phone, "nohp": Phone, "PhoneNumber": Phone, "whatsapp": Phone, "telp_rumah": Phone,
		"tanggal_lahir": BirthDate, "tgl_lahir": BirthDate, "dob": BirthDate, "tempat_lahir": BirthDate,
		"alamat": Address, "address_line_1": Address, "kode_pos": Address, "alamat_rumah": Address,
		"ip_address": IPAddress, "client_ip": IPAddress, "last_login_ip": IPAddress,
		"latitude": Location, "lng": Location,
		"gender": Gender, "jenis_kelamin": Gender, "sex": Gender,
		"username": Username, "user_name": Username,
		"foto_profil": Photo, "avatar": Photo,
		"status_perkawinan": MaritalStatus, "kewarganegaraan": Nationality,
		"nik_karyawan": EmployeeID, "nip": EmployeeID, "nisn": StudentID,
		"nopol": VehiclePlate,
	}
	for name, want := range cases {
		m, ok := ClassifyName(name)
		if !ok || m.Category != want {
			t.Errorf("ClassifyName(%q) = %+v %v, want %q", name, m, ok, want)
		}
	}
	notPII := []string{
		"id", "created_at", "updated_at", "status", "amount", "product_name", "nama_produk", "nama_cabang",
		"branch_name", "file_name", "table_name", "hostname", "company_name", "nama_perusahaan",
		"email_verified_at", "is_email_verified", "phone_type", "address_id", "customer_id", "simpanan",
		"tanggal_simpan", "simulation", "company", "panel", "translation", "jumlah_nasabah", "health_check_url",
		"tingkat_kepercayaan", "suku_bunga", "nama_bank", "mobile_app_version", "sim_card_number", "server_location",
		"description", "notes", "total", "nikah_count", "email_template", "mac_address", "alamat_kantor_cabang",
	}
	for _, name := range notPII {
		if m, ok := ClassifyName(name); ok {
			t.Errorf("ClassifyName(%q) = %+v, want no personal data", name, m)
		}
	}
}

func TestEveryCategoryHasAPDPClass(t *testing.T) {
	for _, c := range All() {
		if pdp := PDPOf(c); pdp != PDPSpecific && pdp != PDPGeneral {
			t.Errorf("category %s has PDP class %q", c, pdp)
		}
	}
	for _, r := range rules {
		if _, ok := Lookup(r.cat); !ok {
			t.Errorf("rule category %s is not registered", r.cat)
		}
	}
}

const sampleText = `Data nasabah (contoh sintetis)
Nama: Budi, NIK: 3171012303900001, HP: 0812-3456-7890, email budi.santoso@example.co.id
NIK istri 3171016303900002 telp +62 812 1111 2222
Kartu kredit 4111 1111 1111 1111 dan NPWP 01.234.567.0-012.000
No. paspor: B1234567, no rekening 1234567890
Kode transaksi a3171012303900001b, versi 1.2.3, total Rp 1.500.000, tanggal 12/05/1990.
Hash 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08
Kontak: 0812345678.budi@example.co.id`

func countsOf(t *testing.T, text string, chunk int) map[Category]int {
	t.Helper()
	tc := NewTextCounter(0)
	for i := 0; i < len(text); i += chunk {
		end := min(len(text), i+chunk)
		if _, err := tc.Write([]byte(text[i:end])); err != nil {
			t.Fatal(err)
		}
	}
	_ = tc.Close()
	return tc.Counts()
}

func TestTextCounterCountsIdentifiers(t *testing.T) {
	got := countsOf(t, sampleText, len(sampleText))
	want := map[Category]int{NIK: 2, Phone: 2, Email: 2, CardNumber: 1, NPWP: 1, Passport: 1, BankAccount: 1}
	for c, n := range want {
		if got[c] != n {
			t.Errorf("%s = %d, want %d (all: %v)", c, got[c], n, got)
		}
	}
	for c, n := range got {
		if _, ok := want[c]; !ok {
			t.Errorf("unexpected %s = %d", c, n)
		}
	}
}

func TestTextCounterIsIndependentOfChunking(t *testing.T) {
	whole := countsOf(t, sampleText, len(sampleText))
	for _, chunk := range []int{1, 2, 7, 13, 64, 401, 1000} {
		got := countsOf(t, sampleText, chunk)
		if len(got) != len(whole) {
			t.Fatalf("chunk %d: %v, want %v", chunk, got, whole)
		}
		for c, n := range whole {
			if got[c] != n {
				t.Fatalf("chunk %d: %s = %d, want %d", chunk, c, got[c], n)
			}
		}
	}
}

func TestTextCounterHandlesLongInput(t *testing.T) {
	var b strings.Builder
	for i := 0; i < 2000; i++ {
		b.WriteString("baris ")
		b.WriteString(nikMale)
		b.WriteString(" ; ")
	}
	got := countsOf(t, b.String(), 4096)
	if got[NIK] != 2000 {
		t.Fatalf("NIK = %d, want 2000", got[NIK])
	}
	digits := strings.Repeat("1234567890", 500) // one long run is not an identifier
	if got := countsOf(t, digits, 300); len(got) != 0 {
		t.Fatalf("a long digit run must not match: %v", got)
	}
}

func TestTextCounterRespectsTheByteLimit(t *testing.T) {
	tc := NewTextCounter(20)
	n, _ := tc.WriteString("aaaaaaaaaaaaaaaaaaaa " + nikMale)
	_ = tc.Close()
	if n != 21+len(nikMale) || !tc.Truncated() || tc.Counts()[NIK] != 0 {
		t.Fatalf("n=%d truncated=%v counts=%v", n, tc.Truncated(), tc.Counts())
	}
}

func TestColumnSamplerFindsDataTheNameHides(t *testing.T) {
	s := NewColumnSampler("keterangan")
	for i := 0; i < 10; i++ {
		s.Add("hubungi nasabah di 0812-3456-7890 sebelum jam 5 sore, pesan sudah dikirim lewat email", false)
	}
	s.Add("", true)
	res := s.Result(DefaultThresholds)
	if !res.Detected || res.Category != Phone || res.Sampled != 11 || res.NonEmpty != 10 {
		t.Fatalf("%+v", res)
	}
	f := Combine("keterangan", &res)
	if !f.IsPII || f.Category != Phone || f.Source != SourceContent || !f.Shadow || f.PDP != PDPGeneral {
		t.Fatalf("%+v", f)
	}
}

func TestColumnSamplerAgreesWithTheName(t *testing.T) {
	s := NewColumnSampler("nik")
	for i := 0; i < 20; i++ {
		s.Add(nikMale, false)
	}
	res := s.Result(DefaultThresholds)
	f := Combine("nik", &res)
	if !f.IsPII || f.Category != NIK || f.Source != SourceNameContent || f.Shadow || f.PDP != PDPSpecific {
		t.Fatalf("%+v", f)
	}
	if res.Protection != ProtectionPlaintext {
		t.Fatalf("protection = %s", res.Protection)
	}
}

func TestColumnSamplerProtectionStates(t *testing.T) {
	masked := NewColumnSampler("nik")
	encrypted := NewColumnSampler("nik")
	mixed := NewColumnSampler("nik")
	for i := 0; i < 5; i++ {
		masked.Add("3171********0001", false)
		encrypted.Add("eyJpdiI6ImFiYyIsInZhbHVlIjoiZGVmIiwibWFjIjoiMTIzIn0=", false)
		mixed.Add(nikMale, false)
		mixed.Add("3171********0001", false)
	}
	if r := masked.Result(DefaultThresholds); r.Protection != ProtectionMasked || r.Detected {
		t.Fatalf("masked: %+v", r)
	}
	if r := encrypted.Result(DefaultThresholds); r.Protection != ProtectionEncrypted || r.Detected {
		t.Fatalf("encrypted: %+v", r)
	}
	if r := mixed.Result(DefaultThresholds); r.Protection != ProtectionMixed {
		t.Fatalf("mixed: %+v", r)
	}
	// A masked NIK column is still a NIK column by its name.
	r := masked.Result(DefaultThresholds)
	if f := Combine("nik", &r); !f.IsPII || f.Category != NIK || f.Source != SourceName {
		t.Fatalf("%+v", f)
	}
}

func TestColumnSamplerThresholds(t *testing.T) {
	s := NewColumnSampler("kode")
	s.Add(nikMale, false)
	s.Add(nikMale, false)
	for i := 0; i < 8; i++ {
		s.Add("ABC", false)
	}
	if r := s.Result(DefaultThresholds); r.Detected {
		t.Fatalf("two matches are below the minimum: %+v", r)
	}
	if r := s.Result(Thresholds{MinMatches: 2, Ratio: 0.2}); !r.Detected || r.Category != NIK {
		t.Fatalf("%+v", r)
	}
	if r := s.Result(Thresholds{MinMatches: 2, Ratio: 0.5}); r.Detected {
		t.Fatalf("20%% is below a 50%% ratio: %+v", r)
	}
}

// TestResultsNeverCarryValues is the data-minimisation guarantee of this package: the
// serialized result of sampling and of text counting holds no sampled value.
func TestResultsNeverCarryValues(t *testing.T) {
	values := []string{nikMale, "budi.santoso@example.co.id", "081234567890", visa, "B1234567"}
	s := NewColumnSampler("data")
	for _, v := range values {
		for i := 0; i < 5; i++ {
			s.Add(v, false)
		}
	}
	res := s.Result(Thresholds{MinMatches: 1, Ratio: 0.01})
	f := Combine("data", &res)
	tc := NewTextCounter(0)
	_, _ = tc.WriteString(sampleText)
	_ = tc.Close()
	raw, _ := json.Marshal(map[string]any{"finding": f, "counts": tc.Counts()})
	for _, v := range append(values, "3171", "0812", "budi") {
		if strings.Contains(string(raw), v) {
			t.Fatalf("result carries %q: %s", v, raw)
		}
	}
}
