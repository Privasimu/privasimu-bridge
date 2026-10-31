// Package detect finds personal data locally: it classifies column names, validates sampled
// values and counts identifiers in text. Nothing in this package stores, returns or logs a
// value; results are categories, counts and confidence only.
package detect

import "sort"

// Category is a stable code for a kind of personal data. Codes are part of the bridge's
// output contracts and never change meaning.
type Category string

// Identifier categories that have value validators.
const (
	NIK                 Category = "nik"                  // Nomor Induk Kependudukan (16 digits)
	KK                  Category = "kk"                   // Kartu Keluarga number (16 digits)
	NPWP                Category = "npwp"                 // tax number (15 digits, or 16 since 2024)
	BPJSKesehatan       Category = "bpjs_kesehatan"       // JKN-KIS card number (13 digits)
	BPJSKetenagakerjaan Category = "bpjs_ketenagakerjaan" // KPJ number (11 digits)
	Phone               Category = "phone"                // Indonesian phone number
	Email               Category = "email"
	CardNumber          Category = "card_number" // payment card (Luhn)
	Passport            Category = "passport"
	BankAccount         Category = "bank_account"
)

// Categories detected from column names only.
const (
	PersonName       Category = "name"
	MotherMaidenName Category = "mother_maiden_name"
	BirthDate        Category = "birth_date"
	Address          Category = "address"
	Gender           Category = "gender"
	Religion         Category = "religion"
	Health           Category = "health"
	Biometric        Category = "biometric"
	Genetic          Category = "genetic"
	Financial        Category = "financial" // salary, income, compensation
	CriminalRecord   Category = "criminal_record"
	DrivingLicense   Category = "driving_license"
	IPAddress        Category = "ip_address"
	Location         Category = "location"
	Username         Category = "username"
	Photo            Category = "photo"
	MaritalStatus    Category = "marital_status"
	Nationality      Category = "nationality"
	EmployeeID       Category = "employee_id"
	StudentID        Category = "student_id"
	VehiclePlate     Category = "vehicle_plate"
)

// PDP categories as used by the Privasimu platform (UU PDP Art. 4): "spesifik" (specific
// personal data) or "umum" (general personal data).
const (
	PDPSpecific = "spesifik"
	PDPGeneral  = "umum"
)

// Info describes a category.
type Info struct {
	// PDP is the UU PDP category the platform stores in pdp_category.
	PDP string
	// Group is a coarse grouping (identity, contact, financial, ...).
	Group string
}

var registry = map[Category]Info{
	NIK:                 {PDPSpecific, "identity"},
	KK:                  {PDPSpecific, "identity"},
	NPWP:                {PDPSpecific, "identity"},
	Passport:            {PDPSpecific, "identity"},
	DrivingLicense:      {PDPSpecific, "identity"},
	BPJSKesehatan:       {PDPSpecific, "health"},
	BPJSKetenagakerjaan: {PDPSpecific, "financial"},
	CardNumber:          {PDPSpecific, "financial"},
	BankAccount:         {PDPSpecific, "financial"},
	Financial:           {PDPSpecific, "financial"},
	Health:              {PDPSpecific, "health"},
	Biometric:           {PDPSpecific, "biometric"},
	Genetic:             {PDPSpecific, "biometric"},
	Religion:            {PDPSpecific, "belief"},
	CriminalRecord:      {PDPSpecific, "legal"},
	PersonName:          {PDPGeneral, "identity"},
	MotherMaidenName:    {PDPGeneral, "identity"},
	BirthDate:           {PDPGeneral, "demographic"},
	Gender:              {PDPGeneral, "demographic"},
	MaritalStatus:       {PDPGeneral, "demographic"},
	Nationality:         {PDPGeneral, "demographic"},
	Email:               {PDPGeneral, "contact"},
	Phone:               {PDPGeneral, "contact"},
	Address:             {PDPGeneral, "contact"},
	IPAddress:           {PDPGeneral, "online"},
	Location:            {PDPGeneral, "location"},
	Username:            {PDPGeneral, "online"},
	Photo:               {PDPGeneral, "identity"},
	EmployeeID:          {PDPGeneral, "identity"},
	StudentID:           {PDPGeneral, "identity"},
	VehiclePlate:        {PDPGeneral, "identity"},
}

// Lookup returns the description of a category.
func Lookup(c Category) (Info, bool) {
	info, ok := registry[c]
	return info, ok
}

// PDPOf returns the UU PDP category of c, or "" for an unknown category.
func PDPOf(c Category) string { return registry[c].PDP }

// All returns every category code, sorted.
func All() []Category {
	out := make([]Category, 0, len(registry))
	for c := range registry {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// ValueCategories are the categories that value validators can confirm.
func ValueCategories() []Category {
	return []Category{NIK, KK, NPWP, BPJSKesehatan, BPJSKetenagakerjaan, Phone, Email, CardNumber, Passport, BankAccount}
}
