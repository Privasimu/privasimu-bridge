package detect

import "strings"

// Validators for Indonesian and international identifiers. Each takes the identifier with
// separators already removed unless stated otherwise, and only answers yes or no.

// provinceCodes are the two-digit province codes that start a NIK or KK number
// (Kemendagri region codes, including the Papua provinces created in 2022).
var provinceCodes = map[string]bool{
	"11": true, "12": true, "13": true, "14": true, "15": true, "16": true, "17": true, "18": true, "19": true,
	"21": true,
	"31": true, "32": true, "33": true, "34": true, "35": true, "36": true,
	"51": true, "52": true, "53": true,
	"61": true, "62": true, "63": true, "64": true, "65": true,
	"71": true, "72": true, "73": true, "74": true, "75": true, "76": true,
	"81": true, "82": true,
	"91": true, "92": true, "93": true, "94": true, "95": true, "96": true, "97": true,
}

func allDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

func allSame(s string) bool {
	for i := 1; i < len(s); i++ {
		if s[i] != s[0] {
			return false
		}
	}
	return true
}

func twoDigits(s string) int { return int(s[0]-'0')*10 + int(s[1]-'0') }

var daysInMonth = [13]int{0, 31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31}

// regionAndDate checks the shared structure of NIK and KK: province, regency and district
// codes, a day and month (the day of a woman's NIK is increased by 40) and a non-zero
// sequence number.
func regionAndDate(d string, allowFemaleDay bool) bool {
	if len(d) != 16 || !allDigits(d) || allSame(d) {
		return false
	}
	if !provinceCodes[d[0:2]] || d[2:4] == "00" || d[4:6] == "00" {
		return false
	}
	day, month := twoDigits(d[6:8]), twoDigits(d[8:10])
	if allowFemaleDay && day > 40 {
		day -= 40
	}
	if month < 1 || month > 12 || day < 1 || day > daysInMonth[month] {
		return false
	}
	return d[12:16] != "0000"
}

// ValidNIK reports whether d (16 digits) has the structure of a NIK: region codes, a
// birth date (day + 40 for women) and a sequence number.
func ValidNIK(d string) bool { return regionAndDate(d, true) }

// ValidKK reports whether d (16 digits) has the structure of a family card number: region
// codes, an issue date and a sequence number. Every valid KK number is also shaped like a
// man's NIK, so a KK is only told apart by context.
func ValidKK(d string) bool { return regionAndDate(d, false) }

// Luhn reports whether the digit string passes the Luhn (mod 10) check.
func Luhn(d string) bool {
	if len(d) < 2 || !allDigits(d) {
		return false
	}
	sum := 0
	double := false
	for i := len(d) - 1; i >= 0; i-- {
		n := int(d[i] - '0')
		if double {
			n *= 2
			if n > 9 {
				n -= 9
			}
		}
		sum += n
		double = !double
	}
	return sum%10 == 0
}

// ValidNPWP15 reports whether d is a 15-digit NPWP whose ninth digit is a Luhn check digit
// over the first eight. DJP does not publish the algorithm; the Luhn check is the one used
// by common validators, so a raw 15-digit number is only accepted when it passes.
func ValidNPWP15(d string) bool {
	return len(d) == 15 && allDigits(d) && !allSame(d) && Luhn(d[:9])
}

// ValidNPWP16 reports whether d is a 16-digit NPWP of an entity: "0" followed by a valid
// 15-digit NPWP. The 16-digit NPWP of a person is their NIK and is reported as NIK.
func ValidNPWP16(d string) bool {
	return len(d) == 16 && d[0] == '0' && ValidNPWP15(d[1:])
}

// formattedNPWP reports whether raw is written as 99.999.999.9-999.999, the printed form of
// a 15-digit NPWP. The format alone is distinctive, so the check digit is not required.
func formattedNPWP(raw string) bool {
	groups := splitGroups(raw)
	if len(groups) != 6 {
		return false
	}
	want := [6]int{2, 3, 3, 1, 3, 3}
	for i, g := range groups {
		if len(g) != want[i] || !allDigits(g) {
			return false
		}
	}
	return true
}

// splitGroups splits a formatted number on '.', '-' and ' '.
func splitGroups(raw string) []string {
	return strings.FieldsFunc(raw, func(r rune) bool { return r == '.' || r == '-' || r == ' ' })
}

// LooksBPJSKesehatan reports whether d is shaped like a JKN-KIS card number: 13 digits
// starting with "000". There is no public check digit, so this is a shape check.
func LooksBPJSKesehatan(d string) bool {
	return len(d) == 13 && allDigits(d) && strings.HasPrefix(d, "000") && strings.Trim(d, "0") != ""
}

// LooksBPJSKetenagakerjaan reports whether d is shaped like a KPJ number (11 digits). It is
// only meaningful with context.
func LooksBPJSKetenagakerjaan(d string) bool {
	return len(d) == 11 && allDigits(d) && !allSame(d)
}

// LooksBankAccount reports whether d is shaped like an Indonesian bank account number
// (10 to 16 digits). Banks use their own formats without a public check digit, so this is
// only meaningful with context.
func LooksBankAccount(d string) bool {
	return len(d) >= 10 && len(d) <= 16 && allDigits(d) && !allSame(d)
}

// LooksPassport reports whether s is shaped like a passport number: one or two letters and
// six or seven digits (Indonesian passports are one letter and seven digits). Only
// meaningful with context.
func LooksPassport(s string) bool {
	n := len(s)
	if n < 7 || n > 9 {
		return false
	}
	letters := 0
	for letters < n && letters < 2 && isLetter(s[letters]) {
		letters++
	}
	if letters == 0 {
		return false
	}
	digits := s[letters:]
	return (len(digits) == 6 || len(digits) == 7) && allDigits(digits) && !allSame(digits)
}

func isLetter(b byte) bool { return (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z') }

func hasPrefixRange(d string, width, lo, hi int) bool {
	if len(d) < width {
		return false
	}
	n := 0
	for i := 0; i < width; i++ {
		n = n*10 + int(d[i]-'0')
	}
	return n >= lo && n <= hi
}

// ValidCard reports whether d (digits only) is a payment card number: a known issuer
// prefix, a length that issuer uses, and a valid Luhn check digit.
func ValidCard(d string) bool {
	n := len(d)
	if n < 13 || n > 19 || !allDigits(d) || allSame(d) || !Luhn(d) {
		return false
	}
	switch {
	case d[0] == '4':
		return n == 13 || n == 16 || n == 19 // Visa
	case hasPrefixRange(d, 2, 51, 55), hasPrefixRange(d, 4, 2221, 2720):
		return n == 16 // Mastercard
	case strings.HasPrefix(d, "34"), strings.HasPrefix(d, "37"):
		return n == 15 // American Express
	case hasPrefixRange(d, 4, 3528, 3589):
		return n >= 16 // JCB
	case strings.HasPrefix(d, "6011"), hasPrefixRange(d, 3, 644, 649), strings.HasPrefix(d, "65"):
		return n >= 16 // Discover
	case hasPrefixRange(d, 3, 300, 305), strings.HasPrefix(d, "36"), strings.HasPrefix(d, "38"), strings.HasPrefix(d, "39"):
		return n >= 14 // Diners Club
	case strings.HasPrefix(d, "62"):
		return n >= 16 // UnionPay
	case strings.HasPrefix(d, "60"), strings.HasPrefix(d, "50"), strings.HasPrefix(d, "56"), strings.HasPrefix(d, "57"),
		strings.HasPrefix(d, "58"), strings.HasPrefix(d, "63"), strings.HasPrefix(d, "67"):
		return n >= 16 // domestic debit (GPN) and Maestro ranges
	}
	return false
}

// phoneShape is the result of normalizing a phone number candidate.
type phoneShape struct {
	national string // starts with 0
	intl     bool   // written with +62 or 62
	paren    bool   // area code in parentheses
}

// normalizePhone strips separators from raw and returns the national form.
func normalizePhone(raw string) (phoneShape, bool) {
	s := strings.TrimSpace(raw)
	var out phoneShape
	if strings.HasPrefix(s, "+") {
		if !strings.HasPrefix(s, "+62") {
			return out, false
		}
		out.intl = true
		s = s[1:]
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= '0' && c <= '9':
			b.WriteByte(c)
		case c == ' ' || c == '-' || c == '.':
		case c == '(' || c == ')':
			out.paren = true
		default:
			return out, false
		}
	}
	d := b.String()
	switch {
	case strings.HasPrefix(d, "62") && len(d) >= 10:
		out.intl = true
		out.national = "0" + d[2:]
	case strings.HasPrefix(d, "0"):
		if out.intl {
			return out, false // "+620..." is not a number
		}
		out.national = d
	default:
		return out, false
	}
	return out, true
}

// ValidPhone reports whether raw is an Indonesian phone number: a mobile number
// (08x, +628x or 628x with 10 to 13 digits in national form), or a landline written with
// +62 or with its area code in parentheses.
func ValidPhone(raw string) bool {
	p, ok := normalizePhone(raw)
	if !ok {
		return false
	}
	d := p.national
	if len(d) < 9 || len(d) > 13 || allSame(d[1:]) {
		return false
	}
	if d[1] == '8' {
		return len(d) >= 10 && strings.IndexByte("1235789", d[2]) >= 0
	}
	if d[1] >= '2' && d[1] <= '7' {
		return (p.intl || p.paren) && len(d) <= 12
	}
	return false
}

// ValidEmail reports whether s is a plausible e-mail address.
func ValidEmail(s string) bool {
	at := strings.IndexByte(s, '@')
	if at < 1 || at != strings.LastIndexByte(s, '@') || len(s) > 254 {
		return false
	}
	local, domain := s[:at], s[at+1:]
	if len(local) > 64 || local[0] == '.' || local[len(local)-1] == '.' || strings.Contains(local, "..") {
		return false
	}
	for i := 0; i < len(local); i++ {
		if !isEmailLocalChar(local[i]) {
			return false
		}
	}
	labels := strings.Split(domain, ".")
	if len(labels) < 2 {
		return false
	}
	for i, l := range labels {
		if l == "" || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return false
		}
		for j := 0; j < len(l); j++ {
			c := l[j]
			if !(isLetter(c) || (c >= '0' && c <= '9') || c == '-') {
				return false
			}
		}
		if i == len(labels)-1 {
			if len(l) < 2 || len(l) > 24 {
				return false
			}
			for j := 0; j < len(l); j++ {
				if !isLetter(l[j]) {
					return false
				}
			}
		}
	}
	return true
}

func isEmailLocalChar(c byte) bool {
	return isLetter(c) || (c >= '0' && c <= '9') || strings.IndexByte(".!#$%&'*+/=?^_`{|}~-", c) >= 0
}
