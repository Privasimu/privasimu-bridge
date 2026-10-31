package detect

import "strings"

// Hints say which identifiers the context of a value mentions: the words of a column
// name, or the words around a match in text. Some identifiers (passport, bank account,
// KPJ, KK) have no distinctive shape and are only reported when a hint names them.
type Hints uint32

const (
	HintNIK Hints = 1 << iota
	HintKK
	HintNPWP
	HintBPJSKes
	HintBPJSTK
	HintPassport
	HintBank
	HintCard
	HintPhone
	HintEmail
)

// Has reports whether every bit of x is set.
func (h Hints) Has(x Hints) bool { return h&x == x }

// hintWords maps a lower-case word to the hint it gives.
var hintWords = map[string]Hints{
	"nik": HintNIK, "ktp": HintNIK, "ektp": HintNIK, "kependudukan": HintNIK,
	"kk": HintKK, "keluarga": HintKK,
	"npwp": HintNPWP, "pajak": HintNPWP, "tax": HintNPWP, "taxpayer": HintNPWP,
	"bpjs": HintBPJSKes, "jkn": HintBPJSKes, "kis": HintBPJSKes,
	"kpj": HintBPJSTK, "ketenagakerjaan": HintBPJSTK, "jamsostek": HintBPJSTK, "bpjstk": HintBPJSTK,
	"paspor": HintPassport, "passport": HintPassport,
	"rekening": HintBank, "rek": HintBank, "norek": HintBank, "account": HintBank, "acct": HintBank,
	"iban": HintBank, "accno": HintBank, "acctno": HintBank,
	"kartu": HintCard, "card": HintCard, "cc": HintCard, "visa": HintCard, "mastercard": HintCard,
	"kredit": HintCard, "credit": HintCard, "debit": HintCard, "pan": HintCard, "amex": HintCard, "jcb": HintCard,
	"telepon": HintPhone, "telp": HintPhone, "tlp": HintPhone, "phone": HintPhone, "hp": HintPhone, "ponsel": HintPhone,
	"handphone": HintPhone, "mobile": HintPhone, "wa": HintPhone, "whatsapp": HintPhone, "msisdn": HintPhone,
	"email": HintEmail, "surel": HintEmail, "mail": HintEmail,
}

// HintsFromWords derives hints from lower-case words.
func HintsFromWords(words []string) Hints {
	var h Hints
	seen := make(map[string]bool, len(words))
	for i, w := range words {
		seen[w] = true
		switch w {
		case "account", "kartu":
			// Weak words, decided below from their companions.
		default:
			h |= hintWords[w]
		}
		// "BPJS TK" names the employment programme, not the health one.
		if w == "tk" && i > 0 && words[i-1] == "bpjs" {
			h |= HintBPJSTK
		}
	}
	// "account" alone is often a user account; it names a bank account only next to a
	// number word or the word bank.
	if seen["account"] && (seen["number"] || seen["no"] || seen["num"] || seen["nomor"] || seen["bank"] || seen["acct"]) {
		h |= HintBank
	}
	// "kartu keluarga" is the family card, not a payment card.
	if seen["kartu"] && !seen["keluarga"] {
		h |= HintCard
	}
	if h.Has(HintBPJSTK) {
		h &^= HintBPJSKes
	}
	return h
}

// HintsFromName derives hints from a column or field name.
func HintsFromName(name string) Hints { return HintsFromWords(Tokens(name)) }

// ValueMatch is what a single value was confirmed as.
type ValueMatch struct {
	Category Category
	// Strength is 1 for a validated structure (check digit, region codes, format), lower
	// for a shape that is only plausible.
	Strength float64
}

// numericForm returns the digits of s when s holds only digits and the separators used in
// written identifiers (space, '-', '.', parentheses, a leading '+').
func numericForm(s string) (digits string, separated bool, ok bool) {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= '0' && c <= '9':
			b.WriteByte(c)
		case c == ' ' || c == '-' || c == '.' || c == '(' || c == ')':
			separated = true
		case c == '+' && i == 0:
			separated = true
		default:
			return "", false, false
		}
	}
	return b.String(), separated, b.Len() > 0
}

// cardGrouping reports whether raw is written in the groups card numbers are printed in:
// fours (the last group may be shorter) or the 4-6-5 grouping of American Express.
func cardGrouping(raw string) bool {
	groups := strings.FieldsFunc(raw, func(r rune) bool { return r == ' ' || r == '-' })
	if len(groups) < 3 {
		return false
	}
	if len(groups) == 3 && len(groups[0]) == 4 && len(groups[1]) == 6 && len(groups[2]) == 5 {
		return true
	}
	for i, g := range groups {
		if !allDigits(g) {
			return false
		}
		if i < len(groups)-1 && len(g) != 4 {
			return false
		}
		if i == len(groups)-1 && (len(g) < 1 || len(g) > 4) {
			return false
		}
	}
	return true
}

// ClassifyValue reports which identifier a single value is, if any. The value is examined
// and dropped; it is never stored. Hints come from the column name or nearby words.
func ClassifyValue(raw string, h Hints) (ValueMatch, bool) {
	s := strings.TrimSpace(raw)
	if s == "" || len(s) > 254 {
		return ValueMatch{}, false
	}
	if strings.IndexByte(s, '@') >= 0 {
		if ValidEmail(s) {
			return ValueMatch{Email, 1}, true
		}
		return ValueMatch{}, false
	}
	if isLetter(s[0]) {
		if h.Has(HintPassport) && LooksPassport(strings.ToUpper(strings.ReplaceAll(s, " ", ""))) {
			return ValueMatch{Passport, 0.9}, true
		}
		return ValueMatch{}, false
	}
	digits, separated, ok := numericForm(s)
	if !ok || len(digits) < 9 || len(digits) > 19 {
		return ValueMatch{}, false
	}
	if formattedNPWP(s) {
		return ValueMatch{NPWP, 1}, true
	}
	bankContext := h.Has(HintBank) && !h.Has(HintPhone) && !h.Has(HintNIK) && !h.Has(HintCard)
	if ValidPhone(s) && !bankContext {
		return ValueMatch{Phone, 1}, true
	}
	grouped := separated && cardGrouping(s)
	n := len(digits)
	switch n {
	case 16:
		nik, kk, card, npwp := ValidNIK(digits), ValidKK(digits), ValidCard(digits), ValidNPWP16(digits)
		switch {
		case kk && h.Has(HintKK) && !h.Has(HintNIK):
			return ValueMatch{KK, 1}, true
		case card && (h.Has(HintCard) || grouped):
			return ValueMatch{CardNumber, 1}, true
		case npwp && h.Has(HintNPWP):
			return ValueMatch{NPWP, 1}, true
		case bankContext && LooksBankAccount(digits):
			return ValueMatch{BankAccount, 0.8}, true
		case nik:
			return ValueMatch{NIK, 1}, true
		case card:
			return ValueMatch{CardNumber, 0.8}, true
		case npwp:
			return ValueMatch{NPWP, 0.8}, true
		}
	case 15:
		npwp, card := ValidNPWP15(digits), ValidCard(digits)
		switch {
		case card && (h.Has(HintCard) || grouped):
			return ValueMatch{CardNumber, 1}, true
		case npwp && h.Has(HintNPWP):
			return ValueMatch{NPWP, 1}, true
		case bankContext && LooksBankAccount(digits):
			return ValueMatch{BankAccount, 0.8}, true
		case npwp:
			return ValueMatch{NPWP, 0.7}, true
		case card:
			return ValueMatch{CardNumber, 0.8}, true
		}
	case 13:
		switch {
		case LooksBPJSKesehatan(digits) && h.Has(HintBPJSKes):
			return ValueMatch{BPJSKesehatan, 0.9}, true
		case ValidCard(digits) && (h.Has(HintCard) || grouped):
			return ValueMatch{CardNumber, 1}, true
		case bankContext && LooksBankAccount(digits):
			return ValueMatch{BankAccount, 0.8}, true
		case LooksBPJSKesehatan(digits):
			return ValueMatch{BPJSKesehatan, 0.6}, true
		}
	case 11:
		if h.Has(HintBPJSTK) && LooksBPJSKetenagakerjaan(digits) {
			return ValueMatch{BPJSKetenagakerjaan, 0.8}, true
		}
	}
	if ValidCard(digits) && (h.Has(HintCard) || grouped) {
		return ValueMatch{CardNumber, 1}, true
	}
	if bankContext && LooksBankAccount(digits) {
		return ValueMatch{BankAccount, 0.8}, true
	}
	return ValueMatch{}, false
}
