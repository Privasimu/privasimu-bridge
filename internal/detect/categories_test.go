package detect

import "testing"

// Buglist T-2026W47-294: religion is general personal data (UU PDP Pasal 4 ayat (3) huruf d), and the registry splits
// the codes as the platform does (Laravel AgentResults::SPECIFIC_CATEGORIES, backend-go bridgeagent
// specificCategories), so the bridge and the platform give a code the same category.
func TestPDPCategoriesMatchThePlatform(t *testing.T) {
	specific := map[Category]bool{NIK: true, KK: true, NPWP: true, Passport: true, DrivingLicense: true,
		BPJSKesehatan: true, BPJSKetenagakerjaan: true, CardNumber: true, BankAccount: true, Financial: true,
		Health: true, Biometric: true, Genetic: true, CriminalRecord: true}
	all := All()
	if len(all) != 31 {
		t.Fatalf("%d categories, the platform knows 31", len(all))
	}
	for _, c := range all {
		want := PDPGeneral
		if specific[c] {
			want = PDPSpecific
		}
		if got := PDPOf(c); got != want {
			t.Errorf("PDPOf(%s) = %q, want %q", c, got, want)
		}
	}
}
