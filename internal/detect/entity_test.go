package detect

import (
	"slices"
	"testing"
)

func TestEntityCategoriesLeaveTheValidatorsAlone(t *testing.T) {
	for _, c := range ValueCategories() {
		if IsEntityCategory(c) || slices.Contains(EntityCategories(), c) {
			t.Errorf("%s is confirmed by a validator, never by a model", c)
		}
	}
	if !IsEntityCategory(PersonName) || !IsEntityCategory(Address) || IsEntityCategory("child_data") {
		t.Fatal("names and addresses are model categories; unknown codes are not")
	}
	got := MergeEntityCounts(map[Category]int{Phone: 2, PersonName: 1}, map[Category]int{PersonName: 3, Phone: 9, Address: 1, "x": 4})
	if got[Phone] != 2 || got[PersonName] != 3 || got[Address] != 1 || got["x"] != 0 {
		t.Fatalf("%v", got)
	}
	if MergeEntityCounts(nil, map[Category]int{Religion: 1})[Religion] != 1 {
		t.Fatal("a nil map gets the entities")
	}
}

func TestColumnSamplerAddsWhatAModelFound(t *testing.T) {
	s := NewColumnSampler("catatan")
	s.KeepLongText(20, 100)
	for _, v := range []string{"nasabah atas nama Budi Contoh datang", "short", "nasabah atas nama Siti Aminah datang",
		"nasabah atas nama Budi Contoh lagi", "x x x x x x x x x x x x x x x x x x x x x x x x x x x x x x x x"} {
		s.Add(v, false)
	}
	kept := s.LongText()
	if len(kept) != 2 {
		// The third long value would pass max_bytes (100) and is not kept.
		t.Fatalf("kept %d texts: %q", len(kept), kept)
	}
	s.AddEntities([]map[Category]int{{PersonName: 1}, {PersonName: 2, NIK: 1}})
	if s.LongText() != nil {
		t.Fatal("the kept values must be dropped")
	}
	r := s.Result(Thresholds{MinMatches: 2, Ratio: 0.2})
	if !r.Detected || r.Category != PersonName || r.Matches[PersonName] != 2 || r.Matches[NIK] != 0 {
		t.Fatalf("%+v", r)
	}
}
