package files

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/privasimu/bridge/internal/detect"
)

// fileEntities finds a name in a text that holds "Budi Contoh", like a model would.
type fileEntities struct{ texts []string }

func (f *fileEntities) Count(_ context.Context, texts []string) ([]map[detect.Category]int, error) {
	f.texts = append(f.texts, texts...)
	out := make([]map[detect.Category]int, len(texts))
	for i, t := range texts {
		if n := strings.Count(t, "Budi Contoh"); n > 0 {
			out[i] = map[detect.Category]int{detect.PersonName: n, detect.Phone: 7}
		}
	}
	return out, nil
}

func TestFileTextGoesToTheEntityCounter(t *testing.T) {
	dir := t.TempDir()
	write(t, filepath.Join(dir, "surat.txt"), []byte("Surat kuasa dari Budi Contoh kepada Budi Contoh. Telp "+phone+". "+strings.Repeat("isi surat ", 40)))
	write(t, filepath.Join(dir, "pendek.txt"), []byte("Budi Contoh"))
	ec := &fileEntities{}
	s := testScanner()
	s.opts.Entities, s.opts.EntityMinChars, s.opts.EntityMaxBytes = ec, 50, 200
	rep, err := s.Scan(context.Background(), rootFor(t, dir, nil), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(ec.texts) != 1 || len(ec.texts[0]) > 200 {
		t.Fatalf("only the long file, at most max_bytes of it: %d texts", len(ec.texts))
	}
	for _, f := range rep.Files {
		if f.Path != "surat.txt" {
			continue
		}
		// The model adds names; the phone number stays the validators' count.
		if f.Categories[detect.PersonName] != 2 || f.Categories[detect.Phone] != 1 {
			t.Fatalf("%v", f.Categories)
		}
		return
	}
	t.Fatal("surat.txt not reported")
}
