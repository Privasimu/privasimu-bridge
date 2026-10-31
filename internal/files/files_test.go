package files

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/privasimu/bridge/internal/config"
	"github.com/privasimu/bridge/internal/detect"
)

// TestMain lets the test binary act as the PDF child process, the way the bridge binary
// does, plus a "hang" child used to test the timeout.
func TestMain(m *testing.M) {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case ChildCommand:
			maxIn, _ := strconv.ParseInt(os.Args[2], 10, 64)
			maxOut, _ := strconv.ParseInt(os.Args[3], 10, 64)
			os.Exit(RunChild(os.Stdin, os.Stdout, maxIn, maxOut))
		case "__hang":
			time.Sleep(30 * time.Second)
			os.Exit(0)
		}
	}
	os.Exit(m.Run())
}

// Synthetic content only.
const (
	nik   = "3171012303900001"
	phone = "0812-3456-7890"
	email = "budi.contoh@example.co.id"
)

func makeDOCX(t *testing.T, paragraphs ...string) []byte {
	t.Helper()
	var body strings.Builder
	for _, p := range paragraphs {
		fmt.Fprintf(&body, `<w:p><w:r><w:t xml:space="preserve">%s</w:t></w:r></w:p>`, p)
	}
	return makeZip(t, map[string]string{
		"[Content_Types].xml": `<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"/>`,
		"word/document.xml": `<?xml version="1.0" encoding="UTF-8"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body>` +
			body.String() + `</w:body></w:document>`,
		"word/footer1.xml": `<w:ftr xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:p><w:r><w:t>Rahasia</w:t></w:r></w:p></w:ftr>`,
	})
}

func makeXLSX(t *testing.T) []byte {
	t.Helper()
	return makeZip(t, map[string]string{
		"xl/sharedStrings.xml": `<sst xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><si><t>NIK</t></si><si><t>` + nik + `</t></si><si><t>3171016303900002</t></si></sst>`,
		"xl/worksheets/sheet1.xml": `<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData>` +
			`<row r="1"><c r="A1" t="s"><v>0</v></c><c r="B1" t="inlineStr"><is><t>Email</t></is></c></row>` +
			`<row r="2"><c r="A2" t="s"><v>1</v></c><c r="B2" t="inlineStr"><is><t>` + email + `</t></is></c><c r="C2"><v>12345</v></c></row>` +
			`<row r="3"><c r="A3" t="s"><v>2</v></c></row></sheetData></worksheet>`,
	})
}

func makeZip(t *testing.T, entries map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, content := range entries {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = w.Write([]byte(content))
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// makePDF builds a one-page PDF with the given lines in Helvetica.
func makePDF(lines ...string) []byte {
	var content strings.Builder
	content.WriteString("BT /F1 12 Tf 72 720 Td 14 TL\n")
	for _, l := range lines {
		fmt.Fprintf(&content, "(%s) Tj T*\n", strings.NewReplacer(`\`, `\\`, "(", `\(`, ")", `\)`).Replace(l))
	}
	content.WriteString("ET")
	widths := strings.TrimSpace(strings.Repeat("556 ", 95))
	objects := []string{
		"<< /Type /Catalog /Pages 2 0 R >>",
		"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
		"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 5 0 R >> >> /Contents 4 0 R >>",
		fmt.Sprintf("<< /Length %d >>\nstream\n%s\nendstream", content.Len()+1, content.String()),
		"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding /FirstChar 32 /LastChar 126 /Widths [" + widths + "] >>",
	}
	var b bytes.Buffer
	b.WriteString("%PDF-1.4\n")
	offsets := make([]int, len(objects))
	for i, o := range objects {
		offsets[i] = b.Len()
		fmt.Fprintf(&b, "%d 0 obj\n%s\nendobj\n", i+1, o)
	}
	xref := b.Len()
	fmt.Fprintf(&b, "xref\n0 %d\n0000000000 65535 f \n", len(objects)+1)
	for _, off := range offsets {
		fmt.Fprintf(&b, "%010d 00000 n \n", off)
	}
	fmt.Fprintf(&b, "trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n", len(objects)+1, xref)
	return b.Bytes()
}

func write(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
}

func testScanner() *Scanner {
	return NewScanner(Options{Key: bytes.Repeat([]byte{7}, 32), MaxTextBytes: 1 << 20, MaxFileBytes: 4 << 20, PDFTimeout: 20 * time.Second,
		ChildCommand: func() (string, []string, error) { return os.Args[0], []string{ChildCommand}, nil }})
}

func rootFor(t *testing.T, dir string, mutate func(*config.FileRoot)) *Root {
	t.Helper()
	rc := config.FileRoot{ID: "hr-share", Label: "HR", Path: dir, MaxFiles: 1000, MaxDepth: 10, ReportPaths: config.PathsHashed}
	if mutate != nil {
		mutate(&rc)
	}
	r, err := OpenRoot(rc, nil)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestExtractorsCountIdentifiers(t *testing.T) {
	dir := t.TempDir()
	write(t, filepath.Join(dir, "karyawan.csv"), []byte("nama,nik,telp\nBudi,"+nik+","+phone+"\n"))
	write(t, filepath.Join(dir, "data.json"), []byte(`{"email":"`+email+`","nik":"`+nik+`"}`))
	write(t, filepath.Join(dir, "utf16.txt"), utf16le("Telp "+phone+"\r\n"))
	write(t, filepath.Join(dir, "surat.docx"), makeDOCX(t, "Kepada Budi, NIK "+nik, "Hubungi "+phone))
	write(t, filepath.Join(dir, "rekap.xlsx"), makeXLSX(t))
	write(t, filepath.Join(dir, "scan", "formulir.pdf"), makePDF("Formulir pendaftaran", "NIK: "+nik, "Email: "+email))
	write(t, filepath.Join(dir, "foto.jpg"), []byte{0xFF, 0xD8, 0xFF})
	write(t, filepath.Join(dir, "kosong.txt"), []byte("tidak ada data pribadi di sini"))

	rep, err := testScanner().Scan(context.Background(), rootFor(t, dir, nil), nil)
	if err != nil {
		t.Fatal(err)
	}
	byPath := map[string]FileResult{}
	for _, f := range rep.Files {
		byPath[f.Path] = f
	}
	expect := map[string]map[detect.Category]int{
		"karyawan.csv":       {detect.NIK: 1, detect.Phone: 1},
		"data.json":          {detect.NIK: 1, detect.Email: 1},
		"utf16.txt":          {detect.Phone: 1},
		"surat.docx":         {detect.NIK: 1, detect.Phone: 1},
		"rekap.xlsx":         {detect.NIK: 2, detect.Email: 1},
		"scan/formulir.pdf":  {detect.NIK: 1, detect.Email: 1},
	}
	for path, want := range expect {
		got, ok := byPath[path]
		if !ok {
			t.Errorf("%s: no finding (skipped: %v)", path, rep.Skipped)
			continue
		}
		for c, n := range want {
			if got.Categories[c] != n {
				t.Errorf("%s: %s = %d, want %d (all %v)", path, c, got.Categories[c], n, got.Categories)
			}
		}
	}
	if rep.Skipped[SkipUnsupported] != 1 || rep.FilesWithPII != 6 || rep.FilesScanned != 7 || rep.FilesSeen != 8 {
		t.Fatalf("summary: seen=%d scanned=%d pii=%d skipped=%v", rep.FilesSeen, rep.FilesScanned, rep.FilesWithPII, rep.Skipped)
	}
	if _, listed := byPath["kosong.txt"]; listed {
		t.Fatal("a file without findings is not listed")
	}
}

func utf16le(s string) []byte {
	out := []byte{0xFF, 0xFE}
	for _, r := range s {
		out = append(out, byte(r), byte(r>>8))
	}
	return out
}

func TestViewHidesPathsAndContent(t *testing.T) {
	dir := t.TempDir()
	write(t, filepath.Join(dir, "Budi Santoso", "KTP_"+nik+".txt"), []byte("NIK "+nik))
	rep, err := testScanner().Scan(context.Background(), rootFor(t, dir, nil), nil)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(rep.View())
	for _, leak := range []string{"Budi", nik, "KTP_", dir} {
		if strings.Contains(string(raw), leak) {
			t.Fatalf("the outbound view carries %q: %s", leak, raw)
		}
	}
	v := rep.View()
	if len(v.Files) != 1 || !strings.HasPrefix(v.Files[0].ID, "f_") || v.Files[0].PDP != detect.PDPSpecific || v.Files[0].Categories["nik"] != 1 {
		t.Fatalf("%+v", v.Files)
	}
	// The same file keeps its id across scans.
	rep2, _ := testScanner().Scan(context.Background(), rootFor(t, dir, nil), nil)
	if rep2.View().Files[0].ID != v.Files[0].ID {
		t.Fatal("file ids must be stable")
	}
	// relative mode reports the path, still without content.
	rel, _ := testScanner().Scan(context.Background(), rootFor(t, dir, func(r *config.FileRoot) { r.ReportPaths = config.PathsRelative }), nil)
	rv := rel.View()
	if rv.Files[0].Path != "Budi Santoso/KTP_"+nik+".txt" {
		t.Fatalf("relative path: %q", rv.Files[0].Path)
	}
}

func TestSymlinksNeverLeaveTheRoot(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "share")
	outside := filepath.Join(base, "outside")
	write(t, filepath.Join(root, "ok.txt"), []byte("tidak ada"))
	write(t, filepath.Join(outside, "secret.txt"), []byte("NIK "+nik+" "+nik+" "+nik))
	if err := os.Symlink(filepath.Join(outside, "secret.txt"), filepath.Join(root, "link.txt")); err != nil {
		t.Skipf("symbolic links are not available here: %v", err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "linkdir")); err != nil {
		t.Skipf("symbolic links are not available here: %v", err)
	}
	if err := os.Symlink(filepath.Join(root, "ok.txt"), filepath.Join(root, "inside-link.txt")); err != nil {
		t.Skipf("symbolic links are not available here: %v", err)
	}
	rep, err := testScanner().Scan(context.Background(), rootFor(t, root, nil), nil)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Totals[detect.NIK] != 0 {
		t.Fatalf("content outside the root was read: %v", rep.Totals)
	}
	if rep.Skipped[SkipLink] != 3 {
		t.Fatalf("every link is skipped: %v", rep.Skipped)
	}
}

func TestWindowsJunctionsNeverLeaveTheRoot(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("junctions are a Windows feature")
	}
	base := t.TempDir()
	root := filepath.Join(base, "share")
	outside := filepath.Join(base, "outside")
	write(t, filepath.Join(root, "ok.txt"), []byte("tidak ada"))
	write(t, filepath.Join(outside, "secret.txt"), []byte("NIK "+nik))
	if out, err := exec.Command("cmd", "/c", "mklink", "/J", filepath.Join(root, "jn"), outside).CombinedOutput(); err != nil {
		t.Skipf("mklink /J failed: %v %s", err, out)
	}
	rep, err := testScanner().Scan(context.Background(), rootFor(t, root, nil), nil)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Totals[detect.NIK] != 0 || rep.Skipped[SkipLink] != 1 {
		t.Fatalf("a junction must be skipped: totals=%v skipped=%v", rep.Totals, rep.Skipped)
	}
	// Even a direct open through the root refuses the junction.
	r, _ := os.OpenRoot(root)
	defer r.Close()
	if f, err := r.Open("jn/secret.txt"); err == nil {
		f.Close()
		t.Fatal("os.Root must refuse a path through a junction that leaves the root")
	}
}

func TestOpenRootValidation(t *testing.T) {
	base := t.TempDir()
	share := filepath.Join(base, "share")
	data := filepath.Join(base, "bridge-data")
	_ = os.MkdirAll(filepath.Join(share, "bridge"), 0o755)
	_ = os.MkdirAll(data, 0o755)
	cases := []struct {
		path      string
		protected []string
		want      error
	}{
		{filepath.Join(base, "missing"), nil, ErrRootMissing},
		{"relative/path", nil, ErrRootMissing},
		{share, []string{filepath.Join(share)}, ErrRootProtected},
		{filepath.Join(data), []string{base}, ErrRootProtected},
	}
	if runtime.GOOS == "windows" {
		cases = append(cases, struct {
			path      string
			protected []string
			want      error
		}{os.Getenv("SystemRoot"), nil, ErrRootSystem}, struct {
			path      string
			protected []string
			want      error
		}{`C:\`, nil, ErrRootSystem})
	} else {
		cases = append(cases, struct {
			path      string
			protected []string
			want      error
		}{"/etc", nil, ErrRootSystem}, struct {
			path      string
			protected []string
			want      error
		}{"/", nil, ErrRootSystem})
	}
	for _, c := range cases {
		if _, err := OpenRoot(config.FileRoot{ID: "x", Path: c.path}, c.protected); err != c.want {
			t.Errorf("%s: %v, want %v", c.path, err, c.want)
		}
	}
	r, err := OpenRoot(config.FileRoot{ID: "x", Path: share}, []string{filepath.Join(share, "bridge")})
	if err != nil {
		t.Fatal(err)
	}
	if !r.isProtected("bridge") || !r.isProtected("bridge/secrets.enc") || r.isProtected("bridge2") {
		t.Fatalf("protected: %v", r.protected)
	}
}

func TestProtectedAndExcludedPathsAreSkipped(t *testing.T) {
	root := t.TempDir()
	write(t, filepath.Join(root, "bridge", "secrets.txt"), []byte("NIK "+nik))
	write(t, filepath.Join(root, "arsip", "lama.txt"), []byte("NIK "+nik))
	write(t, filepath.Join(root, "~$draft.docx"), []byte("x"))
	write(t, filepath.Join(root, "a", "b", "c", "d", "deep.txt"), []byte("NIK "+nik))
	write(t, filepath.Join(root, "ok.txt"), []byte("NIK "+nik))
	rc := config.FileRoot{ID: "r", Path: root, MaxFiles: 100, MaxDepth: 3, Exclude: []string{"arsip/**"}, ReportPaths: config.PathsHashed}
	r, err := OpenRoot(rc, []string{filepath.Join(root, "bridge")})
	if err != nil {
		t.Fatal(err)
	}
	rep, err := testScanner().Scan(context.Background(), r, nil)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Totals[detect.NIK] != 1 || len(rep.Files) != 1 || rep.Files[0].Path != "ok.txt" {
		t.Fatalf("only ok.txt may be read: %+v %v", rep.Files, rep.Skipped)
	}
	if rep.Skipped[SkipProtected] != 1 || rep.Skipped[SkipExcluded] < 2 || rep.Skipped[SkipDepth] != 1 {
		t.Fatalf("skipped: %v", rep.Skipped)
	}
}

func TestLimits(t *testing.T) {
	root := t.TempDir()
	for i := 0; i < 5; i++ {
		write(t, filepath.Join(root, fmt.Sprintf("f%d.txt", i)), []byte("NIK "+nik))
	}
	write(t, filepath.Join(root, "big.txt"), bytes.Repeat([]byte("x"), 5<<20))
	rep, err := testScanner().Scan(context.Background(), rootFor(t, root, func(r *config.FileRoot) { r.MaxFiles = 3 }), nil)
	if err != nil {
		t.Fatal(err)
	}
	if !rep.Truncated || rep.FilesSeen != 3 {
		t.Fatalf("max_files: truncated=%v seen=%d", rep.Truncated, rep.FilesSeen)
	}
	rep, _ = testScanner().Scan(context.Background(), rootFor(t, root, nil), nil)
	if rep.Skipped[SkipTooLarge] != 1 {
		t.Fatalf("a file over max_file_bytes is skipped: %v", rep.Skipped)
	}
}

func TestBrokenAndHangingPDFs(t *testing.T) {
	root := t.TempDir()
	write(t, filepath.Join(root, "broken.pdf"), []byte("%PDF-1.4 this is not a pdf"))
	rep, err := testScanner().Scan(context.Background(), rootFor(t, root, nil), nil)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Skipped[SkipParse] != 1 {
		t.Fatalf("a broken PDF is a parse error: %v", rep.Skipped)
	}
	hang := NewScanner(Options{Key: []byte("k"), PDFTimeout: 300 * time.Millisecond,
		ChildCommand: func() (string, []string, error) { return os.Args[0], []string{"__hang"}, nil }})
	write(t, filepath.Join(root, "ok.pdf"), makePDF("x"))
	started := time.Now()
	rep, err = hang.Scan(context.Background(), rootFor(t, root, func(r *config.FileRoot) { r.Include = []string{"ok.pdf"} }), nil)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Skipped[SkipTimeout] != 1 || time.Since(started) > 10*time.Second {
		t.Fatalf("a hanging parser is killed at the timeout: %v after %v", rep.Skipped, time.Since(started))
	}
}

func TestChildEnvironmentCarriesNoSecrets(t *testing.T) {
	t.Setenv("PRIVASIMU_BRIDGE_SECRETS_KEY", "placeholder-key")
	t.Setenv("CRM_PASSWORD", "placeholder-password")
	for _, kv := range childEnv() {
		if strings.Contains(kv, "placeholder") || strings.HasPrefix(kv, "PRIVASIMU_BRIDGE_SECRETS") {
			t.Fatalf("the child inherits %q", kv)
		}
	}
}

func TestGlob(t *testing.T) {
	cases := []struct {
		pattern, name string
		want          bool
	}{
		{"**/~$*", "~$draft.docx", true},
		{"**/~$*", "a/b/~$draft.docx", true},
		{"arsip/**", "arsip/2020/x.txt", true},
		{"arsip/**", "arsip2/x.txt", false},
		{"**/*.pdf", "a/b.pdf", true},
		{"*.pdf", "a/b.pdf", false},
		{"**/.git/**", "src/.git/config", true},
	}
	for _, c := range cases {
		if got := matchGlob(c.pattern, c.name); got != c.want {
			t.Errorf("matchGlob(%q, %q) = %v", c.pattern, c.name, got)
		}
	}
}

func TestServiceStoresReportsAndSchedules(t *testing.T) {
	dir := t.TempDir()
	share := filepath.Join(dir, "share")
	write(t, filepath.Join(share, "a.txt"), []byte("NIK "+nik))
	cfg, _ := config.Parse([]byte("files:\n  roots:\n    - id: hr\n      path: " + strconv.Quote(share) + "\n"))
	// The configuration lives beside the share, not above it: a root inside the bridge's
	// own directory is refused.
	cfg.SetPath(filepath.Join(dir, "conf", "bridge.yaml"))
	s, err := NewService(cfg, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Invalid) != 0 {
		t.Fatalf("invalid roots: %v", s.Invalid)
	}
	s.SetScanner(testScanner())
	if _, err := s.Latest("hr"); err != ErrNoReport {
		t.Fatalf("%v", err)
	}
	if _, err := s.Latest("nope"); err != ErrUnknownRoot {
		t.Fatalf("%v", err)
	}
	if _, err := s.ScanNow(context.Background(), "hr", nil); err != nil {
		t.Fatal(err)
	}
	rep, err := s.Latest("hr")
	if err != nil || rep.Totals[detect.NIK] != 1 {
		t.Fatalf("%+v %v", rep, err)
	}
	roots := s.Roots()
	if len(roots) != 1 || roots[0].LastScan == nil || roots[0].LastScan.FilesWithPII != 1 {
		t.Fatalf("%+v", roots)
	}
	if st, err := os.Stat(filepath.Join(dir, "conf", "state", "file-id.key")); err != nil || (runtime.GOOS != "windows" && st.Mode().Perm() != 0o600) {
		t.Fatalf("file-id key: %v", err)
	}
}
