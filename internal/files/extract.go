package files

import (
	"archive/zip"
	"bufio"
	"bytes"
	"encoding/xml"
	"errors"
	"io"
	"path"
	"sort"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// Kinds of files the scanner reads.
const (
	kindText = "text"
	kindDOCX = "docx"
	kindXLSX = "xlsx"
	kindPDF  = "pdf"
)

// supported maps a lower-case extension to the extractor that reads it.
var supported = map[string]string{
	".txt": kindText, ".csv": kindText, ".tsv": kindText, ".log": kindText, ".md": kindText, ".json": kindText,
	".jsonl": kindText, ".ndjson": kindText, ".xml": kindText, ".html": kindText, ".htm": kindText,
	".yaml": kindText, ".yml": kindText, ".sql": kindText, ".ini": kindText, ".conf": kindText,
	".docx": kindDOCX, ".xlsx": kindXLSX, ".pdf": kindPDF,
}

// Skip reasons reported in summaries.
const (
	SkipUnsupported = "unsupported"
	SkipTooLarge    = "too_large"
	SkipLink        = "link"
	SkipSpecial     = "special"
	SkipExcluded    = "excluded"
	SkipPermission  = "permission"
	SkipEncrypted   = "encrypted"
	SkipParse       = "parse_error"
	SkipTimeout     = "timeout"
	SkipDepth       = "depth"
	SkipProtected   = "protected"
	SkipError       = "error"
)

var errEncrypted = errors.New("encrypted document")

// writeText copies text from r to w, decoding UTF-16 (with a byte order mark) and
// replacing invalid UTF-8, so that the detectors see the same text an editor shows.
func writeText(w io.Writer, r io.Reader) error {
	br := bufio.NewReaderSize(r, 64<<10)
	bom, _ := br.Peek(3)
	switch {
	case len(bom) >= 2 && bom[0] == 0xFF && bom[1] == 0xFE:
		_, _ = br.Discard(2)
		return copyUTF16(w, br, false)
	case len(bom) >= 2 && bom[0] == 0xFE && bom[1] == 0xFF:
		_, _ = br.Discard(2)
		return copyUTF16(w, br, true)
	case len(bom) == 3 && bom[0] == 0xEF && bom[1] == 0xBB && bom[2] == 0xBF:
		_, _ = br.Discard(3)
	}
	buf := make([]byte, 32<<10)
	for {
		n, err := br.Read(buf)
		if n > 0 {
			chunk := buf[:n]
			if !utf8.Valid(chunk) {
				chunk = bytes.ToValidUTF8(chunk, []byte(" "))
			}
			if _, werr := w.Write(chunk); werr != nil {
				return werr
			}
		}
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
	}
}

func copyUTF16(w io.Writer, r io.Reader, bigEndian bool) error {
	buf := make([]byte, 32<<10)
	units := make([]uint16, 0, 16<<10)
	var carry []byte
	for {
		n, err := r.Read(buf)
		data := append(carry, buf[:n]...)
		carry = nil
		if len(data)%2 == 1 {
			carry = []byte{data[len(data)-1]}
			data = data[:len(data)-1]
		}
		units = units[:0]
		for i := 0; i+1 < len(data); i += 2 {
			if bigEndian {
				units = append(units, uint16(data[i])<<8|uint16(data[i+1]))
			} else {
				units = append(units, uint16(data[i+1])<<8|uint16(data[i]))
			}
		}
		if len(units) > 0 {
			if _, werr := io.WriteString(w, string(utf16.Decode(units))); werr != nil {
				return werr
			}
		}
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
	}
}

// ooxmlLimits bound how much of an Office document is decompressed.
type ooxmlLimits struct {
	maxEntryBytes int64
	maxTotalBytes int64
}

// openZip opens an Office document and refuses entries that are too large.
func openZip(r io.ReaderAt, size int64) (*zip.Reader, error) {
	zr, err := zip.NewReader(r, size)
	if err != nil {
		return nil, err
	}
	for _, f := range zr.File {
		if f.Name == "EncryptedPackage" || strings.EqualFold(f.Name, "encryptioninfo") {
			return nil, errEncrypted
		}
	}
	return zr, nil
}

// extractDOCX writes the text of a Word document: the body, headers, footers, footnotes,
// endnotes and comments.
func extractDOCX(w io.Writer, r io.ReaderAt, size int64, lim ooxmlLimits) error {
	zr, err := openZip(r, size)
	if err != nil {
		return err
	}
	var parts []*zip.File
	for _, f := range zr.File {
		n := f.Name
		if n == "word/document.xml" || n == "word/footnotes.xml" || n == "word/endnotes.xml" || n == "word/comments.xml" ||
			(strings.HasPrefix(n, "word/header") && strings.HasSuffix(n, ".xml")) ||
			(strings.HasPrefix(n, "word/footer") && strings.HasSuffix(n, ".xml")) {
			parts = append(parts, f)
		}
	}
	if len(parts) == 0 {
		return errors.New("not a Word document")
	}
	budget := lim.maxTotalBytes
	for _, f := range parts {
		if err := xmlText(w, f, lim.maxEntryBytes, &budget, wordElements); err != nil {
			return err
		}
	}
	return nil
}

// extractXLSX writes the cell text of a workbook: shared strings, inline strings and
// cell values, one row per line.
func extractXLSX(w io.Writer, r io.ReaderAt, size int64, lim ooxmlLimits) error {
	zr, err := openZip(r, size)
	if err != nil {
		return err
	}
	var parts []*zip.File
	for _, f := range zr.File {
		if f.Name == "xl/sharedStrings.xml" || (strings.HasPrefix(f.Name, "xl/worksheets/") && path.Ext(f.Name) == ".xml") {
			parts = append(parts, f)
		}
	}
	if len(parts) == 0 {
		return errors.New("not a workbook")
	}
	sort.Slice(parts, func(i, j int) bool { return parts[i].Name < parts[j].Name })
	budget := lim.maxTotalBytes
	for _, f := range parts {
		if err := xmlText(w, f, lim.maxEntryBytes, &budget, sheetElements); err != nil {
			return err
		}
	}
	return nil
}

// elementRules say which elements hold text and which end a line or a cell.
type elementRules struct {
	text      map[string]bool
	lineEnd   map[string]bool
	separator map[string]bool
	// skipSharedIndex: in a worksheet, <v> of a cell with t="s" is an index into the
	// shared strings, which are written already.
	skipSharedIndex bool
}

var wordElements = elementRules{
	text:      map[string]bool{"t": true},
	lineEnd:   map[string]bool{"p": true, "br": true, "cr": true},
	separator: map[string]bool{"tab": true, "tc": true},
}

var sheetElements = elementRules{
	text:            map[string]bool{"t": true, "v": true},
	lineEnd:         map[string]bool{"si": true, "row": true},
	separator:       map[string]bool{"c": true},
	skipSharedIndex: true,
}

var errTooMuchText = errors.New("document text limit reached")

// xmlText streams the character data of the text elements of one zip entry.
func xmlText(w io.Writer, f *zip.File, maxEntry int64, budget *int64, rules elementRules) error {
	if int64(f.UncompressedSize64) > maxEntry {
		return errTooMuchText
	}
	rc, err := f.Open()
	if err != nil {
		return err
	}
	defer rc.Close()
	dec := xml.NewDecoder(io.LimitReader(rc, maxEntry))
	dec.Strict = false
	dec.Entity = nil
	inText := 0
	sharedIndex := false
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		switch t := tok.(type) {
		case xml.StartElement:
			name := t.Name.Local
			if name == "c" && rules.skipSharedIndex {
				sharedIndex = false
				for _, a := range t.Attr {
					if a.Name.Local == "t" && a.Value == "s" {
						sharedIndex = true
					}
				}
			}
			if rules.text[name] && !(name == "v" && sharedIndex) {
				inText++
			}
		case xml.EndElement:
			name := t.Name.Local
			if rules.text[name] && inText > 0 && !(name == "v" && sharedIndex) {
				inText--
			}
			switch {
			case rules.lineEnd[name]:
				if _, err := io.WriteString(w, "\n"); err != nil {
					return err
				}
			case rules.separator[name]:
				if _, err := io.WriteString(w, "\t"); err != nil {
					return err
				}
			}
		case xml.CharData:
			if inText == 0 {
				continue
			}
			*budget -= int64(len(t))
			if *budget < 0 {
				return errTooMuchText
			}
			if _, err := w.Write(t); err != nil {
				return err
			}
		}
	}
}
