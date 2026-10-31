package files

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"os/exec"
	"runtime"
	"runtime/debug"
	"strings"
	"time"

	"github.com/digitorus/pdf"
)

// ChildCommand is the hidden sub-command that extracts the text of a PDF in a separate
// process. PDF parsers are complex; a malformed or hostile file can make one loop or
// exhaust memory. In a child process with a hard timeout, such a file costs one killed
// process instead of the bridge.
const ChildCommand = "__extract-pdf"

// Exit codes of the child.
const (
	childOK        = 0
	childEncrypted = 2
	childParse     = 3
	childTooLarge  = 4
)

const maxPDFPages = 2000

// RunChild is the body of the child process: it reads a PDF from in (at most maxIn bytes)
// and writes its text to out (at most maxOut bytes). It returns the exit code.
func RunChild(in io.Reader, out io.Writer, maxIn, maxOut int64) (code int) {
	debug.SetMemoryLimit(768 << 20)
	defer func() {
		if recover() != nil {
			code = childParse
		}
	}()
	data, err := io.ReadAll(io.LimitReader(in, maxIn+1))
	if err != nil {
		return childParse
	}
	if int64(len(data)) > maxIn {
		return childTooLarge
	}
	lw := &limitWriter{w: out, left: maxOut}
	if err := pdfText(lw, data); err != nil {
		if errors.Is(err, errEncrypted) {
			return childEncrypted
		}
		if errors.Is(err, errLimit) {
			return childOK
		}
		return childParse
	}
	return childOK
}

var errLimit = errors.New("output limit reached")

type limitWriter struct {
	w    io.Writer
	left int64
}

func (l *limitWriter) Write(p []byte) (int, error) {
	if l.left <= 0 {
		return 0, errLimit
	}
	if int64(len(p)) > l.left {
		p = p[:l.left]
	}
	n, err := l.w.Write(p)
	l.left -= int64(n)
	if err == nil && l.left <= 0 {
		err = errLimit
	}
	return n, err
}

// pdfText writes the text of every page, inserting spaces between words and line breaks
// between lines from the glyph positions.
func pdfText(w io.Writer, data []byte) error {
	r, err := pdf.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		if errors.Is(err, pdf.ErrInvalidPassword) || strings.Contains(strings.ToLower(err.Error()), "encrypt") {
			return errEncrypted
		}
		return err
	}
	pages := r.NumPage()
	if pages > maxPDFPages {
		pages = maxPDFPages
	}
	var b strings.Builder
	for i := 1; i <= pages; i++ {
		p := r.Page(i)
		if p.V.IsNull() {
			continue
		}
		b.Reset()
		var prevY, prevEnd float64
		first := true
		for _, t := range p.Content().Text {
			switch {
			case first:
			case math.Abs(t.Y-prevY) > math.Max(1, t.FontSize*0.5):
				b.WriteByte('\n')
			case t.X > prevEnd+math.Max(0.5, t.FontSize*0.15):
				b.WriteByte(' ')
			}
			b.WriteString(t.S)
			prevY, prevEnd, first = t.Y, t.X+t.W, false
		}
		b.WriteString("\n\f")
		if _, err := io.WriteString(w, b.String()); err != nil {
			return err
		}
	}
	return nil
}

// pdfExtractor runs the child process on one file.
type pdfExtractor struct {
	// command returns the executable and arguments of the child (the bridge itself).
	command func() (string, []string, error)
	timeout time.Duration
	maxIn   int64
	maxOut  int64
}

func defaultChildCommand() (string, []string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", nil, err
	}
	return exe, []string{ChildCommand}, nil
}

// childEnv is the whole environment of the child: nothing is inherited, so secrets in
// the bridge's environment (store key, passwords) never reach the parser process.
func childEnv() []string {
	env := []string{"PRIVASIMU_BRIDGE_CHILD=1"}
	if runtime.GOOS == "windows" {
		for _, k := range []string{"SystemRoot", "SYSTEMROOT", "TEMP", "TMP"} {
			if v := os.Getenv(k); v != "" {
				env = append(env, k+"="+v)
			}
		}
	}
	return env
}

// extract feeds file to the child and writes the extracted text to w.
func (p *pdfExtractor) extract(ctx context.Context, w io.Writer, file io.Reader) (truncated bool, err error) {
	exe, args, err := p.command()
	if err != nil {
		return false, err
	}
	ctx, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()
	args = append(args, fmt.Sprint(p.maxIn), fmt.Sprint(p.maxOut))
	cmd := exec.CommandContext(ctx, exe, args...) // #nosec G204 -- the bridge's own executable
	cmd.Env = childEnv()
	cmd.Stdin = file
	var out bytes.Buffer
	cmd.Stdout = &limitWriter{w: &out, left: p.maxOut + 1}
	cmd.Stderr = io.Discard
	cmd.WaitDelay = 2 * time.Second
	runErr := cmd.Run()
	if ctx.Err() != nil {
		return false, errTimeout
	}
	if runErr != nil {
		var exit *exec.ExitError
		if errors.As(runErr, &exit) {
			switch exit.ExitCode() {
			case childEncrypted:
				return false, errEncrypted
			case childTooLarge:
				return false, errTooLarge
			}
			return false, errParse
		}
		if !errors.Is(runErr, errLimit) {
			return false, runErr
		}
	}
	truncated = int64(out.Len()) >= p.maxOut
	_, err = w.Write(out.Bytes())
	return truncated, err
}

var (
	errTimeout  = errors.New("extraction timed out")
	errParse    = errors.New("document could not be parsed")
	errTooLarge = errors.New("file too large")
)
