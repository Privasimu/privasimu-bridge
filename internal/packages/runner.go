package packages

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"hash"
	"io"
	"os"
	"os/exec"
	"runtime"
	"sync"
	"time"

	"github.com/privasimu/bridge/internal/config"
)

// Output limits of the child processes.
var (
	// maxStdout caps what a tool may write (the SBOM or the matcher report); tests lower it.
	maxStdout int64 = 256 << 20
	// maxStderr is the tail of standard error kept to classify a failure. It is never sent
	// to the platform and never logged verbatim (it can name local paths).
	maxStderr = 64 << 10
)

var (
	errOutputTooLarge = errors.New("the tool wrote more than the output limit")
	errToolMissing    = errors.New("the tool is not installed at the configured path or is not a regular file")
	errToolChecksum   = errors.New("the tool does not match the configured SHA-256")
)

// VerifyTool checks that a tool is a regular file whose SHA-256 is the configured one. It
// runs before every use, so a replaced binary is refused even while the bridge runs.
func VerifyTool(t config.ToolConfig) error {
	if !t.IsSet() {
		return errToolMissing
	}
	fi, err := os.Stat(t.Path)
	if err != nil || !fi.Mode().IsRegular() {
		return errToolMissing
	}
	f, err := os.Open(t.Path) // #nosec G304 -- the operator-configured tool path
	if err != nil {
		return errToolMissing
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return errToolMissing
	}
	if hex.EncodeToString(h.Sum(nil)) != t.SHA256 {
		return errToolChecksum
	}
	return nil
}

// toolFailure turns a VerifyTool error into a scan failure.
func toolFailure(tool string, err error) *Error {
	if errors.Is(err, errToolChecksum) {
		return scanError(CodeToolChecksum, "tool", tool, err)
	}
	return scanError(CodeToolMissing, "tool", tool, err)
}

// run describes one child process.
type run struct {
	tool    config.ToolConfig
	name    string // syft, grype or trivy (for errors)
	args    []string
	env     []string
	dir     string
	stdout  string // file the output goes to
	timeout time.Duration
}

// outcome is what a finished child left behind.
type outcome struct {
	stderr []byte
	sha256 string // of stdout
	bytes  int64
}

// execute verifies the tool, runs it and waits. Standard output goes to run.stdout,
// capped at maxStdout; standard error keeps its last maxStderr bytes. A cancelled parent
// context (job cancelled, lease lost) returns its error; a deadline (the run's timeout or
// the scan's) returns a tool_timeout failure; a non-zero exit returns a *exitFailure with
// the stderr tail.
func execute(ctx context.Context, r run) (outcome, error) {
	var out outcome
	if err := VerifyTool(r.tool); err != nil {
		return out, toolFailure(r.name, err)
	}
	f, err := os.OpenFile(r.stdout, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600) // #nosec G304 -- inside the private work directory
	if err != nil {
		return out, err
	}
	defer f.Close()
	rctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()
	h := sha256.New()
	stdout := &capWriter{w: f, h: h, left: maxStdout, onLimit: cancel}
	stderr := &tailBuffer{max: maxStderr}
	cmd := exec.CommandContext(rctx, r.tool.Path, r.args...) // #nosec G204 -- fixed argument list of a checksum-verified tool
	cmd.Env = r.env
	cmd.Dir = r.dir
	cmd.Stdin = nil
	// Writers that are not *os.File make os/exec copy through a pipe, so the cap applies.
	cmd.Stdout, cmd.Stderr = stdout, stderr
	cmd.WaitDelay = 5 * time.Second
	if err := startLowPriority(cmd); err != nil {
		switch {
		case errors.Is(ctx.Err(), context.Canceled):
			return out, ctx.Err() // the job was cancelled or lost its lease
		case rctx.Err() != nil:
			// The deadline passed before the tool could start (a busy host): a timeout,
			// retried like one that passes while the tool runs, not a broken tool.
			return out, scanError(CodeToolTimeout, "run", r.name, rctx.Err())
		}
		return out, scanError(CodeToolFailed, "tool", r.name, err)
	}
	waitErr := cmd.Wait()
	out.stderr, out.bytes, out.sha256 = stderr.bytes(), stdout.written, hex.EncodeToString(h.Sum(nil))
	switch {
	case errors.Is(ctx.Err(), context.Canceled):
		return out, ctx.Err() // the job was cancelled or lost its lease
	case stdout.exceeded:
		return out, scanError(CodeToolFailed, "output", r.name, errOutputTooLarge)
	case errors.Is(rctx.Err(), context.DeadlineExceeded):
		return out, scanError(CodeToolTimeout, "run", r.name, rctx.Err())
	case waitErr != nil:
		return out, &exitFailure{name: r.name, err: waitErr, stderr: out.stderr}
	}
	if err := f.Sync(); err != nil {
		return out, err
	}
	return out, nil
}

// exitFailure is a tool that exited with an error; the caller classifies it.
type exitFailure struct {
	name   string
	err    error
	stderr []byte
}

func (e *exitFailure) Error() string { return e.name + " failed: " + e.err.Error() }

// capWriter writes to w and hashes what it writes, until left bytes; then it stops the
// child and reports the limit.
type capWriter struct {
	w        io.Writer
	h        hash.Hash
	left     int64
	written  int64
	exceeded bool
	onLimit  func()
}

func (c *capWriter) Write(p []byte) (int, error) {
	if int64(len(p)) > c.left {
		c.exceeded = true
		c.onLimit()
		return 0, errOutputTooLarge
	}
	n, err := c.w.Write(p)
	c.h.Write(p[:n])
	c.left -= int64(n)
	c.written += int64(n)
	return n, err
}

// tailBuffer keeps the last max bytes written.
type tailBuffer struct {
	mu  sync.Mutex
	max int
	buf []byte
}

func (t *tailBuffer) Write(p []byte) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.buf = append(t.buf, p...)
	if over := len(t.buf) - t.max; over > 0 {
		t.buf = append(t.buf[:0], t.buf[over:]...)
	}
	return len(p), nil
}

func (t *tailBuffer) bytes() []byte {
	t.mu.Lock()
	defer t.mu.Unlock()
	return append([]byte(nil), t.buf...)
}

// childEnv is the whole environment of a tool: nothing is inherited from the bridge (its
// environment can hold the secret-store key or passwords). HOME and the temporary
// directory point below the state directory, so a tool writes nowhere else.
func childEnv(home, tmp string, extra ...string) []string {
	env := []string{"HOME=" + home, "TMPDIR=" + tmp}
	if runtime.GOOS == "windows" {
		// Windows programs need these to start; the home and temporary directories are the
		// same private ones.
		env = append(env, "USERPROFILE="+home, "TEMP="+tmp, "TMP="+tmp)
		for _, k := range []string{"SystemRoot", "SYSTEMROOT", "windir"} {
			if v := os.Getenv(k); v != "" {
				env = append(env, k+"="+v)
			}
		}
	}
	return append(env, extra...)
}
