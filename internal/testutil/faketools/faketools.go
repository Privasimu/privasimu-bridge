// Package faketools lets a test binary stand in for Syft, Grype and Trivy, so package
// scans are tested without downloading or running the real scanners. A test points the
// tool paths of the configuration at its own executable (os.Executable) with that file's
// SHA-256, and calls Main from TestMain.
//
// The bridge runs tools with an emptied environment, so the fake reads what to do from
// $HOME/fake-tools.json (HOME is the bridge's private home directory below the state
// directory), and records every call (arguments and environment) there too.
package faketools

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Behaviour is what one fake tool does.
type Behaviour struct {
	// StdoutFile is copied to standard output.
	StdoutFile string `json:"stdout_file"`
	// StdoutBytes writes that many bytes of filler instead (output limit tests).
	StdoutBytes int64  `json:"stdout_bytes"`
	Stderr      string `json:"stderr"`
	Exit        int    `json:"exit"`
	SleepMS     int    `json:"sleep_ms"`
}

// Control is $HOME/fake-tools.json: one behaviour per tool ("syft", "grype", "trivy",
// "trivy-version").
type Control map[string]Behaviour

// Call is one recorded invocation.
type Call struct {
	Tool string   `json:"tool"`
	Args []string `json:"args"`
	Env  []string `json:"env"`
}

// ControlFile and CallsFile are the names below HOME.
const (
	ControlFile = "fake-tools.json"
	CallsFile   = "fake-tools-calls.jsonl"
)

// toolOf names the tool an argument list belongs to ("" for a normal test run).
func toolOf(args []string) string {
	if len(args) < 2 {
		return ""
	}
	switch {
	case args[1] == "scan":
		return "syft"
	case strings.HasPrefix(args[1], "sbom:"):
		return "grype"
	case args[1] == "sbom":
		return "trivy"
	case args[1] == "version":
		return "trivy-version"
	}
	return ""
}

// Main acts as a fake tool when the process was started as one (it then exits) and
// returns false otherwise.
func Main() bool {
	tool := toolOf(os.Args)
	if tool == "" {
		return false
	}
	home := os.Getenv("HOME")
	if f, err := os.OpenFile(filepath.Join(home, CallsFile), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600); err == nil {
		raw, _ := json.Marshal(Call{Tool: tool, Args: os.Args[1:], Env: os.Environ()})
		_, _ = f.Write(append(raw, '\n'))
		f.Close()
	}
	var ctl Control
	if raw, err := os.ReadFile(filepath.Join(home, ControlFile)); err == nil {
		_ = json.Unmarshal(raw, &ctl)
	}
	b := ctl[tool]
	if b.SleepMS > 0 {
		time.Sleep(time.Duration(b.SleepMS) * time.Millisecond)
	}
	if b.StdoutFile != "" {
		if raw, err := os.ReadFile(b.StdoutFile); err == nil {
			_, _ = os.Stdout.Write(raw)
		}
	}
	if b.StdoutBytes > 0 {
		chunk := []byte(strings.Repeat("x", 64<<10))
		for left := b.StdoutBytes; left > 0; left -= int64(len(chunk)) {
			if _, err := os.Stdout.Write(chunk); err != nil {
				os.Exit(3)
			}
		}
	}
	if b.Stderr != "" {
		fmt.Fprintln(os.Stderr, b.Stderr)
	}
	os.Exit(b.Exit)
	return true
}

// Write stores the control file below home.
func Write(home string, c Control) error {
	if err := os.MkdirAll(home, 0o700); err != nil {
		return err
	}
	raw, err := json.Marshal(c)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(home, ControlFile), raw, 0o600)
}

// Calls reads the recorded invocations below home.
func Calls(home string) []Call {
	raw, err := os.ReadFile(filepath.Join(home, CallsFile))
	if err != nil {
		return nil
	}
	var out []Call
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		var c Call
		if json.Unmarshal([]byte(line), &c) == nil {
			out = append(out, c)
		}
	}
	return out
}
