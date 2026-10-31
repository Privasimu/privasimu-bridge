//go:build !windows

package secrets

import "errors"

const (
	dpapiAvailable = false
	isWindows      = false
)

func protect([]byte) ([]byte, error)   { return nil, errors.New("DPAPI is only available on Windows") }
func unprotect([]byte) ([]byte, error) { return nil, errors.New("DPAPI is only available on Windows") }
