//go:build !linux && !windows

package service

import (
	"context"
	"fmt"
	"io"
)

// Install prints the systemd unit for reference; other systems need their own setup.
func Install(s Spec, out io.Writer, dryRun bool) error {
	if !dryRun {
		return ErrUnsupported
	}
	unit, err := Unit(s)
	if err != nil {
		return err
	}
	fmt.Fprint(out, unit)
	return nil
}

// Uninstall is not supported here.
func Uninstall(string, io.Writer) error { return ErrUnsupported }

// RunIfService reports false: there is no service manager integration here.
func RunIfService(string, func(context.Context) error) (bool, error) { return false, nil }
