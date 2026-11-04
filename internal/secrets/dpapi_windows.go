//go:build windows

package secrets

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	dpapiAvailable = true
	isWindows      = true
)

// protect seals data with DPAPI in machine scope: any process on this machine can unseal
// it, no other machine can. The file ACL set by init limits who can read the file.
func protect(data []byte) ([]byte, error) {
	return dpapi(data, true)
}

func unprotect(data []byte) ([]byte, error) {
	return dpapi(data, false)
}

func dpapi(data []byte, seal bool) ([]byte, error) {
	if len(data) == 0 {
		return nil, ErrBadKey
	}
	if len(data) > 1<<20 {
		return nil, ErrBadKey
	}
	in := windows.DataBlob{Size: uint32(len(data)), Data: &data[0]} // #nosec G115 -- at most 1 MiB
	var out windows.DataBlob
	var err error
	flags := uint32(windows.CRYPTPROTECT_UI_FORBIDDEN)
	if seal {
		err = windows.CryptProtectData(&in, nil, nil, 0, nil, flags|windows.CRYPTPROTECT_LOCAL_MACHINE, &out)
	} else {
		err = windows.CryptUnprotectData(&in, nil, nil, 0, nil, flags, &out)
	}
	if err != nil {
		return nil, err
	}
	// out.Data and out.Size describe the buffer CryptUnprotectData allocated with LocalAlloc:
	// it is copied once and freed.
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(out.Data))) // #nosec G103 -- the documented way to free a DPAPI buffer
	result := make([]byte, out.Size)
	copy(result, unsafe.Slice(out.Data, out.Size)) // #nosec G103 -- bounded by out.Size from DPAPI
	return result, nil
}
