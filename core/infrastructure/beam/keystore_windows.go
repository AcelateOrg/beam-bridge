//go:build windows

package beam

// On Windows the master key is wrapped with DPAPI at the current-user scope,
// so only this Windows account can unwrap it and only on this machine. An
// extra app entropy string means a raw DPAPI call from another program still
// needs the value compiled into this binary.

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

// appEntropy is mixed into every DPAPI blob. It is not a secret store on its
// own; it just means another process cannot unwrap the key with a bare
// CryptUnprotectData call.
var appEntropy = []byte("beam.profile.store.v1\x00\xa7\x3e\x91")

func dpapiBlob(b []byte) *windows.DataBlob {
	if len(b) == 0 {
		return &windows.DataBlob{}
	}
	return &windows.DataBlob{Size: uint32(len(b)), Data: &b[0]}
}

func protect(plain []byte) ([]byte, error) {
	in := dpapiBlob(plain)
	entropy := dpapiBlob(appEntropy)
	var out windows.DataBlob
	if err := windows.CryptProtectData(in, nil, entropy, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out); err != nil {
		return nil, err
	}
	defer localFree(out.Data)
	return copyBlob(&out), nil
}

func unprotect(wrapped []byte) ([]byte, error) {
	in := dpapiBlob(wrapped)
	entropy := dpapiBlob(appEntropy)
	var out windows.DataBlob
	if err := windows.CryptUnprotectData(in, nil, entropy, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out); err != nil {
		return nil, err
	}
	defer localFree(out.Data)
	return copyBlob(&out), nil
}

func copyBlob(b *windows.DataBlob) []byte {
	if b.Size == 0 || b.Data == nil {
		return nil
	}
	src := unsafe.Slice(b.Data, b.Size)
	out := make([]byte, b.Size)
	copy(out, src)
	return out
}

func localFree(p *byte) {
	if p != nil {
		_, _ = windows.LocalFree(windows.Handle(unsafe.Pointer(p)))
	}
}
