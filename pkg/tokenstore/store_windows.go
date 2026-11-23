package tokenstore

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
)

func platformBackend() backend { return dpapi{} }

// dpapi seals the session with the user's DPAPI key (CryptProtectData): only
// that user, on that machine, can open the blob.
type dpapi struct{}

func dpapiPath() (string, error) {
	p, err := Path()
	if err != nil {
		return "", err
	}
	return filepath.Join(filepath.Dir(p), "session.dpapi"), nil
}

func blobOf(b []byte) *windows.DataBlob {
	if len(b) == 0 {
		return &windows.DataBlob{}
	}
	return &windows.DataBlob{Size: uint32(len(b)), Data: &b[0]}
}

func (dpapi) get() ([]byte, error) {
	p, err := dpapiPath()
	if err != nil {
		return nil, err
	}
	enc, err := os.ReadFile(p)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, errNotFound
	}
	if err != nil {
		return nil, err
	}
	var out windows.DataBlob
	if err := windows.CryptUnprotectData(blobOf(enc), nil, nil, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out); err != nil {
		return nil, err
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(out.Data)))
	return append([]byte(nil), unsafe.Slice(out.Data, out.Size)...), nil
}

func (dpapi) set(data []byte) error {
	var out windows.DataBlob
	if err := windows.CryptProtectData(blobOf(data), nil, nil, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out); err != nil {
		return err
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(out.Data)))
	p, err := dpapiPath()
	if err != nil {
		return err
	}
	return writeAtomic(p, unsafe.Slice(out.Data, out.Size))
}

func (dpapi) del() error {
	p, err := dpapiPath()
	if err != nil {
		return err
	}
	if err := os.Remove(p); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}
