package tokenstore

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// keyring holds one short secret in a platform secret store. The session
// itself is too long for the command-line front ends of those stores, so it is
// sealed with AES-256-GCM and only the key lives in the keyring.
type keyring interface {
	get() (string, error) // errNotFound when empty
	set(string) error
	del() error // a missing entry is not an error
}

// sealedBackend keeps the session as an AES-GCM blob in the config dir, the
// key in a keyring.
type sealedBackend struct{ kr keyring }

func sealedPath() (string, error) {
	p, err := Path()
	if err != nil {
		return "", err
	}
	return filepath.Join(filepath.Dir(p), "session.enc"), nil
}

// key returns the sealing key, creating and storing one when create is set.
func (b sealedBackend) key(create bool) ([]byte, error) {
	h, err := b.kr.get()
	if errors.Is(err, errNotFound) && create {
		k := make([]byte, 32)
		if _, err := rand.Read(k); err != nil {
			return nil, err
		}
		if err := b.kr.set(hex.EncodeToString(k)); err != nil {
			return nil, err
		}
		return k, nil
	}
	if err != nil {
		return nil, err
	}
	k, err := hex.DecodeString(h)
	if err != nil || len(k) != 32 {
		return nil, errors.New("tokenstore: the stored sealing key is malformed")
	}
	return k, nil
}

func gcm(key []byte) (cipher.AEAD, error) {
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(blk)
}

func (b sealedBackend) get() ([]byte, error) {
	p, err := sealedPath()
	if err != nil {
		return nil, err
	}
	blob, err := os.ReadFile(p)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, errNotFound
	}
	if err != nil {
		return nil, err
	}
	k, err := b.key(false)
	if errors.Is(err, errNotFound) {
		return nil, fmt.Errorf("tokenstore: the sealing key is missing from the secret store; log in again")
	}
	if err != nil {
		return nil, err
	}
	g, err := gcm(k)
	if err != nil {
		return nil, err
	}
	if len(blob) < g.NonceSize() {
		return nil, errors.New("tokenstore: the sealed session is truncated")
	}
	return g.Open(nil, blob[:g.NonceSize()], blob[g.NonceSize():], nil)
}

func (b sealedBackend) set(data []byte) error {
	k, err := b.key(true)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrNoSecretStore, err)
	}
	g, err := gcm(k)
	if err != nil {
		return err
	}
	nonce := make([]byte, g.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	p, err := sealedPath()
	if err != nil {
		return err
	}
	return writeAtomic(p, g.Seal(nonce, nonce, data, nil))
}

func (b sealedBackend) del() error {
	p, err := sealedPath()
	if err != nil {
		return err
	}
	if err := os.Remove(p); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return b.kr.del()
}
