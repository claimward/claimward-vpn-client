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
		rand.Read(k) // never fails: it ends the program if the system has no entropy
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

// gcm builds the AEAD for a 32-byte key; key() only returns such keys, for
// which neither call can fail.
func gcm(key []byte) cipher.AEAD {
	blk, _ := aes.NewCipher(key)
	g, _ := cipher.NewGCM(blk)
	return g
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
	g := gcm(k)
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
	g := gcm(k)
	nonce := make([]byte, g.NonceSize())
	rand.Read(nonce) // never fails, see key
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
	if err := removeIfPresent(p); err != nil {
		return err
	}
	return b.kr.del()
}
