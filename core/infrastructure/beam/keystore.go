package beam

// The keystore holds one random 32-byte master key per installation. Every
// profile file and the sensitive settings fields are encrypted with keys
// derived from it, so the files on disk are useless to another program or on
// another machine. The master key itself is wrapped by the OS (DPAPI on
// Windows) or bound to the machine (see keystore_other.go), never stored in
// the clear.

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

const keystoreFile = ".bkeystore"

// ErrNoKeystore means encryption was requested before InitKeystore ran. In
// that state the package falls back to the plaintext interchange format so
// tests and tools keep working, but the desktop always initialises it.
var ErrNoKeystore = errors.New("beam keystore not initialised")

type keystore struct {
	master []byte
}

var (
	activeMu       sync.RWMutex
	activeKeystore *keystore
)

// InitKeystore loads the installation's master key from dataDir, creating and
// wrapping a fresh one on first run. It is safe to call more than once.
func InitKeystore(dataDir string) error {
	k, err := openKeystore(dataDir)
	if err != nil {
		return err
	}
	activeMu.Lock()
	activeKeystore = k
	activeMu.Unlock()
	return nil
}

// KeystoreReady reports whether encryption is available.
func KeystoreReady() bool {
	activeMu.RLock()
	defer activeMu.RUnlock()
	return activeKeystore != nil
}

func currentKeystore() *keystore {
	activeMu.RLock()
	defer activeMu.RUnlock()
	return activeKeystore
}

func openKeystore(dataDir string) (*keystore, error) {
	path := filepath.Join(dataDir, keystoreFile)
	blob, err := os.ReadFile(path)
	switch {
	case err == nil:
		// An existing key is never overwritten: if it cannot be unwrapped the
		// profiles are unreadable anyway, and regenerating would only make it
		// permanent. Surface the error instead.
		master, uerr := unprotect(blob)
		if uerr != nil {
			return nil, fmt.Errorf("beam keystore: %w", uerr)
		}
		if len(master) != 32 {
			return nil, fmt.Errorf("beam keystore: unexpected key size %d", len(master))
		}
		return &keystore{master: master}, nil
	case !os.IsNotExist(err):
		return nil, err
	}

	master := make([]byte, 32)
	if _, err := rand.Read(master); err != nil {
		return nil, err
	}
	wrapped, err := protect(master)
	if err != nil {
		return nil, err
	}
	// Atomic: a torn keystore would lock the user out of every profile.
	if err := writeFileAtomic(path, wrapped); err != nil {
		return nil, err
	}
	return &keystore{master: master}, nil
}

// derive produces a per-purpose subkey so a leak of one ciphertext's key does
// not reveal the master or any other file's key.
func (k *keystore) derive(info string) ([]byte, error) {
	reader := hkdf.New(sha256.New, k.master, nil, []byte(info))
	key := make([]byte, chacha20poly1305.KeySize)
	if _, err := io.ReadFull(reader, key); err != nil {
		return nil, err
	}
	return key, nil
}

// seal returns nonce||ciphertext, authenticating aad without storing it.
func (k *keystore) seal(info string, plaintext, aad []byte) ([]byte, error) {
	key, err := k.derive(info)
	if err != nil {
		return nil, err
	}
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return aead.Seal(nonce, nonce, plaintext, aad), nil
}

func (k *keystore) open(info string, blob, aad []byte) ([]byte, error) {
	key, err := k.derive(info)
	if err != nil {
		return nil, err
	}
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	nonceSize := aead.NonceSize()
	if len(blob) < nonceSize {
		return nil, ErrInvalidBeam
	}
	return aead.Open(nil, blob[:nonceSize], blob[nonceSize:], aad)
}

// SealString encrypts a small sensitive settings value (e.g. the HWID) and
// returns an opaque token. It fails when the keystore is not ready so callers
// can fall back to plaintext.
func SealString(info, plain string) (string, error) {
	k := currentKeystore()
	if k == nil {
		return "", ErrNoKeystore
	}
	sealed, err := k.seal("settings:"+info, []byte(plain), []byte(info))
	if err != nil {
		return "", err
	}
	return encodeToken(sealed), nil
}

// OpenString reverses SealString.
func OpenString(info, token string) (string, error) {
	k := currentKeystore()
	if k == nil {
		return "", ErrNoKeystore
	}
	blob, err := decodeToken(token)
	if err != nil {
		return "", err
	}
	plain, err := k.open("settings:"+info, blob, []byte(info))
	if err != nil {
		return "", err
	}
	return string(plain), nil
}
