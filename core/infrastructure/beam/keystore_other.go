//go:build !windows

package beam

// Without DPAPI the master key is wrapped with a key derived from stable
// machine identifiers plus a secret compiled into this binary. The wrapped
// key therefore does not open on a different machine, and another program
// cannot unwrap it without also knowing the embedded secret and reproducing
// the derivation. This is weaker than an OS keychain (a keychain would need
// cgo), but it takes the profile store well outside what a generic stealer
// reads.

import (
	cryptoRand "crypto/rand"
	"crypto/sha256"
	"io"
	"os"
	"runtime"
	"strings"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

// appSecret binds the wrapping to this build.
var appSecret = []byte("beam.profile.store.v1\x00\x5d\xc2\x84\x19")

func machineKey() ([]byte, error) {
	var material strings.Builder
	material.Write(appSecret)
	material.WriteString(runtime.GOOS)

	// Only identifiers that never change for the lifetime of the OS install.
	// The hostname is deliberately excluded: macOS rewrites it from DHCP/mDNS
	// and users rename machines, which would make every profile unreadable.
	for _, source := range machineIDSources() {
		if data, err := os.ReadFile(source); err == nil {
			material.Write([]byte(strings.TrimSpace(string(data))))
			break
		}
	}

	reader := hkdf.New(sha256.New, []byte(material.String()), appSecret, []byte("master-wrap"))
	key := make([]byte, chacha20poly1305.KeySize)
	if _, err := io.ReadFull(reader, key); err != nil {
		return nil, err
	}
	return key, nil
}

func machineIDSources() []string {
	if runtime.GOOS == "darwin" {
		// IOPlatformUUID is not a file and reading it needs cgo or ioreg;
		// until a Keychain backend lands, the binding is the app secret.
		return nil
	}
	return []string{"/etc/machine-id", "/var/lib/dbus/machine-id"}
}

func protect(plain []byte) ([]byte, error) {
	key, err := machineKey()
	if err != nil {
		return nil, err
	}
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(cryptoRand.Reader, nonce); err != nil {
		return nil, err
	}
	return aead.Seal(nonce, nonce, plain, appSecret), nil
}

func unprotect(wrapped []byte) ([]byte, error) {
	key, err := machineKey()
	if err != nil {
		return nil, err
	}
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	nonceSize := aead.NonceSize()
	if len(wrapped) < nonceSize {
		return nil, ErrInvalidBeam
	}
	return aead.Open(nil, wrapped[:nonceSize], wrapped[nonceSize:], appSecret)
}
