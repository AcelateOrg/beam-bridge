package beam

import (
	"encoding/base64"
)

// sealed settings values are stored as "enc:v1:<base64>" so a plaintext value
// and an encrypted one can never be confused during migration.
const sealedPrefix = "enc:v1:"

func encodeToken(blob []byte) string {
	return sealedPrefix + base64.RawStdEncoding.EncodeToString(blob)
}

func decodeToken(token string) ([]byte, error) {
	if len(token) < len(sealedPrefix) || token[:len(sealedPrefix)] != sealedPrefix {
		return nil, ErrInvalidBeam
	}
	return base64.RawStdEncoding.DecodeString(token[len(sealedPrefix):])
}

// IsSealed reports whether a settings value is one produced by SealString.
func IsSealed(token string) bool {
	return len(token) >= len(sealedPrefix) && token[:len(sealedPrefix)] == sealedPrefix
}

func decodeBase64(s string) ([]byte, error) {
	if decoded, err := base64.StdEncoding.DecodeString(s); err == nil {
		return decoded, nil
	}
	if decoded, err := base64.RawStdEncoding.DecodeString(s); err == nil {
		return decoded, nil
	}
	if decoded, err := base64.URLEncoding.DecodeString(s); err == nil {
		return decoded, nil
	}
	return base64.RawURLEncoding.DecodeString(s)
}
