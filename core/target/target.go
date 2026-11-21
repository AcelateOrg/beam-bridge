package target

import (
	"encoding/base64"
	"errors"
	"net/url"
	"os"
	"strings"

	"beam-bridge/core/profile"
	"beam-bridge/core/types"
)

var ErrUnsupported = errors.New("unknown link or file format")

// maxLinkPayload bounds an inline beam:// profile. A real one is a few
// kilobytes; the OS command line ends near 32K anyway.
const maxLinkPayload = 256 << 10

var ErrLinkTooLong = errors.New("the beam:// link is too long")

type Resolver struct {
	profiles *profile.Manager
}

func NewResolver(profiles *profile.Manager) *Resolver {
	return &Resolver{profiles: profiles}
}

func (r *Resolver) Open(target string) (*types.Profile, error) {
	normalized := strings.TrimSpace(target)
	if normalized == "" {
		return nil, ErrUnsupported
	}

	lower := strings.ToLower(normalized)
	switch {
	case strings.HasPrefix(lower, "beam:"):
		return r.openBeamURL(normalized)
	case strings.HasPrefix(lower, "http://"), strings.HasPrefix(lower, "https://"):
		return r.openSubscription(normalized)
	case strings.HasSuffix(lower, ".beam"):
		data, err := os.ReadFile(normalized)
		if err != nil {
			return nil, err
		}
		return r.OpenBeamData(data)
	default:
		return nil, ErrUnsupported
	}
}

func Supports(target string) bool {
	lower := strings.ToLower(strings.TrimSpace(target))
	if lower == "" {
		return false
	}
	return strings.HasPrefix(lower, "beam:") ||
		strings.HasPrefix(lower, "http://") ||
		strings.HasPrefix(lower, "https://") ||
		strings.HasSuffix(lower, ".beam")
}

func (r *Resolver) OpenBeamData(data []byte) (*types.Profile, error) {
	imported, err := r.profiles.ImportFromBeam(data)
	if err != nil {
		return nil, err
	}
	_ = r.profiles.GetStorage().SetActive(imported.ID)
	return imported, nil
}

func (r *Resolver) openSubscription(rawURL string) (*types.Profile, error) {
	imported, err := r.profiles.ImportFromURL(rawURL)
	if err != nil {
		return nil, err
	}
	_ = r.profiles.GetStorage().SetActive(imported.ID)
	return imported, nil
}

func (r *Resolver) openBeamURL(raw string) (*types.Profile, error) {
	parsed, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}

	if importURL := strings.TrimSpace(parsed.Query().Get("url")); importURL != "" {
		return r.openSubscription(importURL)
	}

	payload := strings.TrimSpace(parsed.Query().Get("data"))

	// "add" mirrors happ://add/ so panel configs copied from Happ just work.
	if payload == "" && (strings.EqualFold(parsed.Host, "import") || strings.EqualFold(parsed.Host, "add")) {
		payload = strings.TrimPrefix(parsed.EscapedPath(), "/")

		lower := strings.ToLower(payload)
		if strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://") {
			if parsed.RawQuery != "" {
				payload += "?" + parsed.RawQuery
			}
		}
	}

	if payload == "" && parsed.Opaque != "" {
		payload = parsed.Opaque
	}

	if payload == "" {
		return nil, ErrUnsupported
	}

	lowerPayload := strings.ToLower(payload)
	if strings.HasPrefix(lowerPayload, "http://") || strings.HasPrefix(lowerPayload, "https://") {
		return r.openSubscription(payload)
	}

	data, err := decodePayload(payload)
	if err != nil {
		return nil, err
	}
	return r.OpenBeamData(data)
}

func decodePayload(encoded string) ([]byte, error) {
	if len(encoded) > maxLinkPayload {
		return nil, ErrLinkTooLong
	}
	payload := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(encoded), "/"))
	if payload == "" {
		return nil, errors.New("empty BEAM payload")
	}
	payload = strings.ReplaceAll(payload, " ", "+")

	encodings := []*base64.Encoding{
		base64.RawURLEncoding,
		base64.URLEncoding,
		base64.RawStdEncoding,
		base64.StdEncoding,
	}
	for _, encoding := range encodings {
		if decoded, err := encoding.DecodeString(payload); err == nil {
			return decoded, nil
		}
	}
	return nil, errors.New("BEAM payload is not valid base64")
}
