package subscription

import (
	"strconv"
	"strings"
)

type SubscriptionMeta struct {
	Title          string
	UpdateInterval int
	WebPageURL     string
	SupportURL     string
	IconURL        string
	CommunityURL   string
	ProviderID     string
	Announce       string
	BannerURL      string
	BannerColor    string
	BannerImage    string

	HideSettings     bool
	SubscriptionPin  bool
	PingOnOpen       bool
	AutoUpdate       bool
	AutoUpdateOnOpen bool

	Upload   int64
	Download int64
	Total    int64
	Expire   int64

	// Raw — все строки "#key: value" тела, ключ нижним регистром.
	Raw map[string]string
}

func ParseSubscriptionMeta(lines []string) *SubscriptionMeta {
	meta := &SubscriptionMeta{Raw: map[string]string{}}

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)

		if !strings.HasPrefix(trimmed, "#") {
			break
		}

		rest := strings.TrimPrefix(trimmed, "#")
		idx := strings.Index(rest, ": ")
		if idx == -1 {
			continue
		}

		key := strings.ToLower(strings.TrimSpace(rest[:idx]))
		value := strings.TrimSpace(rest[idx+2:])

		if value == "" {
			continue
		}
		meta.Raw[key] = value

		switch key {
		case "profile-title":
			meta.Title = decodeIfBase64(value)
		case "subscription-name":
			if meta.Title == "" {
				meta.Title = decodeIfBase64(value)
			}
		case "homepage":
			if meta.WebPageURL == "" {
				meta.WebPageURL = value
			}
		case "announce-url":
			meta.BannerURL = value
		case "profile-update-interval":
			meta.UpdateInterval, _ = strconv.Atoi(value)
		case "profile-web-page-url":
			meta.WebPageURL = value
		case "support-url":
			meta.SupportURL = value
		case "icon-url", "logo-url":
			meta.IconURL = value
		case "community-url", "telegram-url":
			meta.CommunityURL = value
		case "providerid":
			meta.ProviderID = value
		case "announce":
			meta.Announce = decodeAnnounce(value)
		case "banner-url":
			meta.BannerURL = value
		case "banner-color":
			meta.BannerColor = value
		case "banner-image":
			meta.BannerImage = value
		case "subscription-userinfo":
			parseUserInfoInto(value, meta)
		case "hide-settings":
			meta.HideSettings = parseBoolMeta(value)
		case "subscription-pin":
			meta.SubscriptionPin = parseBoolMeta(value)
		case "subscription-ping-onopen-enabled":
			meta.PingOnOpen = parseBoolMeta(value)
		case "subscription-auto-update-enable":
			meta.AutoUpdate = parseBoolMeta(value)
		case "subscription-auto-update-open-enable":
			meta.AutoUpdateOnOpen = parseBoolMeta(value)
		case "subscription-always-hwid-enable",
			"subscriptions-collapse":
		default:
		}
	}

	return meta
}

func IsMetaLine(line string) bool {
	trimmed := strings.TrimSpace(line)
	if !strings.HasPrefix(trimmed, "#") {
		return false
	}
	rest := strings.TrimPrefix(trimmed, "#")
	return strings.Contains(rest, ": ")
}

func decodeAnnounce(value string) string {
	if strings.HasPrefix(value, "base64:") {
		encoded := strings.TrimPrefix(value, "base64:")
		if decoded, err := decodeBase64(encoded); err == nil && len(decoded) > 0 {
			return strings.TrimSpace(string(decoded))
		}
	}
	return value
}

func decodeIfBase64(value string) string {
	if strings.HasPrefix(value, "base64:") {
		encoded := strings.TrimPrefix(value, "base64:")
		if decoded, err := decodeBase64(encoded); err == nil && len(decoded) > 0 {
			return strings.TrimSpace(string(decoded))
		}
	}
	return value
}

func parseBoolMeta(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "true", "1", "yes":
		return true
	}
	return false
}

func parseUserInfoInto(value string, meta *SubscriptionMeta) {
	parts := strings.Split(value, ";")
	for _, part := range parts {
		kv := strings.SplitN(strings.TrimSpace(part), "=", 2)
		if len(kv) != 2 {
			continue
		}
		k := strings.TrimSpace(kv[0])
		v, err := strconv.ParseInt(strings.TrimSpace(kv[1]), 10, 64)
		if err != nil {
			continue
		}
		switch k {
		case "upload":
			meta.Upload = v
		case "download":
			meta.Download = v
		case "total":
			meta.Total = v
		case "expire":
			meta.Expire = normalizeExpire(v)
		}
	}
}

// normalizeExpire: INCY разрешает expire в миллисекундах; секунды до
// 32000000000 — это примерно 2984 год, так что больше — точно мс.
func normalizeExpire(v int64) int64 {
	if v > 32000000000 {
		return v / 1000
	}
	return v
}
