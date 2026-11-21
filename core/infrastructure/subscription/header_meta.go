package subscription

import (
	"encoding/json"
	"net/http"
	"strings"

	"beam-bridge/core/types"
)

// Panels (Remnawave, Marzban, ...) send subscription settings as HTTP
// headers, not as "#key: value" lines in the body. Same keys, same parser.
var headerMetaKeys = []string{
	"profile-web-page-url",
	"support-url",
	"announce",
	"icon-url",
	"logo-url",
	"community-url",
	"telegram-url",
	"banner-url",
	"banner-color",
	"banner-image",
	"providerid",
	"homepage",
	"announce-url",
}

// BrandingHeader carries the whole Beam branding block in one header:
// base64(JSON of types.Branding). Lets a panel set logo/colors through a
// custom response header without knowing every Beam key.
const BrandingHeader = "Beam-Branding"

const maxBrandingHeader = 16 << 10

func metaFromHeaders(header http.Header) *SubscriptionMeta {
	if header == nil {
		return nil
	}
	lines := make([]string, 0, len(headerMetaKeys))
	for _, key := range headerMetaKeys {
		value := strings.TrimSpace(header.Get(key))
		if value == "" || strings.ContainsAny(value, "\r\n") {
			continue
		}
		lines = append(lines, "#"+key+": "+value)
	}
	if len(lines) == 0 {
		return nil
	}
	return ParseSubscriptionMeta(lines)
}

// withHeaderMeta fills fields the body did not set from HTTP headers.
func withHeaderMeta(meta *SubscriptionMeta, header http.Header) *SubscriptionMeta {
	h := metaFromHeaders(header)
	if h == nil {
		return meta
	}
	if meta == nil {
		return h
	}
	fill := func(dst *string, src string) {
		if *dst == "" {
			*dst = src
		}
	}
	fill(&meta.WebPageURL, h.WebPageURL)
	fill(&meta.SupportURL, h.SupportURL)
	fill(&meta.Announce, h.Announce)
	fill(&meta.IconURL, h.IconURL)
	fill(&meta.CommunityURL, h.CommunityURL)
	fill(&meta.BannerURL, h.BannerURL)
	fill(&meta.BannerColor, h.BannerColor)
	fill(&meta.BannerImage, h.BannerImage)
	fill(&meta.ProviderID, h.ProviderID)
	return meta
}

func brandingFromHeader(header http.Header) *types.Branding {
	if header == nil {
		return nil
	}
	raw := strings.TrimSpace(header.Get(BrandingHeader))
	if raw == "" || len(raw) > maxBrandingHeader {
		return nil
	}
	data := []byte(raw)
	if !strings.HasPrefix(raw, "{") {
		decoded, err := decodeBase64(strings.TrimPrefix(raw, "base64:"))
		if err != nil {
			return nil
		}
		data = decoded
	}
	var b types.Branding
	if err := json.Unmarshal(data, &b); err != nil || b.Empty() {
		return nil
	}
	return &b
}

// Beam-only display switches, sent by the panel (Remnawave: Response Rule
// for user-agent "BEAM/").
const (
	NodeSubtitleHeader    = "Beam-Node-Subtitle"    // protocol | none
	GroupsCollapsedHeader = "Beam-Groups-Collapsed" // true: groups start folded
	ProviderBadgeHeader   = "Beam-Provider-Badge"   // none: hide the domain chip
)

func applyDisplayHeaders(d *types.BeamFileData, header http.Header) {
	if header == nil {
		return
	}
	if d.NodeSubtitle == "" {
		switch mode := strings.ToLower(strings.TrimSpace(header.Get(NodeSubtitleHeader))); mode {
		case types.NodeSubtitleNone, types.NodeSubtitleProtocol:
			d.NodeSubtitle = mode
		}
	}
	switch strings.ToLower(strings.TrimSpace(header.Get(ProviderBadgeHeader))) {
	case "none", "hide", "hidden", "false", "0", "off":
		d.HideProvider = true
	}
	if parseBoolMeta(header.Get(GroupsCollapsedHeader)) {
		for i := range d.Categories {
			d.Categories[i].Collapsed = true
		}
	}
}

// applyHeaderBranding adds branding sent as HTTP headers. Whatever the
// profile already has wins; Beam-Branding beats the generic keys.
// Values are sanitized later, when the profile is built.
func applyHeaderBranding(d *types.BeamFileData, header http.Header) {
	d.MergeBrandingFrom(brandingFromHeader(header))
	d.MergeBrandingFrom(brandingFromMeta(metaFromHeaders(header)))
}
