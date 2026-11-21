package types

import (
	"net/url"
	"regexp"
	"strings"
)

// Branding comes from whoever produced the profile (a .beam file, a beam://
// link, subscription headers) and ends up in the UI as <img src>, CSS
// background-image and clickable links. Everything is checked before it gets
// there: images are https or a small inline data:image, links are http(s),
// tg or mailto, colours are plain CSS colours.

// MaxInlineImage bounds an inline data: image (the whole URI). It fits a
// 64x64 logo with room to spare and keeps beam:// links short.
const MaxInlineImage = 12 * 1024

// MaxInlineBanner bounds an inline profile banner: a vector SVG art usually
// takes 10-60 KB, raster banners should be served over https instead.
const MaxInlineBanner = 96 * 1024

var (
	dataImagePattern = regexp.MustCompile(`^data:image/(png|jpeg|jpg|webp|gif|svg\+xml);base64,[A-Za-z0-9+/=]+$`)
	colorPattern     = regexp.MustCompile(`^(#[0-9a-fA-F]{3,8}|[a-zA-Z]{3,20}|rgba?\(\s*[0-9.%]+\s*,\s*[0-9.%]+\s*,\s*[0-9.%]+\s*(,\s*[0-9.%]+\s*)?\)|hsla?\(\s*[0-9.]+(deg)?\s*,\s*[0-9.]+%\s*,\s*[0-9.]+%\s*(,\s*[0-9.%]+\s*)?\))$`)
)

// SafeImageURL returns u if it is an https URL or an inline data:image within
// MaxInlineImage, otherwise "".
func SafeImageURL(u string) string {
	return safeImage(u, MaxInlineImage)
}

// SafeBannerURL is SafeImageURL with the larger MaxInlineBanner limit.
func SafeBannerURL(u string) string {
	return safeImage(u, MaxInlineBanner)
}

func safeImage(u string, inlineLimit int) string {
	u = strings.TrimSpace(u)
	if u == "" {
		return ""
	}
	if strings.HasPrefix(strings.ToLower(u), "data:") {
		if len(u) <= inlineLimit && dataImagePattern.MatchString(u) {
			return u
		}
		return ""
	}
	parsed, err := url.Parse(u)
	if err != nil || !strings.EqualFold(parsed.Scheme, "https") || parsed.Host == "" {
		return ""
	}
	return safeCSSURL(u)
}

// SafeLinkURL returns u if it is an http(s), tg or mailto link, otherwise "".
func SafeLinkURL(u string) string {
	u = strings.TrimSpace(u)
	if u == "" {
		return ""
	}
	parsed, err := url.Parse(u)
	if err != nil {
		return ""
	}
	switch strings.ToLower(parsed.Scheme) {
	case "https", "http":
		if parsed.Host == "" {
			return ""
		}
		return u
	case "tg", "mailto":
		return u
	}
	return ""
}

// SafeColor returns c if it is a plain CSS colour, otherwise "".
func SafeColor(c string) string {
	c = strings.TrimSpace(c)
	if c == "" || !colorPattern.MatchString(c) {
		return ""
	}
	return c
}

// safeCSSURL rejects characters that would end a CSS url(...) early.
func safeCSSURL(u string) string {
	if strings.ContainsAny(u, "()'\"\\ \n\r\t") {
		return ""
	}
	return u
}

// Sanitize drops every value that is not safe to show (see above).
func (b *Branding) Sanitize() {
	if b == nil {
		return
	}
	b.IconURL = SafeImageURL(b.IconURL)
	b.BannerImage = SafeBannerURL(b.BannerImage)
	b.BannerColor = SafeColor(b.BannerColor)
	b.BannerURL = SafeLinkURL(b.BannerURL)
	b.WebPageURL = SafeLinkURL(b.WebPageURL)
	b.SupportURL = SafeLinkURL(b.SupportURL)
	b.CommunityURL = SafeLinkURL(b.CommunityURL)
}
