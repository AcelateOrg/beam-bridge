package parsers

import (
	"net/url"
	"strings"
)

// SocksParser reads socks://, socks5:// and v2rayN's socks://base64(user:pass)@host:port.
type SocksParser struct{}

func (p *SocksParser) Supports(link string) bool {
	lower := strings.ToLower(link)
	return strings.HasPrefix(lower, "socks://") || strings.HasPrefix(lower, "socks5://")
}

func (p *SocksParser) Parse(link string) (map[string]interface{}, error) {
	parsed, err := url.Parse(link)
	if err != nil {
		return nil, err
	}
	outbound := map[string]interface{}{
		"type":        "socks",
		"tag":         decodeTag(parsed.Fragment),
		"server":      parsed.Hostname(),
		"server_port": parsePort(parsed.Port()),
	}
	user := parsed.User.Username()
	pass, hasPass := parsed.User.Password()
	if !hasPass && user != "" {
		if decoded := decodeAnyBase64(user); strings.Contains(decoded, ":") {
			user, pass, _ = strings.Cut(decoded, ":")
		}
	}
	if user != "" {
		outbound["username"] = user
		outbound["password"] = pass
	}
	return outbound, nil
}
