package parsers

import (
	"encoding/base64"
	"errors"
	"net/url"
	"strings"
)

type ShadowsocksParser struct{}

func (p *ShadowsocksParser) Supports(link string) bool {
	lower := strings.ToLower(link)
	return strings.HasPrefix(lower, "ss://") || strings.HasPrefix(lower, "shadowsocks://")
}

func (p *ShadowsocksParser) Parse(link string) (map[string]interface{}, error) {
	link = strings.TrimPrefix(link, "shadowsocks://")
	link = strings.TrimPrefix(link, "ss://")
	var tag string
	if idx := strings.LastIndex(link, "#"); idx != -1 {
		tag = link[idx+1:]
		link = link[:idx]
	}
	// Legacy form: the whole "method:password@host:port" is base64.
	if !strings.Contains(link, "@") {
		body, query, _ := strings.Cut(link, "?")
		if decoded := decodeAnyBase64(strings.TrimSuffix(body, "/")); strings.Contains(decoded, "@") {
			link = decoded
			if query != "" {
				link += "?" + query
			}
		}
	}
	parsed, err := url.Parse("ss://" + link)
	if err != nil {
		return nil, err
	}
	userInfo := parsed.User.String()
	if u, perr := url.PathUnescape(userInfo); perr == nil {
		userInfo = u
	}
	var method, password string
	if decoded := decodeAnyBase64(userInfo); decoded != "" {
		method, password, _ = strings.Cut(decoded, ":")
	}
	if method == "" || password == "" {
		method, password, _ = strings.Cut(userInfo, ":")
	}
	if method == "" || password == "" {
		return nil, errors.New("shadowsocks: no method or password")
	}
	outbound := map[string]interface{}{
		"type":        "shadowsocks",
		"tag":         decodeTag(tag),
		"server":      parsed.Hostname(),
		"server_port": parsePort(parsed.Port()),
		"method":      method,
		"password":    password,
	}
	query := parsed.Query()
	if plugin := query.Get("plugin"); plugin != "" {
		// SIP003 plugins (obfs-local, v2ray-plugin) do not exist in Xray;
		// kept so the converter can say why the server does not work.
		name, opts, _ := strings.Cut(plugin, ";")
		outbound["plugin"] = name
		if opts != "" {
			outbound["plugin_opts"] = opts
		}
	}
	parseSecurity(outbound, query, parsed.Hostname(), false)
	parseTransport(outbound, query)
	return outbound, nil
}

func decodeAnyBase64(s string) string {
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if decoded, err := enc.DecodeString(s); err == nil && len(decoded) > 0 {
			return string(decoded)
		}
	}
	return ""
}
