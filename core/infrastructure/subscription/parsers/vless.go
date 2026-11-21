package parsers

import (
	"net/url"
	"strings"
)

type VLESSParser struct{}

func (p *VLESSParser) Supports(link string) bool {
	return strings.HasPrefix(strings.ToLower(link), "vless://")
}

func (p *VLESSParser) Parse(link string) (map[string]interface{}, error) {
	parsed, err := url.Parse(link)
	if err != nil {
		return nil, err
	}
	query := parsed.Query()
	outbound := map[string]interface{}{
		"type":        "vless",
		"tag":         decodeTag(parsed.Fragment),
		"server":      parsed.Hostname(),
		"server_port": parsePort(parsed.Port()),
		"uuid":        parsed.User.Username(),
	}
	if flow := query.Get("flow"); flow != "" {
		outbound["flow"] = flow
	}
	// VLESS Encryption (often paired with XHTTP): without it the server
	// rejects the handshake.
	if enc := strings.TrimSpace(query.Get("encryption")); enc != "" && enc != "none" {
		outbound["encryption"] = enc
	}
	parseSecurity(outbound, query, parsed.Hostname(), false)
	parseTransport(outbound, query)
	return outbound, nil
}
