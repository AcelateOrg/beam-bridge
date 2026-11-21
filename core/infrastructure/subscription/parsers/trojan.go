package parsers

import (
	"net/url"
	"strings"
)

type TrojanParser struct{}

func (p *TrojanParser) Supports(link string) bool {
	return strings.HasPrefix(strings.ToLower(link), "trojan://")
}

func (p *TrojanParser) Parse(link string) (map[string]interface{}, error) {
	parsed, err := url.Parse(link)
	if err != nil {
		return nil, err
	}
	password, _ := parsed.User.Password()
	if password == "" {
		password = parsed.User.Username()
	}
	query := parsed.Query()
	outbound := map[string]interface{}{
		"type":        "trojan",
		"tag":         decodeTag(parsed.Fragment),
		"server":      parsed.Hostname(),
		"server_port": parsePort(parsed.Port()),
		"password":    password,
	}
	if flow := query.Get("flow"); flow != "" {
		outbound["flow"] = flow
	}
	parseSecurity(outbound, query, parsed.Hostname(), true)
	parseTransport(outbound, query)
	return outbound, nil
}
