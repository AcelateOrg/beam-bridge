package parsers

import (
	"net/url"
	"strconv"
	"strings"
)

// WireGuardParser reads the v2rayN/Hiddify form:
// wireguard://<private key>@host:port?publickey=&address=&mtu=&reserved=&presharedkey=#name
type WireGuardParser struct{}

func (p *WireGuardParser) Supports(link string) bool {
	lower := strings.ToLower(link)
	return strings.HasPrefix(lower, "wireguard://") || strings.HasPrefix(lower, "wg://")
}

func (p *WireGuardParser) Parse(link string) (map[string]interface{}, error) {
	parsed, err := url.Parse(link)
	if err != nil {
		return nil, err
	}
	query := parsed.Query()
	privateKey := parsed.User.Username()
	if privateKey == "" {
		privateKey = query.Get("privatekey")
	}
	outbound := map[string]interface{}{
		"type":            "wireguard",
		"tag":             decodeTag(parsed.Fragment),
		"server":          parsed.Hostname(),
		"server_port":     parsePort(parsed.Port()),
		"private_key":     privateKey,
		"peer_public_key": firstOf(query, "publickey", "publicKey", "peer"),
	}
	if psk := firstOf(query, "presharedkey", "preSharedKey", "psk"); psk != "" {
		outbound["pre_shared_key"] = psk
	}
	if address := firstOf(query, "address", "ip"); address != "" {
		outbound["local_address"] = splitList(address)
	}
	if mtu, err := strconv.Atoi(query.Get("mtu")); err == nil && mtu > 0 {
		outbound["mtu"] = mtu
	}
	if reserved := query.Get("reserved"); reserved != "" {
		var bytes []interface{}
		for _, part := range strings.Split(reserved, ",") {
			if n, err := strconv.Atoi(strings.TrimSpace(part)); err == nil && n >= 0 && n < 256 {
				bytes = append(bytes, n)
			}
		}
		if len(bytes) == 3 {
			outbound["reserved"] = bytes
		}
	}
	return outbound, nil
}

func firstOf(query url.Values, keys ...string) string {
	for _, k := range keys {
		if v := query.Get(k); v != "" {
			return v
		}
	}
	return ""
}
