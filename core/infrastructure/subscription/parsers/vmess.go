package parsers

import (
	"encoding/base64"
	"encoding/json"
	"net/url"
	"strconv"
	"strings"
)

type VMESSParser struct{}

func (p *VMESSParser) Supports(link string) bool {
	return strings.HasPrefix(strings.ToLower(link), "vmess://")
}

func (p *VMESSParser) Parse(link string) (map[string]interface{}, error) {
	data := strings.TrimPrefix(link, "vmess://")
	decoded, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		decoded, err = base64.RawStdEncoding.DecodeString(data)
		if err != nil {
			decoded, _ = base64.RawURLEncoding.DecodeString(data)
		}
	}
	var vmess map[string]interface{}
	if json.Unmarshal(decoded, &vmess) != nil {
		return nil, err
	}
	port := 443
	if p, ok := vmess["port"].(float64); ok {
		port = int(p)
	} else if p, ok := vmess["port"].(string); ok {
		port, _ = strconv.Atoi(p)
	}
	aid := 0
	switch a := vmess["aid"].(type) {
	case float64:
		aid = int(a)
	case string:
		aid, _ = strconv.Atoi(a)
	}
	security := getString(vmess, "scy")
	if security == "" {
		security = "auto"
	}
	outbound := map[string]interface{}{
		"type":        "vmess",
		"tag":         getString(vmess, "ps"),
		"server":      getString(vmess, "add"),
		"server_port": port,
		"uuid":        getString(vmess, "id"),
		"alter_id":    aid,
		"security":    security,
	}
	// The JSON form carries the same TLS/REALITY keys as the URL forms.
	q := url.Values{}
	for _, k := range []string{"sni", "fp", "alpn", "pbk", "sid", "spx", "pqv", "ech", "pcs", "vcn", "allowInsecure", "insecure"} {
		if v := vmessValue(vmess, k); v != "" {
			q.Set(k, v)
		}
	}
	q.Set("security", getString(vmess, "tls"))
	parseSecurity(outbound, q, getString(vmess, "add"), false)
	switch strings.ToLower(getString(vmess, "net")) {
	case "", "tcp", "raw":
		if transport := httpHeaderTransport(getString(vmess, "type"), getString(vmess, "host"), getString(vmess, "path")); transport != nil {
			outbound["transport"] = transport
		}
	case "kcp", "mkcp":
		// v2rayN keeps the mKCP seed in "path".
		outbound["transport"] = kcpTransport(getString(vmess, "type"), getString(vmess, "path"))
	case "ws":
		transport := map[string]interface{}{
			"type": "ws",
			"path": getString(vmess, "path"),
		}
		if host := getString(vmess, "host"); host != "" {
			transport["headers"] = map[string]interface{}{
				"Host": host,
			}
		}
		outbound["transport"] = transport
	case "grpc":
		transport := map[string]interface{}{
			"type":         "grpc",
			"service_name": getString(vmess, "path"),
		}
		if authority := getString(vmess, "authority"); authority != "" {
			transport["authority"] = authority
		}
		if strings.EqualFold(getString(vmess, "type"), "multi") || strings.EqualFold(getString(vmess, "mode"), "multi") {
			transport["multi_mode"] = true
		}
		outbound["transport"] = transport
	case "httpupgrade":
		transport := map[string]interface{}{
			"type": "httpupgrade",
			"path": getString(vmess, "path"),
		}
		if host := getString(vmess, "host"); host != "" {
			transport["host"] = host
		}
		outbound["transport"] = transport
	case "xhttp", "splithttp":
		// Shared vmess JSON often keeps the XHTTP mode in "type", but most
		// panels leave the header type there ("none"): that is not a mode.
		mode := getString(vmess, "mode")
		if t := getString(vmess, "type"); mode == "" && IsXHTTPMode(t) {
			mode = t
		}
		outbound["transport"] = xhttpTransport(getString(vmess, "path"), getString(vmess, "host"), mode, vmessExtra(vmess))
	case "h2", "http":
		transport := map[string]interface{}{
			"type": "http",
		}
		if path := getString(vmess, "path"); path != "" {
			transport["path"] = path
		}
		outbound["transport"] = transport
	}
	return outbound, nil
}

// vmessValue reads a string or boolean/number field of the vmess JSON.
func vmessValue(vmess map[string]interface{}, key string) string {
	switch v := vmess[key].(type) {
	case string:
		return v
	case bool:
		if v {
			return "1"
		}
	case float64:
		return strconv.Itoa(int(v))
	}
	return ""
}

// vmessExtra returns the XHTTP "extra" block, which clients write either as a
// JSON string or as a nested object.
func vmessExtra(vmess map[string]interface{}) string {
	switch extra := vmess["extra"].(type) {
	case string:
		return extra
	case map[string]interface{}:
		if data, err := json.Marshal(extra); err == nil {
			return string(data)
		}
	}
	return ""
}
