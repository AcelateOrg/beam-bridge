package parsers

import (
	"encoding/json"
	"net/url"
	"strconv"
	"strings"
)

func IsServiceOutbound(obType string) bool {
	return isServiceOutbound(obType)
}

func decodeTag(s string) string {
	decoded, err := url.QueryUnescape(s)
	if err != nil {
		return s
	}
	return decoded
}

func parsePort(s string) int {
	if s == "" {
		return 443
	}
	port, err := strconv.Atoi(s)
	if err != nil {
		return 443
	}
	return port
}

func getFingerprint(fp string) string {
	if fp == "" {
		return "chrome"
	}
	return fp
}

func getString(m map[string]interface{}, key string) string {
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}

func isServiceOutbound(obType string) bool {
	serviceTypes := map[string]bool{
		"selector": true,
		"direct":   true,
		"block":    true,
		"dns":      true,
		"urltest":  true,
	}
	return serviceTypes[obType]
}

func parseTransport(outbound map[string]interface{}, query url.Values) {
	switch strings.ToLower(query.Get("type")) {
	case "ws", "websocket":
		transport := map[string]interface{}{
			"type": "ws",
			"path": query.Get("path"),
		}
		if host := query.Get("host"); host != "" {
			transport["headers"] = map[string]interface{}{
				"Host": host,
			}
		}
		outbound["transport"] = transport
	case "grpc", "gun":
		transport := map[string]interface{}{
			"type":         "grpc",
			"service_name": query.Get("serviceName"),
		}
		if authority := query.Get("authority"); authority != "" {
			transport["authority"] = authority
		}
		if strings.EqualFold(query.Get("mode"), "multi") {
			transport["multi_mode"] = true
		}
		outbound["transport"] = transport
	case "httpupgrade":
		transport := map[string]interface{}{
			"type": "httpupgrade",
			"path": query.Get("path"),
		}
		if host := query.Get("host"); host != "" {
			transport["host"] = host
		}
		outbound["transport"] = transport
	case "xhttp", "splithttp":
		outbound["transport"] = xhttpTransport(query.Get("path"), query.Get("host"), query.Get("mode"), query.Get("extra"))
	case "kcp", "mkcp":
		outbound["transport"] = kcpTransport(query.Get("headerType"), query.Get("seed"))
	case "", "tcp", "raw":
		if transport := httpHeaderTransport(query.Get("headerType"), query.Get("host"), query.Get("path")); transport != nil {
			outbound["transport"] = transport
		}
	case "http", "h2":
		// Kept as is so the core converter can report it: Xray dropped the
		// HTTP/2 transport and there is nothing equivalent to map it to.
		transport := map[string]interface{}{
			"type": "http",
		}
		if path := query.Get("path"); path != "" {
			transport["path"] = path
		}
		if host := query.Get("host"); host != "" {
			transport["host"] = []string{host}
		}
		outbound["transport"] = transport
	case "quic":
		outbound["transport"] = map[string]interface{}{"type": "quic"}
	}
}

func kcpTransport(headerType, seed string) map[string]interface{} {
	transport := map[string]interface{}{"type": "kcp"}
	if headerType != "" && headerType != "none" {
		transport["header_type"] = headerType
	}
	if seed != "" {
		transport["seed"] = seed
	}
	return transport
}

// httpHeaderTransport is raw TCP disguised as HTTP/1.1 (headerType=http);
// host and path are comma-separated lists in share links.
func httpHeaderTransport(headerType, host, path string) map[string]interface{} {
	if !strings.EqualFold(headerType, "http") {
		return nil
	}
	request := map[string]interface{}{}
	if path != "" {
		request["path"] = splitList(path)
	}
	if host != "" {
		request["headers"] = map[string]interface{}{"Host": splitList(host)}
	}
	header := map[string]interface{}{"type": "http"}
	if len(request) > 0 {
		header["request"] = request
	}
	return map[string]interface{}{"type": "raw", "header": header}
}

func splitList(s string) []interface{} {
	parts := strings.Split(s, ",")
	out := make([]interface{}, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// parseSecurity reads the TLS/REALITY part of a share link (the XTLS share
// link standard plus the common client extensions). defaultTLS is for
// trojan, which means TLS when the link says nothing.
func parseSecurity(outbound map[string]interface{}, query url.Values, host string, defaultTLS bool) {
	security := strings.ToLower(query.Get("security"))
	if security == "" && defaultTLS {
		security = "tls"
	}
	switch security {
	case "reality":
		reality := map[string]interface{}{
			"enabled":    true,
			"public_key": query.Get("pbk"),
			"short_id":   query.Get("sid"),
		}
		if spx := query.Get("spx"); spx != "" {
			reality["spider_x"] = spx
		}
		if pqv := query.Get("pqv"); pqv != "" {
			reality["mldsa65_verify"] = pqv
		}
		outbound["tls"] = map[string]interface{}{
			"enabled":     true,
			"server_name": query.Get("sni"),
			"utls": map[string]interface{}{
				"enabled":     true,
				"fingerprint": getFingerprint(query.Get("fp")),
			},
			"reality": reality,
		}
	case "tls", "xtls":
		sni := query.Get("sni")
		if sni == "" {
			sni = query.Get("peer")
		}
		if sni == "" && defaultTLS {
			sni = host
		}
		tls := map[string]interface{}{
			"enabled":     true,
			"server_name": sni,
		}
		if fp := query.Get("fp"); fp != "" {
			tls["utls"] = map[string]interface{}{
				"enabled":     true,
				"fingerprint": getFingerprint(fp),
			}
		}
		if alpn := query.Get("alpn"); alpn != "" {
			tls["alpn"] = strings.Split(alpn, ",")
		}
		if isTrue(query.Get("allowInsecure")) || isTrue(query.Get("insecure")) {
			tls["insecure"] = true
		}
		if ech := query.Get("ech"); ech != "" {
			tls["ech"] = map[string]interface{}{"enabled": true, "config_list": ech}
		}
		if pcs := query.Get("pcs"); pcs != "" {
			tls["pinned_peer_cert_sha256"] = pcs
		}
		if vcn := query.Get("vcn"); vcn != "" {
			tls["verify_peer_cert_by_name"] = vcn
		}
		outbound["tls"] = tls
	}
}

func isTrue(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "yes":
		return true
	}
	return false
}

// xhttpTransport builds the intermediate XHTTP transport. extra is the
// share-link JSON blob (padding, xmux, downloadSettings, ...) and reaches the
// core untouched; a blob that is not a JSON object is dropped instead of
// failing the whole link.
// IsXHTTPMode reports whether s is one of Xray's XHTTP modes.
func IsXHTTPMode(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "auto", "packet-up", "stream-up", "stream-one":
		return true
	}
	return false
}

func xhttpTransport(path, host, mode, extra string) map[string]interface{} {
	transport := map[string]interface{}{"type": "xhttp"}
	if path != "" {
		transport["path"] = path
	}
	if host != "" {
		transport["host"] = host
	}
	// Anything else ("none", a header type) means the default mode.
	if mode = strings.ToLower(strings.TrimSpace(mode)); IsXHTTPMode(mode) {
		transport["mode"] = mode
	}
	if extra = strings.TrimSpace(extra); extra != "" {
		var parsed map[string]interface{}
		if err := json.Unmarshal([]byte(extra), &parsed); err == nil && len(parsed) > 0 {
			transport["extra"] = parsed
		}
	}
	return transport
}
