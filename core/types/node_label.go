package types

import "strings"

// DescribeOutbound reports how a node reaches its server, for the node list:
// the transport ("" = raw TCP) and the security layer ("" = none, or implied
// by the protocol itself).
func DescribeOutbound(ob map[string]interface{}) (transport, security string) {
	protocol, _ := ob["type"].(string)
	switch strings.ToLower(protocol) {
	case "hysteria", "hysteria2", "tuic", "wireguard":
		// QUIC/WireGuard based: no pluggable transport, encryption is built in.
		return "", ""
	}

	if t, ok := ob["transport"].(map[string]interface{}); ok {
		kind, _ := t["type"].(string)
		switch kind = strings.ToLower(strings.TrimSpace(kind)); kind {
		case "splithttp":
			transport = "xhttp"
		case "http":
			transport = "h2"
		case "tcp", "raw":
		default:
			transport = kind
		}
	}

	if tls, ok := ob["tls"].(map[string]interface{}); ok && truthy(tls["enabled"]) {
		security = "tls"
		if reality, ok := tls["reality"].(map[string]interface{}); ok && truthy(reality["enabled"]) {
			security = "reality"
		}
	}
	return transport, security
}

// InsecureOutbound reports a TLS server whose certificate is not verified. A
// pinned certificate hash keeps such a node safe: the pin is still enforced.
func InsecureOutbound(ob map[string]interface{}) bool {
	tls, ok := ob["tls"].(map[string]interface{})
	if !ok || !truthy(tls["enabled"]) || !truthy(tls["insecure"]) {
		return false
	}
	pin, _ := tls["pinned_peer_cert_sha256"].(string)
	return pin == ""
}

func truthy(v interface{}) bool {
	switch b := v.(type) {
	case bool:
		return b
	case string:
		return strings.EqualFold(b, "true")
	}
	return false
}
