package subscription

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strings"

	"beam-bridge/core/types"
)

// Xray JSON -> internal outbound. Every field of the provider's outbound is
// either mapped to a named internal key or kept in an "xray" passthrough block
// of the same section, so the config the core finally gets is the one the
// provider wrote. profile.convertOutbound is the reverse direction; the
// format is described in docs/internal-outbound.md.

// maxDetourDepth bounds dialerProxy/proxySettings chains; it matches the
// limit of the config builder.
const maxDetourDepth = 4

// looksLikeXrayConfigArray accepts both an array of Xray configs (Remnawave,
// Marzban "Xray JSON") and a single Xray config object (the usual way to
// share XHTTP). Xray outbounds have "protocol"; other JSON shapes are left to
// the generic parser.
func looksLikeXrayConfigArray(trimmed string) bool {
	if !strings.Contains(trimmed, `"outbounds"`) || !strings.Contains(trimmed, `"protocol"`) {
		return false
	}
	return strings.HasPrefix(trimmed, "[") || strings.HasPrefix(trimmed, "{")
}

// LooksLikeXrayConfig reports whether text is an Xray config (or an array
// of them) rather than a sing-box one.
func LooksLikeXrayConfig(text string) bool {
	return looksLikeXrayConfigArray(strings.TrimSpace(text))
}

// ParseXrayConfig turns an Xray config (or an array of them) into nodes.
func ParseXrayConfig(data []byte) (*ParseResult, error) {
	return parseXrayConfigArray(data)
}

func parseXrayConfigArray(data []byte) (*ParseResult, error) {
	var entries []map[string]interface{}
	if trimmed := strings.TrimSpace(string(data)); strings.HasPrefix(trimmed, "{") {
		var single map[string]interface{}
		if err := json.Unmarshal([]byte(trimmed), &single); err != nil {
			return nil, err
		}
		entries = []map[string]interface{}{single}
	} else if err := json.Unmarshal(data, &entries); err != nil {
		return nil, err
	}

	result := &ParseResult{
		Categories: []types.Category{{ID: "default", Name: "Серверы", Order: 0}},
		Nodes:      []types.BeamNode{},
	}

	nodeIndex := 0
	for _, entry := range entries {
		outbounds := objectList(entry["outbounds"])
		byTag := make(map[string]map[string]interface{}, len(outbounds))
		for _, ob := range outbounds {
			if tag := str(ob, "tag"); tag != "" {
				byTag[tag] = ob
			}
		}
		proxy := findProxyOutbound(outbounds)
		if proxy == nil {
			continue
		}
		outbound, err := convertXrayOutbound(proxy, byTag, 0)
		if err != nil {
			log.Printf("subscription: xray outbound %q skipped: %v", str(proxy, "tag"), err)
			continue
		}
		nodeIndex++
		name := strings.TrimSpace(str(entry, "remarks"))
		if tag := str(proxy, "tag"); name == "" && tag != "" && tag != "proxy" {
			name = tag
		}
		if name == "" {
			name = fmt.Sprintf("Node %d", nodeIndex)
		}
		nodeType, _ := outbound["type"].(string)
		node := types.BeamNode{
			ID:         fmt.Sprintf("node_%d", nodeIndex),
			CategoryID: "default",
			Name:       name,
			Type:       nodeType,
			Outbound:   outbound,
			DNS:        obj(entry, "dns"),
		}
		applyEntryMeta(&node, obj(entry, "meta"))
		result.Nodes = append(result.Nodes, node)
	}

	if len(result.Nodes) == 0 {
		return nil, errors.New("no valid nodes found in the Xray config")
	}
	return result, nil
}

// applyEntryMeta reads the per-server "meta" block panels put next to
// "remarks" (Happ/Remnawave: serverDescription, base64 or plain).
func applyEntryMeta(node *types.BeamNode, meta map[string]interface{}) {
	if meta == nil {
		return
	}
	for _, key := range []string{"serverDescription", "description", paramDesc} {
		if v := str(meta, key); v != "" {
			node.Description = cleanText(maybeBase64Text(strings.TrimPrefix(v, "base64:")), maxDescription)
			break
		}
	}
	if v := str(meta, paramBadge); v != "" {
		node.Badge = cleanText(v, maxBadge)
	}
}

// supportedXrayProtocols are the outbounds that can be a server.
var supportedXrayProtocols = map[string]bool{
	"vless": true, "vmess": true, "trojan": true, "shadowsocks": true,
	"hysteria": true, "socks": true, "http": true, "wireguard": true,
}

// findProxyOutbound prefers the conventional "proxy" tag and otherwise takes
// the first outbound of a supported protocol: hand-written and exported
// configs often tag it "vless-xhttp", "out" and so on.
func findProxyOutbound(outbounds []map[string]interface{}) map[string]interface{} {
	for _, ob := range outbounds {
		if str(ob, "tag") == "proxy" && supportedXrayProtocols[strings.ToLower(str(ob, "protocol"))] {
			return ob
		}
	}
	for _, ob := range outbounds {
		if supportedXrayProtocols[strings.ToLower(str(ob, "protocol"))] {
			return ob
		}
	}
	return nil
}

// convertXrayOutbound maps one Xray outbound. byTag resolves the outbounds
// it dials through (sockopt.dialerProxy, proxySettings.tag).
func convertXrayOutbound(ob map[string]interface{}, byTag map[string]map[string]interface{}, depth int) (map[string]interface{}, error) {
	settings := obj(ob, "settings")
	protocol := strings.ToLower(str(ob, "protocol"))

	var (
		out map[string]interface{}
		err error
	)
	switch protocol {
	case "vless":
		out, err = xrayVless(ob, settings)
	case "vmess":
		out, err = xrayVMess(ob, settings)
	case "trojan":
		out, err = xrayServerUser(ob, settings, "trojan", map[string]string{"password": "password", "flow": "flow"})
	case "shadowsocks":
		out, err = xrayServerUser(ob, settings, "shadowsocks", map[string]string{"method": "method", "password": "password"})
	case "socks", "http":
		out, err = xrayAuthProxy(ob, settings, protocol)
	case "hysteria":
		out, err = xrayHysteria(ob, settings)
	case "wireguard":
		out, err = xrayWireGuard(ob, settings)
	case "freedom":
		if depth == 0 {
			return nil, errors.New("freedom is not a server")
		}
		out = xrayFreedom(settings)
	default:
		return nil, fmt.Errorf("protocol %q is not supported yet", protocol)
	}
	if err != nil {
		return nil, err
	}
	if tag := str(ob, "tag"); tag != "" {
		out["tag"] = tag
	}

	stream := obj(ob, "streamSettings")
	if protocol != "wireguard" {
		if err := applyXrayStream(out, stream); err != nil {
			return nil, err
		}
	}
	if protocol == "hysteria" && out["tls"] == nil {
		// QUIC always carries TLS; the server address is the default SNI.
		out["tls"] = map[string]interface{}{"enabled": true, "server_name": out["server"]}
	}

	if mux := obj(ob, "mux"); mux != nil {
		multiplex := map[string]interface{}{"enabled": mux["enabled"] == true}
		rename(multiplex, mux, map[string]string{
			"concurrency":     "concurrency",
			"xudpConcurrency": "xudp_concurrency",
			"xudpProxyUDP443": "xudp_proxy_udp443",
		})
		out["multiplex"] = multiplex
	}

	leftover := rest(ob, "protocol", "tag", "settings", "streamSettings", "mux", "proxySettings")
	if len(leftover) > 0 {
		out["xray_outbound"] = leftover
	}

	dialer := str(obj(stream, "sockopt"), "dialerProxy")
	if dialer == "" {
		dialer = str(obj(ob, "proxySettings"), "tag")
	}
	if dialer != "" {
		if hop, ok := byTag[dialer]; ok && depth < maxDetourDepth && hop["_visiting"] == nil {
			hop["_visiting"] = true
			detour, err := convertXrayOutbound(hop, byTag, depth+1)
			delete(hop, "_visiting")
			if err == nil {
				out["detour"] = detour
			} else {
				log.Printf("subscription: chain hop %q of %q dropped: %v", dialer, str(ob, "tag"), err)
			}
		}
	}
	return out, nil
}

// --- Protocols --------------------------------------------------------------

func xrayVless(ob, settings map[string]interface{}) (map[string]interface{}, error) {
	address, port, user, extra := firstEndpoint(settings, "vnext")
	if address == "" || user == nil {
		return nil, errors.New("vless: empty vnext/users")
	}
	out := map[string]interface{}{
		"type":        "vless",
		"server":      address,
		"server_port": port,
		"uuid":        str(user, "id"),
	}
	if flow := str(user, "flow"); flow != "" {
		out["flow"] = flow
	}
	if enc := strings.TrimSpace(str(user, "encryption")); enc != "" && enc != "none" {
		out["encryption"] = enc
	}
	keep(out, "xray_user", rest(user, "id", "flow", "encryption"))
	keep(out, "xray_settings", extra)
	return out, nil
}

func xrayVMess(ob, settings map[string]interface{}) (map[string]interface{}, error) {
	address, port, user, extra := firstEndpoint(settings, "vnext")
	if address == "" || user == nil {
		return nil, errors.New("vmess: empty vnext/users")
	}
	out := map[string]interface{}{
		"type":        "vmess",
		"server":      address,
		"server_port": port,
		"uuid":        str(user, "id"),
		"alter_id":    num(user["alterId"]),
	}
	if security := str(user, "security"); security != "" {
		out["security"] = security
	}
	keep(out, "xray_user", rest(user, "id", "alterId", "security"))
	keep(out, "xray_settings", extra)
	return out, nil
}

// xrayServerUser reads protocols that keep credentials next to the address
// (trojan, shadowsocks), in "servers" or flat in settings.
func xrayServerUser(ob, settings map[string]interface{}, kind string, fields map[string]string) (map[string]interface{}, error) {
	server, extra := firstServer(settings)
	address := str(server, "address")
	if address == "" {
		return nil, fmt.Errorf("%s: empty servers", kind)
	}
	out := map[string]interface{}{
		"type":        kind,
		"server":      address,
		"server_port": num(server["port"]),
	}
	rename(out, server, fields)
	consumed := []string{"address", "port"}
	for k := range fields {
		consumed = append(consumed, k)
	}
	keep(out, "xray_user", rest(server, consumed...))
	keep(out, "xray_settings", extra)
	return out, nil
}

func xrayAuthProxy(ob, settings map[string]interface{}, kind string) (map[string]interface{}, error) {
	server, extra := firstServer(settings)
	address := str(server, "address")
	if address == "" {
		return nil, fmt.Errorf("%s: empty servers", kind)
	}
	out := map[string]interface{}{
		"type":        kind,
		"server":      address,
		"server_port": num(server["port"]),
	}
	user := str(server, "user")
	pass := str(server, "pass")
	if users := objectList(server["users"]); len(users) > 0 {
		user, pass = str(users[0], "user"), str(users[0], "pass")
	}
	if user != "" {
		out["username"] = user
		out["password"] = pass
	}
	if kind == "http" {
		if headers := obj(extra, "headers"); len(headers) > 0 {
			out["headers"] = headers
			delete(extra, "headers")
		}
	}
	keep(out, "xray_settings", extra)
	return out, nil
}

func xrayHysteria(ob, settings map[string]interface{}) (map[string]interface{}, error) {
	if v := num(settings["version"]); v != 0 && v != 2 {
		return nil, fmt.Errorf("hysteria version %d is not supported (hysteria2 only)", v)
	}
	address := str(settings, "address")
	if address == "" {
		return nil, errors.New("hysteria2: empty address")
	}
	stream := obj(ob, "streamSettings")
	hysteria := obj(stream, "hysteriaSettings")
	if str(hysteria, "auth") == "" {
		return nil, errors.New("hysteria2: missing auth")
	}
	out := map[string]interface{}{
		"type":        "hysteria2",
		"server":      address,
		"server_port": num(settings["port"]),
		"password":    str(hysteria, "auth"),
	}
	rename(out, hysteria, map[string]string{"congestion": "congestion", "up": "up", "down": "down"})
	if hop := obj(hysteria, "udphop"); hop != nil {
		rename(out, hop, map[string]string{"ports": "hop_ports", "interval": "hop_interval"})
	}
	keep(out, "hysteria_xray", rest(hysteria, "version", "auth", "congestion", "up", "down", "udphop"))
	keep(out, "xray_settings", rest(settings, "version", "address", "port"))
	return out, nil
}

func xrayWireGuard(ob, settings map[string]interface{}) (map[string]interface{}, error) {
	peers := objectList(settings["peers"])
	if str(settings, "secretKey") == "" || len(peers) == 0 {
		return nil, errors.New("wireguard: missing keys or peers")
	}
	host, port := splitEndpoint(str(peers[0], "endpoint"))
	if host == "" {
		return nil, errors.New("wireguard: peer has no endpoint")
	}
	out := map[string]interface{}{
		"type":        "wireguard",
		"server":      host,
		"server_port": port,
		"private_key": str(settings, "secretKey"),
	}
	if addrs, ok := settings["address"].([]interface{}); ok {
		out["local_address"] = addrs
	}
	rename(out, settings, map[string]string{"mtu": "mtu", "reserved": "reserved"})
	extra := rest(settings, "secretKey", "address", "mtu", "reserved", "peers")
	if len(peers) == 1 {
		rename(out, peers[0], map[string]string{
			"publicKey": "peer_public_key", "preSharedKey": "pre_shared_key",
			"allowedIPs": "allowed_ips", "keepAlive": "keep_alive",
		})
	} else {
		// Several peers have no flat form; the list goes through as is.
		extra["peers"] = settings["peers"]
	}
	keep(out, "xray_settings", extra)
	return out, nil
}

func xrayFreedom(settings map[string]interface{}) map[string]interface{} {
	out := map[string]interface{}{"type": "direct"}
	rename(out, settings, map[string]string{"domainStrategy": "domain_strategy"})
	if f := obj(settings, "fragment"); f != nil {
		fragment := map[string]interface{}{}
		rename(fragment, f, map[string]string{
			"packets": "packets", "length": "length", "interval": "interval", "maxSplit": "max_split",
		})
		out["fragment"] = fragment
	}
	var noises []interface{}
	if n := obj(settings, "noise"); n != nil {
		noises = append(noises, n)
	}
	if list, ok := settings["noises"].([]interface{}); ok {
		noises = append(noises, list...)
	}
	if len(noises) > 0 {
		converted := make([]interface{}, 0, len(noises))
		for _, item := range noises {
			if n, ok := item.(map[string]interface{}); ok {
				noise := map[string]interface{}{}
				rename(noise, n, map[string]string{
					"type": "type", "packet": "packet", "delay": "delay", "applyTo": "apply_to",
				})
				converted = append(converted, noise)
			}
		}
		out["noises"] = converted
	}
	keep(out, "xray_settings", rest(settings, "domainStrategy", "fragment", "noise", "noises"))
	return out
}

// --- Transport and security -------------------------------------------------

func applyXrayStream(outbound, stream map[string]interface{}) error {
	if stream == nil {
		return nil
	}
	consumed := []string{"network", "security", "tlsSettings", "realitySettings", "sockopt"}

	defaultSNI, _ := outbound["server"].(string)
	switch strings.ToLower(str(stream, "security")) {
	case "reality":
		r := obj(stream, "realitySettings")
		if r == nil {
			return errors.New("reality: missing realitySettings")
		}
		publicKey := str(r, "publicKey")
		if publicKey == "" {
			// Newer Xray writes the client's public key as "password".
			publicKey = str(r, "password")
		}
		reality := map[string]interface{}{
			"enabled":    true,
			"public_key": publicKey,
			"short_id":   str(r, "shortId"),
		}
		rename(reality, r, map[string]string{"spiderX": "spider_x", "mldsa65Verify": "mldsa65_verify"})
		keep(reality, "xray", rest(r, "serverName", "fingerprint", "publicKey", "password", "shortId", "spiderX", "mldsa65Verify"))
		outbound["tls"] = map[string]interface{}{
			"enabled":     true,
			"server_name": str(r, "serverName"),
			"utls": map[string]interface{}{
				"enabled":     true,
				"fingerprint": xrayFingerprintOrDefault(str(r, "fingerprint")),
			},
			"reality": reality,
		}
	case "tls":
		t := obj(stream, "tlsSettings")
		sni := defaultSNI
		if name := str(t, "serverName"); name != "" {
			sni = name
		}
		tls := map[string]interface{}{"enabled": true, "server_name": sni}
		if fp := str(t, "fingerprint"); fp != "" {
			tls["utls"] = map[string]interface{}{"enabled": true, "fingerprint": xrayFingerprintOrDefault(fp)}
		}
		if t["allowInsecure"] == true {
			tls["insecure"] = true
		}
		rename(tls, t, map[string]string{
			"alpn":                    "alpn",
			"minVersion":              "min_version",
			"maxVersion":              "max_version",
			"cipherSuites":            "cipher_suites",
			"curvePreferences":        "curve_preferences",
			"pinnedPeerCertSha256":    "pinned_peer_cert_sha256",
			"verifyPeerCertByName":    "verify_peer_cert_by_name",
			"disableSystemRoot":       "disable_system_root",
			"enableSessionResumption": "enable_session_resumption",
		})
		if list := str(t, "echConfigList"); list != "" {
			ech := map[string]interface{}{"enabled": true, "config_list": list}
			if fq := str(t, "echForceQuery"); fq != "" {
				ech["force_query"] = fq
			}
			tls["ech"] = ech
		}
		keep(tls, "xray", rest(t, "serverName", "fingerprint", "allowInsecure", "alpn", "minVersion", "maxVersion",
			"cipherSuites", "curvePreferences", "pinnedPeerCertSha256", "verifyPeerCertByName",
			"disableSystemRoot", "enableSessionResumption", "echConfigList", "echForceQuery"))
		outbound["tls"] = tls
	}

	network := strings.ToLower(str(stream, "network"))
	switch network {
	case "", "tcp", "raw":
		consumed = append(consumed, "rawSettings", "tcpSettings")
		raw := obj(stream, "rawSettings")
		if raw == nil {
			raw = obj(stream, "tcpSettings")
		}
		if header := obj(raw, "header"); header != nil && str(header, "type") != "" && str(header, "type") != "none" {
			transport := map[string]interface{}{"type": "raw", "header": header}
			keep(transport, "xray", rest(raw, "header"))
			outbound["transport"] = transport
		}
	case "ws", "websocket":
		consumed = append(consumed, "wsSettings")
		ws := obj(stream, "wsSettings")
		transport := map[string]interface{}{"type": "ws", "path": str(ws, "path")}
		headers := map[string]interface{}{}
		for k, v := range obj(ws, "headers") {
			headers[k] = v
		}
		if host := str(ws, "host"); host != "" {
			headers["Host"] = host
		}
		if len(headers) > 0 {
			transport["headers"] = headers
		}
		rename(transport, ws, map[string]string{"heartbeatPeriod": "heartbeat_period"})
		keep(transport, "xray", rest(ws, "path", "host", "headers", "heartbeatPeriod"))
		outbound["transport"] = transport
	case "grpc", "gun":
		consumed = append(consumed, "grpcSettings")
		g := obj(stream, "grpcSettings")
		transport := map[string]interface{}{"type": "grpc", "service_name": str(g, "serviceName")}
		names := map[string]string{
			"authority":             "authority",
			"multiMode":             "multi_mode",
			"idle_timeout":          "idle_timeout",
			"health_check_timeout":  "health_check_timeout",
			"permit_without_stream": "permit_without_stream",
			"initial_windows_size":  "initial_windows_size",
			"user_agent":            "user_agent",
		}
		rename(transport, g, names)
		keep(transport, "xray", rest(g, append(keys(names), "serviceName")...))
		outbound["transport"] = transport
	case "httpupgrade":
		consumed = append(consumed, "httpupgradeSettings")
		h := obj(stream, "httpupgradeSettings")
		transport := map[string]interface{}{"type": "httpupgrade", "path": str(h, "path")}
		rename(transport, h, map[string]string{"host": "host", "headers": "headers"})
		keep(transport, "xray", rest(h, "path", "host", "headers"))
		outbound["transport"] = transport
	case "xhttp", "splithttp":
		consumed = append(consumed, "xhttpSettings", "splithttpSettings")
		settings := obj(stream, "xhttpSettings")
		if settings == nil {
			settings = obj(stream, "splithttpSettings")
		}
		outbound["transport"] = xhttpTransportFromXray(settings)
	case "kcp", "mkcp":
		consumed = append(consumed, "kcpSettings")
		k := obj(stream, "kcpSettings")
		transport := map[string]interface{}{"type": "kcp"}
		names := map[string]string{
			"mtu":              "mtu",
			"tti":              "tti",
			"uplinkCapacity":   "uplink_capacity",
			"downlinkCapacity": "downlink_capacity",
			"congestion":       "congestion",
			"readBufferSize":   "read_buffer_size",
			"writeBufferSize":  "write_buffer_size",
			"seed":             "seed",
		}
		rename(transport, k, names)
		if ht := str(obj(k, "header"), "type"); ht != "" {
			transport["header_type"] = ht
		}
		keep(transport, "xray", rest(k, append(keys(names), "header")...))
		outbound["transport"] = transport
	case "hysteria":
		// Read by xrayHysteria.
		consumed = append(consumed, "hysteriaSettings")
	case "http", "h2":
		consumed = append(consumed, "httpSettings")
		outbound["transport"] = map[string]interface{}{"type": "http"}
	default:
		return fmt.Errorf("transport %q is not supported yet", network)
	}

	if sockopt := obj(stream, "sockopt"); len(sockopt) > 0 {
		own := rest(sockopt, "dialerProxy")
		if len(own) > 0 {
			outbound["sockopt"] = own
		}
	}
	keep(outbound, "xray_stream", rest(stream, consumed...))
	return nil
}

// xhttpTransportFromXray keeps path/host/mode as first-class fields and moves
// everything else into "extra", which the core applies verbatim. Xray uses an
// explicit "extra" block instead of the inline fields, never on top of them,
// so a nested block wins.
func xhttpTransportFromXray(settings map[string]interface{}) map[string]interface{} {
	transport := map[string]interface{}{"type": "xhttp"}
	extra := map[string]interface{}{}
	for key, value := range settings {
		switch key {
		case "path", "host", "mode":
			if s, ok := value.(string); ok && s != "" {
				transport[key] = s
			}
		case "extra":
		default:
			extra[key] = value
		}
	}
	if nested, ok := settings["extra"].(map[string]interface{}); ok && len(nested) > 0 {
		extra = nested
	}
	if len(extra) > 0 {
		transport["extra"] = extra
	}
	return transport
}

func xrayFingerprintOrDefault(fp string) string {
	if fp == "" {
		return "chrome"
	}
	return fp
}

// --- Helpers ----------------------------------------------------------------

// firstEndpoint reads vless/vmess settings in both shapes: vnext[0].users[0]
// or the flat form newer Xray accepts ({address, port, id, ...}). extra is
// what the settings hold besides the endpoint.
func firstEndpoint(settings map[string]interface{}, list string) (string, int, map[string]interface{}, map[string]interface{}) {
	if vnext := objectList(settings[list]); len(vnext) > 0 {
		users := objectList(vnext[0]["users"])
		if len(users) == 0 {
			return "", 0, nil, nil
		}
		return str(vnext[0], "address"), num(vnext[0]["port"]), users[0], rest(settings, list)
	}
	if str(settings, "address") == "" {
		return "", 0, nil, nil
	}
	return str(settings, "address"), num(settings["port"]), rest(settings, "address", "port"), map[string]interface{}{}
}

func firstServer(settings map[string]interface{}) (map[string]interface{}, map[string]interface{}) {
	if servers := objectList(settings["servers"]); len(servers) > 0 {
		return servers[0], rest(settings, "servers")
	}
	return settings, map[string]interface{}{}
}

func splitEndpoint(endpoint string) (string, int) {
	i := strings.LastIndex(endpoint, ":")
	if i <= 0 {
		return "", 0
	}
	host := strings.Trim(endpoint[:i], "[]")
	port := 0
	fmt.Sscanf(endpoint[i+1:], "%d", &port)
	return host, port
}

func obj(m map[string]interface{}, key string) map[string]interface{} {
	v, _ := m[key].(map[string]interface{})
	return v
}

func str(m map[string]interface{}, key string) string {
	v, _ := m[key].(string)
	return v
}

func num(v interface{}) int {
	switch n := v.(type) {
	case float64:
		return int(n)
	case int:
		return n
	case string:
		var out int
		fmt.Sscanf(n, "%d", &out)
		return out
	}
	return 0
}

func objectList(v interface{}) []map[string]interface{} {
	list, _ := v.([]interface{})
	out := make([]map[string]interface{}, 0, len(list))
	for _, item := range list {
		if m, ok := item.(map[string]interface{}); ok {
			out = append(out, m)
		}
	}
	return out
}

// rest returns a copy of m without the given keys; nil for an empty result.
func rest(m map[string]interface{}, drop ...string) map[string]interface{} {
	skip := make(map[string]bool, len(drop))
	for _, k := range drop {
		skip[k] = true
	}
	out := map[string]interface{}{}
	for k, v := range m {
		if !skip[k] && !strings.HasPrefix(k, "_") {
			out[k] = v
		}
	}
	return out
}

// rename copies present values of src under new names.
func rename(dst, src map[string]interface{}, names map[string]string) {
	for from, to := range names {
		if v, ok := src[from]; ok && v != nil {
			dst[to] = v
		}
	}
}

func keep(dst map[string]interface{}, key string, value map[string]interface{}) {
	if len(value) > 0 {
		dst[key] = value
	}
}

func keys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
