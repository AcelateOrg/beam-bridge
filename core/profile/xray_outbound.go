package profile

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

// Internal outbound -> Xray outbound. The internal format follows sing-box
// naming where sing-box has the field; everything Xray has and sing-box does
// not lives under explicit keys (sockopt, multiplex, detour) or in "xray"
// passthrough blocks that are copied into the matching Xray object as is.
// The reverse direction is subscription.convertXrayOutbound; the format is
// described in docs/internal-outbound.md.

type ErrUnsupportedOutbound struct {
	Type   string
	Reason string
}

func (e *ErrUnsupportedOutbound) Error() string {
	if e.Reason == "" {
		return fmt.Sprintf("outbound type %q is not supported by Xray", e.Type)
	}
	return fmt.Sprintf("outbound type %q is not supported: %s", e.Type, e.Reason)
}

// chainKey holds the converted detour outbounds until the caller tags them
// (takeChain). It never reaches the core.
const chainKey = "_chain"

// maxDetourDepth bounds detour nesting; real chains are one or two hops.
const maxDetourDepth = 4

func convertOutbound(ob map[string]interface{}) (map[string]interface{}, error) {
	return convertOutboundAt(ob, 0)
}

func convertOutboundAt(ob map[string]interface{}, depth int) (map[string]interface{}, error) {
	obType := strings.ToLower(getStr(ob, "type"))
	server := getStr(ob, "server")
	port, _ := outboundPort(ob)

	var (
		out map[string]interface{}
		err error
	)
	switch obType {
	case "vless":
		out, err = convertVLESS(ob, server, port)
	case "vmess":
		out, err = convertVMess(ob, server, port)
	case "trojan":
		out, err = convertTrojan(ob, server, port)
	case "shadowsocks":
		out, err = convertShadowsocks(ob, server, port)
	case "hysteria2":
		out, err = convertHysteria2(ob, server, port)
	case "socks":
		out, err = convertSocks(ob, server, port)
	case "http":
		out, err = convertHTTP(ob, server, port)
	case "wireguard":
		out, err = convertWireGuard(ob, server, port)
	case "direct":
		// Only as a hop of a chain (a provider's own fragment outbound): as
		// a server it would just be no VPN.
		if depth == 0 {
			return nil, &ErrUnsupportedOutbound{Type: obType, Reason: "a direct outbound is not a server"}
		}
		out = convertDirect(ob)
	default:
		return nil, &ErrUnsupportedOutbound{Type: obType}
	}
	if err != nil {
		return nil, err
	}

	mergeMissing(out, getMap(ob, "xray_outbound"))

	if entryRefOf(ob) != nil {
		return nil, &ErrUnsupportedOutbound{
			Type:   obType,
			Reason: "entry server not found, the chain loops, or the node already has a provider chain",
		}
	}
	if viaEntry, _ := ob[entryViaKey].(bool); viaEntry {
		if protocol := getStr(out, "protocol"); protocol == "hysteria" || protocol == "wireguard" {
			return nil, &ErrUnsupportedOutbound{
				Type:   obType,
				Reason: "a chain carries TCP only; this protocol cannot be an exit behind an entry server",
			}
		}
	}

	if detour := getMap(ob, "detour"); detour != nil {
		if depth >= maxDetourDepth {
			return nil, &ErrUnsupportedOutbound{Type: obType, Reason: "the proxy chain is too long"}
		}
		hop, err := convertOutboundAt(detour, depth+1)
		if err != nil {
			return nil, fmt.Errorf("chain: %w", err)
		}
		chain := []map[string]interface{}{hop}
		chain = append(chain, takeChain(hop)...)
		out[chainKey] = chain
	}
	return out, nil
}

// takeChain removes the detour hops from a converted outbound, outermost
// first. The caller tags them and links each through sockopt.dialerProxy
// (linkChain).
func takeChain(converted map[string]interface{}) []map[string]interface{} {
	chain, _ := converted[chainKey].([]map[string]interface{})
	delete(converted, chainKey)
	return chain
}

// linkChain tags the hops after tag and points every outbound at the next
// one. Hop tags start with "direct" so traffic accounting skips them: the
// bytes are already counted on the node itself.
func linkChain(converted map[string]interface{}, tag string, chain []map[string]interface{}) []interface{} {
	out := make([]interface{}, 0, len(chain))
	prev := converted
	for i, hop := range chain {
		hopTag := fmt.Sprintf("direct-chain-%s-%d", tag, i+1)
		hop["tag"] = hopTag
		sockoptOf(prev)["dialerProxy"] = hopTag
		prev = hop
		out = append(out, hop)
	}
	return out
}

// lastHop is the outbound that actually dials the network.
func lastHop(converted map[string]interface{}, chain []map[string]interface{}) map[string]interface{} {
	if len(chain) > 0 {
		return chain[len(chain)-1]
	}
	return converted
}

// --- Protocols --------------------------------------------------------------

func convertVLESS(ob map[string]interface{}, server string, port int) (map[string]interface{}, error) {
	// VLESS Encryption (mlkem768x25519plus...) must match the server, or
	// the handshake fails; plain links say "none".
	encryption := strings.TrimSpace(getStr(ob, "encryption"))
	if encryption == "" {
		encryption = "none"
	}
	user := map[string]interface{}{
		"id":         getStr(ob, "uuid"),
		"encryption": encryption,
	}
	if flow := getStr(ob, "flow"); flow != "" {
		user["flow"] = flow
	}
	mergeMissing(user, getMap(ob, "xray_user"))

	stream, err := buildStreamSettings(ob)
	if err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"protocol": "vless",
		"settings": withExtra(map[string]interface{}{
			"vnext": []interface{}{map[string]interface{}{
				"address": server,
				"port":    port,
				"users":   []interface{}{user},
			}},
		}, ob),
		"streamSettings": stream,
	}, nil
}

func convertVMess(ob map[string]interface{}, server string, port int) (map[string]interface{}, error) {
	security := getStr(ob, "security")
	if security == "" {
		security = "auto"
	}
	user := map[string]interface{}{
		"id":       getStr(ob, "uuid"),
		"security": security,
		"alterId":  intValue(ob["alter_id"]),
	}
	mergeMissing(user, getMap(ob, "xray_user"))

	stream, err := buildStreamSettings(ob)
	if err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"protocol": "vmess",
		"settings": withExtra(map[string]interface{}{
			"vnext": []interface{}{map[string]interface{}{
				"address": server,
				"port":    port,
				"users":   []interface{}{user},
			}},
		}, ob),
		"streamSettings": stream,
	}, nil
}

func convertTrojan(ob map[string]interface{}, server string, port int) (map[string]interface{}, error) {
	stream, err := buildStreamSettings(ob)
	if err != nil {
		return nil, err
	}
	target := map[string]interface{}{
		"address":  server,
		"port":     port,
		"password": getStr(ob, "password"),
	}
	if flow := getStr(ob, "flow"); flow != "" {
		target["flow"] = flow
	}
	mergeMissing(target, getMap(ob, "xray_user"))
	return map[string]interface{}{
		"protocol":       "trojan",
		"settings":       withExtra(map[string]interface{}{"servers": []interface{}{target}}, ob),
		"streamSettings": stream,
	}, nil
}

func convertShadowsocks(ob map[string]interface{}, server string, port int) (map[string]interface{}, error) {
	if plugin := getStr(ob, "plugin"); plugin != "" {
		return nil, &ErrUnsupportedOutbound{
			Type:   "shadowsocks plugin " + plugin,
			Reason: "Xray has no SIP003 plugins",
		}
	}
	stream, err := buildStreamSettings(ob)
	if err != nil {
		return nil, err
	}
	target := map[string]interface{}{
		"address":  server,
		"port":     port,
		"method":   getStr(ob, "method"),
		"password": getStr(ob, "password"),
	}
	mergeMissing(target, getMap(ob, "xray_user"))
	return map[string]interface{}{
		"protocol":       "shadowsocks",
		"settings":       withExtra(map[string]interface{}{"servers": []interface{}{target}}, ob),
		"streamSettings": stream,
	}, nil
}

// convertHysteria2 follows Xray's hysteria schema: the outbound settings hold
// a single flat endpoint (HysteriaClientConfig), while the credentials live in
// the transport (HysteriaConfig). A "servers" array is silently dropped during
// decoding and leaves the address nil, which crashes the core config builder.
// Congestion, bandwidth and port hopping are not read from hysteriaSettings
// any more (the core only logs a warning): they live in finalmask.quicParams.
func convertHysteria2(ob map[string]interface{}, server string, port int) (map[string]interface{}, error) {
	if server == "" {
		return nil, &ErrUnsupportedOutbound{
			Type:   "hysteria2",
			Reason: "node has no server address",
		}
	}

	settings := map[string]interface{}{
		"version": 2,
		"address": server,
		"port":    port,
	}

	hysteria := map[string]interface{}{
		"version": 2,
		"auth":    getStr(ob, "password"),
	}
	mergeMissing(hysteria, getMap(ob, "hysteria_xray"))

	// Hysteria2 always runs over QUIC with TLS, so the security block is not
	// optional the way it is for the TCP-based protocols.
	tlsSettings := buildTLSSettings(ob)
	if tlsSettings == nil {
		tlsSettings = map[string]interface{}{}
	}

	stream := map[string]interface{}{
		"network":          "hysteria",
		"hysteriaSettings": hysteria,
		"security":         "tls",
		"tlsSettings":      tlsSettings,
	}
	// A provider's own finalmask (xray_stream) is the base: what it already
	// carries (salamander, quicParams) is kept.
	finalmask := map[string]interface{}{}
	if own := getMap(getMap(ob, "xray_stream"), "finalmask"); own != nil {
		finalmask = copyOutbound(own)
	}
	if obfs := getMap(ob, "obfs"); obfs != nil && getStr(obfs, "type") != "" {
		if !strings.EqualFold(getStr(obfs, "type"), "salamander") {
			return nil, &ErrUnsupportedOutbound{
				Type:   "hysteria2 obfs " + getStr(obfs, "type"),
				Reason: "Xray masks Hysteria with salamander only",
			}
		}
		if finalmask["udp"] == nil {
			finalmask["udp"] = []interface{}{map[string]interface{}{
				"type":     "salamander",
				"settings": map[string]interface{}{"password": getStr(obfs, "password")},
			}}
		}
	}
	if quic := hysteriaQuicParams(ob); quic != nil && finalmask["quicParams"] == nil {
		finalmask["quicParams"] = quic
	}
	if len(finalmask) > 0 {
		stream["finalmask"] = finalmask
	}
	applyStreamExtras(stream, ob)

	return map[string]interface{}{
		"protocol":       "hysteria",
		"settings":       settings,
		"streamSettings": stream,
	}, nil
}

// hysteriaQuicParams builds finalmask.quicParams of a Hysteria2 outbound.
func hysteriaQuicParams(ob map[string]interface{}) map[string]interface{} {
	quic := map[string]interface{}{}
	if c := getStr(ob, "congestion"); c != "" {
		quic["congestion"] = c
	}
	if up := bandwidth(ob["up"], ob["up_mbps"]); up != "" {
		quic["brutalUp"] = up
	}
	if down := bandwidth(ob["down"], ob["down_mbps"]); down != "" {
		quic["brutalDown"] = down
	}
	if ports := hopPorts(ob["hop_ports"]); ports != "" {
		hop := map[string]interface{}{"ports": ports}
		// The core rejects intervals under 5 seconds; leave it to its default.
		if interval := intValue(ob["hop_interval"]); interval >= 5 {
			hop["interval"] = interval
		}
		quic["udpHop"] = hop
	}
	if len(quic) == 0 {
		return nil
	}
	return quic
}

func convertSocks(ob map[string]interface{}, server string, port int) (map[string]interface{}, error) {
	stream, err := buildStreamSettings(ob)
	if err != nil {
		return nil, err
	}
	target := map[string]interface{}{"address": server, "port": port}
	if user := getStr(ob, "username"); user != "" {
		target["users"] = []interface{}{map[string]interface{}{"user": user, "pass": getStr(ob, "password")}}
	}
	return map[string]interface{}{
		"protocol":       "socks",
		"settings":       withExtra(map[string]interface{}{"servers": []interface{}{target}}, ob),
		"streamSettings": stream,
	}, nil
}

func convertHTTP(ob map[string]interface{}, server string, port int) (map[string]interface{}, error) {
	stream, err := buildStreamSettings(ob)
	if err != nil {
		return nil, err
	}
	target := map[string]interface{}{"address": server, "port": port}
	if user := getStr(ob, "username"); user != "" {
		target["users"] = []interface{}{map[string]interface{}{"user": user, "pass": getStr(ob, "password")}}
	}
	settings := map[string]interface{}{"servers": []interface{}{target}}
	if headers := getMap(ob, "headers"); len(headers) > 0 {
		settings["headers"] = headers
	}
	return map[string]interface{}{
		"protocol":       "http",
		"settings":       withExtra(settings, ob),
		"streamSettings": stream,
	}, nil
}

func convertWireGuard(ob map[string]interface{}, server string, port int) (map[string]interface{}, error) {
	key := getStr(ob, "private_key")
	peerKey := getStr(ob, "peer_public_key")
	if key == "" || (peerKey == "" && getMap(ob, "xray_settings")["peers"] == nil) {
		return nil, &ErrUnsupportedOutbound{Type: "wireguard", Reason: "missing keys"}
	}
	settings := map[string]interface{}{"secretKey": key}
	if addrs := getStrings(ob, "local_address"); len(addrs) > 0 {
		settings["address"] = addrs
	}
	if peerKey != "" {
		peer := map[string]interface{}{
			"publicKey": peerKey,
			"endpoint":  net.JoinHostPort(server, strconv.Itoa(port)),
		}
		if psk := getStr(ob, "pre_shared_key"); psk != "" {
			peer["preSharedKey"] = psk
		}
		if ips := getStrings(ob, "allowed_ips"); len(ips) > 0 {
			peer["allowedIPs"] = ips
		}
		if ka := intValue(ob["keep_alive"]); ka > 0 {
			peer["keepAlive"] = ka
		}
		settings["peers"] = []interface{}{peer}
	}
	if mtu := intValue(ob["mtu"]); mtu > 0 {
		settings["mtu"] = mtu
	}
	if reserved, ok := ob["reserved"].([]interface{}); ok && len(reserved) > 0 {
		settings["reserved"] = reserved
	}
	return map[string]interface{}{
		"protocol": "wireguard",
		"settings": withExtra(settings, ob),
	}, nil
}

// convertDirect is a freedom hop of a chain, usually the provider's own
// fragmentation in front of the server.
func convertDirect(ob map[string]interface{}) map[string]interface{} {
	settings := map[string]interface{}{}
	if ds := getStr(ob, "domain_strategy"); ds != "" {
		settings["domainStrategy"] = ds
	}
	if f := getMap(ob, "fragment"); f != nil {
		fragment := map[string]interface{}{}
		copyKeys(fragment, f, map[string]string{
			"packets": "packets", "length": "length", "interval": "interval", "max_split": "maxSplit",
		})
		settings["fragment"] = fragment
	}
	if noises, ok := ob["noises"].([]interface{}); ok && len(noises) > 0 {
		out := make([]interface{}, 0, len(noises))
		for _, item := range noises {
			if n, ok := item.(map[string]interface{}); ok {
				noise := map[string]interface{}{}
				copyKeys(noise, n, map[string]string{
					"type": "type", "packet": "packet", "delay": "delay", "apply_to": "applyTo",
				})
				out = append(out, noise)
			}
		}
		settings["noises"] = out
	}
	out := map[string]interface{}{"protocol": "freedom", "settings": withExtra(settings, ob)}
	if stream := map[string]interface{}{}; applyStreamExtras(stream, ob) {
		out["streamSettings"] = stream
	}
	return out
}

// --- Transport and security -------------------------------------------------

func buildStreamSettings(ob map[string]interface{}) (map[string]interface{}, error) {
	stream := map[string]interface{}{}

	network := "raw"
	if transport := getMap(ob, "transport"); transport != nil {
		switch strings.ToLower(getStr(transport, "type")) {
		case "ws":
			network = "ws"
			ws := map[string]interface{}{"path": getStr(transport, "path")}
			headers := map[string]interface{}{}
			for k, v := range getMap(transport, "headers") {
				if strings.EqualFold(k, "host") {
					if host, _ := v.(string); host != "" {
						ws["host"] = host
					}
					continue
				}
				headers[k] = v
			}
			if host := getStr(transport, "host"); host != "" {
				ws["host"] = host
			}
			if len(headers) > 0 {
				ws["headers"] = headers
			}
			if hb := intValue(transport["heartbeat_period"]); hb > 0 {
				ws["heartbeatPeriod"] = hb
			}
			stream["wsSettings"] = withXray(ws, transport)
		case "grpc":
			network = "grpc"
			grpc := map[string]interface{}{"serviceName": getStr(transport, "service_name")}
			copyKeys(grpc, transport, map[string]string{
				"authority":             "authority",
				"multi_mode":            "multiMode",
				"idle_timeout":          "idle_timeout",
				"health_check_timeout":  "health_check_timeout",
				"permit_without_stream": "permit_without_stream",
				"initial_windows_size":  "initial_windows_size",
				"user_agent":            "user_agent",
			})
			stream["grpcSettings"] = withXray(grpc, transport)
		case "httpupgrade":
			network = "httpupgrade"
			up := map[string]interface{}{"path": getStr(transport, "path")}
			if host := getStr(transport, "host"); host != "" {
				up["host"] = host
			}
			if headers := getMap(transport, "headers"); len(headers) > 0 {
				up["headers"] = headers
			}
			stream["httpupgradeSettings"] = withXray(up, transport)
		case "xhttp", "splithttp":
			network = "xhttp"
			mode := strings.ToLower(getStr(transport, "mode"))
			switch mode {
			case "auto", "packet-up", "stream-up", "stream-one":
			default:
				// Empty or junk ("none" from a vmess header type, nodes
				// saved by older builds): the server picks the mode itself,
				// so auto works instead of hiding the node.
				mode = "auto"
			}
			xh := map[string]interface{}{"mode": mode}
			if path := getStr(transport, "path"); path != "" {
				xh["path"] = path
			}
			if host := getStr(transport, "host"); host != "" {
				xh["host"] = host
			}
			if headers := getMap(transport, "headers"); len(headers) > 0 {
				xh["headers"] = headers
			}
			// Padding, xmux, downloadSettings, ...: Xray applies the block
			// itself, so it is passed through without interpretation.
			if extra := getMap(transport, "extra"); len(extra) > 0 {
				xh["extra"] = extra
			}
			stream["xhttpSettings"] = xh
		case "kcp", "mkcp":
			network = "kcp"
			kcp := map[string]interface{}{}
			copyKeys(kcp, transport, map[string]string{
				"mtu":               "mtu",
				"tti":               "tti",
				"uplink_capacity":   "uplinkCapacity",
				"downlink_capacity": "downlinkCapacity",
				"congestion":        "congestion",
				"read_buffer_size":  "readBufferSize",
				"write_buffer_size": "writeBufferSize",
				"seed":              "seed",
			})
			if ht := getStr(transport, "header_type"); ht != "" && ht != "none" {
				kcp["header"] = map[string]interface{}{"type": ht}
			}
			stream["kcpSettings"] = withXray(kcp, transport)
		case "raw", "tcp":
			// Only the HTTP header obfuscation lives here.
			if header := getMap(transport, "header"); header != nil && getStr(header, "type") != "" && getStr(header, "type") != "none" {
				stream["rawSettings"] = withXray(map[string]interface{}{"header": header}, transport)
			}
		case "http", "h2":
			return nil, &ErrUnsupportedOutbound{
				Type:   "http/2 transport",
				Reason: "Xray no longer has the HTTP/2 transport; ask the provider for an XHTTP link",
			}
		case "quic":
			return nil, &ErrUnsupportedOutbound{
				Type:   "quic transport",
				Reason: "Xray has no v2ray-style QUIC transport",
			}
		case "":
		default:
			return nil, &ErrUnsupportedOutbound{
				Type:   getStr(transport, "type") + " transport",
				Reason: "unknown transport",
			}
		}
	}
	stream["network"] = network

	tls := getMap(ob, "tls")
	if tls != nil && boolValue(tls["enabled"]) {
		if reality := getMap(tls, "reality"); reality != nil && boolValue(reality["enabled"]) {
			switch network {
			case "raw", "xhttp", "grpc":
			default:
				return nil, &ErrUnsupportedOutbound{
					Type:   "reality over " + network,
					Reason: "REALITY works only over raw, xhttp or grpc",
				}
			}
			stream["security"] = "reality"
			settings := map[string]interface{}{
				"serverName":  getStr(tls, "server_name"),
				"publicKey":   getStr(reality, "public_key"),
				"shortId":     getStr(reality, "short_id"),
				"fingerprint": fingerprintOf(tls),
			}
			copyKeys(settings, reality, map[string]string{
				"spider_x":       "spiderX",
				"mldsa65_verify": "mldsa65Verify",
			})
			stream["realitySettings"] = withXray(settings, reality)
		} else {
			stream["security"] = "tls"
			stream["tlsSettings"] = buildTLSSettings(ob)
		}
	}

	applyStreamExtras(stream, ob)
	return stream, nil
}

// applyStreamExtras adds the node's own sockopt and the streamSettings keys
// the internal format has no name for (finalmask, ...). Reports whether it
// added anything.
func applyStreamExtras(stream, ob map[string]interface{}) bool {
	added := false
	if sockopt := getMap(ob, "sockopt"); len(sockopt) > 0 {
		own := make(map[string]interface{}, len(sockopt))
		for k, v := range sockopt {
			// Chains are explicit (detour); a dangling tag would fail the
			// whole config.
			if k != "dialerProxy" {
				own[k] = v
			}
		}
		if len(own) > 0 {
			stream["sockopt"] = own
			added = true
		}
	}
	for k, v := range getMap(ob, "xray_stream") {
		if _, set := stream[k]; !set {
			stream[k] = v
			added = true
		}
	}
	return added
}

func buildTLSSettings(ob map[string]interface{}) map[string]interface{} {
	tls := getMap(ob, "tls")
	if tls == nil || !boolValue(tls["enabled"]) {
		return nil
	}
	settings := map[string]interface{}{
		"serverName": getStr(tls, "server_name"),
	}
	if boolValue(tls["insecure"]) {
		settings["allowInsecure"] = true
	}
	if alpn := getStrings(tls, "alpn"); len(alpn) > 0 {
		settings["alpn"] = alpn
	}
	if fp := fingerprintOf(tls); fp != "" {
		settings["fingerprint"] = fp
	}
	copyKeys(settings, tls, map[string]string{
		"min_version":               "minVersion",
		"max_version":               "maxVersion",
		"cipher_suites":             "cipherSuites",
		"curve_preferences":         "curvePreferences",
		"pinned_peer_cert_sha256":   "pinnedPeerCertSha256",
		"verify_peer_cert_by_name":  "verifyPeerCertByName",
		"disable_system_root":       "disableSystemRoot",
		"enable_session_resumption": "enableSessionResumption",
	})
	if ech := getMap(tls, "ech"); ech != nil {
		if list := getStr(ech, "config_list"); list != "" {
			settings["echConfigList"] = list
		}
		if fq := getStr(ech, "force_query"); fq != "" {
			settings["echForceQuery"] = fq
		}
	}
	return withXray(settings, tls)
}

func fingerprintOf(tls map[string]interface{}) string {
	if utls := getMap(tls, "utls"); utls != nil && boolValue(utls["enabled"]) {
		if fp := getStr(utls, "fingerprint"); fp != "" {
			return fp
		}
		return "chrome"
	}
	return ""
}

// --- Helpers ----------------------------------------------------------------

// withXray copies the "xray" passthrough block of an internal section into
// the Xray object built from it; fields set from named keys win.
func withXray(dst, section map[string]interface{}) map[string]interface{} {
	mergeMissing(dst, getMap(section, "xray"))
	return dst
}

// withExtra does the same for the protocol settings (outbound "xray_settings").
func withExtra(settings, ob map[string]interface{}) map[string]interface{} {
	mergeMissing(settings, getMap(ob, "xray_settings"))
	return settings
}

func mergeMissing(dst, src map[string]interface{}) {
	for k, v := range src {
		if _, set := dst[k]; !set {
			dst[k] = v
		}
	}
}

// copyKeys copies present, non-empty values from src[internal] to dst[xray].
func copyKeys(dst, src map[string]interface{}, names map[string]string) {
	for from, to := range names {
		v, ok := src[from]
		if !ok || v == nil {
			continue
		}
		if s, isStr := v.(string); isStr && s == "" {
			continue
		}
		dst[to] = v
	}
}

// bandwidth turns "100 mbps" / 100 (Mbit/s) into Xray's Bandwidth string.
func bandwidth(raw, mbps interface{}) string {
	if s, ok := raw.(string); ok && strings.TrimSpace(s) != "" {
		return strings.TrimSpace(s)
	}
	for _, v := range []interface{}{raw, mbps} {
		if n := intValue(v); n > 0 {
			return strconv.Itoa(n) + " mbps"
		}
		if s, ok := v.(string); ok {
			if n, err := strconv.Atoi(strings.TrimSpace(s)); err == nil && n > 0 {
				return strconv.Itoa(n) + " mbps"
			}
		}
	}
	return ""
}

func hopPorts(v interface{}) string {
	switch p := v.(type) {
	case string:
		// sing-box writes ranges as "20000:30000"; Xray wants a dash.
		return strings.ReplaceAll(strings.TrimSpace(p), ":", "-")
	case []interface{}:
		parts := make([]string, 0, len(p))
		for _, item := range p {
			switch x := item.(type) {
			case string:
				parts = append(parts, strings.TrimSpace(x))
			case float64:
				parts = append(parts, strconv.Itoa(int(x)))
			}
		}
		return strings.Join(parts, ",")
	}
	return ""
}

func getStr(m map[string]interface{}, key string) string {
	v, _ := m[key].(string)
	return v
}

func getMap(m map[string]interface{}, key string) map[string]interface{} {
	v, _ := m[key].(map[string]interface{})
	return v
}

func getStrings(m map[string]interface{}, key string) []string {
	switch v := m[key].(type) {
	case string:
		if v == "" {
			return nil
		}
		return []string{v}
	case []string:
		return v
	case []interface{}:
		out := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok && s != "" {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

func boolValue(v interface{}) bool {
	b, _ := v.(bool)
	return b
}

func intValue(v interface{}) int {
	switch n := v.(type) {
	case int:
		return n
	case int64:
		return int(n)
	case float64:
		return int(n)
	}
	return 0
}
