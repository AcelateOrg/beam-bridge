package xray

import (
	"encoding/json"
	"strings"
)

// quicPort is where QUIC (HTTP/3) lives.
const quicPort = 443

// visionOutbounds lists the proxy outbounds of config that use XTLS Vision.
// Vision refuses UDP/443 by design, but only after the core has dialed and
// handshaken with the server, so every QUIC attempt costs a full round trip
// to the server before the app may fall back to TCP. all reports that every
// proxy outbound is Vision, for flows the core routes by its own rules.
func visionOutbounds(config json.RawMessage) (tags map[string]bool, all bool) {
	var parsed struct {
		Outbounds []struct {
			Tag      string          `json:"tag"`
			Protocol string          `json:"protocol"`
			Settings json.RawMessage `json:"settings"`
		} `json:"outbounds"`
	}
	if json.Unmarshal(config, &parsed) != nil {
		return nil, false
	}
	tags = map[string]bool{}
	proxies := 0
	for _, o := range parsed.Outbounds {
		switch o.Protocol {
		case "freedom", "blackhole", "dns", "loopback", "":
			continue
		}
		proxies++
		if usesVision(o.Settings) {
			tags[o.Tag] = true
		}
	}
	return tags, proxies > 0 && len(tags) == proxies
}

// usesVision finds a "flow": "xtls-rprx-vision..." anywhere in an outbound's
// settings (vnext users or the flat VLESS form).
func usesVision(raw json.RawMessage) bool {
	var v any
	if json.Unmarshal(raw, &v) != nil {
		return false
	}
	var walk func(any) bool
	walk = func(n any) bool {
		switch x := n.(type) {
		case map[string]any:
			if f, ok := x["flow"].(string); ok && strings.HasPrefix(f, "xtls-rprx-vision") {
				return true
			}
			for _, c := range x {
				if walk(c) {
					return true
				}
			}
		case []any:
			for _, c := range x {
				if walk(c) {
					return true
				}
			}
		}
		return false
	}
	return walk(v)
}

// SetConfig tells the tunnel which outbounds of the running config reject
// QUIC, so such flows are refused at once instead of after a server dial.
func (t *Tunnel) SetConfig(config json.RawMessage) {
	tags, all := visionOutbounds(config)
	t.mu.Lock()
	t.noQUIC = tags
	t.noQUICAll = all
	t.mu.Unlock()
}

// rejectsQUIC reports whether a proxied UDP/443 flow would be refused by its
// outbound anyway.
func (t *Tunnel) rejectsQUIC(decision routeDecision) bool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	if decision.outbound == "" {
		return t.noQUICAll
	}
	return t.noQUIC[decision.outbound]
}
