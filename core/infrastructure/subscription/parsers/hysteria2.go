package parsers

import (
	"net/url"
	"strconv"
	"strings"
)

type Hysteria2Parser struct{}

func (p *Hysteria2Parser) Supports(link string) bool {
	lower := strings.ToLower(link)
	return strings.HasPrefix(lower, "hy2://") || strings.HasPrefix(lower, "hysteria2://")
}

func (p *Hysteria2Parser) Parse(link string) (map[string]interface{}, error) {
	link = strings.TrimPrefix(link, "hysteria2://")
	link = strings.TrimPrefix(link, "hy2://")

	// Port hopping in the authority ("host:443,20000-30000") is not a valid
	// URL port; it is cut out before parsing.
	var hopPorts string
	head := link
	if i := strings.IndexAny(head, "?#"); i >= 0 {
		head = head[:i]
	}
	start := strings.LastIndex(head, "@") + 1
	end := len(head)
	if i := strings.IndexByte(head[start:], '/'); i >= 0 {
		end = start + i
	}
	authority := head[start:end]
	if colon := strings.LastIndex(authority, ":"); colon >= 0 && strings.ContainsAny(authority[colon+1:], ",-") {
		ports := authority[colon+1:]
		if first := strings.FieldsFunc(ports, func(r rune) bool { return r == ',' || r == '-' }); len(first) > 0 {
			hopPorts = ports
			link = link[:start] + authority[:colon+1] + first[0] + link[end:]
		}
	}

	parsed, err := url.Parse("hy2://" + link)
	if err != nil {
		return nil, err
	}
	query := parsed.Query()
	password := parsed.User.Username()
	if pw, ok := parsed.User.Password(); ok && pw != "" {
		password = parsed.User.Username() + ":" + pw
	}
	if auth := query.Get("auth"); auth != "" {
		password = auth
	}
	outbound := map[string]interface{}{
		"type":        "hysteria2",
		"tag":         decodeTag(parsed.Fragment),
		"server":      parsed.Hostname(),
		"server_port": parsePort(parsed.Port()),
		"password":    password,
	}
	sni := query.Get("sni")
	if sni == "" {
		sni = parsed.Hostname()
	}
	tls := map[string]interface{}{
		"enabled":     true,
		"server_name": sni,
	}
	if isTrue(query.Get("insecure")) || isTrue(query.Get("allowInsecure")) {
		tls["insecure"] = true
	}
	if alpn := query.Get("alpn"); alpn != "" {
		tls["alpn"] = strings.Split(alpn, ",")
	}
	if fp := query.Get("fp"); fp != "" {
		tls["utls"] = map[string]interface{}{"enabled": true, "fingerprint": getFingerprint(fp)}
	}
	if pin := query.Get("pinSHA256"); pin != "" {
		tls["pinned_peer_cert_sha256"] = strings.ToLower(strings.ReplaceAll(pin, ":", ""))
	} else if pcs := query.Get("pcs"); pcs != "" {
		tls["pinned_peer_cert_sha256"] = pcs
	}
	if ech := query.Get("ech"); ech != "" {
		tls["ech"] = map[string]interface{}{"enabled": true, "config_list": ech}
	}
	outbound["tls"] = tls
	if obfs := query.Get("obfs"); obfs != "" {
		outbound["obfs"] = map[string]interface{}{
			"type":     obfs,
			"password": query.Get("obfs-password"),
		}
	}
	if mport := query.Get("mport"); mport != "" {
		hopPorts = mport
	}
	if hopPorts != "" {
		outbound["hop_ports"] = hopPorts
		if interval := query.Get("hopInterval"); interval != "" {
			if n, err := strconv.Atoi(strings.TrimSuffix(interval, "s")); err == nil {
				outbound["hop_interval"] = n
			}
		}
	}
	for param, key := range map[string]string{"upmbps": "up_mbps", "downmbps": "down_mbps"} {
		if v, err := strconv.Atoi(strings.TrimSpace(query.Get(param))); err == nil && v > 0 {
			outbound[key] = v
		}
	}
	return outbound, nil
}
