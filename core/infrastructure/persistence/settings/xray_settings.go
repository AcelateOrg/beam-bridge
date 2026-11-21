package settings

import (
	"bytes"
	"encoding/json"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	domainSettings "beam-bridge/core/domain/settings"
)

// Валидация и дефолты разделов «Ядро» и «DNS». Ядро
// отвергает весь конфиг из-за одного кривого значения, поэтому всё, что
// сюда приходит, приводится к допустимому виду или отбрасывается.

const (
	maxDNSServers = 16
	maxDNSRules   = 64
	maxDNSHosts   = 256
	maxNoises     = 8
)

func (r *JSONRepository) UpdateCore(core domainSettings.CoreSettings) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.settings.Core = validateCore(core)
	return r.save()
}

func (r *JSONRepository) UpdateDNS(dns domainSettings.DNSSettings) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.settings.DNS = validateDNS(dns)
	syncTunnelResolvers(&r.settings.Connection, r.settings.DNS)
	return r.save()
}

// --- Ядро -----------------------------------------------------------------

func defaultCore() domainSettings.CoreSettings {
	standard := domainSettings.FragmentPresets["standard"]
	return domainSettings.CoreSettings{
		Fragment: domainSettings.FragmentSettings{
			Enabled:  false,
			Preset:   "standard",
			Packets:  standard.Packets,
			Length:   standard.Length,
			Interval: standard.Interval,
			MaxSplit: standard.MaxSplit,
			Noises:   []domainSettings.NoiseSettings{},
		},
		Mux: domainSettings.MuxSettings{
			Enabled:         false,
			Concurrency:     8,
			XUDPConcurrency: 16,
			XUDPProxyUDP443: "reject",
		},
	}
}

var rangeRe = regexp.MustCompile(`^\d{1,6}(-\d{1,6})?$`)

// normalizeRange приводит "10 - 20" / "20-10" / "15" к каноническому "10-20" и
// проверяет границы. Пустая строка или мусор — ok=false.
func normalizeRange(value string, min, max int) (string, bool) {
	v := strings.ReplaceAll(strings.TrimSpace(value), " ", "")
	if !rangeRe.MatchString(v) {
		return "", false
	}
	fromStr, toStr, isRange := strings.Cut(v, "-")
	from, _ := strconv.Atoi(fromStr)
	to := from
	if isRange {
		to, _ = strconv.Atoi(toStr)
	}
	if from > to {
		from, to = to, from
	}
	if from < min || to > max {
		return "", false
	}
	if from == to {
		return strconv.Itoa(from), true
	}
	return strconv.Itoa(from) + "-" + strconv.Itoa(to), true
}

func validateCore(core domainSettings.CoreSettings) domainSettings.CoreSettings {
	def := defaultCore()
	f := core.Fragment
	switch f.Preset {
	case "standard", "strong", "custom":
	default:
		// В т.ч. убранный пресет "light".
		f.Preset = def.Fragment.Preset
	}
	if p := strings.ToLower(strings.TrimSpace(f.Packets)); p == "tlshello" {
		f.Packets = p
	} else if v, ok := normalizeRange(p, 1, 1000); ok {
		f.Packets = v
	} else {
		f.Packets = def.Fragment.Packets
	}
	if v, ok := normalizeRange(f.Length, 1, 65535); ok {
		f.Length = v
	} else {
		f.Length = def.Fragment.Length
	}
	if v, ok := normalizeRange(f.Interval, 0, 10000); ok {
		f.Interval = v
	} else {
		f.Interval = def.Fragment.Interval
	}
	if strings.TrimSpace(f.MaxSplit) == "" {
		f.MaxSplit = ""
	} else if v, ok := normalizeRange(f.MaxSplit, 1, 10000); ok {
		f.MaxSplit = v
	} else {
		f.MaxSplit = ""
	}
	noises := make([]domainSettings.NoiseSettings, 0, len(f.Noises))
	for _, n := range f.Noises {
		if len(noises) >= maxNoises {
			break
		}
		if valid, ok := validateNoise(n); ok {
			noises = append(noises, valid)
		}
	}
	f.Noises = noises
	core.Fragment = f

	m := core.Mux
	m.Concurrency = clampMuxConcurrency(m.Concurrency, def.Mux.Concurrency)
	m.XUDPConcurrency = clampMuxConcurrency(m.XUDPConcurrency, def.Mux.XUDPConcurrency)
	switch m.XUDPProxyUDP443 {
	case "reject", "allow", "skip":
	default:
		m.XUDPProxyUDP443 = def.Mux.XUDPProxyUDP443
	}
	core.Mux = m
	return core
}

func clampMuxConcurrency(v, def int) int {
	switch {
	case v == -1:
		return -1
	case v <= 0:
		return def
	case v > 1024:
		return 1024
	}
	return v
}

var hexRe = regexp.MustCompile(`^[0-9a-fA-F]+$`)

func validateNoise(n domainSettings.NoiseSettings) (domainSettings.NoiseSettings, bool) {
	n.Type = strings.ToLower(strings.TrimSpace(n.Type))
	n.Packet = strings.TrimSpace(n.Packet)
	switch n.Type {
	case "rand":
		v, ok := normalizeRange(n.Packet, 1, 2048)
		if !ok {
			return n, false
		}
		n.Packet = v
	case "str":
		if n.Packet == "" || len(n.Packet) > 2048 {
			return n, false
		}
	case "hex":
		if n.Packet == "" || len(n.Packet)%2 != 0 || len(n.Packet) > 4096 || !hexRe.MatchString(n.Packet) {
			return n, false
		}
	case "base64":
		if n.Packet == "" || len(n.Packet) > 4096 {
			return n, false
		}
	default:
		return n, false
	}
	if strings.TrimSpace(n.Delay) == "" {
		n.Delay = ""
	} else if v, ok := normalizeRange(n.Delay, 0, 10000); ok {
		n.Delay = v
	} else {
		n.Delay = ""
	}
	return n, true
}

// --- DNS -------------------------------------------------------------------

// defaultDNSFrom собирает список серверов из старых полей Primary/Secondary —
// и для свежей установки, и для миграции v7. Запросы и раньше шли через
// VPN, поэтому Direct не выставляется.
func defaultDNSFrom(conn domainSettings.ConnectionSettings) domainSettings.DNSSettings {
	servers := []domainSettings.DNSServer{}
	seen := map[string]bool{}
	for _, candidate := range []string{conn.PrimaryDNS, conn.SecondaryDNS} {
		addr, ok := normalizeDNSAddress(candidate)
		if !ok || seen[addr] {
			continue
		}
		seen[addr] = true
		servers = append(servers, domainSettings.DNSServer{Address: addr})
	}
	if len(servers) == 0 {
		servers = []domainSettings.DNSServer{{Address: "8.8.8.8"}, {Address: "1.1.1.1"}}
	}
	return domainSettings.DNSSettings{
		Servers: servers,
		Rules:   []domainSettings.DNSRule{},
		Hosts:   []domainSettings.DNSHost{},
	}
}

// dnsSchemes — транспорты, которые есть в ядре. DNS-over-TLS в Xray нет,
// DNS-over-QUIC бывает только прямым (+local).
var dnsSchemes = map[string]bool{
	"https": true, "https+local": true,
	"h2c": true, "h2c+local": true,
	"tcp": true, "tcp+local": true,
	"quic+local": true,
}

// normalizeDNSAddress проверяет адрес DNS-сервера. Допустимы IP, IP:порт
// и URL со схемой из dnsSchemes. Системный резолвер (localhost) не допускается:
// в TUN он спрашивает сам туннель и зацикливает DNS.
func normalizeDNSAddress(value string) (string, bool) {
	v := strings.TrimSpace(value)
	if v == "" || len(v) > 512 {
		return "", false
	}
	if strings.Contains(v, "://") {
		u, err := url.Parse(v)
		if err != nil || u.Host == "" {
			return "", false
		}
		u.Scheme = strings.ToLower(u.Scheme)
		if !dnsSchemes[u.Scheme] {
			return "", false
		}
		if host := u.Hostname(); host == "" || unusableResolverIP(host) {
			return "", false
		}
		return u.String(), true
	}
	if ap, err := netip.ParseAddrPort(v); err == nil {
		if ap.Port() == 0 || unusableResolverIP(ap.Addr().String()) {
			return "", false
		}
		if ap.Port() == 53 {
			return ap.Addr().Unmap().String(), true
		}
		return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port()).String(), true
	}
	if addr, err := netip.ParseAddr(v); err == nil {
		if unusableResolverIP(addr.String()) {
			return "", false
		}
		return addr.Unmap().String(), true
	}
	return "", false
}

// tunResolverSubnet — подсеть интерфейса туннеля: резолвер в ней отправлял бы
// запросы обратно в туннель.
var tunResolverSubnet = netip.MustParsePrefix("172.19.0.0/30")

// unusableResolverIP отсекает адреса, которые не могут обслуживать DNS из
// ядра. Имена (dns.google) пропускаются.
func unusableResolverIP(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	addr, err := netip.ParseAddr(strings.Trim(host, "[]"))
	if err != nil {
		return false
	}
	addr = addr.Unmap()
	return tunResolverSubnet.Contains(addr) || addr.IsLoopback() || addr.IsUnspecified() ||
		addr.IsMulticast() || addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast()
}

// isLocalScheme — серверы +local всегда прямые: ядро ходит к ним мимо маршрутизации.
func isLocalScheme(addr string) bool {
	scheme, _, ok := strings.Cut(addr, "://")
	return ok && strings.HasSuffix(strings.ToLower(scheme), "+local")
}

var dnsDomainPrefixes = []string{"geosite:", "domain:", "full:", "keyword:", "regexp:", "dotless:"}

// normalizeDNSDomain пропускает домен правила DNS в синтаксисе Xray.
// Голый домен остаётся как есть — его к формату ядра приводит сборщик.
func normalizeDNSDomain(value string) (string, bool) {
	v := strings.TrimSpace(value)
	if v == "" || len(v) > 512 || strings.ContainsAny(v, " \t\r\n") {
		return "", false
	}
	lower := strings.ToLower(v)
	for _, prefix := range dnsDomainPrefixes {
		if strings.HasPrefix(lower, prefix) {
			rest := v[len(prefix):]
			if rest == "" && prefix != "dotless:" {
				return "", false
			}
			if prefix == "regexp:" {
				if _, err := regexp.Compile(rest); err != nil {
					return "", false
				}
				return prefix + rest, true
			}
			return prefix + strings.ToLower(rest), true
		}
	}
	if strings.Contains(lower, ":") {
		return "", false
	}
	return lower, true
}

func validateDNS(dns domainSettings.DNSSettings) domainSettings.DNSSettings {
	servers := make([]domainSettings.DNSServer, 0, len(dns.Servers))
	seen := map[string]bool{}
	for _, s := range dns.Servers {
		if len(servers) >= maxDNSServers {
			break
		}
		addr, ok := normalizeDNSAddress(s.Address)
		if !ok || seen[addr] {
			continue
		}
		seen[addr] = true
		servers = append(servers, domainSettings.DNSServer{Address: addr, Direct: s.Direct || isLocalScheme(addr)})
	}
	if len(servers) == 0 {
		servers = defaultDNSFrom(domainSettings.ConnectionSettings{}).Servers
	}

	rules := make([]domainSettings.DNSRule, 0, len(dns.Rules))
	for _, rule := range dns.Rules {
		if len(rules) >= maxDNSRules {
			break
		}
		addr, ok := normalizeDNSAddress(rule.Server)
		if !ok {
			continue
		}
		domains := make([]string, 0, len(rule.Domains))
		domainSeen := map[string]bool{}
		for _, d := range rule.Domains {
			if nd, ok := normalizeDNSDomain(d); ok && !domainSeen[nd] {
				domainSeen[nd] = true
				domains = append(domains, nd)
			}
		}
		if len(domains) == 0 {
			continue
		}
		rules = append(rules, domainSettings.DNSRule{Domains: domains, Server: addr, Direct: rule.Direct || isLocalScheme(addr)})
	}

	hosts := make([]domainSettings.DNSHost, 0, len(dns.Hosts))
	hostSeen := map[string]bool{}
	for _, h := range dns.Hosts {
		if len(hosts) >= maxDNSHosts {
			break
		}
		domain, ok := normalizeDNSDomain(h.Domain)
		if !ok || hostSeen[domain] || strings.HasPrefix(domain, "geosite:") {
			continue
		}
		if addrs, ok := normalizeHostAddresses(h.Address); ok {
			hostSeen[domain] = true
			hosts = append(hosts, domainSettings.DNSHost{Domain: domain, Address: addrs})
		}
	}

	dns.Servers = servers
	dns.Rules = rules
	dns.Hosts = hosts
	return dns
}

var hostnameRe = regexp.MustCompile(`^(?i)[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$`)

// normalizeHostAddresses: либо набор IP, либо один домен (перенаправление).
func normalizeHostAddresses(in []string) ([]string, bool) {
	ips := make([]string, 0, len(in))
	var domain string
	for _, raw := range in {
		v := strings.TrimSpace(raw)
		if v == "" {
			continue
		}
		if addr, err := netip.ParseAddr(v); err == nil {
			ips = append(ips, addr.Unmap().String())
			continue
		}
		if hostnameRe.MatchString(v) && domain == "" {
			domain = strings.ToLower(v)
		}
	}
	if len(ips) > 0 {
		return ips, true
	}
	if domain != "" {
		return []string{domain}, true
	}
	return nil, false
}

// syncTunnelResolvers пишет первые обычные (UDP) серверы в Primary/Secondary:
// туннель перенаправляет на них порт 53, а отвечает всё равно DNS ядра.
func syncTunnelResolvers(conn *domainSettings.ConnectionSettings, dns domainSettings.DNSSettings) {
	plain := make([]string, 0, 2)
	for _, s := range dns.Servers {
		if addr, err := netip.ParseAddr(s.Address); err == nil {
			plain = append(plain, addr.String())
			if len(plain) == 2 {
				break
			}
		}
	}
	if len(plain) > 0 {
		conn.PrimaryDNS = plain[0]
	}
	if len(plain) > 1 {
		conn.SecondaryDNS = plain[1]
	}
}

func sameJSON(a, b any) bool {
	ja, errA := json.Marshal(a)
	jb, errB := json.Marshal(b)
	return errA == nil && errB == nil && bytes.Equal(ja, jb)
}

// fillXrayDefaults достраивает разделы, которых нет в старом config.json.
func (r *JSONRepository) fillXrayDefaults() bool {
	changed := false
	if r.settings.Core.Fragment.Preset == "" && r.settings.Core.Mux.XUDPProxyUDP443 == "" {
		r.settings.Core = defaultCore()
		changed = true
	} else if validated := validateCore(r.settings.Core); !sameJSON(validated, r.settings.Core) {
		r.settings.Core = validated
		changed = true
	}
	if r.settings.DNS.Servers == nil {
		dns := defaultDNSFrom(r.settings.Connection)
		r.settings.DNS.Servers = dns.Servers
		changed = true
	}
	if r.settings.DNS.Rules == nil {
		r.settings.DNS.Rules = []domainSettings.DNSRule{}
		changed = true
	}
	if r.settings.DNS.Hosts == nil {
		r.settings.DNS.Hosts = []domainSettings.DNSHost{}
		changed = true
	}
	return changed
}
