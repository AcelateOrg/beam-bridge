package profile

import (
	"net/netip"
	"strings"

	domainSettings "beam-bridge/core/domain/settings"
)

// Тонкая настройка сгенерированного конфига: фрагментация, Mux/XUDP и DNS.

const (
	// outboundFragment — freedom-outbound с фрагментацией, через который ноды
	// открывают соединение с сервером (sockopt.dialerProxy). Префикс "direct"
	// исключает его из счётчика VPN-трафика: иначе байты ноды считались
	// бы дважды.
	outboundFragment = "direct-fragment"

	// dnsDirectTag помечает запросы к DNS-серверам «напрямую»: маршрутизация
	// отправляет их в direct, привязанный к физическому интерфейсу, так что
	// в TUN они не возвращаются в туннель.
	dnsDirectTag = "dns-direct"
)

func (b *XrayConfigBuilder) WithCore(core domainSettings.CoreSettings) *XrayConfigBuilder {
	b.core = core
	return b
}

func (b *XrayConfigBuilder) WithDNS(dns domainSettings.DNSSettings) *XrayConfigBuilder {
	b.dns = dns
	return b
}

// --- Переопределения ноды -----------------------------------------------------

// nodeOptionsKey — ключ outbound ноды с настройками BEAM (не параметрами
// протокола): beam.fragment = false — не фрагментировать, beam.mux = "on" |
// "off" — переопределить Mux. Задаются правками ноды (Overrides).
const nodeOptionsKey = "beam"

type nodeOptions struct {
	noFragment bool
	mux        string
}

func nodeOptionsOf(source map[string]interface{}) nodeOptions {
	opts := getMap(source, nodeOptionsKey)
	if opts == nil {
		return nodeOptions{}
	}
	out := nodeOptions{}
	if v, ok := opts["fragment"].(bool); ok && !v {
		out.noFragment = true
	}
	switch mux := getStr(opts, "mux"); mux {
	case "on", "off":
		out.mux = mux
	}
	return out
}

// nodeTuning применяет глобальные настройки ядра к outbound ноды. Общий для
// конфига подключения и изолированного пинга: пинг по протоколу должен
// идти тем же путём, что и трафик, иначе заблокированная без фрагментации
// нода показывала бы таймаут.
type nodeTuning struct {
	core domainSettings.CoreSettings
}

// apply правит converted на месте и сообщает, нужен ли outboundFragment.
// chain — хопы цепочки ноды (уже связанные linkChain): фрагментируется
// последний, он и открывает соединение. Если последний хоп — freedom
// провайдера, у цепочки своя фрагментация и глобальная не нужна.
func (t nodeTuning) apply(source, converted map[string]interface{}, chain []map[string]interface{}, withMux bool) bool {
	opts := nodeOptionsOf(source)
	usesFragment := false
	dialer := lastHop(converted, chain)
	if t.core.Fragment.Enabled && !opts.noFragment && getStr(dialer, "protocol") != "freedom" &&
		fragmentApplies(dialer, t.core.Fragment) {
		sockoptOf(dialer)["dialerProxy"] = outboundFragment
		usesFragment = true
	}
	if withMux {
		if mux := t.muxFor(source, converted, opts); mux != nil {
			converted["mux"] = mux
		}
	}
	return usesFragment
}

// fragmentApplies: фрагментация — свойство TCP. Hysteria работает поверх QUIC, ей
// можно помочь только шумом перед первым пакетом.
func fragmentApplies(converted map[string]interface{}, f domainSettings.FragmentSettings) bool {
	if getStr(converted, "protocol") == "hysteria" {
		return len(f.Noises) > 0
	}
	return true
}

func sockoptOf(outbound map[string]interface{}) map[string]interface{} {
	stream, ok := outbound["streamSettings"].(map[string]interface{})
	if !ok {
		stream = map[string]interface{}{}
		outbound["streamSettings"] = stream
	}
	sockopt, ok := stream["sockopt"].(map[string]interface{})
	if !ok {
		sockopt = map[string]interface{}{}
		stream["sockopt"] = sockopt
	}
	return sockopt
}

func streamNetwork(outbound map[string]interface{}) string {
	if stream := getMap(outbound, "streamSettings"); stream != nil {
		return getStr(stream, "network")
	}
	return ""
}

// muxFor собирает блок mux или nil. Vision и Hysteria с Mux.Cool не
// совместимы вообще; XHTTP мультиплексирует сам (xmux), поэтому
// глобальный выключатель его не трогает — только явное «вкл» у ноды.
func (t nodeTuning) muxFor(source, converted map[string]interface{}, opts nodeOptions) map[string]interface{} {
	enabled := t.core.Mux.Enabled
	// Mux из конфига провайдера (multiplex) важнее глобального; явное
	// «вкл/выкл» у ноды важнее обоих.
	own := getMap(source, "multiplex")
	if own != nil {
		enabled = boolValue(own["enabled"])
	}
	switch opts.mux {
	case "on":
		enabled = true
	case "off":
		enabled = false
	}
	if !enabled {
		return nil
	}
	if getStr(converted, "protocol") == "hysteria" || strings.Contains(strings.ToLower(getStr(source, "flow")), "vision") {
		return nil
	}
	if streamNetwork(converted) == "xhttp" && opts.mux != "on" {
		return nil
	}
	m := t.core.Mux
	if own != nil {
		if v, ok := own["concurrency"]; ok {
			m.Concurrency = intValue(v)
		}
		if v, ok := own["xudp_concurrency"]; ok {
			m.XUDPConcurrency = intValue(v)
		}
		if v := getStr(own, "xudp_proxy_udp443"); v != "" {
			m.XUDPProxyUDP443 = v
		}
	}
	if m.Concurrency == -1 && m.XUDPConcurrency == -1 {
		return nil
	}
	mux := map[string]interface{}{
		"enabled":         true,
		"concurrency":     m.Concurrency,
		"xudpConcurrency": m.XUDPConcurrency,
	}
	if m.XUDPProxyUDP443 != "" {
		mux["xudpProxyUDP443"] = m.XUDPProxyUDP443
	}
	return mux
}

// fragmentSettings — settings freedom-outbound с фрагментацией и шумом.
func fragmentSettings(f domainSettings.FragmentSettings) map[string]interface{} {
	params := f.Params()
	settings := map[string]interface{}{}
	// Провайдер может прислать только шум, без фрагментации.
	if params.Packets != "" {
		fragment := map[string]interface{}{
			"packets":  params.Packets,
			"length":   params.Length,
			"interval": params.Interval,
		}
		if params.MaxSplit != "" {
			fragment["maxSplit"] = params.MaxSplit
		}
		settings["fragment"] = fragment
	}
	if len(f.Noises) > 0 {
		noises := make([]interface{}, 0, len(f.Noises))
		for _, n := range f.Noises {
			noise := map[string]interface{}{"type": n.Type, "packet": n.Packet}
			if n.Delay != "" {
				noise["delay"] = n.Delay
			}
			noises = append(noises, noise)
		}
		settings["noises"] = noises
	}
	return settings
}

func (t nodeTuning) fragmentOutbound() map[string]interface{} {
	return map[string]interface{}{
		"tag":      outboundFragment,
		"protocol": "freedom",
		"settings": fragmentSettings(t.core.Fragment),
	}
}

// directOutbound — прямой outbound; с включённой «фрагментацией прямого
// трафика» он сам фрагментирует и шумит.
func (b *XrayConfigBuilder) directOutbound() map[string]interface{} {
	direct := map[string]interface{}{"tag": outboundDirect, "protocol": "freedom"}
	if b.fragmentDirect() {
		direct["settings"] = fragmentSettings(b.core.Fragment)
	}
	return direct
}

func (b *XrayConfigBuilder) fragmentDirect() bool {
	return b.core.Fragment.Enabled && b.core.Fragment.Direct
}

// --- DNS -------------------------------------------------------------------

// dnsServerEntry переводит адрес из настроек в объект сервера Xray. IP:порт
// раскладывается на address и port, URL передаётся как есть.
func dnsServerEntry(address string) (map[string]interface{}, bool) {
	address = strings.TrimSpace(address)
	if address == "" {
		return nil, false
	}
	if strings.Contains(address, "://") {
		return map[string]interface{}{"address": address}, true
	}
	if ap, err := netip.ParseAddrPort(address); err == nil {
		dns, ok := usableResolver(ap.Addr().String())
		if !ok {
			return nil, false
		}
		return map[string]interface{}{"address": dns, "port": int(ap.Port())}, true
	}
	dns, ok := usableResolver(address)
	if !ok {
		return nil, false
	}
	if _, err := netip.ParseAddr(dns); err != nil {
		return nil, false
	}
	return map[string]interface{}{"address": dns}, true
}

func isLocalDNS(address string) bool {
	scheme, _, ok := strings.Cut(address, "://")
	return ok && strings.HasSuffix(strings.ToLower(scheme), "+local")
}

// dnsRuleDomains приводит домены правила к синтаксису ядра: с префиксом — как
// есть, голый домен — тем же правилом, что и в маршрутизации.
func dnsRuleDomains(items []string) []string {
	out := make([]string, 0, len(items))
	plain := make([]string, 0, len(items))
	for _, item := range items {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if strings.Contains(item, ":") {
			out = append(out, item)
			continue
		}
		plain = append(plain, item)
	}
	return append(out, xrayDomainPatterns(plain)...)
}

// WithProfileDNS подставляет DNS из конфига профиля (см. buildProfileDNS)
// вместо настроек BEAM; nil оставляет настройки BEAM.
func (b *XrayConfigBuilder) WithProfileDNS(dns map[string]interface{}) *XrayConfigBuilder {
	b.profileDNS = dns
	return b
}

func (b *XrayConfigBuilder) hasDirectDNS() bool {
	if b.profileDNS != nil {
		return false
	}
	for _, s := range b.dns.Servers {
		if s.Direct && !isLocalDNS(s.Address) {
			return true
		}
	}
	for _, r := range b.dns.Rules {
		if r.Direct && !isLocalDNS(r.Server) {
			return true
		}
	}
	return false
}

func (b *XrayConfigBuilder) buildDNS() map[string]interface{} {
	if b.profileDNS != nil {
		return b.profileDNS
	}
	servers := []interface{}{}
	add := func(address string, direct bool, domains []string) bool {
		entry, ok := dnsServerEntry(address)
		if !ok {
			return false
		}
		if direct && !isLocalDNS(address) {
			entry["tag"] = dnsDirectTag
		}
		if len(domains) > 0 {
			entry["domains"] = domains
			entry["skipFallback"] = true
		}
		servers = append(servers, entry)
		return true
	}

	// Servers of domain rules go first: their domains are matched before
	// the general list, and skipFallback keeps them out of other lookups.
	for _, rule := range b.dns.Rules {
		if domains := dnsRuleDomains(rule.Domains); len(domains) > 0 {
			add(rule.Server, rule.Direct, domains)
		}
	}
	general := 0
	for _, s := range b.dns.Servers {
		if add(s.Address, s.Direct, nil) {
			general++
		}
	}
	// Old configs (and the builder used without WithDNS) still carry only
	// the primary/secondary pair.
	if general == 0 {
		for _, candidate := range []string{b.settings.PrimaryDNS, b.settings.SecondaryDNS} {
			if add(candidate, false, nil) {
				general++
			}
		}
	}
	if general == 0 {
		add(fallbackDNS, false, nil)
	}

	dns := map[string]interface{}{
		"servers":       servers,
		"queryStrategy": "UseIPv4",
		"disableCache":  b.dns.DisableCache,
		"tag":           dnsInboundTag,
	}
	if b.dns.ServeStale {
		dns["serveStale"] = true
	}
	if b.dns.ParallelQuery {
		dns["enableParallelQuery"] = true
	}
	if b.dns.SystemHosts {
		dns["useSystemHosts"] = true
	}
	if len(b.dns.Hosts) > 0 {
		hosts := make(map[string]interface{}, len(b.dns.Hosts))
		for _, h := range b.dns.Hosts {
			if h.Domain == "" || len(h.Address) == 0 {
				continue
			}
			if len(h.Address) == 1 {
				hosts[h.Domain] = h.Address[0]
			} else {
				hosts[h.Domain] = h.Address
			}
		}
		if len(hosts) > 0 {
			dns["hosts"] = hosts
		}
	}
	return dns
}

// hasIPRules: пользовательские правила с IP/GeoIP. Только тогда маршрутизации
// есть смысл резолвить домен (IPIfNonMatch), иначе это лишний DNS-запрос на
// каждое новое соединение.
func hasIPRules(rules []userRule) bool {
	for _, rule := range rules {
		if _, ok := rule.object["ip"]; ok {
			return true
		}
	}
	return false
}
