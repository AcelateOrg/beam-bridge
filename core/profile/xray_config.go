package profile

import (
	"net/netip"
	"strings"

	"beam-bridge/core/coreapi"
	domainSettings "beam-bridge/core/domain/settings"
	infraBeam "beam-bridge/core/infrastructure/beam"
	"beam-bridge/core/types"
)

const (
	outboundDirect = "direct"
	outboundBlock  = "block"
)

// dnsInboundTag marks the queries the built-in DNS app sends upstream, so
// routing can forward them through the proxy instead of intercepting them
// again and looping.
const dnsInboundTag = "dns-in"

// outboundDNS answers port 53 traffic from the core's DNS app. Without it
// every lookup is relayed to the upstream resolver through the proxy, which
// means a fresh tunnelled session per query and no caching at all.
const outboundDNS = "dns-out"

const dnsPort = 53

const fallbackDNS = "1.1.1.1"

// tunSubnet mirrors the tunnel interface subnet. Resolvers inside it would
// send queries back into the tunnel, so they are never written to the config.
var tunSubnet = netip.MustParsePrefix("172.19.0.0/30")

// privateIPRanges replaces the geoip:private list. Spelling the CIDRs out
// keeps the config free of geoip.dat, which is not shipped with the app.
var privateIPRanges = []string{
	"0.0.0.0/8",
	"10.0.0.0/8",
	"100.64.0.0/10",
	"127.0.0.0/8",
	"169.254.0.0/16",
	"172.16.0.0/12",
	"192.0.0.0/24",
	"192.0.2.0/24",
	"192.88.99.0/24",
	"192.168.0.0/16",
	"198.18.0.0/15",
	"198.51.100.0/24",
	"203.0.113.0/24",
	"224.0.0.0/4",
	"240.0.0.0/4",
	"255.255.255.255/32",
	"::1/128",
	"fc00::/7",
	"fe80::/10",
	"ff00::/8",
}

type XrayConfig struct {
	Config           map[string]interface{}
	Routes           coreapi.RoutePlan
	ProxyTag         string
	UnsupportedNodes map[string]string
}

type XrayConfigBuilder struct {
	settings    domainSettings.ConnectionSettings
	splitTunnel types.SplitTunnelSettings
	routingMode string
	proTunGraph types.ProTunGraph
	// proTunProfile is the layer of the active profile; its rules go
	// before proTunGraph (the global layer).
	proTunProfile types.ProTunGraph
	servers       []serverTarget
	// serverTags: ref key -> outbound tag of the servers that made it into
	// the config (filled by BuildFromBeam).
	serverTags   map[string]string
	logPath      string
	extendedLogs bool
	logLevel     string
	core         domainSettings.CoreSettings
	dns          domainSettings.DNSSettings
	// profileDNS — готовый раздел "dns" из конфига профиля; если задан,
	// заменяет собранный из dns.
	profileDNS map[string]interface{}
}

func NewXrayConfigBuilder(
	s domainSettings.ConnectionSettings,
	st types.SplitTunnelSettings,
) *XrayConfigBuilder {
	return &XrayConfigBuilder{settings: s, splitTunnel: st}
}

// WithLogPath заставляет ядро писать свой лог в файл. Без этого лог уходит только
// в консоль процесса, и разобрать упавшее подключение постфактум нечем.
func (b *XrayConfigBuilder) WithLogPath(path string) *XrayConfigBuilder {
	b.logPath = path
	return b
}

// WithLogLevel задаёт базовый уровень логов ядра из пользовательской
// настройки ("off" | "error" | "info" | "debug"). Режим разработчика
// (WithExtendedLogs) всегда перекрывает его на debug.
func (b *XrayConfigBuilder) WithLogLevel(level string) *XrayConfigBuilder {
	b.logLevel = level
	return b
}

// WithExtendedLogs включает режим разработчика для сгенерированного конфига:
// уровень логов ядра debug и запись xray-core.log. По умолчанию — warning и
// никаких файлов.
func (b *XrayConfigBuilder) WithExtendedLogs(enabled bool) *XrayConfigBuilder {
	b.extendedLogs = enabled
	return b
}

func (b *XrayConfigBuilder) WithProTunGraph(mode string, graph types.ProTunGraph) *XrayConfigBuilder {
	b.routingMode = mode
	b.proTunGraph = graph
	return b
}

// WithProTunProfileLayer sets the active profile's ProTun layer.
func (b *XrayConfigBuilder) WithProTunProfileLayer(graph types.ProTunGraph) *XrayConfigBuilder {
	b.proTunProfile = graph
	return b
}

// serverTarget is a server a «Сервер» destination points at. node is set
// for servers of other profiles: their outbound is added under tag. For the
// active profile node is nil and tag is the node ID already in the config.
type serverTarget struct {
	key  string
	tag  string
	node *types.BeamNode
}

func serverRefKey(ref *types.ProTunServerRef) string {
	if ref == nil {
		return ""
	}
	key := ref.ProfileID + "/" + ref.NodeID
	if ref.Via != nil {
		key += "|via:" + ref.Via.ProfileID + "/" + ref.Via.NodeID
	}
	return key
}

func (b *XrayConfigBuilder) withServerTargets(targets []serverTarget) *XrayConfigBuilder {
	b.servers = targets
	return b
}

func (b *XrayConfigBuilder) resolveServer(ref *types.ProTunServerRef) string {
	return b.serverTags[serverRefKey(ref)]
}

func (b *XrayConfigBuilder) BuildFromBeam(beam *infraBeam.BeamFile) *XrayConfig {
	selected := beam.GetSelectedNode()
	if selected == nil {
		return nil
	}

	unsupported := map[string]string{}
	outbounds := make([]interface{}, 0, len(beam.Data.Nodes)+2)
	var selectedTag string
	tuning := nodeTuning{core: b.core}
	fragmentUsed := false

	for i := range beam.Data.Nodes {
		node := &beam.Data.Nodes[i]
		source := node.EffectiveOutbound()
		if !usableOutbound(source) {
			unsupported[node.ID] = "node has no usable server address"
			continue
		}
		if node.ID == selected.ID {
			source = resolveOutboundAddress(source)
		}

		converted, err := convertOutbound(source)
		if err != nil {
			unsupported[node.ID] = err.Error()
			continue
		}
		converted["tag"] = node.ID
		chain := takeChain(converted)
		hops := linkChain(converted, node.ID, chain)
		if tuning.apply(source, converted, chain, true) {
			fragmentUsed = true
		}
		outbounds = append(outbounds, converted)
		outbounds = append(outbounds, hops...)
		if node.ID == selected.ID {
			selectedTag = node.ID
		}
	}

	if selectedTag == "" {
		return &XrayConfig{UnsupportedNodes: unsupported}
	}

	built := make(map[string]bool, len(outbounds))
	for _, item := range outbounds {
		if ob, ok := item.(map[string]interface{}); ok {
			built[getStr(ob, "tag")] = true
		}
	}
	b.serverTags = make(map[string]string, len(b.servers))
	for _, target := range b.servers {
		if target.node != nil && !built[target.tag] {
			source := target.node.EffectiveOutbound()
			if !usableOutbound(source) {
				continue
			}
			// Routed to by rules, so dialed like the selected server.
			source = resolveOutboundAddress(source)
			converted, err := convertOutbound(source)
			if err != nil {
				continue
			}
			converted["tag"] = target.tag
			chain := takeChain(converted)
			hops := linkChain(converted, target.tag, chain)
			if tuning.apply(source, converted, chain, true) {
				fragmentUsed = true
			}
			outbounds = append(outbounds, converted)
			outbounds = append(outbounds, hops...)
			built[target.tag] = true
		}
		if built[target.tag] {
			b.serverTags[target.key] = target.tag
		}
	}

	outbounds = moveTagFirst(outbounds, selectedTag)
	if fragmentUsed {
		outbounds = append(outbounds, tuning.fragmentOutbound())
	}
	outbounds = append(outbounds,
		map[string]interface{}{"tag": outboundDNS, "protocol": "dns"},
		b.directOutbound(),
		map[string]interface{}{"tag": outboundBlock, "protocol": "blackhole"},
	)

	routing := b.buildRouting(selectedTag)

	return &XrayConfig{
		Config: map[string]interface{}{
			"log":       b.buildLog(),
			"dns":       b.buildDNS(),
			"inbounds":  b.buildInbounds(),
			"outbounds": outbounds,
			"routing":   routing.object,
			// No "api" section: the gRPC API had no authentication, so any
			// local program could reconfigure the elevated core through it.
			// Counters are read in-process (see xray/stats.go).
			"stats":  map[string]interface{}{},
			"policy": b.buildPolicy(),
		},
		Routes:           routing.plan,
		ProxyTag:         selectedTag,
		UnsupportedNodes: unsupported,
	}
}

func moveTagFirst(outbounds []interface{}, tag string) []interface{} {
	for i, item := range outbounds {
		ob, ok := item.(map[string]interface{})
		if !ok || getStr(ob, "tag") != tag {
			continue
		}
		if i == 0 {
			return outbounds
		}
		reordered := make([]interface{}, 0, len(outbounds))
		reordered = append(reordered, ob)
		reordered = append(reordered, outbounds[:i]...)
		reordered = append(reordered, outbounds[i+1:]...)
		return reordered
	}
	return outbounds
}

func (b *XrayConfigBuilder) buildLog() map[string]interface{} {
	// Уровень ядра следует пользовательской настройке вкладки «Логи»:
	// "off" глушит ядро полностью, "error" — только ошибки, "info" —
	// соединения и ошибки без отладочного спама. Режим разработчика
	// безусловно поднимает уровень до debug и включает xray-core.log.
	level := "info"
	switch b.logLevel {
	case "off":
		level = "none"
	case "error":
		level = "error"
	case "debug":
		level = "debug"
	}
	if b.extendedLogs {
		level = "debug"
	}
	log := map[string]interface{}{
		"loglevel": level,
		"access":   "none",
	}
	if b.extendedLogs && b.logPath != "" {
		log["error"] = b.logPath
	}
	return log
}

// usableResolver normalizes a configured resolver and rejects addresses that
// cannot safely serve DNS from inside the core: the tunnel subnet itself,
// loopback, unspecified, multicast and link-local addresses.
func usableResolver(value string) (string, bool) {
	dns := strings.TrimSpace(value)
	if dns == "" {
		return "", false
	}
	addr, err := netip.ParseAddr(dns)
	if err != nil {
		return dns, true
	}
	addr = addr.Unmap()
	if tunSubnet.Contains(addr) ||
		addr.IsLoopback() ||
		addr.IsUnspecified() ||
		addr.IsMulticast() ||
		addr.IsLinkLocalUnicast() ||
		addr.IsLinkLocalMulticast() {
		return "", false
	}
	return addr.String(), true
}

func (b *XrayConfigBuilder) buildInbounds() []interface{} {
	if b.settings.Mode == "tun" {
		return []interface{}{}
	}

	port := b.settings.ProxyPort
	if port <= 0 {
		port = 2080
	}
	return []interface{}{
		map[string]interface{}{
			"tag":      "socks-in",
			"protocol": "socks",
			"listen":   "127.0.0.1",
			"port":     port,
			"settings": map[string]interface{}{
				"udp": true,
			},
			"sniffing": map[string]interface{}{
				"enabled":      true,
				"destOverride": []string{"http", "tls", "quic"},
				"routeOnly":    true,
			},
		},
	}
}

func (b *XrayConfigBuilder) buildPolicy() map[string]interface{} {
	levels := map[string]interface{}{
		"0": map[string]interface{}{
			"statsUserUplink":   true,
			"statsUserDownlink": true,
			"handshake":         8,
			"connIdle":          300,
		},
	}
	return map[string]interface{}{
		"levels": levels,
		"system": map[string]interface{}{
			"statsOutboundUplink":   true,
			"statsOutboundDownlink": true,
		},
	}
}

type routingResult struct {
	object map[string]interface{}
	plan   coreapi.RoutePlan
}

func (b *XrayConfigBuilder) buildRouting(proxyTag string) routingResult {
	rules := []interface{}{
		// Upstream queries made by the DNS app must reach the resolver
		// through the proxy; catching them with the port 53 rule below
		// would feed them back into the DNS app.
		map[string]interface{}{
			"type":        "field",
			"inboundTag":  []string{dnsInboundTag},
			"outboundTag": proxyTag,
		},
	}
	if b.hasDirectDNS() {
		// Servers marked «direct» bypass the proxy; in TUN mode the direct
		// outbound is bound to the physical interface, so no loop.
		rules = append(rules, map[string]interface{}{
			"type":        "field",
			"inboundTag":  []string{dnsDirectTag},
			"outboundTag": outboundDirect,
		})
	}
	rules = append(rules,
		// Everything else asking for DNS is served by the DNS app, which
		// caches answers instead of opening a tunnelled session per query.
		map[string]interface{}{
			"type":        "field",
			"ruleTag":     ruleTag(ruleTagDNS, 0, ""),
			"port":        dnsPort,
			"outboundTag": outboundDNS,
		},
		map[string]interface{}{
			"type":        "field",
			"ruleTag":     ruleTag(ruleTagLAN, 0, ""),
			"ip":          privateIPRanges,
			"outboundTag": outboundDirect,
		},
	)

	// Режимы взаимоисключающие: "pro" — только ProTun-граф, иначе ("easy") —
	// только сплит-туннель. Всё, что явно не указано, идёт в VPN; в ProTun
	// финал меняет только узел «Остальное».
	finalOutbound := proxyTag
	var ordered []userRule
	var known []string
	if b.routingMode == "pro" {
		known = knownApps(b.proTunProfile, b.proTunGraph)
		// Layers in strict priority: the active profile's rules, then the
		// global ones. Each layer keeps its own order;
		// «Остальное» comes from the first layer that wires it.
		finalSet := false
		for _, graph := range []types.ProTunGraph{b.proTunProfile, b.proTunGraph} {
			if len(graph.Edges) == 0 {
				continue
			}
			compiled := compileProTun(graph, proxyTag, b.resolveServer, known)
			// compileProTun already orders the rules (specificity, then the
			// place of the cards on the canvas).
			ordered = append(ordered, compiled.Rules...)
			if compiled.HasFinal && !finalSet {
				finalOutbound = compiled.FinalOutbound
				finalSet = true
			}
		}
		resolveExceptOutbound(ordered, finalOutbound)
	} else if b.splitTunnel.Enabled {
		ordered = orderUserRules(b.buildSplitTunnelRules(proxyTag))
	}

	rules = append(rules, ruleObjects(ordered)...)
	plan := buildRoutePlan(ordered, finalOutbound, known)
	plan.DisableBypass = b.fragmentDirect()

	domainStrategy := "AsIs"
	if hasIPRules(ordered) {
		domainStrategy = "IPIfNonMatch"
	}

	rules = append(rules, map[string]interface{}{
		"type":        "field",
		"ruleTag":     ruleTag(ruleTagFinal, 0, ""),
		"network":     "tcp,udp",
		"outboundTag": finalOutbound,
	})

	return routingResult{
		object: map[string]interface{}{
			// AsIs keeps routing from resolving every sniffed domain before
			// it picks an outbound. IPIfNonMatch adds a DNS round trip to
			// each new connection, so it is used only when user rules match
			// by IP/GeoIP and a sniffed domain must be checked against them.
			"domainStrategy": domainStrategy,
			"domainMatcher":  "hybrid",
			"rules":          rules,
		},
		plan: plan,
	}
}

func (b *XrayConfigBuilder) buildSplitTunnelRules(proxyTag string) []userRule {
	st := b.splitTunnel
	target := proxyTag
	if st.Mode == "exclude" {
		target = outboundDirect
	}

	var rules []userRule

	// Приложения сопоставляются по inboundTag (по тегу на приложение, его
	// проставляет туннель по процессу-владельцу соединения).
	if apps := trimAll(st.Apps); len(apps) > 0 {
		rules = append(rules, userRule{
			object: map[string]interface{}{
				"type":        "field",
				"inboundTag":  appTags(apps),
				"outboundTag": target,
			},
			apps:     apps,
			outbound: target,
			label:    labelOf(apps),
		})
	}
	if domains := xrayDomainPatterns(st.Domains); len(domains) > 0 {
		rules = append(rules, userRule{
			object: map[string]interface{}{
				"type":        "field",
				"domain":      domains,
				"outboundTag": target,
			},
			conditional: true,
			outbound:    target,
			label:       labelOf(domains),
		})
	}
	if ips := trimAll(st.IPs); len(ips) > 0 {
		rules = append(rules, userRule{
			object: map[string]interface{}{
				"type":        "field",
				"ip":          ips,
				"outboundTag": target,
			},
			conditional: true,
			outbound:    target,
			label:       labelOf(ips),
		})
	}

	return rules
}
