package profile

import (
	"net/netip"
	"sort"
	"strconv"
	"strings"

	"beam-bridge/core/coreapi"
	"beam-bridge/core/types"
)

// exceptOutbound marks the rules carved out by a card's «кроме» list. They
// go wherever unmatched traffic goes, which is only known once every layer
// is compiled (see resolveExceptOutbound).
const exceptOutbound = "\x00rest"

type xrayField string

const (
	fieldApps     xrayField = "apps"
	fieldDomains  xrayField = "domain"
	fieldIP       xrayField = "ip"
	fieldProtocol xrayField = "protocol"
	fieldPort     xrayField = "port"
	fieldNetwork  xrayField = "network"
)

// knownProtocols are the values a protocols card may select, spelled as the
// core's sniffer reports them ("http" also covers "http1"/"http2": the core
// matches protocols by prefix). Anything else is dropped before it reaches
// the config.
var knownProtocols = map[string]bool{
	"bittorrent": true,
	"quic":       true,
	"tls":        true,
	"http":       true,
}

type xrayTerm struct {
	fields map[xrayField][]string
	// except: values carved out of the term («кроме»), per field.
	except map[xrayField][]string
	// all: the term matches every flow but the carved-out ones («Все, кроме»
	// on a domain, IP or geo card). Without fields it has no condition of its
	// own, so it compiles to a catch-all rule behind its carve-outs.
	all bool
	// notApps: the apps an inverted apps card excluded, for the label only
	// (the term itself lists the remaining apps explicitly).
	notApps []string
	// origins: the cards each field came from (conflict highlighting).
	origins map[xrayField][]string
}

func newTerm() *xrayTerm {
	return &xrayTerm{
		fields:  map[xrayField][]string{},
		except:  map[xrayField][]string{},
		origins: map[xrayField][]string{},
	}
}

func (t *xrayTerm) clone() *xrayTerm {
	out := newTerm()
	for k, v := range t.fields {
		out.fields[k] = append([]string(nil), v...)
	}
	for k, v := range t.except {
		out.except[k] = append([]string(nil), v...)
	}
	out.all = t.all
	out.notApps = append([]string(nil), t.notApps...)
	for k, v := range t.origins {
		out.origins[k] = append([]string(nil), v...)
	}
	return out
}

func (t *xrayTerm) and(other *xrayTerm) bool {
	for field, values := range other.except {
		t.except[field] = append(t.except[field], values...)
	}
	t.notApps = append(t.notApps, other.notApps...)
	t.all = t.all && other.all
	for field, ids := range other.origins {
		t.origins[field] = append(t.origins[field], ids...)
	}
	for field, values := range other.fields {
		existing, ok := t.fields[field]
		if !ok {
			t.fields[field] = append([]string(nil), values...)
			continue
		}
		merged := intersect(existing, values)
		if len(merged) == 0 {
			return false
		}
		t.fields[field] = merged
	}
	return true
}

func intersect(a, b []string) []string {
	index := make(map[string]struct{}, len(a))
	for _, v := range a {
		index[v] = struct{}{}
	}
	out := make([]string, 0, len(b))
	for _, v := range b {
		if _, ok := index[v]; ok {
			out = append(out, v)
		}
	}
	return out
}

type xrayDNF struct {
	terms []*xrayTerm
}

func dnfLeaf(field xrayField, values []string) *xrayDNF {
	if len(values) == 0 {
		return nil
	}
	term := newTerm()
	term.fields[field] = append([]string(nil), values...)
	return &xrayDNF{terms: []*xrayTerm{term}}
}

func dnfOr(parts []*xrayDNF) *xrayDNF {
	out := &xrayDNF{}
	for _, part := range parts {
		if part == nil {
			continue
		}
		out.terms = append(out.terms, part.terms...)
	}
	if len(out.terms) == 0 {
		return nil
	}
	return out
}

func dnfAnd(parts []*xrayDNF) *xrayDNF {
	var acc *xrayDNF
	for _, part := range parts {
		if part == nil {
			continue
		}
		if acc == nil {
			acc = part
			continue
		}
		next := &xrayDNF{}
		for _, left := range acc.terms {
			for _, right := range part.terms {
				combined := left.clone()
				if combined.and(right) {
					next.terms = append(next.terms, combined)
				}
			}
		}
		if len(next.terms) == 0 {
			return nil
		}
		acc = next
	}
	return acc
}

// withExcept attaches a card's «кроме» values to its leaf: IPs/CIDRs carve
// by address, everything else by domain.
func withExcept(leaf *xrayDNF, except []string) *xrayDNF {
	if leaf == nil {
		return nil
	}
	var ips, domains []string
	for _, item := range trimAll(except) {
		if _, err := netip.ParsePrefix(item); err == nil {
			ips = append(ips, item)
		} else if _, err := netip.ParseAddr(item); err == nil {
			ips = append(ips, item)
		} else {
			domains = append(domains, item)
		}
	}
	domains = xrayDomainPatterns(domains)
	for _, term := range leaf.terms {
		if len(ips) > 0 {
			term.except[fieldIP] = append(term.except[fieldIP], ips...)
		}
		if len(domains) > 0 {
			term.except[fieldDomains] = append(term.except[fieldDomains], domains...)
		}
	}
	return leaf
}

// invertedLeaf is a domain, IP or geo card in «Все, кроме» mode: everything
// goes to the card's destination except the listed values, which go where
// unmatched traffic goes.
func invertedLeaf(field xrayField, except []string) *xrayDNF {
	term := newTerm()
	term.all = true
	if len(except) > 0 {
		term.except[field] = dedupe(except)
	}
	return &xrayDNF{terms: []*xrayTerm{term}}
}

// invertedApps turns "every app except items" into an explicit list: every
// app known to the graphs but the excluded ones, plus the "other apps" key
// that stands for every app no card names.
func invertedApps(items, known []string) *xrayDNF {
	excluded := make(map[string]bool, len(items))
	for _, item := range items {
		excluded[appKey(item)] = true
	}
	seen := map[string]bool{}
	apps := make([]string, 0, len(known)+1)
	for _, app := range known {
		key := appKey(app)
		if key == "" || excluded[key] || seen[key] {
			continue
		}
		seen[key] = true
		apps = append(apps, app)
	}
	apps = append(apps, coreapi.OtherAppsKey)
	leaf := dnfLeaf(fieldApps, apps)
	leaf.terms[0].notApps = trimAll(items)
	return leaf
}

func resolveGraphCondition(
	nodeID string,
	nodesByID map[string]types.ProTunNode,
	incoming map[string][]types.ProTunEdge,
	ancestors map[string]bool,
	known []string,
) *xrayDNF {
	if ancestors[nodeID] {
		return nil
	}
	node, ok := nodesByID[nodeID]
	if !ok {
		return nil
	}
	if node.Kind != types.ProTunKindLogic {
		return withOrigin(resolveLeafCondition(node, known), node.ID)
	}

	next := make(map[string]bool, len(ancestors)+1)
	for k := range ancestors {
		next[k] = true
	}
	next[nodeID] = true

	isAnd := node.Op == types.ProTunLogicAnd
	var children []*xrayDNF
	for _, edge := range incoming[nodeID] {
		child := resolveGraphCondition(edge.Source, nodesByID, incoming, next, known)
		if child == nil {
			// An empty/invalid input of AND matches nothing, so the
			// whole AND matches nothing. Skipping it would broaden the
			// rule (e.g. «app AND empty geosite» → the whole app).
			if isAnd {
				return nil
			}
			continue
		}
		children = append(children, child)
	}
	if isAnd {
		return dnfAnd(children)
	}
	return dnfOr(children)
}

// withOrigin marks every field of a card's terms as coming from that card.
func withOrigin(leaf *xrayDNF, nodeID string) *xrayDNF {
	if leaf == nil {
		return nil
	}
	for _, term := range leaf.terms {
		for field := range term.fields {
			term.origins[field] = []string{nodeID}
		}
	}
	return leaf
}

func resolveLeafCondition(node types.ProTunNode, known []string) *xrayDNF {
	switch node.Kind {
	case types.ProTunKindApps:
		if node.Invert {
			return invertedApps(node.Items, known)
		}
		return dnfLeaf(fieldApps, trimAll(node.Items))

	case types.ProTunKindIPRanges:
		if node.Invert {
			return invertedLeaf(fieldIP, trimAll(node.Items))
		}
		return withExcept(dnfLeaf(fieldIP, trimAll(node.Items)), node.Except)

	case types.ProTunKindDomains:
		if node.Invert {
			return invertedLeaf(fieldDomains, xrayDomainPatterns(node.Items))
		}
		return withExcept(dnfLeaf(fieldDomains, xrayDomainPatterns(node.Items)), node.Except)

	case types.ProTunKindProtocols:
		return dnfLeaf(fieldProtocol, xrayProtocols(node.Items))

	case types.ProTunKindPorts:
		return dnfLeaf(fieldPort, xrayPorts(node.Items))

	// Codes are checked against the local databases before the graph gets
	// here (Manager.resolveGeo): the core rejects the config over one
	// unknown code.
	case types.ProTunKindGeoIP:
		if node.Invert {
			return invertedLeaf(fieldIP, prefixedCodes("geoip:", node.Items))
		}
		return withExcept(dnfLeaf(fieldIP, prefixedCodes("geoip:", node.Items)), node.Except)

	case types.ProTunKindGeoSite:
		if node.Invert {
			return invertedLeaf(fieldDomains, prefixedCodes("geosite:", node.Items))
		}
		return withExcept(dnfLeaf(fieldDomains, prefixedCodes("geosite:", node.Items)), node.Except)

	case types.ProTunKindNetwork:
		return dnfLeaf(fieldNetwork, xrayNetworks(node.Items))

	default:
		return nil
	}
}

func xrayDomainPatterns(items []string) []string {
	exact, suffix, keyword, regex := classifyDomains(items)
	out := make([]string, 0, len(items))
	for _, d := range exact {
		out = append(out, "full:"+d)
	}
	for _, d := range suffix {
		out = append(out, "domain:"+strings.TrimPrefix(d, "."))
	}
	for _, d := range keyword {
		out = append(out, "keyword:"+d)
	}
	for _, d := range regex {
		out = append(out, "regexp:"+d)
	}
	return out
}

func xrayNetworks(items []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, 2)
	for _, item := range items {
		n := strings.ToLower(strings.TrimSpace(item))
		if (n == "tcp" || n == "udp") && !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	sort.Strings(out)
	return out
}

func xrayProtocols(items []string) []string {
	seen := make(map[string]bool, len(items))
	out := make([]string, 0, len(items))
	for _, item := range items {
		p := strings.ToLower(strings.TrimSpace(item))
		if !knownProtocols[p] || seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, p)
	}
	return out
}

// xrayPorts keeps valid ports and ranges ("443", "1000-2000") in canonical
// form: one malformed value would make the core reject the whole config.
func xrayPorts(items []string) []string {
	seen := make(map[string]bool, len(items))
	out := make([]string, 0, len(items))
	for _, item := range items {
		port, ok := normalizePort(item)
		if !ok || seen[port] {
			continue
		}
		seen[port] = true
		out = append(out, port)
	}
	return out
}

func normalizePort(item string) (string, bool) {
	from, to, isRange := strings.Cut(strings.TrimSpace(item), "-")
	lo, err := strconv.Atoi(strings.TrimSpace(from))
	if err != nil || lo < 1 || lo > 65535 {
		return "", false
	}
	if !isRange {
		return strconv.Itoa(lo), true
	}
	hi, err := strconv.Atoi(strings.TrimSpace(to))
	if err != nil || hi < lo || hi > 65535 {
		return "", false
	}
	if hi == lo {
		return strconv.Itoa(lo), true
	}
	return strconv.Itoa(lo) + "-" + strconv.Itoa(hi), true
}

func prefixedCodes(prefix string, items []string) []string {
	out := make([]string, 0, len(items))
	for _, item := range items {
		if code := strings.ToLower(strings.TrimSpace(item)); code != "" {
			out = append(out, prefix+code)
		}
	}
	return out
}

func trimAll(items []string) []string {
	out := make([]string, 0, len(items))
	for _, item := range items {
		if item = strings.TrimSpace(item); item != "" {
			out = append(out, item)
		}
	}
	return out
}

type xrayRouting struct {
	Rules         []userRule
	FinalOutbound string
	// HasFinal: the graph wires «Остальное» itself.
	HasFinal bool
}

// serverResolver maps a «Сервер» destination to its outbound tag.
type serverResolver func(ref *types.ProTunServerRef) string

// knownApps lists every app named by an apps card of the graphs (for
// "all apps except ..." cards).
func knownApps(graphs ...types.ProTunGraph) []string {
	var out []string
	for _, graph := range graphs {
		for _, node := range graph.Nodes {
			if node.Kind == types.ProTunKindApps {
				out = append(out, trimAll(node.Items)...)
			}
		}
	}
	return out
}

// resolveExceptOutbound sends the «кроме» rules to the final outbound.
func resolveExceptOutbound(rules []userRule, final string) {
	for i := range rules {
		if rules[i].outbound == exceptOutbound {
			rules[i].outbound = final
			rules[i].object["outboundTag"] = final
		}
	}
}

func compileProTun(graph types.ProTunGraph, proxyTag string, server serverResolver, known []string) xrayRouting {
	result := xrayRouting{FinalOutbound: proxyTag}
	outboundOf := func(node types.ProTunNode) string {
		if node.Kind == types.ProTunKindServer {
			if server != nil {
				if tag := server(node.Server); tag != "" {
					return tag
				}
			}
			// Unknown server: fall back to the current VPN server.
			return proxyTag
		}
		return outboundForKind(node.Kind, proxyTag)
	}

	nodesByID := make(map[string]types.ProTunNode, len(graph.Nodes))
	for _, node := range graph.Nodes {
		nodesByID[node.ID] = node
	}
	incoming := make(map[string][]types.ProTunEdge, len(graph.Nodes))
	for _, edge := range graph.Edges {
		incoming[edge.Target] = append(incoming[edge.Target], edge)
	}

	destIDs := make([]string, 0, len(graph.Nodes))
	for _, node := range graph.Nodes {
		if outboundOf(node) != "" {
			destIDs = append(destIDs, node.ID)
		}
	}
	// Fixed priority between destinations instead of random node IDs:
	// Block → VPN → Direct. An explicit VPN rule never leaks to direct
	// because of an overlapping direct rule, and block always wins.
	sort.SliceStable(destIDs, func(i, j int) bool {
		ri := destRank(nodesByID[destIDs[i]].Kind)
		rj := destRank(nodesByID[destIDs[j]].Kind)
		if ri != rj {
			return ri < rj
		}
		return destIDs[i] < destIDs[j]
	})
	finalSet := false
	var entries []routeEntry

	for _, destID := range destIDs {
		dest := nodesByID[destID]
		outbound := outboundOf(dest)

		for _, edge := range incoming[destID] {
			source, ok := nodesByID[edge.Source]
			if !ok {
				continue
			}
			if source.Kind == types.ProTunKindOther {
				// Several «Остальное» edges: the highest priority wins.
				if !finalSet {
					result.FinalOutbound = outbound
					result.HasFinal = true
					finalSet = true
				}
				continue
			}

			cond := resolveGraphCondition(edge.Source, nodesByID, incoming, map[string]bool{}, known)
			if cond == nil {
				continue
			}
			y := source.Position.Y
			for _, term := range cond.terms {
				entry := routeEntry{term: term, dest: destKey(dest), y: y}
				// «Кроме» first: the carve-out must be seen before the rule.
				for _, field := range []xrayField{fieldDomains, fieldIP} {
					values := term.except[field]
					if len(values) == 0 {
						continue
					}
					carve := term.clone()
					carve.except = map[xrayField][]string{}
					carve.all = false
					delete(carve.fields, fieldDomains)
					delete(carve.fields, fieldIP)
					carve.fields[field] = dedupe(values)
					if rule, ok := termToRule(carve, exceptOutbound); ok {
						rule.label = "кроме " + rule.label
						entry.rules = append(entry.rules, rule)
					}
				}
				if rule, ok := termToRule(term, outbound); ok {
					entry.rules = append(entry.rules, rule)
				}
				if len(entry.rules) > 0 {
					for i := range entry.rules {
						entry.rules[i].head = edge.Source
					}
					entries = append(entries, entry)
				}
			}
		}
	}

	for _, entry := range orderEntries(entries) {
		result.Rules = append(result.Rules, entry.rules...)
	}
	return result
}

// routeEntry is one term of the graph with the rules it compiles to (its
// «кроме» carve-outs, then the rule itself). y is the place of the card on the
// canvas: of two overlapping rules the upper one wins.
type routeEntry struct {
	term  *xrayTerm
	dest  string
	y     float64
	rules []userRule
}

// group is the position of the entry among apps / domains / IPs (see
// ruleGroup): app rules go before plain domain and IP rules.
func (e routeEntry) group() int {
	return ruleGroup(e.rules[len(e.rules)-1])
}

// orderEntries gives the order of the rules in the core config.
//
// The base order is the built-in one: narrower before broader, then apps
// before domains and IPs, then block, VPN, direct. It only matters where two
// rules go to different places and share traffic, so only such pairs are
// reordered: of two overlapping rules the one whose card is higher on the
// canvas goes first. A rule that lies entirely inside another one still goes
// first wherever it is drawn (it is a refinement of the broader rule).
func orderEntries(entries []routeEntry) []routeEntry {
	byGroup := make([]routeEntry, 0, len(entries))
	sorted := orderBySpecificity(entries)
	for group := 0; group < 3; group++ {
		for _, entry := range sorted {
			if entry.group() == group {
				byGroup = append(byGroup, entry)
			}
		}
	}
	n := len(byGroup)
	if n < 2 {
		return byGroup
	}

	// before[j] lists the entries that must precede j.
	before := make([][]int, n)
	for i := 0; i < n; i++ {
		for j := 0; j < n; j++ {
			a, b := byGroup[i], byGroup[j]
			if i == j || a.dest == b.dest {
				continue
			}
			aInB, bInA := termWithin(a.term, b.term), termWithin(b.term, a.term)
			switch {
			case aInB && !bInA:
				before[j] = append(before[j], i)
			case aInB == bInA && a.y < b.y && termsIntersect(a.term, b.term):
				before[j] = append(before[j], i)
			}
		}
	}

	placed := make([]bool, n)
	out := make([]routeEntry, 0, n)
	for len(out) < n {
		next := -1
		for j := 0; j < n && next < 0; j++ {
			if placed[j] {
				continue
			}
			ready := true
			for _, i := range before[j] {
				if !placed[i] {
					ready = false
					break
				}
			}
			if ready {
				next = j
			}
		}
		if next < 0 {
			// Contradicting constraints (a cycle through refinements and
			// canvas positions): break it at the rule with the fewest
			// unmet constraints, so the rest keeps following the canvas.
			best := -1
			for j := 0; j < n; j++ {
				if placed[j] {
					continue
				}
				unmet := 0
				for _, i := range before[j] {
					if !placed[i] {
						unmet++
					}
				}
				if best < 0 || unmet < best {
					best, next = unmet, j
				}
			}
		}
		placed[next] = true
		out = append(out, byGroup[next])
	}
	return out
}

// orderBySpecificity puts a narrower term before a broader one it lies in
// when they go to different places: «chrome И 1.1.1.1 → Напрямую» must be
// seen before «1.1.1.1 → VPN», or it would never fire. Everything else
// keeps the destination priority order (stable topological sort).
func orderBySpecificity(entries []routeEntry) []routeEntry {
	n := len(entries)
	if n < 2 {
		return entries
	}
	// before[j] lists the entries that must precede j.
	before := make([][]int, n)
	for i := 0; i < n; i++ {
		for j := 0; j < n; j++ {
			if i == j || entries[i].dest == entries[j].dest {
				continue
			}
			if termWithin(entries[i].term, entries[j].term) && !termWithin(entries[j].term, entries[i].term) {
				before[j] = append(before[j], i)
			}
		}
	}
	placed := make([]bool, n)
	out := make([]routeEntry, 0, n)
	for len(out) < n {
		progress := false
		for j := 0; j < n; j++ {
			if placed[j] {
				continue
			}
			ready := true
			for _, i := range before[j] {
				if !placed[i] {
					ready = false
					break
				}
			}
			if ready {
				placed[j] = true
				out = append(out, entries[j])
				progress = true
				break
			}
		}
		if !progress {
			// Strict containment has no cycles; this is only a guard.
			for j := 0; j < n; j++ {
				if !placed[j] {
					placed[j] = true
					out = append(out, entries[j])
				}
			}
		}
	}
	return out
}

func termToRule(term *xrayTerm, outbound string) (userRule, bool) {
	apps := term.fields[fieldApps]

	rule := map[string]interface{}{
		"type":        "field",
		"outboundTag": outbound,
	}
	conditional := false
	if domains := term.fields[fieldDomains]; len(domains) > 0 {
		rule["domain"] = domains
		conditional = true
	}
	if ips := term.fields[fieldIP]; len(ips) > 0 {
		rule["ip"] = ips
		conditional = true
	}
	// A protocol is only known once the core has sniffed the flow, so such
	// rules are conditional: the tunnel never bypasses or blocks them itself.
	if protocols := term.fields[fieldProtocol]; len(protocols) > 0 {
		rule["protocol"] = protocols
		conditional = true
	}
	if ports := term.fields[fieldPort]; len(ports) > 0 {
		rule["port"] = strings.Join(ports, ",")
		conditional = true
	}
	// The network, on the contrary, is known to the tunnel: it splits the
	// app's verdict per network instead of deferring to the core. Both
	// networks together are no constraint at all.
	var networks []string
	if n := term.fields[fieldNetwork]; len(n) == 1 {
		networks = n
		rule["network"] = n[0]
	}

	// Узел «только приложения» (apps → direct/block/vpn) — типичный сценарий
	// ProTun: пользователь выбирает cs2.exe и шлёт его напрямую. Раньше такой
	// терм не давал НИ ОДНОГО правила (matched оставался false), поэтому в
	// конфиге не появлялось правило inboundTag -> outboundTag. Ядро получало
	// соединение с тегом beam-apps-<hash>, но сопоставить его было не с чем, и
	// трафик проваливался в финальное правило (обычно VPN) — игра шла через
	// VPN с пингом 100-120 вместо прямого. Теперь наличие приложений само по
	// себе формирует правило по inboundTag.
	tags := appTags(apps)
	if len(tags) > 0 {
		rule["inboundTag"] = tags
	}

	if !conditional && len(tags) == 0 && len(networks) == 0 {
		if !term.all {
			return userRule{}, false
		}
		// «Все, кроме»: the carve-outs came first, everything else is here.
		rule["network"] = "tcp,udp"
		conditional = true
	}
	return userRule{object: rule, apps: apps, conditional: conditional, outbound: outbound, networks: networks, label: termLabel(term)}, true
}

func dedupe(values []string) []string {
	seen := make(map[string]bool, len(values))
	out := make([]string, 0, len(values))
	for _, v := range values {
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}

// termLabel names a rule by what it matches, most specific values first.
func termLabel(term *xrayTerm) string {
	var values []string
	if term.all {
		var carved []string
		for _, field := range []xrayField{fieldDomains, fieldIP} {
			carved = append(carved, term.except[field]...)
		}
		if len(carved) > 0 {
			values = append(values, "все, кроме "+labelOf(carved))
		} else {
			values = append(values, "все")
		}
	}
	if len(term.notApps) > 0 {
		// "все, кроме telegram" reads better than the long explicit list.
		values = append(values, "все, кроме "+labelOf(term.notApps))
	}
	for _, field := range []xrayField{fieldApps, fieldDomains, fieldIP, fieldProtocol, fieldPort, fieldNetwork} {
		if field == fieldApps && len(term.notApps) > 0 {
			continue
		}
		for _, value := range term.fields[field] {
			if field == fieldPort {
				value = "порт " + value
			} else if field == fieldNetwork || field == fieldProtocol {
				value = strings.ToUpper(value)
			}
			values = append(values, value)
		}
	}
	return labelOf(values)
}

func destRank(kind types.ProTunNodeKind) int {
	switch kind {
	case types.ProTunKindBlock:
		return 0
	case types.ProTunKindVPN, types.ProTunKindServer:
		return 1
	default:
		return 2
	}
}

func outboundForKind(kind types.ProTunNodeKind, proxyTag string) string {
	switch kind {
	case types.ProTunKindVPN:
		return proxyTag
	case types.ProTunKindDirect:
		return outboundDirect
	case types.ProTunKindBlock:
		return outboundBlock
	default:
		return ""
	}
}

func shortHash(s string) string {
	const offset = uint32(2166136261)
	const prime = uint32(16777619)
	hash := offset
	for i := 0; i < len(s); i++ {
		hash ^= uint32(s[i])
		hash *= prime
	}
	const digits = "0123456789abcdef"
	out := make([]byte, 8)
	for i := 7; i >= 0; i-- {
		out[i] = digits[hash&0xf]
		hash >>= 4
	}
	return string(out)
}
