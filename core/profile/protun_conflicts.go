package profile

import (
	"errors"
	"fmt"
	"net/netip"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"beam-bridge/core/coreapi"
	"beam-bridge/core/types"
)

// Конфликты ProTun.
//
// Правила пересекаются постоянно, и это нормально: «1.1.1.1 → VPN» и
// «chrome И 1.1.1.1 → Напрямую» — это общее правило и уточнение к нему.
// Уточнение целиком лежит внутри общего правила и всегда побеждает
// (см. orderBySpecificity). Конфликт — когда один и тот же трафик уходит в два
// разных назначения и ни одно из правил не уже другого:
//
//   - одинаковые условия: fdm.exe → Напрямую и fdm.exe → VPN;
//   - частичное пересечение: {fdm, chrome} → VPN и {fdm, telegram} → Напрямую.
//
// Считаются только точные совпадения значений одного вида (приложение
// с приложением, домен с доменом или его поддоменом, IP с подсетью, порт с
// диапазоном). Разные виды условий (chrome → VPN и youtube.com → Напрямую)
// конфликтом не считаются: там работает обычный порядок (приложения
// раньше доменов и IP). Geo-коды, keyword и regexp сравниваются только
// на равенство: лучше пропустить спорный случай, чем заблокировать
// подключение из-за ложной тревоги.

// destKey identifies where a destination card sends traffic. Two «Напрямую»
// cards are the same place; two «Сервер» cards are the same only for the
// same server.
func destKey(node types.ProTunNode) string {
	if node.Kind == types.ProTunKindServer {
		if key := serverRefKey(node.Server); key != "" {
			return "server:" + key
		}
		// Without a server it falls back to the current VPN server.
		return string(types.ProTunKindVPN)
	}
	return string(node.Kind)
}

func isDestinationKind(kind types.ProTunNodeKind) bool {
	return kind == types.ProTunKindServer || outboundForKind(kind, "proxy") != ""
}

// constrained returns the fields that actually restrict a term: both
// networks together are no restriction.
func constrained(t *xrayTerm) map[xrayField][]string {
	out := make(map[xrayField][]string, len(t.fields))
	for field, values := range t.fields {
		if len(values) == 0 || (field == fieldNetwork && len(values) > 1) {
			continue
		}
		out[field] = values
	}
	return out
}

// termWithin: every flow matched by a is matched by b (only when certain).
func termWithin(a, b *xrayTerm) bool {
	af, bf := constrained(a), constrained(b)
	if len(bf) == 0 {
		return true
	}
	for field, bValues := range bf {
		aValues, ok := af[field]
		if !ok {
			return false
		}
		for _, av := range aValues {
			covered := false
			for _, bv := range bValues {
				if valueWithin(field, av, bv) {
					covered = true
					break
				}
			}
			if !covered {
				return false
			}
		}
	}
	return true
}

// termsOverlap reports the fields both terms constrain and the values they
// certainly share there. ok is false when the terms are disjoint or have no
// field in common (different kinds of conditions are not compared).
func termsOverlap(a, b *xrayTerm) (shared []xrayField, values map[xrayField][]string, ok bool) {
	af, bf := constrained(a), constrained(b)
	values = map[xrayField][]string{}
	for field, aValues := range af {
		bValues, both := bf[field]
		if !both {
			continue
		}
		for _, av := range aValues {
			for _, bv := range bValues {
				v, hit := valueOverlap(field, av, bv)
				if hit && !excepted(field, v, a, b) {
					values[field] = appendUnique(values[field], v)
				}
			}
		}
		if len(values[field]) == 0 {
			return nil, nil, false
		}
		shared = append(shared, field)
	}
	// «Кроме» on a field the other term lists entirely: no common traffic.
	if carvedOut(a, bf) || carvedOut(b, af) {
		return nil, nil, false
	}
	if len(shared) == 0 {
		return nil, nil, false
	}
	sort.Slice(shared, func(i, j int) bool { return shared[i] < shared[j] })
	return shared, values, true
}

func excepted(field xrayField, value string, terms ...*xrayTerm) bool {
	for _, t := range terms {
		for _, e := range t.except[field] {
			if valueWithin(field, value, e) {
				return true
			}
		}
	}
	return false
}

func carvedOut(t *xrayTerm, other map[xrayField][]string) bool {
	for field, except := range t.except {
		values, ok := other[field]
		if !ok || len(except) == 0 {
			continue
		}
		all := true
		for _, v := range values {
			if !excepted(field, v, t) {
				all = false
				break
			}
		}
		if all {
			return true
		}
	}
	return false
}

// valueWithin: every flow matched by value a is matched by value b.
func valueWithin(field xrayField, a, b string) bool {
	switch field {
	case fieldApps:
		return appKey(a) == appKey(b)
	case fieldIP:
		return ipWithin(a, b)
	case fieldDomains:
		return domainWithin(a, b)
	case fieldPort:
		alo, ahi, okA := portBounds(a)
		blo, bhi, okB := portBounds(b)
		return okA && okB && blo <= alo && ahi <= bhi
	default:
		return strings.EqualFold(strings.TrimSpace(a), strings.TrimSpace(b))
	}
}

// valueOverlap returns a value matched by both a and b, if certain.
func valueOverlap(field xrayField, a, b string) (string, bool) {
	if valueWithin(field, a, b) {
		return a, true
	}
	if valueWithin(field, b, a) {
		return b, true
	}
	if field == fieldPort {
		alo, ahi, okA := portBounds(a)
		blo, bhi, okB := portBounds(b)
		if okA && okB {
			lo, hi := max(alo, blo), min(ahi, bhi)
			if lo <= hi {
				if lo == hi {
					return strconv.Itoa(lo), true
				}
				return strconv.Itoa(lo) + "-" + strconv.Itoa(hi), true
			}
		}
	}
	return "", false
}

func parseNet(value string) (netip.Prefix, bool) {
	if p, err := netip.ParsePrefix(value); err == nil {
		return p.Masked(), true
	}
	if a, err := netip.ParseAddr(value); err == nil {
		return netip.PrefixFrom(a, a.BitLen()), true
	}
	return netip.Prefix{}, false
}

func ipWithin(a, b string) bool {
	a, b = strings.ToLower(strings.TrimSpace(a)), strings.ToLower(strings.TrimSpace(b))
	if a == b {
		return true
	}
	pa, okA := parseNet(a)
	pb, okB := parseNet(b)
	return okA && okB && pb.Bits() <= pa.Bits() && pb.Contains(pa.Addr())
}

// domainWithin compares the core's domain patterns: "domain:x" covers x and
// its subdomains, "keyword:k" every name containing k, "full:x" only x.
func domainWithin(a, b string) bool {
	a, b = strings.ToLower(strings.TrimSpace(a)), strings.ToLower(strings.TrimSpace(b))
	if a == b {
		return true
	}
	ak, av, _ := strings.Cut(a, ":")
	bk, bv, _ := strings.Cut(b, ":")
	if ak != "full" && ak != "domain" {
		return false
	}
	switch bk {
	case "domain":
		return av == bv || strings.HasSuffix(av, "."+bv)
	case "keyword":
		return bv != "" && strings.Contains(av, bv)
	default:
		return false
	}
}

func portBounds(value string) (int, int, bool) {
	from, to, isRange := strings.Cut(strings.TrimSpace(value), "-")
	lo, err := strconv.Atoi(strings.TrimSpace(from))
	if err != nil {
		return 0, 0, false
	}
	if !isRange {
		return lo, lo, true
	}
	hi, err := strconv.Atoi(strings.TrimSpace(to))
	if err != nil {
		return 0, 0, false
	}
	return lo, hi, true
}

func appendUnique(list []string, value string) []string {
	for _, v := range list {
		if v == value {
			return list
		}
	}
	return append(list, value)
}

// conflictValue shows a value the way the user typed it on the card.
func conflictValue(field xrayField, value string) string {
	switch field {
	case fieldApps:
		if appKey(value) == coreapi.OtherAppsKey {
			return "другие приложения"
		}
		return filepath.Base(strings.ReplaceAll(strings.TrimSpace(value), `\`, "/"))
	case fieldPort:
		return "порт " + value
	case fieldNetwork, fieldProtocol:
		return strings.ToUpper(value)
	default:
		return displayValue(value)
	}
}

func destLabel(node types.ProTunNode) string {
	if node.Kind == types.ProTunKindServer && node.Server != nil && strings.TrimSpace(node.Server.Name) != "" {
		return strings.TrimSpace(node.Server.Name)
	}
	if label := strings.TrimSpace(node.Label); label != "" {
		return label
	}
	switch node.Kind {
	case types.ProTunKindVPN:
		return "Через VPN"
	case types.ProTunKindDirect:
		return "Напрямую"
	case types.ProTunKindBlock:
		return "Блокировка"
	default:
		return "Сервер"
	}
}

type graphTerm struct {
	term   *xrayTerm
	destID string
	dest   string
	// head is the card that feeds the destination; y its place on the canvas.
	head string
	y    float64
}

// collectGraphTerms lists every term of the graph with its destination, the
// same way compileProTun reads it.
func collectGraphTerms(graph types.ProTunGraph) ([]graphTerm, map[string]types.ProTunNode) {
	nodesByID := make(map[string]types.ProTunNode, len(graph.Nodes))
	for _, node := range graph.Nodes {
		nodesByID[node.ID] = node
	}
	incoming := make(map[string][]types.ProTunEdge, len(graph.Nodes))
	for _, edge := range graph.Edges {
		incoming[edge.Target] = append(incoming[edge.Target], edge)
	}
	known := knownApps(graph)

	var out []graphTerm
	for _, dest := range graph.Nodes {
		if !isDestinationKind(dest.Kind) {
			continue
		}
		for _, edge := range incoming[dest.ID] {
			source, ok := nodesByID[edge.Source]
			if !ok || source.Kind == types.ProTunKindOther {
				continue
			}
			cond := resolveGraphCondition(edge.Source, nodesByID, incoming, map[string]bool{}, known)
			if cond == nil {
				continue
			}
			for _, term := range cond.terms {
				out = append(out, graphTerm{term: term, destID: dest.ID, dest: destKey(dest), head: edge.Source, y: source.Position.Y})
			}
		}
	}
	return out, nodesByID
}

// DetectProTunConflicts finds the contradictions of one ProTun graph (see the
// comment at the top of the file). Each pair of colliding cards is reported
// once, with every value they share.
func DetectProTunConflicts(graph types.ProTunGraph) []types.ProTunConflict {
	terms, nodesByID := collectGraphTerms(graph)

	var order []string
	byKey := map[string]*types.ProTunConflict{}
	for i := 0; i < len(terms); i++ {
		for j := i + 1; j < len(terms); j++ {
			a, b := terms[i], terms[j]
			if a.dest == b.dest {
				continue
			}
			// Cards at different heights: the upper one wins (see orderEntries).
			if a.y != b.y {
				continue
			}
			shared, values, ok := termsOverlap(a.term, b.term)
			if !ok {
				continue
			}
			aInB, bInA := termWithin(a.term, b.term), termWithin(b.term, a.term)
			if aInB != bInA {
				// One rule refines the other: the narrower one wins.
				continue
			}

			var cards []string
			for _, field := range shared {
				for _, id := range a.term.origins[field] {
					cards = appendUnique(cards, id)
				}
				for _, id := range b.term.origins[field] {
					cards = appendUnique(cards, id)
				}
			}
			sort.Strings(cards)
			targets := []string{a.destID, b.destID}
			key := strings.Join(cards, ",") + "|" + strings.Join(targets, ",")

			conflict := byKey[key]
			if conflict == nil {
				conflict = &types.ProTunConflict{Nodes: cards, Targets: targets, Identical: true}
				byKey[key] = conflict
				order = append(order, key)
			}
			conflict.Identical = conflict.Identical && aInB && bInA
			for _, field := range shared {
				for _, v := range values[field] {
					conflict.Values = appendUnique(conflict.Values, conflictValue(field, v))
				}
			}
		}
	}

	out := make([]types.ProTunConflict, 0, len(order))
	for _, key := range order {
		c := byKey[key]
		first, second := destLabel(nodesByID[c.Targets[0]]), destLabel(nodesByID[c.Targets[1]])
		c.Message = fmt.Sprintf("%s — и в «%s», и в «%s»", summarize(c.Values), first, second)
		out = append(out, *c)
	}
	return out
}

func summarize(values []string) string {
	if len(values) <= 2 {
		return strings.Join(values, ", ")
	}
	return strings.Join(values[:2], ", ") + " +" + strconv.Itoa(len(values)-2)
}

// ProTunConflictError refuses to connect while a ProTun layer the user can
// edit contradicts itself. A locked provider preset is the provider's
// business and is not checked.
func (m *Manager) ProTunConflictError() error {
	settings := m.settingsRepo.Get()
	if settings == nil || settings.RoutingMode != "pro" {
		return nil
	}
	type layer struct {
		name  string
		graph types.ProTunGraph
	}
	layers := []layer{{name: "«Общие»", graph: settings.ProTunGraph}}
	if profile, beamFile, _ := m.storage.GetActive(); profile != nil {
		locked := beamFile != nil && beamFile.Data.ProTunPreset != nil && beamFile.Data.ProTunLocked
		if own, ok := settings.ProTunProfiles[profile.ID]; ok && !locked && !emptyProTunGraph(own) {
			layers = append([]layer{{name: "«" + profile.Name + "»", graph: own}}, layers...)
		}
	}
	for _, l := range layers {
		conflicts := DetectProTunConflicts(l.graph)
		if len(conflicts) == 0 {
			continue
		}
		msg := "Конфликт правил ProTun в " + l.name + ": " + conflicts[0].Message
		if len(conflicts) > 1 {
			msg += fmt.Sprintf(" (и ещё %d)", len(conflicts)-1)
		}
		return errors.New(msg + ". Исправьте схему во вкладке «Маршрутизация»")
	}
	return nil
}
