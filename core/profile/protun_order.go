package profile

import (
	"strings"

	"beam-bridge/core/types"
)

// termsIntersect reports whether some flow can match both terms. Unlike
// termsOverlap it is for ordering, so it errs on the side of "yes": terms that
// constrain different things (an app and a subnet) share a flow of that app to
// that subnet, and values it cannot compare (geo codes, keywords, regexps)
// may well share traffic. Only values that are certainly disjoint split the
// terms, so the canvas decides between rules that merely look unrelated.
func termsIntersect(a, b *xrayTerm) bool {
	af, bf := constrained(a), constrained(b)
	for field, aValues := range af {
		bValues, both := bf[field]
		if !both {
			continue
		}
		overlap := false
		for _, av := range aValues {
			for _, bv := range bValues {
				if valueMayOverlap(field, av, bv) {
					overlap = true
				}
			}
		}
		if !overlap {
			return false
		}
	}
	return !carvedOut(a, bf) && !carvedOut(b, af)
}

// valueMayOverlap: values a and b can match the same flow.
func valueMayOverlap(field xrayField, a, b string) bool {
	if _, ok := valueOverlap(field, a, b); ok {
		return true
	}
	switch field {
	case fieldIP:
		_, okA := parseNet(strings.ToLower(strings.TrimSpace(a)))
		_, okB := parseNet(strings.ToLower(strings.TrimSpace(b)))
		return !okA || !okB
	case fieldDomains:
		return opaqueDomain(a) || opaqueDomain(b)
	case fieldPort:
		_, _, okA := portBounds(a)
		_, _, okB := portBounds(b)
		return !okA || !okB
	}
	return false
}

// opaqueDomain: a pattern the comparison cannot reason about (geosite,
// keyword, regexp, a bare substring).
func opaqueDomain(value string) bool {
	kind, _, _ := strings.Cut(strings.ToLower(strings.TrimSpace(value)), ":")
	return kind != "domain" && kind != "full"
}

// ProTunRuleOrder lists the rules of a graph in the order the core checks
// them (see orderEntries), with the pairs that matter to the user: rules that
// take over part of a lower rule's traffic, and rules that never fire because
// a higher one covers them.
func ProTunRuleOrder(graph types.ProTunGraph) []types.ProTunRuleInfo {
	compiled := compileProTun(graph, "proxy", nil, knownApps(graph))
	rules := compiled.Rules
	terms, nodesByID := collectGraphTerms(graph)

	byHead := map[string][]graphTerm{}
	for _, t := range terms {
		byHead[t.head] = append(byHead[t.head], t)
	}

	var rows []types.ProTunRuleInfo
	index := map[string]int{}
	for _, rule := range rules {
		if rule.head == "" {
			continue
		}
		if _, seen := index[rule.head]; seen {
			continue
		}
		heads := byHead[rule.head]
		if len(heads) == 0 {
			continue
		}
		node := nodesByID[heads[0].destID]
		label := rule.label
		if strings.HasPrefix(label, "кроме ") {
			label = ""
		}
		index[rule.head] = len(rows)
		rows = append(rows, types.ProTunRuleInfo{
			NodeID:    rule.head,
			NodeKind:  string(nodesByID[rule.head].Kind),
			Rank:      len(rows) + 1,
			Label:     label,
			DestID:    node.ID,
			DestKind:  string(node.Kind),
			Overrides: []string{},
		})
	}
	// A rule whose first compiled rule was a «кроме» carve-out has no label
	// yet: take it from the main rule of the same card.
	for _, rule := range rules {
		if i, ok := index[rule.head]; ok && rows[i].Label == "" && !strings.HasPrefix(rule.label, "кроме ") {
			rows[i].Label = rule.label
		}
	}

	for i := range rows {
		his := byHead[rows[i].NodeID]
		for j := i + 1; j < len(rows); j++ {
			los := byHead[rows[j].NodeID]
			overrides := false
			coveredAll := len(los) > 0
			for _, lo := range los {
				covered := false
				for _, hi := range his {
					if hi.dest == lo.dest {
						continue
					}
					loInHi, hiInLo := termWithin(lo.term, hi.term), termWithin(hi.term, lo.term)
					if loInHi {
						covered = true
					} else if !hiInLo && termsIntersect(hi.term, lo.term) {
						overrides = true
					}
				}
				if !covered {
					coveredAll = false
				}
			}
			if overrides {
				rows[i].Overrides = append(rows[i].Overrides, rows[j].NodeID)
			}
			if coveredAll && rows[j].ShadowedBy == "" {
				rows[j].ShadowedBy = rows[i].NodeID
			}
		}
	}
	return rows
}
