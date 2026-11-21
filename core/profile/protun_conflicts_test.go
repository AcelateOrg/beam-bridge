package profile

import (
	"strings"
	"testing"

	"beam-bridge/core/types"
)

// graphBuilder keeps the test graphs short.
type graphBuilder struct{ g types.ProTunGraph }

func (b *graphBuilder) node(id string, kind types.ProTunNodeKind, items ...string) *graphBuilder {
	b.g.Nodes = append(b.g.Nodes, types.ProTunNode{ID: id, Kind: kind, Items: items})
	return b
}

func (b *graphBuilder) logic(id string, op types.ProTunLogicOp) *graphBuilder {
	b.g.Nodes = append(b.g.Nodes, types.ProTunNode{ID: id, Kind: types.ProTunKindLogic, Op: op})
	return b
}

func (b *graphBuilder) except(id string, values ...string) *graphBuilder {
	for i := range b.g.Nodes {
		if b.g.Nodes[i].ID == id {
			b.g.Nodes[i].Except = values
		}
	}
	return b
}

func (b *graphBuilder) edge(from, to string) *graphBuilder {
	b.g.Edges = append(b.g.Edges, types.ProTunEdge{ID: from + ">" + to, Source: from, Target: to})
	return b
}

func newGraph() *graphBuilder {
	return (&graphBuilder{}).
		node("vpn", types.ProTunKindVPN).
		node("direct", types.ProTunKindDirect).
		node("block", types.ProTunKindBlock)
}

func TestConflictSameAppTwoDestinations(t *testing.T) {
	g := newGraph().
		node("a", types.ProTunKindApps, "fdm.exe").
		node("b", types.ProTunKindApps, "fdm.exe").
		edge("a", "direct").edge("b", "vpn").g
	conflicts := DetectProTunConflicts(g)
	if len(conflicts) != 1 {
		t.Fatalf("want 1 conflict, got %+v", conflicts)
	}
	c := conflicts[0]
	if !c.Identical || strings.Join(c.Nodes, ",") != "a,b" || strings.Join(c.Values, ",") != "fdm.exe" {
		t.Fatalf("unexpected conflict %+v", c)
	}
}

func TestNoConflictForRefinement(t *testing.T) {
	// 1.1.1.1 → VPN, chrome И 1.1.1.1 → Напрямую: the AND is a refinement.
	g := newGraph().
		node("ip", types.ProTunKindIPRanges, "1.1.1.1").
		node("chrome", types.ProTunKindApps, "chrome.exe").
		node("ip2", types.ProTunKindIPRanges, "1.1.1.1").
		logic("and", types.ProTunLogicAnd).
		edge("ip", "vpn").
		edge("chrome", "and").edge("ip2", "and").edge("and", "direct").g
	if conflicts := DetectProTunConflicts(g); len(conflicts) != 0 {
		t.Fatalf("want no conflicts, got %+v", conflicts)
	}
}

func TestConflictPartialAppLists(t *testing.T) {
	g := newGraph().
		node("a", types.ProTunKindApps, "fdm.exe", "chrome.exe").
		node("b", types.ProTunKindApps, "fdm.exe", "telegram.exe").
		edge("a", "vpn").edge("b", "direct").g
	conflicts := DetectProTunConflicts(g)
	if len(conflicts) != 1 || conflicts[0].Identical || strings.Join(conflicts[0].Values, ",") != "fdm.exe" {
		t.Fatalf("unexpected %+v", conflicts)
	}
}

func TestSubsetAppListWinsAndGoesFirst(t *testing.T) {
	g := newGraph().
		node("a", types.ProTunKindApps, "fdm.exe", "chrome.exe").
		node("b", types.ProTunKindApps, "fdm.exe").
		edge("a", "vpn").edge("b", "direct").g
	if conflicts := DetectProTunConflicts(g); len(conflicts) != 0 {
		t.Fatalf("want no conflicts, got %+v", conflicts)
	}
	rules := orderUserRules(compileProTun(g, "proxy", nil, knownApps(g)).Rules)
	if len(rules) != 2 || rules[0].outbound != outboundDirect {
		t.Fatalf("the narrower fdm rule must come first, got %+v", rules)
	}
	plan := buildRoutePlan(rules, "proxy", knownApps(g))
	if !plan.Apps["fdm.exe"].Bypass || plan.Apps["chrome.exe"].Bypass {
		t.Fatalf("fdm must bypass, chrome must not: %+v", plan.Apps)
	}
}

func TestDifferentKindsAreNotConflicts(t *testing.T) {
	g := newGraph().
		node("a", types.ProTunKindApps, "chrome.exe").
		node("d", types.ProTunKindDomains, "youtube.com").
		edge("a", "vpn").edge("d", "direct").g
	if conflicts := DetectProTunConflicts(g); len(conflicts) != 0 {
		t.Fatalf("want no conflicts, got %+v", conflicts)
	}
}

func TestSubdomainRefinesDomain(t *testing.T) {
	g := newGraph().
		node("wide", types.ProTunKindDomains, "google.com").
		node("narrow", types.ProTunKindDomains, "mail.google.com").
		edge("wide", "vpn").edge("narrow", "direct").g
	if conflicts := DetectProTunConflicts(g); len(conflicts) != 0 {
		t.Fatalf("want no conflicts, got %+v", conflicts)
	}
	rules := compileProTun(g, "proxy", nil, nil).Rules
	if len(rules) != 2 || rules[0].outbound != outboundDirect {
		t.Fatalf("mail.google.com must come before google.com, got %+v", rules)
	}
}

func TestSameDomainTwoDestinations(t *testing.T) {
	g := newGraph().
		node("a", types.ProTunKindDomains, "youtube.com").
		node("b", types.ProTunKindDomains, "youtube.com", "vk.com").
		edge("a", "block").edge("b", "direct").g
	// b is wider than a: a refines it.
	if conflicts := DetectProTunConflicts(g); len(conflicts) != 0 {
		t.Fatalf("want no conflicts, got %+v", conflicts)
	}
	g = newGraph().
		node("a", types.ProTunKindDomains, "youtube.com").
		node("b", types.ProTunKindDomains, "youtube.com").
		edge("a", "block").edge("b", "direct").g
	if conflicts := DetectProTunConflicts(g); len(conflicts) != 1 {
		t.Fatalf("want 1 conflict, got %+v", conflicts)
	}
}

func TestExceptRemovesOverlap(t *testing.T) {
	g := newGraph().
		node("a", types.ProTunKindDomains, "mail.google.com").
		node("b", types.ProTunKindDomains, "mail.google.com").
		except("b", "mail.google.com").
		edge("a", "block").edge("b", "direct").g
	if conflicts := DetectProTunConflicts(g); len(conflicts) != 0 {
		t.Fatalf("want no conflicts, got %+v", conflicts)
	}
}

func TestSubnetRefinesNetwork(t *testing.T) {
	g := newGraph().
		node("wide", types.ProTunKindIPRanges, "10.0.0.0/8").
		node("narrow", types.ProTunKindIPRanges, "10.1.0.0/16").
		edge("wide", "vpn").edge("narrow", "direct").g
	if conflicts := DetectProTunConflicts(g); len(conflicts) != 0 {
		t.Fatalf("want no conflicts, got %+v", conflicts)
	}
}

func TestOverlappingPortRanges(t *testing.T) {
	g := newGraph().
		node("a", types.ProTunKindPorts, "1000-2000").
		node("b", types.ProTunKindPorts, "1500-2500").
		edge("a", "vpn").edge("b", "direct").g
	conflicts := DetectProTunConflicts(g)
	if len(conflicts) != 1 || strings.Join(conflicts[0].Values, ",") != "порт 1500-2000" {
		t.Fatalf("unexpected %+v", conflicts)
	}
}

func TestSameDestinationIsFine(t *testing.T) {
	g := newGraph().
		node("direct2", types.ProTunKindDirect).
		node("a", types.ProTunKindApps, "fdm.exe").
		node("b", types.ProTunKindApps, "fdm.exe").
		edge("a", "direct").edge("b", "direct2").g
	if conflicts := DetectProTunConflicts(g); len(conflicts) != 0 {
		t.Fatalf("want no conflicts, got %+v", conflicts)
	}
}

func TestConflictThroughOrBlock(t *testing.T) {
	g := newGraph().
		node("a", types.ProTunKindApps, "fdm.exe").
		node("d", types.ProTunKindDomains, "example.com").
		logic("or", types.ProTunLogicOr).
		node("b", types.ProTunKindApps, "fdm.exe").
		edge("a", "or").edge("d", "or").edge("or", "vpn").
		edge("b", "direct").g
	conflicts := DetectProTunConflicts(g)
	if len(conflicts) != 1 || strings.Join(conflicts[0].Nodes, ",") != "a,b" {
		t.Fatalf("unexpected %+v", conflicts)
	}
}
