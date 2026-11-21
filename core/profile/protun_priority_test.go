package profile

import (
	"strings"
	"testing"

	"beam-bridge/core/types"
)

func setY(g *types.ProTunGraph, id string, y float64) {
	for i := range g.Nodes {
		if g.Nodes[i].ID == id {
			g.Nodes[i].Position.Y = y
		}
	}
}

// subnets → Напрямую next to YandexBrowser.exe → VPN: the user's report.
func subnetVsAppGraph() types.ProTunGraph {
	return newGraph().
		node("subnets", types.ProTunKindIPRanges, "10.0.0.0/8").
		node("yandex", types.ProTunKindApps, "YandexBrowser.exe").
		edge("subnets", "direct").edge("yandex", "vpn").g
}

func orderedHeads(g types.ProTunGraph) []string {
	compiled := compileProTun(g, "proxy", nil, knownApps(g))
	var heads []string
	for _, rule := range compiled.Rules {
		heads = append(heads, rule.head)
	}
	return heads
}

func TestSameHeightKeepsBuiltInOrder(t *testing.T) {
	heads := orderedHeads(subnetVsAppGraph())
	if strings.Join(heads, ",") != "yandex,subnets" {
		t.Fatalf("built-in order changed: %v", heads)
	}
}

func TestUpperCardWins(t *testing.T) {
	g := subnetVsAppGraph()
	setY(&g, "subnets", 0)
	setY(&g, "yandex", 300)
	if heads := orderedHeads(g); strings.Join(heads, ",") != "subnets,yandex" {
		t.Fatalf("the subnet card is higher, its rule must go first: %v", heads)
	}

	setY(&g, "subnets", 600)
	if heads := orderedHeads(g); strings.Join(heads, ",") != "yandex,subnets" {
		t.Fatalf("the app card is higher, its rule must go first: %v", heads)
	}
}

func TestPositionOnlyReordersOverlappingRules(t *testing.T) {
	// Two apps never share flows, so their order does not follow the canvas;
	// an app and a subnet do, so the subnet card below stays below.
	g := newGraph().
		node("subnets", types.ProTunKindIPRanges, "10.0.0.0/8").
		node("a", types.ProTunKindApps, "a.exe").
		node("b", types.ProTunKindApps, "b.exe").
		edge("subnets", "direct").edge("a", "vpn").edge("b", "vpn").g
	setY(&g, "b", 0)
	setY(&g, "a", 100)
	setY(&g, "subnets", 200)
	heads := orderedHeads(g)
	if strings.Join(heads, ",") != "a,b,subnets" {
		t.Fatalf("apps keep the built-in order and go before the lower subnet: %v", heads)
	}
}

func TestRefinementWinsWhereverItIsDrawn(t *testing.T) {
	g := newGraph().
		node("ip", types.ProTunKindIPRanges, "1.1.1.1").
		node("chrome", types.ProTunKindApps, "chrome.exe").
		node("ip2", types.ProTunKindIPRanges, "1.1.1.1").
		logic("and", types.ProTunLogicAnd).
		edge("ip", "vpn").
		edge("chrome", "and").edge("ip2", "and").edge("and", "direct").g
	setY(&g, "ip", 0)
	setY(&g, "and", 500)
	heads := orderedHeads(g)
	if strings.Join(heads, ",") != "and,ip" {
		t.Fatalf("a refinement must precede the broader rule: %v", heads)
	}
}

func TestPositionResolvesConflict(t *testing.T) {
	g := newGraph().
		node("a", types.ProTunKindApps, "fdm.exe").
		node("b", types.ProTunKindApps, "fdm.exe").
		edge("a", "direct").edge("b", "vpn").g
	if len(DetectProTunConflicts(g)) != 1 {
		t.Fatal("expected a conflict for cards at the same height")
	}
	setY(&g, "a", 0)
	setY(&g, "b", 100)
	if conflicts := DetectProTunConflicts(g); len(conflicts) != 0 {
		t.Fatalf("the upper card wins, nothing to resolve: %+v", conflicts)
	}
	if heads := orderedHeads(g); strings.Join(heads, ",") != "a,b" {
		t.Fatalf("upper card first: %v", heads)
	}
}

func TestRuleOrderReportsOverrideAndShadow(t *testing.T) {
	g := subnetVsAppGraph()
	rows := ProTunRuleOrder(g)
	if len(rows) != 2 || rows[0].NodeID != "yandex" || rows[1].NodeID != "subnets" {
		t.Fatalf("unexpected order %+v", rows)
	}
	if len(rows[0].Overrides) != 1 || rows[0].Overrides[0] != "subnets" {
		t.Fatalf("yandex should override subnets traffic: %+v", rows[0])
	}

	// The same condition twice, sent to two places: the lower one never fires.
	g = newGraph().
		node("a", types.ProTunKindApps, "fdm.exe").
		node("b", types.ProTunKindApps, "fdm.exe").
		edge("a", "direct").edge("b", "vpn").g
	setY(&g, "a", 0)
	setY(&g, "b", 100)
	rows = ProTunRuleOrder(g)
	if len(rows) != 2 || rows[0].NodeID != "a" || rows[1].ShadowedBy != "a" {
		t.Fatalf("shadowed rule not reported: %+v", rows)
	}
}

func TestUpperSubnetDefersAppToCore(t *testing.T) {
	g := subnetVsAppGraph()
	setY(&g, "subnets", 0)
	setY(&g, "yandex", 300)
	compiled := compileProTun(g, "proxy", nil, knownApps(g))
	plan := buildRoutePlan(compiled.Rules, "proxy", knownApps(g))
	route, ok := plan.Apps["yandexbrowser.exe"]
	if !ok {
		t.Fatalf("app missing from plan: %+v", plan.Apps)
	}
	if route.Outbound != "" || route.Bypass || route.Block || len(route.Networks) > 0 {
		t.Fatalf("the tunnel must not decide for the app, the subnet rule goes first: %+v", route)
	}
}

func TestCanvasOrdersGeoAgainstPlainDomains(t *testing.T) {
	g := newGraph().
		node("geo", types.ProTunKindGeoSite, "youtube").
		node("site", types.ProTunKindDomains, "youtube.com").
		edge("geo", "vpn").edge("site", "direct").g

	setY(&g, "site", 0)
	setY(&g, "geo", 300)
	if heads := orderedHeads(g); strings.Join(heads, ",") != "site,geo" {
		t.Fatalf("the domain card is higher and must go first: %v", heads)
	}

	setY(&g, "geo", 0)
	setY(&g, "site", 300)
	if heads := orderedHeads(g); strings.Join(heads, ",") != "geo,site" {
		t.Fatalf("the geo card is higher and must go first: %v", heads)
	}
}

func TestCanvasOrdersGeoIPAgainstSubnets(t *testing.T) {
	g := newGraph().
		node("country", types.ProTunKindGeoIP, "ru").
		node("subnet", types.ProTunKindIPRanges, "10.0.0.0/8").
		edge("country", "vpn").edge("subnet", "direct").g

	setY(&g, "subnet", 0)
	setY(&g, "country", 300)
	if heads := orderedHeads(g); strings.Join(heads, ",") != "subnet,country" {
		t.Fatalf("the subnet card is higher and must go first: %v", heads)
	}
	setY(&g, "country", 0)
	setY(&g, "subnet", 300)
	if heads := orderedHeads(g); strings.Join(heads, ",") != "country,subnet" {
		t.Fatalf("the geo card is higher and must go first: %v", heads)
	}
}
