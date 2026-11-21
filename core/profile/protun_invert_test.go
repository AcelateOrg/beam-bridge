package profile

import (
	"testing"

	"beam-bridge/core/types"
)

func setInvert(g *types.ProTunGraph, id string) {
	for i := range g.Nodes {
		if g.Nodes[i].ID == id {
			g.Nodes[i].Invert = true
		}
	}
}

func TestInvertedGeoCardCarvesThenCatchesAll(t *testing.T) {
	g := newGraph().
		node("geo", types.ProTunKindGeoSite, "youtube").
		edge("geo", "direct").g
	setInvert(&g, "geo")

	rules := compileProTun(g, "proxy", nil, nil).Rules
	if len(rules) != 2 {
		t.Fatalf("want a carve-out and a catch-all, got %d rules", len(rules))
	}
	if rules[0].outbound != exceptOutbound || rules[0].object["domain"] == nil {
		t.Fatalf("the listed values must be carved out first: %+v", rules[0])
	}
	if rules[1].outbound != outboundDirect || rules[1].object["network"] != "tcp,udp" {
		t.Fatalf("everything else goes to the destination: %+v", rules[1])
	}
}

func TestInvertedCardGoesAfterNarrowerRules(t *testing.T) {
	g := newGraph().
		node("subnet", types.ProTunKindIPRanges, "10.0.0.0/8").
		node("domains", types.ProTunKindDomains, "example.com").
		edge("subnet", "vpn").edge("domains", "direct").g
	setInvert(&g, "domains")

	rules := compileProTun(g, "proxy", nil, nil).Rules
	last := rules[len(rules)-1]
	if last.outbound != outboundDirect || last.object["network"] != "tcp,udp" {
		t.Fatalf("the catch-all must be the last rule: %+v", rules)
	}
}

func TestInvertedCardWithoutListSendsEverything(t *testing.T) {
	g := newGraph().node("ips", types.ProTunKindIPRanges).edge("ips", "direct").g
	setInvert(&g, "ips")

	rules := compileProTun(g, "proxy", nil, nil).Rules
	if len(rules) != 1 || rules[0].outbound != outboundDirect {
		t.Fatalf("an empty «Все, кроме» is a catch-all: %+v", rules)
	}
}
