package profile

import (
	"strings"
	"testing"

	infraBeam "beam-bridge/core/infrastructure/beam"
	"beam-bridge/core/types"
)

func vlessNode(id, server string, beamOpts map[string]interface{}) types.BeamNode {
	ob := map[string]interface{}{
		"type":        "vless",
		"server":      server,
		"server_port": float64(443),
		"uuid":        "11111111-1111-1111-1111-111111111111",
	}
	if beamOpts != nil {
		ob[nodeOptionsKey] = beamOpts
	}
	return types.BeamNode{ID: id, Name: id, Type: "vless", Outbound: ob}
}

func entryOpts(profileID, nodeID string) map[string]interface{} {
	return map[string]interface{}{entryKey: map[string]interface{}{"profileId": profileID, "nodeId": nodeID}}
}

func testExpander(files map[string][]types.BeamNode) *entryExpander {
	beams := map[string]*infraBeam.BeamFile{}
	for id, nodes := range files {
		bf := infraBeam.New(id, "T", "")
		bf.Data.Nodes = nodes
		beams[id] = bf
	}
	return &entryExpander{beams: beams, load: func(string) *infraBeam.BeamFile { return nil }}
}

func TestEntryExpandsIntoDetourAcrossProfiles(t *testing.T) {
	e := testExpander(map[string][]types.BeamNode{
		"p1": {vlessNode("exit", "1.1.1.1", entryOpts("p2", "entry"))},
		"p2": {vlessNode("entry", "2.2.2.2", nil)},
	})
	node := e.node("p1", e.beam("p1").Data.Nodes[0])

	converted, err := convertOutbound(node.EffectiveOutbound())
	if err != nil {
		t.Fatal(err)
	}
	chain := takeChain(converted)
	if len(chain) != 1 {
		t.Fatalf("chain length = %d, want 1", len(chain))
	}
	hops := linkChain(converted, "exit", chain)
	if len(hops) != 1 {
		t.Fatalf("hops = %d, want 1", len(hops))
	}
	if got := sockoptOf(converted)["dialerProxy"]; got != "direct-chain-exit-1" {
		t.Fatalf("dialerProxy = %v", got)
	}
}

func TestEntryLoopIsRejected(t *testing.T) {
	e := testExpander(map[string][]types.BeamNode{
		"p1": {
			vlessNode("a", "1.1.1.1", entryOpts("p1", "b")),
			vlessNode("b", "2.2.2.2", entryOpts("p1", "a")),
		},
	})
	node := e.node("p1", e.beam("p1").Data.Nodes[0])
	_, err := convertOutbound(node.EffectiveOutbound())
	if err == nil || !strings.Contains(err.Error(), "entry server") {
		t.Fatalf("want entry error, got %v", err)
	}
}

func TestEntryMissingNodeIsRejected(t *testing.T) {
	e := testExpander(map[string][]types.BeamNode{
		"p1": {vlessNode("a", "1.1.1.1", entryOpts("p9", "gone"))},
	})
	node := e.node("p1", e.beam("p1").Data.Nodes[0])
	if _, err := convertOutbound(node.EffectiveOutbound()); err == nil {
		t.Fatal("unresolved entry must not convert")
	}
}

func TestEntryRejectsUDPOnlyExit(t *testing.T) {
	hy := types.BeamNode{ID: "hy", Name: "hy", Type: "hysteria2", Outbound: map[string]interface{}{
		"type": "hysteria2", "server": "1.1.1.1", "server_port": float64(443), "password": "x",
		nodeOptionsKey: entryOpts("p1", "entry"),
	}}
	e := testExpander(map[string][]types.BeamNode{
		"p1": {hy, vlessNode("entry", "2.2.2.2", nil)},
	})
	node := e.node("p1", e.beam("p1").Data.Nodes[0])
	if _, err := convertOutbound(node.EffectiveOutbound()); err == nil {
		t.Fatal("hysteria2 behind an entry must be rejected")
	}
}

func TestNodeListKeepsNodesWithEntry(t *testing.T) {
	e := testExpander(map[string][]types.BeamNode{
		"p1": {
			vlessNode("ok", "1.1.1.1", entryOpts("p1", "entry")),
			vlessNode("broken", "3.3.3.3", entryOpts("p9", "gone")),
			vlessNode("entry", "2.2.2.2", nil),
		},
	})
	if got := unsupportedNodeIDs(e.beam("p1"), e, "p1"); len(got) != 0 {
		t.Fatalf("nodes with an entry must stay listed, hidden: %v", got)
	}
}

func TestWithEntryMatchesNodeEntry(t *testing.T) {
	e := testExpander(map[string][]types.BeamNode{
		"p1": {vlessNode("exit", "1.1.1.1", nil)},
		"p2": {vlessNode("entry", "2.2.2.2", nil)},
	})
	exit := e.beam("p1").Data.Nodes[0]
	exit.PinnedOutbound = withEntry(exit.EffectiveOutbound(), &types.ProTunServerRef{ProfileID: "p2", NodeID: "entry"})
	node := e.node("p1", exit)

	converted, err := convertOutbound(node.EffectiveOutbound())
	if err != nil {
		t.Fatal(err)
	}
	if chain := takeChain(converted); len(chain) != 1 {
		t.Fatalf("chain length = %d, want 1", len(chain))
	}
	if e.beam("p1").Data.Nodes[0].PinnedOutbound != nil {
		t.Fatal("stored node must stay untouched")
	}
}

func TestServerRefKeyIncludesVia(t *testing.T) {
	plain := &types.ProTunServerRef{ProfileID: "p1", NodeID: "a"}
	chained := &types.ProTunServerRef{ProfileID: "p1", NodeID: "a", Via: &types.ProTunServerRef{ProfileID: "p2", NodeID: "b"}}
	if serverRefKey(plain) == serverRefKey(chained) {
		t.Fatal("a chained server must get its own outbound")
	}
}
