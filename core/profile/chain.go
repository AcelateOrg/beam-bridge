package profile

import (
	infraBeam "beam-bridge/core/infrastructure/beam"
	"beam-bridge/core/types"
)

// entryKey is beam.entry of a node outbound: the server the node's traffic
// enters the chain through (a types.ProTunServerRef). The node itself is the
// exit. The user sets it through the node's Overrides, so it survives
// subscription refreshes like any other edit.
const entryKey = "entry"

// entryViaKey marks an outbound whose detour was built from beam.entry, so
// the converter can reject exits that cannot be carried over a proxy hop.
const entryViaKey = "_entry_via"

func entryRefOf(source map[string]interface{}) *types.ProTunServerRef {
	raw := getMap(getMap(source, nodeOptionsKey), entryKey)
	if raw == nil {
		return nil
	}
	ref := &types.ProTunServerRef{
		ProfileID:   getStr(raw, "profileId"),
		NodeID:      getStr(raw, "nodeId"),
		Name:        getStr(raw, "name"),
		ProfileName: getStr(raw, "profileName"),
	}
	if ref.ProfileID == "" || (ref.NodeID == "" && ref.Name == "") {
		return nil
	}
	return ref
}

// entryExpander turns beam.entry into detour. Only the copies it returns are
// expanded; stored nodes keep the plain reference.
type entryExpander struct {
	activeID string
	beams    map[string]*infraBeam.BeamFile
	load     func(profileID string) *infraBeam.BeamFile
}

func (m *Manager) newEntryExpander(activeID string, active *infraBeam.BeamFile) *entryExpander {
	return &entryExpander{
		activeID: activeID,
		beams:    map[string]*infraBeam.BeamFile{activeID: active},
		load: func(profileID string) *infraBeam.BeamFile {
			beamFile, _ := m.storage.GetBeam(profileID)
			return beamFile
		},
	}
}

func (e *entryExpander) beam(profileID string) *infraBeam.BeamFile {
	if beamFile, ok := e.beams[profileID]; ok {
		return beamFile
	}
	beamFile := e.load(profileID)
	e.beams[profileID] = beamFile
	return beamFile
}

// node returns a copy of node with its entry hop resolved into the outbound
// (as PinnedOutbound, which wins over Overrides). A node without an entry is
// returned untouched.
func (e *entryExpander) node(profileID string, node types.BeamNode) types.BeamNode {
	source := node.EffectiveOutbound()
	if entryRefOf(source) == nil {
		return node
	}
	expanded := e.expand(source, 0, map[string]bool{profileID + "/" + node.ID: true})
	node.PinnedOutbound = expanded
	return node
}

// beamFile returns beamFile with every entry resolved; the original is not
// modified.
func (e *entryExpander) beamFile(profileID string, beamFile *infraBeam.BeamFile) *infraBeam.BeamFile {
	hasEntry := false
	for i := range beamFile.Data.Nodes {
		if entryRefOf(beamFile.Data.Nodes[i].EffectiveOutbound()) != nil {
			hasEntry = true
			break
		}
	}
	if !hasEntry {
		return beamFile
	}
	clone := *beamFile
	clone.Data.Nodes = make([]types.BeamNode, len(beamFile.Data.Nodes))
	for i, node := range beamFile.Data.Nodes {
		clone.Data.Nodes[i] = e.node(profileID, node)
	}
	return &clone
}

// expand sets source.detour to the entry node's outbound. When the entry
// cannot be resolved (node gone, loop, too deep, or the exit already has a
// provider chain) beam.entry stays in place and convertOutbound rejects the
// node with a reason.
func (e *entryExpander) expand(source map[string]interface{}, depth int, visiting map[string]bool) map[string]interface{} {
	ref := entryRefOf(source)
	if ref == nil {
		return source
	}
	if depth >= maxDetourDepth || getMap(source, "detour") != nil {
		return source
	}
	found := findServerNode(e.beam(ref.ProfileID), ref)
	if found == nil {
		return source
	}
	key := ref.ProfileID + "/" + found.ID
	if visiting[key] {
		return source
	}
	visiting[key] = true
	defer delete(visiting, key)

	hop := e.expand(found.EffectiveOutbound(), depth+1, visiting)
	if entryRefOf(hop) != nil {
		return source
	}
	// Chain hops are not resolved by the core's own address pass, and the
	// tunnel bypass list only knows IPs: a hostname here would loop.
	hop = resolveOutboundAddress(hop)

	out := copyOutbound(source)
	beamOpts := copyOutbound(getMap(source, nodeOptionsKey))
	delete(beamOpts, entryKey)
	out[nodeOptionsKey] = beamOpts
	out["detour"] = hop
	out[entryViaKey] = true
	return out
}

func (e *entryExpander) nodes(profileID string, nodes []types.BeamNode) []types.BeamNode {
	out := make([]types.BeamNode, len(nodes))
	for i, node := range nodes {
		out[i] = e.node(profileID, node)
	}
	return out
}

// withEntry returns source with beam.entry set to ref.
func withEntry(source map[string]interface{}, ref *types.ProTunServerRef) map[string]interface{} {
	out := copyOutbound(source)
	opts := copyOutbound(getMap(source, nodeOptionsKey))
	opts[entryKey] = map[string]interface{}{
		"profileId":   ref.ProfileID,
		"nodeId":      ref.NodeID,
		"name":        ref.Name,
		"profileName": ref.ProfileName,
	}
	out[nodeOptionsKey] = opts
	return out
}

func withoutEntry(source map[string]interface{}) map[string]interface{} {
	out := copyOutbound(source)
	opts := copyOutbound(getMap(source, nodeOptionsKey))
	delete(opts, entryKey)
	out[nodeOptionsKey] = opts
	return out
}
