package profile

import (
	domainSettings "beam-bridge/core/domain/settings"
	infraBeam "beam-bridge/core/infrastructure/beam"
	"beam-bridge/core/types"
)

// GetProTunPreset returns the provider routing preset of a profile and
// whether it is locked (true only when the preset exists and is locked).
func (m *Manager) GetProTunPreset(profileID string) (*types.ProTunGraph, bool) {
	beamFile, ok := m.storage.GetBeam(profileID)
	if !ok || beamFile == nil || beamFile.Data.ProTunPreset == nil {
		return nil, false
	}
	preset := presetForProfile(*beamFile.Data.ProTunPreset, profileID)
	return &preset, beamFile.Data.ProTunLocked
}

// presetForProfile rebinds the «Сервер» cards of a provider preset to the
// profile that carries it: the provider drew the graph against its own copy
// of the profile, whose ID exists on no other machine. The node is then
// found by name (findServerNode).
func presetForProfile(preset types.ProTunGraph, profileID string) types.ProTunGraph {
	if profileID == "" {
		return preset
	}
	rebind := func(ref *types.ProTunServerRef) *types.ProTunServerRef {
		if ref == nil || ref.ProfileID == profileID {
			return ref
		}
		bound := *ref
		bound.ProfileID = profileID
		bound.ProfileName = ""
		return &bound
	}
	nodes := make([]types.ProTunNode, len(preset.Nodes))
	copy(nodes, preset.Nodes)
	for i := range nodes {
		if nodes[i].Server == nil {
			continue
		}
		server := rebind(nodes[i].Server)
		if via := rebind(server.Via); via != server.Via {
			if server == nodes[i].Server {
				copied := *server
				server = &copied
			}
			server.Via = via
		}
		nodes[i].Server = server
	}
	preset.Nodes = nodes
	return preset
}

// GetActiveProfileID returns the ID of the active profile ("" if none).
func (m *Manager) GetActiveProfileID() string {
	profile, _, _ := m.storage.GetActive()
	if profile == nil {
		return ""
	}
	return profile.ID
}

func emptyProTunGraph(g types.ProTunGraph) bool {
	return len(g.Nodes) == 0 && len(g.Edges) == 0
}

// effectiveProfileLayer is the ProTun layer of a profile as it applies: a
// locked provider preset is forced, otherwise the preset only fills an empty
// user layer.
func effectiveProfileLayer(settings *domainSettings.Settings, profileID string, beamFile *infraBeam.BeamFile) types.ProTunGraph {
	layer := settings.ProTunProfiles[profileID]
	if beamFile != nil && beamFile.Data.ProTunPreset != nil {
		if beamFile.Data.ProTunLocked || emptyProTunGraph(layer) {
			layer = presetForProfile(*beamFile.Data.ProTunPreset, profileID)
		}
	}
	return layer
}

// findServerNode looks a referenced server up by ID, then by name
// (subscription refreshes may regenerate IDs).
func findServerNode(beamFile *infraBeam.BeamFile, ref *types.ProTunServerRef) *types.BeamNode {
	if beamFile == nil || ref == nil {
		return nil
	}
	nodes := beamFile.Data.Nodes
	for i := range nodes {
		if ref.NodeID != "" && nodes[i].ID == ref.NodeID {
			return &nodes[i]
		}
	}
	if ref.Name == "" {
		return nil
	}
	for i := range nodes {
		if nodes[i].DisplayName() == ref.Name || nodes[i].Name == ref.Name {
			return &nodes[i]
		}
	}
	return nil
}

// serverTargets resolves every «Сервер» destination of the graphs. Servers
// of the active profile reuse their outbound (tag = node ID); servers of
// other profiles get their own outbound. Unresolved ones are left out and
// fall back to the current VPN server.
func (m *Manager) serverTargets(activeID string, active *infraBeam.BeamFile, graphs ...types.ProTunGraph) []serverTarget {
	var out []serverTarget
	seen := map[string]bool{}
	beams := map[string]*infraBeam.BeamFile{activeID: active}
	expander := m.newEntryExpander(activeID, active)
	for _, graph := range graphs {
		for _, node := range graph.Nodes {
			if node.Kind != types.ProTunKindServer || node.Server == nil {
				continue
			}
			ref := node.Server
			key := serverRefKey(ref)
			if seen[key] {
				continue
			}
			seen[key] = true

			beamFile, loaded := beams[ref.ProfileID]
			if !loaded {
				beamFile, _ = m.storage.GetBeam(ref.ProfileID)
				beams[ref.ProfileID] = beamFile
			}
			found := findServerNode(beamFile, ref)
			if found == nil {
				continue
			}
			if ref.ProfileID == activeID && ref.Via == nil {
				out = append(out, serverTarget{key: key, tag: found.ID})
				continue
			}
			nodeCopy := *found
			if ref.Via != nil {
				// The chain is set on the card, so the node gets its own outbound
				// even in the active profile and the node itself stays untouched.
				nodeCopy.PinnedOutbound = withEntry(found.EffectiveOutbound(), ref.Via)
			}
			nodeCopy = expander.node(ref.ProfileID, nodeCopy)
			out = append(out, serverTarget{
				key:  key,
				tag:  "srv-" + shortHash(key+"/"+found.ID),
				node: &nodeCopy,
			})
		}
	}
	return out
}
