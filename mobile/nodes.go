//go:build linux

package mobile

import (
	"encoding/json"
	"errors"

	"beam-bridge/core/types"
	"beam-bridge/core/vpn"
)

// NodeConfig returns a server's editable configuration (types.NodeConfig) as
// JSON: the effective outbound, the provider's original and the user's
// overrides, keyed by dotted path ("tls.server_name").
func NodeConfig(profileID, nodeID string) (string, error) {
	m, err := manager()
	if err != nil {
		return "", err
	}
	config, err := m.GetNodeConfig(profileID, nodeID)
	if err != nil {
		return "", err
	}
	return toJSON(config)
}

// UpdateNodeConfig stores the user's edits of a server: a display name (empty
// = the provider's), overrides as a JSON object of path to value (null removes
// the field) and pinned, which keeps the whole config off subscription updates.
// Returns the updated types.NodeConfig as JSON. Call Reconnect afterwards when
// the server belongs to the profile of a live tunnel.
func UpdateNodeConfig(profileID, nodeID, name, overridesJSON string, pinned bool) (string, error) {
	m, err := manager()
	if err != nil {
		return "", err
	}
	update := types.NodeConfigUpdate{Name: name, Pinned: pinned}
	if overridesJSON != "" {
		if err := json.Unmarshal([]byte(overridesJSON), &update.Overrides); err != nil {
			return "", errors.New("не удалось прочитать правки: " + err.Error())
		}
	}
	config, err := m.UpdateNodeConfig(profileID, nodeID, update)
	if err != nil {
		return "", err
	}
	return toJSON(config)
}

// Connections returns the tunnel's live flows followed by the recently closed
// ones as JSON ([]types.ActiveConnection, as desktop's connections view gets
// them). On Android a flow's process is the owning app's package name.
func Connections() (string, error) {
	m, err := manager()
	if err != nil {
		return "", err
	}
	coreMu.Lock()
	svc := core
	coreMu.Unlock()
	if svc == nil {
		return "[]", nil
	}
	nodeName := ""
	if node, ok := m.GetActiveNode(); ok && node != nil {
		nodeName = node.DisplayName()
		if nodeName == "" {
			nodeName = node.ID
		}
	}
	conns, err := vpn.Snapshot(svc, nodeName)
	if err != nil {
		return "", err
	}
	return toJSON(conns)
}

// CloseConnections tears down live flows by ID (idsJSON is a JSON array) and
// returns how many were closed.
func CloseConnections(idsJSON string) (int, error) {
	var ids []string
	if err := json.Unmarshal([]byte(idsJSON), &ids); err != nil {
		return 0, err
	}
	coreMu.Lock()
	svc := core
	coreMu.Unlock()
	if svc == nil || len(ids) == 0 {
		return 0, nil
	}
	return svc.CloseConnections(ids), nil
}
