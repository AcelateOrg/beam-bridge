package vpn

import (
	"path/filepath"
	"sort"
	"strings"
	"time"

	"beam-bridge/core/coreapi"
	"beam-bridge/core/types"
)

// maxRecentClosed caps the recently closed flows sent to the UI: torrent
// clients close thousands of UDP flows within the 2-minute window, and
// shipping all of them every second only costs JSON and rendering time.
const maxRecentClosed = 1000

// GetActiveConnections returns the live flows followed by the recently
// closed ones (marked Closed), so short requests can still be seen.
func (m *Manager) GetActiveConnections() ([]types.ActiveConnection, error) {
	nodeName := ""
	if node, ok := m.profiles.GetActiveNode(); ok && node != nil {
		nodeName = node.Name
		if nodeName == "" {
			nodeName = node.ID
		}
	}
	return Snapshot(m.core, nodeName)
}

// Snapshot lists the live flows of core followed by the recently closed ones
// (marked Closed). nodeName is shown on flows that go through the proxy. It is
// the part of GetActiveConnections that needs no Manager, for platforms (the
// mobile bridge) that run the core without one.
func Snapshot(core coreapi.Core, nodeName string) ([]types.ActiveConnection, error) {
	if core == nil || !core.Running() {
		return []types.ActiveConnection{}, nil
	}

	raw, err := core.Connections()
	if err != nil {
		return nil, err
	}
	var recent []coreapi.Connection
	if history, ok := core.(coreapi.ConnectionHistory); ok {
		recent = history.RecentConnections()
	}
	if len(recent) > maxRecentClosed {
		recent = append([]coreapi.Connection(nil), recent...)
		sort.Slice(recent, func(i, j int) bool { return recent[i].End.After(recent[j].End) })
		recent = recent[:maxRecentClosed]
	}

	now := time.Now()
	result := make([]types.ActiveConnection, 0, len(raw)+len(recent))
	for _, c := range raw {
		result = append(result, toActiveConnection(c, nodeName, now))
	}
	for _, c := range recent {
		result = append(result, toActiveConnection(c, nodeName, now))
	}
	return result, nil
}

// CloseConnections tears down live flows by ID and returns how many closed.
func (m *Manager) CloseConnections(ids []string) int {
	if len(ids) == 0 {
		return 0
	}
	if history, ok := m.core.(coreapi.ConnectionHistory); ok {
		return history.CloseConnections(ids)
	}
	return 0
}

func toActiveConnection(c coreapi.Connection, nodeName string, now time.Time) types.ActiveConnection {
	entry := types.ActiveConnection{
		ID:          c.ID,
		Network:     strings.ToLower(c.Network),
		Host:        c.Host,
		Destination: c.Destination,
		Outbound:    c.Outbound,
		Rule:        c.Rule,
		Process:     processName(c.ProcessPath),
		ProcessPath: c.ProcessPath,
		Upload:      c.Upload,
		Download:    c.Download,
		Domain:      c.Domain,
		Protocol:    c.Protocol,
		Route:       c.Route,
		RuleKind:    c.RuleKind,
	}
	if c.Outbound != "" {
		entry.Chains = []string{c.Outbound}
	}
	if entry.Route == "proxy" || (entry.Route == "" && c.Outbound != "" && c.Outbound != "direct" && c.Outbound != "block") {
		entry.NodeName = nodeName
	}

	end := now
	if !c.End.IsZero() {
		entry.Closed = true
		entry.EndedAt = c.End.UnixMilli()
		end = c.End
	}
	if !c.Start.IsZero() {
		entry.StartedAt = c.Start.UnixMilli()
		entry.Duration = int64(end.Sub(c.Start).Seconds())
		if entry.Duration < 0 {
			entry.Duration = 0
		}
	}
	if entry.Network == "" {
		entry.Network = "tcp"
	}
	return entry
}

func processName(path string) string {
	if path == "" {
		return ""
	}
	return filepath.Base(path)
}
