//go:build linux

package mobile

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	"beam-bridge/core/profile"
	"beam-bridge/core/types"
)

// Routing: the phone offers Easy split tunneling (apps, domains, IPs) and, for
// ProTun, only importing a .protun schema into a layer. A layer is "general"
// (scope "") or one profile's; a provider's locked preset always wins over a
// profile's own layer, so it cannot be replaced here.

const (
	maxProTunBytes = 2 << 20
	maxProTunNodes = 2000
)

// Routing returns {"mode":"easy"|"pro","split":types.SplitTunnelSettings} as JSON.
func Routing() (string, error) {
	mu.Lock()
	s := settings
	mu.Unlock()
	if s == nil {
		return "", errNotInitialized
	}
	cur := s.Get()
	mode := cur.RoutingMode
	if mode == "" {
		mode = "easy"
	}
	split := cur.SplitTunnel
	if split.Apps == nil {
		split.Apps = []string{}
	}
	if split.Domains == nil {
		split.Domains = []string{}
	}
	if split.IPs == nil {
		split.IPs = []string{}
	}
	return toJSON(map[string]any{"mode": mode, "split": split})
}

// SetRoutingMode switches between "easy" and "pro". The other mode keeps its rules.
func SetRoutingMode(mode string) error {
	mu.Lock()
	s := settings
	mu.Unlock()
	if s == nil {
		return errNotInitialized
	}
	return s.UpdateRoutingMode(mode)
}

// SetSplitTunnel stores the Easy rules (types.SplitTunnelSettings as JSON).
// Package names are the app identifiers; the settings store normalises the
// rest. Call Reconnect afterwards to apply them to a live tunnel.
func SetSplitTunnel(jsonSettings string) error {
	mu.Lock()
	s := settings
	mu.Unlock()
	if s == nil {
		return errNotInitialized
	}
	var st types.SplitTunnelSettings
	if err := json.Unmarshal([]byte(jsonSettings), &st); err != nil {
		return err
	}
	return s.UpdateSplitTunnel(st)
}

type scopeInfo struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Nodes     int    `json:"nodes"`
	Edges     int    `json:"edges"`
	Items     int    `json:"items"`
	Targets   string `json:"targets"`
	HasPreset bool   `json:"hasPreset"`
	Locked    bool   `json:"locked"`
	Active    bool   `json:"active"`
}

// describe summarises a graph for the UI without sending the whole schema over.
func describe(g types.ProTunGraph) (nodes, edges, items int, targets string) {
	seen := map[string]bool{}
	for _, n := range g.Nodes {
		switch n.Kind {
		case types.ProTunKindComment, types.ProTunKindLogic:
			continue
		case types.ProTunKindVPN, types.ProTunKindServer, types.ProTunKindDirect, types.ProTunKindBlock:
			seen[string(n.Kind)] = true
		}
		nodes++
		items += len(n.Items)
	}
	edges = len(g.Edges)
	kinds := make([]string, 0, len(seen))
	for k := range seen {
		kinds = append(kinds, k)
	}
	sort.Strings(kinds)
	return nodes, edges, items, strings.Join(kinds, ",")
}

// ProTunScopes lists the ProTun layers as JSON:
// {"general":scopeInfo,"profiles":[scopeInfo],"activeId":string}. For a profile
// the counts describe the layer that applies: its own, or the provider's preset
// when the preset is locked or the profile has no rules of its own.
func ProTunScopes() (string, error) {
	m, err := manager()
	if err != nil {
		return "", err
	}
	mu.Lock()
	s := settings
	mu.Unlock()
	cur := s.Get()

	general := scopeInfo{Name: "Общие"}
	general.Nodes, general.Edges, general.Items, general.Targets = describe(cur.ProTunGraph)

	activeID := m.GetActiveProfileID()
	profiles := m.GetProfiles()
	out := make([]scopeInfo, 0, len(profiles))
	for _, p := range profiles {
		info := scopeInfo{ID: p.ID, Name: p.Name, Active: p.ID == activeID}
		if g, ok := cur.ProTunProfiles[p.ID]; ok {
			info.Nodes, info.Edges, info.Items, info.Targets = describe(g)
		}
		if preset, locked := m.GetProTunPreset(p.ID); preset != nil {
			info.HasPreset = true
			info.Locked = locked
			if locked || info.Nodes == 0 {
				info.Nodes, info.Edges, info.Items, info.Targets = describe(*preset)
			}
		}
		out = append(out, info)
	}
	return toJSON(map[string]any{"general": general, "profiles": out, "activeId": activeID})
}

type protunFile struct {
	Format  string `json:"format"`
	Version int    `json:"version"`
	Meta    struct {
		Name string `json:"name"`
	} `json:"meta"`
	Graph types.ProTunGraph `json:"graph"`
}

var knownKinds = map[types.ProTunNodeKind]bool{
	types.ProTunKindApps: true, types.ProTunKindDomains: true, types.ProTunKindIPRanges: true,
	types.ProTunKindProtocols: true, types.ProTunKindPorts: true, types.ProTunKindGeoIP: true,
	types.ProTunKindGeoSite: true, types.ProTunKindNetwork: true, types.ProTunKindVPN: true,
	types.ProTunKindDirect: true, types.ProTunKindBlock: true, types.ProTunKindServer: true,
	types.ProTunKindComment: true, types.ProTunKindLogic: true, types.ProTunKindOther: true,
}

// parseProTun checks a .protun file the way desktop's importer does and drops
// edges that point nowhere. It returns the graph, the schema name and warnings.
func parseProTun(data []byte) (types.ProTunGraph, string, []string, error) {
	var empty types.ProTunGraph
	if len(data) == 0 || len(data) > maxProTunBytes {
		return empty, "", nil, errors.New("файл пустой или слишком большой")
	}
	var f protunFile
	if err := json.Unmarshal(data, &f); err != nil {
		return empty, "", nil, errors.New("это не файл ProTun: не удалось прочитать JSON")
	}
	if f.Format != "protun" {
		return empty, "", nil, errors.New("это не файл ProTun (.protun)")
	}
	if f.Version != 1 {
		return empty, "", nil, fmt.Errorf("версия формата %d не поддерживается этим приложением", f.Version)
	}
	if len(f.Graph.Nodes) == 0 {
		return empty, "", nil, errors.New("в схеме нет правил")
	}
	if len(f.Graph.Nodes) > maxProTunNodes {
		return empty, "", nil, errors.New("в схеме слишком много карточек")
	}

	ids := make(map[string]bool, len(f.Graph.Nodes))
	for i, n := range f.Graph.Nodes {
		if strings.TrimSpace(n.ID) == "" {
			return empty, "", nil, fmt.Errorf("карточка #%d без id", i)
		}
		if !knownKinds[n.Kind] {
			return empty, "", nil, fmt.Errorf("карточка «%s»: неизвестный тип «%s»", n.ID, n.Kind)
		}
		if ids[n.ID] {
			return empty, "", nil, fmt.Errorf("повторяется id «%s»", n.ID)
		}
		ids[n.ID] = true
	}
	var warnings []string
	edges := make([]types.ProTunEdge, 0, len(f.Graph.Edges))
	for i, e := range f.Graph.Edges {
		if !ids[e.Source] || !ids[e.Target] {
			warnings = append(warnings, fmt.Sprintf("связь #%d ведёт в никуда и пропущена", i))
			continue
		}
		edges = append(edges, e)
	}
	f.Graph.Edges = edges
	return f.Graph, strings.TrimSpace(f.Meta.Name), warnings, nil
}

// ImportProTun validates a .protun file and stores it as the layer of scope
// ("" = general, otherwise a profile ID), replacing that layer. Schemas with
// contradicting rules are refused: such a graph would not connect. A profile
// whose provider locked its routing cannot be changed. Returns
// {"name":string,"nodes":n,"edges":n,"warnings":[string]} as JSON.
func ImportProTun(scope string, data []byte) (string, error) {
	m, err := manager()
	if err != nil {
		return "", err
	}
	mu.Lock()
	s := settings
	mu.Unlock()

	graph, name, warnings, err := parseProTun(data)
	if err != nil {
		return "", err
	}
	if conflicts := profile.DetectProTunConflicts(graph); len(conflicts) > 0 {
		return "", fmt.Errorf("в схеме противоречия: %s", conflicts[0].Message)
	}
	if scope == "" {
		if err := s.UpdateProTunGraph(graph); err != nil {
			return "", err
		}
	} else {
		if preset, locked := m.GetProTunPreset(scope); preset != nil && locked {
			return "", errors.New("правила этого профиля задаёт провайдер, заменить их нельзя")
		}
		if err := s.UpdateProTunProfileGraph(scope, &graph); err != nil {
			return "", err
		}
	}
	nodes, edges, _, _ := describe(graph)
	if warnings == nil {
		warnings = []string{}
	}
	return toJSON(map[string]any{"name": name, "nodes": nodes, "edges": edges, "warnings": warnings})
}

// ClearProTun removes the user's layer of a scope. A provider's locked preset stays.
func ClearProTun(scope string) error {
	m, err := manager()
	if err != nil {
		return err
	}
	mu.Lock()
	s := settings
	mu.Unlock()
	if scope == "" {
		return s.UpdateProTunGraph(types.DefaultProTunGraph())
	}
	if preset, locked := m.GetProTunPreset(scope); preset != nil && locked {
		return errors.New("правила этого профиля задаёт провайдер")
	}
	return s.UpdateProTunProfileGraph(scope, nil)
}

// PrepareGeo downloads geosite.dat and/or geoip.dat when the Easy rules use
// geosite:/geoip: entries and the file is not on disk yet. It blocks (up to a
// few minutes); the app calls it before rebuilding the core so such rules apply
// at once instead of being skipped until the next connect.
func PrepareGeo(sites, ips bool) error {
	m, err := manager()
	if err != nil {
		return err
	}
	return m.PrepareGeo(sites, ips)
}
