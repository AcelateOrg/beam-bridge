package profile

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"beam-bridge/core/coreapi"
	domainSettings "beam-bridge/core/domain/settings"
	"beam-bridge/core/geodata"
	infraBeam "beam-bridge/core/infrastructure/beam"
	"beam-bridge/core/infrastructure/mediacache"
	infraProfile "beam-bridge/core/infrastructure/persistence/profile"
	"beam-bridge/core/infrastructure/subscription"
	corePaths "beam-bridge/core/paths"
	"beam-bridge/core/types"
)

type Manager struct {
	mu               sync.RWMutex
	storage          *infraProfile.FileRepository
	client           *http.Client
	subscription     *subscription.Aggregator
	settingsRepo     domainSettings.Repository
	core             coreapi.Core
	coreFactory      coreapi.Factory
	unsupportedNodes map[string]string
	routes           coreapi.RoutePlan
	proxyTag         string
	paths            corePaths.Paths
	geo              *geodata.Store
	media            *mediacache.Cache

	// pingObserver gets every ping result the moment it is known, so the UI
	// can show finished servers while the rest are still being measured.
	pingObserver func(PingResult)
}

func NewManager(
	storage *infraProfile.FileRepository,
	settingsRepo domainSettings.Repository,
	paths corePaths.Paths,
) *Manager {
	client := &http.Client{Timeout: 30 * time.Second}
	return &Manager{
		storage:      storage,
		client:       client,
		subscription: subscription.NewAggregator(client),
		settingsRepo: settingsRepo,
		paths:        paths,
		geo:          geodata.New(filepath.Join(paths.Data, "geo")),
		media:        mediacache.New(filepath.Join(paths.Data, "media"), client),
	}
}

// geoResolveTimeout bounds how long building a config may wait for a missing
// database. The card picker downloads them earlier, so this only matters for
// graphs imported or preset while offline.
const geoResolveTimeout = time.Minute

func geoFile(kind types.ProTunNodeKind) string {
	switch kind {
	case types.ProTunKindGeoIP:
		return geodata.FileIP
	case types.ProTunKindGeoSite:
		return geodata.FileSite
	}
	return ""
}

// PrewarmGeo indexes the geo databases already on disk in the background, so
// the first connect does not read and parse them. Nothing is downloaded.
func (m *Manager) PrewarmGeo() {
	go func() {
		for _, file := range []string{geodata.FileSite, geodata.FileIP} {
			if !m.geo.Present(file) {
				continue
			}
			ctx, cancel := context.WithTimeout(context.Background(), geoResolveTimeout)
			_, _ = m.geo.Known(ctx, file)
			cancel()
		}
	}()
}

// GeoCodes lists the codes available for a geoip or geosite card,
// downloading the database on first use.
func (m *Manager) GeoCodes(kind string) ([]string, error) {
	file := geoFile(types.ProTunNodeKind(kind))
	if file == "" {
		return nil, fmt.Errorf("unknown geo kind %q", kind)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	return m.geo.Codes(ctx, file)
}

// resolveGeo keeps only the geo codes present in the local databases: the
// core rejects the whole config over a single unknown code. Without a
// database (offline first run) such cards are left out rather than failing
// the connection.
func (m *Manager) resolveGeo(graph types.ProTunGraph) types.ProTunGraph {
	copied := false
	for i, node := range graph.Nodes {
		file := geoFile(node.Kind)
		if file == "" || len(node.Items) == 0 {
			continue
		}
		if !copied {
			graph.Nodes = append([]types.ProTunNode(nil), graph.Nodes...)
			copied = true
		}
		ctx, cancel := context.WithTimeout(context.Background(), geoResolveTimeout)
		known, err := m.geo.Known(ctx, file)
		cancel()
		if err != nil {
			log.Printf("protun: %s unavailable, card %s skipped: %v", file, node.ID, err)
		}
		kept := make([]string, 0, len(node.Items))
		for _, item := range node.Items {
			entry := strings.ToLower(strings.TrimSpace(item))
			if m.geoEntryKnown(file, entry, known) {
				kept = append(kept, entry)
			} else if err == nil {
				log.Printf("protun: code %q not found in %s, skipped", item, file)
			}
		}
		graph.Nodes[i].Items = kept
	}
	return graph
}

// geoEntryKnown checks a card item against the database. geosite items may
// carry an attribute ("google@cn"): the core fails on an attribute that
// selects no domain, so it is checked as well.
func (m *Manager) geoEntryKnown(file, entry string, known map[string]bool) bool {
	code, attr, hasAttr := strings.Cut(entry, "@")
	if !known[code] {
		return false
	}
	if !hasAttr {
		return true
	}
	if file != geodata.FileSite || attr == "" {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), geoResolveTimeout)
	defer cancel()
	ok, err := m.geo.KnownSiteAttribute(ctx, code, attr)
	return err == nil && ok
}

// resolveSplitGeo keeps only the geosite:/geoip: entries of the Easy rules that
// the local databases know: the core rejects the whole config over a missing
// database or a single unknown code. A database that is not on disk yet is not
// waited for (on a phone the tunnel interface may already be up with no core
// behind it, so a download would hang the connect); its entries are left out
// this time and the file is fetched in the background for the next rebuild.
func (m *Manager) resolveSplitGeo(st types.SplitTunnelSettings) types.SplitTunnelSettings {
	filter := func(items []string, prefix, file string) []string {
		needs := false
		for _, it := range items {
			if strings.HasPrefix(strings.ToLower(strings.TrimSpace(it)), prefix) {
				needs = true
				break
			}
		}
		if !needs {
			return items
		}
		var known map[string]bool
		if m.geo.Present(file) {
			ctx, cancel := context.WithTimeout(context.Background(), geoResolveTimeout)
			set, err := m.geo.Known(ctx, file)
			cancel()
			if err != nil {
				log.Printf("routing: %s unreadable, %s rules skipped: %v", file, prefix, err)
			}
			known = set
		} else {
			log.Printf("routing: %s not downloaded yet, %s rules skipped for now", file, prefix)
			go func() {
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
				defer cancel()
				if _, err := m.geo.Known(ctx, file); err != nil {
					log.Printf("routing: download %s: %v", file, err)
				}
			}()
		}
		kept := make([]string, 0, len(items))
		for _, it := range items {
			entry := strings.ToLower(strings.TrimSpace(it))
			if code, ok := strings.CutPrefix(entry, prefix); ok {
				if known == nil || !m.geoEntryKnown(file, code, known) {
					continue
				}
			}
			kept = append(kept, it)
		}
		return kept
	}
	st.Domains = filter(st.Domains, "geosite:", geodata.FileSite)
	st.IPs = filter(st.IPs, "geoip:", geodata.FileIP)
	return st
}

// PrepareGeo downloads the databases the Easy rules refer to and that are not on
// disk yet, so the next connect can use them. It blocks; call it off the UI thread.
func (m *Manager) PrepareGeo(sites, ips bool) error {
	var errs []error
	for _, f := range []struct {
		want bool
		file string
	}{{sites, geodata.FileSite}, {ips, geodata.FileIP}} {
		if !f.want || m.geo.Present(f.file) {
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
		_, err := m.geo.Known(ctx, f.file)
		cancel()
		if err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// GeoSiteAttributes lists the attributes of a geosite category for the
// attribute picker of a ProTun card.
func (m *Manager) GeoSiteAttributes(code string) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	return m.geo.SiteAttributes(ctx, code)
}

// resolveDNSGeo drops geosite entries of DNS rules that the local database
// does not know, for the same reason as resolveGeo. Rules left without
// domains are dropped by the builder.
func (m *Manager) resolveDNSGeo(dns domainSettings.DNSSettings) domainSettings.DNSSettings {
	needs := false
	for _, rule := range dns.Rules {
		for _, d := range rule.Domains {
			if strings.HasPrefix(d, "geosite:") {
				needs = true
			}
		}
	}
	if !needs {
		return dns
	}
	ctx, cancel := context.WithTimeout(context.Background(), geoResolveTimeout)
	known, err := m.geo.Known(ctx, geodata.FileSite)
	cancel()
	if err != nil {
		log.Printf("dns: %s unavailable, geosite rules skipped: %v", geodata.FileSite, err)
	}
	rules := make([]domainSettings.DNSRule, 0, len(dns.Rules))
	for _, rule := range dns.Rules {
		domains := make([]string, 0, len(rule.Domains))
		for _, d := range rule.Domains {
			if entry, ok := strings.CutPrefix(d, "geosite:"); ok {
				if err != nil || !m.geoEntryKnown(geodata.FileSite, strings.ToLower(entry), known) {
					continue
				}
			}
			domains = append(domains, d)
		}
		rule.Domains = domains
		rules = append(rules, rule)
	}
	dns.Rules = rules
	return dns
}

// profileDNS returns the DNS section of the selected node's provider config
// when the user chose it over BEAM's DNS, nil otherwise.
func (m *Manager) profileDNS(dns domainSettings.DNSSettings, beamFile *infraBeam.BeamFile) map[string]interface{} {
	if ps := beamFile.Data.ProviderSettings; !dns.UseProfileDNS && (ps == nil || !ps.ProfileDNS) {
		return nil
	}
	node := beamFile.GetSelectedNode()
	if node == nil || len(node.DNS) == 0 {
		return nil
	}
	known := map[string]map[string]bool{}
	keep := func(file, entry string) bool {
		set, loaded := known[file]
		if !loaded {
			ctx, cancel := context.WithTimeout(context.Background(), geoResolveTimeout)
			var err error
			set, err = m.geo.Known(ctx, file)
			cancel()
			if err != nil {
				log.Printf("dns: %s unavailable, profile DNS geo entries skipped: %v", file, err)
				set = nil
			}
			known[file] = set
		}
		return set != nil && m.geoEntryKnown(file, entry, set)
	}
	return buildProfileDNS(node.DNS, keep)
}

// coreLogPath — файл, в который ядро пишет собственный лог. Имя фиксированное:
// диагностика должна лежать всегда по одному и тому же пути, иначе её невозможно
// попросить у пользователя или прочитать автоматически.
// SetCoreFactory wires the engine builder used for isolated (protocol) ping.
// It is the only way the profile package reaches a core, keeping it free of any
// direct xray import.
func (m *Manager) SetCoreFactory(factory coreapi.Factory) {
	m.mu.Lock()
	m.coreFactory = factory
	m.mu.Unlock()
}

func (m *Manager) coreLogPath() string {
	if m.paths.Data == "" {
		return ""
	}
	return filepath.Join(m.paths.Data, "logs", "xray-core.log")
}

func (m *Manager) GetStorage() *infraProfile.FileRepository {
	return m.storage
}

func (m *Manager) Load() error {
	if err := m.storage.Load(); err != nil {
		return err
	}
	m.storage.RefreshTransports(m.subscription.Parser().Parse)
	go m.syncAllMedia()
	return nil
}

func (m *Manager) GetProfiles() []types.ProfileSummary {
	profiles, _ := m.storage.GetAll()
	result := make([]types.ProfileSummary, len(profiles))
	for i, p := range profiles {
		result[i] = m.toSummary(p)
	}
	return result
}

func (m *Manager) toSummary(p *types.Profile) types.ProfileSummary {
	daysLeft := -1
	isExpired := false
	if !p.NeverExpires() {
		remaining := time.Until(p.ExpiresAt)
		if remaining <= 0 {
			isExpired = true
			daysLeft = 0
		} else {
			days := int(remaining.Hours() / 24)
			if days < 0 {
				days = 0
			}
			daysLeft = days
		}
	}

	var usedPercent float64
	if !p.IsUnlimited() && p.DataLimit > 0 {
		usedPercent = float64(p.DataUsed) / float64(p.DataLimit) * 100
		if usedPercent > 100 {
			usedPercent = 100
		}
	}

	summary := types.ProfileSummary{
		ID:                  p.ID,
		Name:                p.Name,
		Provider:            p.Provider,
		Announce:            p.Announce,
		SupportURL:          p.SupportURL,
		IconURL:             p.IconURL,
		CommunityURL:        p.CommunityURL,
		Branding:            p.Branding,
		ProTunLocked:        p.ProTunLocked,
		HideProvider:        p.HideProvider,
		ProviderSettings:    p.ProviderSettings,
		DataLimit:           p.DataLimit,
		DataUsed:            p.DataUsed,
		DaysLeft:            daysLeft,
		IsExpired:           isExpired,
		UsedPercent:         usedPercent,
		IsActive:            p.IsActive,
		HasSubscription:     p.URL != "",
		URL:                 p.URL,
		UpdateIntervalHours: p.UpdateIntervalHours,
		AutoRefreshDisabled: p.AutoRefreshDisabled,

		UpdateIntervalOverrideHours: p.UpdateIntervalOverrideHours,
	}
	m.localSummaryMedia(&summary)
	return summary
}

func (m *Manager) AddDataUsed(id string, delta int64) error {
	return m.storage.AddDataUsed(id, delta)
}

func (m *Manager) GetActiveProfile() *types.Profile {
	profile, _, _ := m.storage.GetActive()
	return profile
}

func (m *Manager) GetActiveNode() (*types.BeamNode, bool) {
	_, beamFile, err := m.storage.GetActive()
	if err != nil || beamFile == nil {
		return nil, false
	}
	for i := range beamFile.Data.Nodes {
		if beamFile.Data.Nodes[i].ID == beamFile.Data.SelectedID {
			return &beamFile.Data.Nodes[i], true
		}
	}
	return nil, false
}

// effectiveLogLevel выводит уровень логов ядра из настроек: явно выключенные
// логи — "off", пустое поле старых settings.json — "info".
func effectiveLogLevel(s *domainSettings.Settings) string {
	if s.DisableCoreLogging {
		return "off"
	}
	switch s.LogLevel {
	case "off", "error", "info", "debug":
		return s.LogLevel
	default:
		return "info"
	}
}

func (m *Manager) GetActiveConfig() json.RawMessage {
	activeProfile, beamFile, _ := m.storage.GetActive()
	if beamFile == nil {
		return nil
	}
	activeID := ""
	if activeProfile != nil {
		activeID = activeProfile.ID
	}

	settings := m.settingsRepo.Get()

	// Два слоя ProTun: слой активного профиля (или провайдерский
	// пресет) строго выше общих правил.
	proTunGraph := settings.ProTunGraph
	profileLayer := effectiveProfileLayer(settings, activeID, beamFile)
	var servers []serverTarget
	if settings.RoutingMode == "pro" {
		proTunGraph = m.resolveGeo(proTunGraph)
		profileLayer = m.resolveGeo(profileLayer)
		servers = m.serverTargets(activeID, beamFile, profileLayer, proTunGraph)
	}

	builder := NewXrayConfigBuilder(
		settings.Connection,
		m.resolveSplitGeo(settings.SplitTunnel),
	).WithProTunGraph(settings.RoutingMode, proTunGraph).
		WithProTunProfileLayer(profileLayer).
		withServerTargets(servers).
		WithCore(withProviderCore(settings.Core, beamFile.Data.ProviderSettings)).
		WithDNS(m.resolveDNSGeo(settings.DNS)).
		WithProfileDNS(m.profileDNS(settings.DNS, beamFile)).
		WithLogPath(m.coreLogPath()).
		WithExtendedLogs(settings.ExtendedLogs).
		WithLogLevel(effectiveLogLevel(settings))
	expander := m.newEntryExpander(activeID, beamFile)
	generated := builder.BuildFromBeam(expander.beamFile(activeID, beamFile))
	if generated == nil {
		return nil
	}

	m.setUnsupportedNodes(generated.UnsupportedNodes)

	if generated.Config == nil {
		return nil
	}

	m.mu.Lock()
	m.routes = generated.Routes
	m.proxyTag = generated.ProxyTag
	m.mu.Unlock()

	configBytes, _ := json.Marshal(generated.Config)
	return configBytes
}

func (m *Manager) setUnsupportedNodes(nodes map[string]string) {
	m.mu.Lock()
	m.unsupportedNodes = nodes
	m.mu.Unlock()
}

// GetActiveProTunPreset возвращает провайдерский пресет маршрутизации
// активного профиля и признак принудительного лока (второе значение true
// только когда пресет есть И залочен).
func (m *Manager) GetActiveProTunPreset() (*types.ProTunGraph, bool) {
	profile, beamFile, err := m.storage.GetActive()
	if err != nil || beamFile == nil || beamFile.Data.ProTunPreset == nil {
		return nil, false
	}
	preset := *beamFile.Data.ProTunPreset
	if profile != nil {
		preset = presetForProfile(preset, profile.ID)
	}
	return &preset, beamFile.Data.ProTunLocked
}

func (m *Manager) GetUnsupportedNodes() map[string]string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	result := make(map[string]string, len(m.unsupportedNodes))
	for id, reason := range m.unsupportedNodes {
		result[id] = reason
	}
	return result
}

// GetRoutePlan returns the tunnel-side routing plan of the last generated
// config (per-app inbound tags and bypass/block decisions).
func (m *Manager) GetRoutePlan() coreapi.RoutePlan {
	m.mu.RLock()
	defer m.mu.RUnlock()
	plan := coreapi.RoutePlan{
		Apps:          make(map[string]coreapi.AppRoute, len(m.routes.Apps)),
		FinalOutbound: m.routes.FinalOutbound,
		DefaultBypass: m.routes.DefaultBypass,
		DisableBypass: m.routes.DisableBypass,
	}
	if m.routes.DefaultBypassNetworks != nil {
		plan.DefaultBypassNetworks = make(map[string]bool, len(m.routes.DefaultBypassNetworks))
		for network, bypass := range m.routes.DefaultBypassNetworks {
			plan.DefaultBypassNetworks[network] = bypass
		}
	}
	for app, route := range m.routes.Apps {
		plan.Apps[app] = route
	}
	return plan
}

func (m *Manager) GetProxyTag() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.proxyTag
}

func (m *Manager) SetActive(id string) error {
	return m.storage.SetActive(id)
}

func (m *Manager) Delete(id string) error {
	if err := m.storage.Delete(id); err != nil {
		return err
	}
	go m.pruneMedia()
	return nil
}

func (m *Manager) ImportFromURL(rawURL string) (*types.Profile, error) {
	if m.subscription.Parser().IsProtocolLink(rawURL) {
		return m.importProtocolLink(rawURL)
	}

	body, header, err := m.subscription.Fetcher().Fetch(rawURL, m.buildFetchHeaders())
	if err != nil {
		return nil, err
	}

	beamFile, err := m.subscription.BuildBeamFromSubscription(body, rawURL, header)
	if err != nil {
		return nil, err
	}
	followProviderMove(beamFile)

	return m.addWithMedia(beamFile)
}

func (m *Manager) addWithMedia(beamFile *infraBeam.BeamFile) (*types.Profile, error) {
	p, err := m.storage.Add(beamFile)
	if err == nil && p != nil {
		m.syncProfileMedia(p.ID, false)
	}
	return p, err
}

func (m *Manager) ImportFromBeam(data []byte) (*types.Profile, error) {
	beamFile, err := infraBeam.ParseData(data)
	if err != nil {
		return nil, err
	}
	if err := m.subscription.ExpandLinks(beamFile); err != nil {
		return nil, err
	}
	if len(beamFile.Data.Nodes) == 0 {
		return nil, errors.New("the profile has no servers")
	}
	return m.addWithMedia(beamFile)
}

func (m *Manager) RefreshProfile(id string) error {
	profile, err := m.storage.GetByID(id)
	if err != nil {
		return err
	}
	if profile.URL == "" {
		return ErrProfileNotFound
	}

	oldBeam, ok := m.storage.GetBeam(id)

	body, header, err := m.subscription.Fetcher().Fetch(profile.URL, m.buildFetchHeaders())
	if err != nil {
		fallback := ""
		if ok && oldBeam.Data.ProviderSettings != nil {
			fallback = oldBeam.Data.ProviderSettings.FallbackURL
		}
		if fallback == "" || fallback == profile.URL {
			return err
		}
		log.Printf("profile: %s unreachable (%v), trying the provider fallback URL", id, err)
		var fallbackErr error
		if body, header, fallbackErr = m.subscription.Fetcher().Fetch(fallback, m.buildFetchHeaders()); fallbackErr != nil {
			return err
		}
	}

	newBeam, err := m.subscription.BuildBeamFromSubscription(body, profile.URL, header)
	if err != nil {
		return err
	}
	followProviderMove(newBeam)
	if ok {
		carryOverNodeEdits(oldBeam, newBeam)
	}
	if ok && oldBeam.Data.SelectedID != "" {
		for i := range oldBeam.Data.Nodes {
			oldNode := &oldBeam.Data.Nodes[i]
			if oldNode.ID != oldBeam.Data.SelectedID {
				continue
			}
			anchor := nodeAnchor(oldNode)
			for j := range newBeam.Data.Nodes {
				if nodeAnchor(&newBeam.Data.Nodes[j]) == anchor {
					newBeam.Data.SelectedID = newBeam.Data.Nodes[j].ID
					break
				}
			}
			break
		}
	}
	if ok {
		newBeam.Data.AutoRefreshDisabled = oldBeam.Data.AutoRefreshDisabled
		newBeam.Data.UpdateIntervalOverrideHours = oldBeam.Data.UpdateIntervalOverrideHours
		if newBeam.Data.UpdateIntervalHours <= 0 {
			newBeam.Data.UpdateIntervalHours = oldBeam.Data.UpdateIntervalHours
		}
	}

	if newBeam.Data.SelectedID == "" && len(newBeam.Data.Nodes) > 0 {
		newBeam.Data.SelectedID = newBeam.Data.Nodes[0].ID
	}

	if err := m.storage.UpdateBeam(id, newBeam); err != nil {
		return err
	}
	m.syncProfileMedia(id, true)
	return nil
}

func (m *Manager) ExportBeam(id string) ([]byte, error) {
	return m.storage.ExportBeam(id)
}

func (m *Manager) ExportRawLinks(id string) ([]types.ExportedLink, error) {
	beamFile, ok := m.storage.GetBeam(id)
	if !ok {
		return nil, ErrProfileNotFound
	}
	links := make([]types.ExportedLink, 0, len(beamFile.Data.Nodes))
	for i := range beamFile.Data.Nodes {
		node := &beamFile.Data.Nodes[i]
		if node.RawLink == "" || node.IsEdited() {
			continue
		}
		links = append(links, types.ExportedLink{Name: node.DisplayName(), Link: node.RawLink})
	}
	return links, nil
}

func (m *Manager) GetProfileNodes(id string) (*types.ProfileNodesResponse, error) {
	beam, ok := m.storage.GetBeam(id)
	if !ok {
		return nil, ErrProfileNotFound
	}

	unsupported := unsupportedNodeIDs(beam, m.newEntryExpander(id, beam), id)
	grouped := dropNodes(beam.GetNodesGrouped(), unsupported)

	m.setUnsupportedNodes(unsupported)

	return &types.ProfileNodesResponse{
		Categories: grouped,
		SelectedID: beam.Data.SelectedID,
		TotalNodes: len(beam.Data.Nodes) - len(unsupported),
	}, nil
}

// unsupportedNodeIDs reports the nodes the core cannot run, mapped to the
// reason, so they can be hidden from the node list.
func unsupportedNodeIDs(beam *infraBeam.BeamFile, entries *entryExpander, profileID string) map[string]string {
	unsupported := make(map[string]string)
	for i := range beam.Data.Nodes {
		node := &beam.Data.Nodes[i]
		// The list judges the node itself. A broken or unsupported chain must
		// not hide it: it is where the user fixes the chain, and connecting
		// still fails with the reason.
		outbound := node.EffectiveOutbound()
		if !usableOutbound(outbound) {
			unsupported[node.ID] = "node has no usable server address"
			continue
		}
		if entryRefOf(outbound) != nil {
			expanded := entries.node(profileID, *node)
			if _, err := convertOutbound(expanded.EffectiveOutbound()); err != nil {
				log.Printf("chain: node %q (%s): %v", node.DisplayName(), node.ID, err)
			}
			outbound = withoutEntry(outbound)
		}
		if _, err := convertOutbound(outbound); err != nil {
			unsupported[node.ID] = err.Error()
		}
	}
	return unsupported
}

// dropNodes removes the given nodes and any category left empty.
func dropNodes(categories []types.CategoryWithNodes, drop map[string]string) []types.CategoryWithNodes {
	if len(drop) == 0 {
		return categories
	}

	filtered := make([]types.CategoryWithNodes, 0, len(categories))
	for _, category := range categories {
		kept := make([]types.NodeInfo, 0, len(category.Nodes))
		for _, node := range category.Nodes {
			if _, hidden := drop[node.ID]; hidden {
				continue
			}
			kept = append(kept, node)
		}
		if len(kept) == 0 {
			continue
		}
		category.Nodes = kept
		filtered = append(filtered, category)
	}
	return filtered
}

func (m *Manager) SelectProfileNode(profileID, nodeID string) error {
	return m.storage.SelectNode(profileID, nodeID)
}

func nodeAnchor(n *types.BeamNode) string {
	if n.BaseName != "" {
		return n.BaseName
	}
	return n.Name
}

func carryOverNodeEdits(oldBeam, newBeam *infraBeam.BeamFile) {
	edited := make(map[string]*types.BeamNode, len(oldBeam.Data.Nodes))
	for i := range oldBeam.Data.Nodes {
		oldNode := &oldBeam.Data.Nodes[i]
		if oldNode.IsEdited() {
			edited[nodeAnchor(oldNode)] = oldNode
		}
	}
	if len(edited) == 0 {
		return
	}

	for i := range newBeam.Data.Nodes {
		newNode := &newBeam.Data.Nodes[i]
		oldNode, ok := edited[nodeAnchor(newNode)]
		if !ok {
			continue
		}

		newNode.BaseName = newNode.Name
		newNode.NameOverride = oldNode.NameOverride
		newNode.Overrides = oldNode.Overrides
		newNode.PinnedOutbound = oldNode.PinnedOutbound
	}
}

func (m *Manager) GetNodeConfig(profileID, nodeID string) (*types.NodeConfig, error) {
	beam, ok := m.storage.GetBeam(profileID)
	if !ok {
		return nil, ErrProfileNotFound
	}

	for i := range beam.Data.Nodes {
		node := &beam.Data.Nodes[i]
		if node.ID != nodeID {
			continue
		}

		overrides := make(map[string]interface{}, len(node.Overrides))
		for key, value := range node.Overrides {
			overrides[key] = value
		}

		return &types.NodeConfig{
			NodeID:          node.ID,
			Name:            node.DisplayName(),
			BaseName:        nodeAnchor(node),
			Type:            node.Type,
			Outbound:        node.EffectiveOutbound(),
			Original:        types.ApplyOverrides(node.Outbound, nil),
			Overrides:       overrides,
			IsEdited:        node.IsEdited(),
			IsPinned:        node.IsPinned(),
			HasSubscription: beam.Data.URL != "",
			RawLinkStale:    node.RawLink != "" && node.IsEdited() && editsProtocol(node),
		}, nil
	}

	return nil, ErrNodeNotFound
}

// editsProtocol: правки ноды меняют что-то кроме BEAM-опций (beam.*), которые
// в ссылку не входят и не делают её устаревшей.
func editsProtocol(node *types.BeamNode) bool {
	if node.IsPinned() {
		return true
	}
	for key := range node.Overrides {
		if key != nodeOptionsKey && !strings.HasPrefix(key, nodeOptionsKey+".") {
			return true
		}
	}
	return false
}

func (m *Manager) UpdateNodeConfig(profileID, nodeID string, update types.NodeConfigUpdate) (*types.NodeConfig, error) {
	if err := m.storage.UpdateNodeConfig(profileID, nodeID, update); err != nil {
		return nil, err
	}
	return m.GetNodeConfig(profileID, nodeID)
}

func (m *Manager) ImportRawConfig(name string, configJSON string) (*types.Profile, error) {
	if name == "" {
		name = "Custom Config"
	}
	beamFile := infraBeam.New(name, "RAW", "")

	if subscription.LooksLikeXrayConfig(configJSON) {
		result, err := subscription.ParseXrayConfig([]byte(configJSON))
		if err != nil {
			return nil, err
		}
		beamFile.Data.Categories = result.Categories
		beamFile.Data.Nodes = result.Nodes
		return m.storage.Add(beamFile)
	}

	var rawConfig map[string]interface{}
	if err := json.Unmarshal([]byte(configJSON), &rawConfig); err != nil {
		return nil, fmt.Errorf("invalid JSON: %w", err)
	}
	outbounds, ok := rawConfig["outbounds"].([]interface{})
	if !ok || len(outbounds) == 0 {
		return nil, errors.New("'outbounds' must be a non-empty array")
	}

	beamFile.Data.Categories = append(beamFile.Data.Categories, types.Category{
		ID:    "default",
		Name:  "Серверы",
		Order: 0,
	})
	for i, ob := range subscription.SingBoxProxies(outbounds) {
		tag, _ := ob["tag"].(string)
		typ, _ := ob["type"].(string)
		beamFile.AddNode(fmt.Sprintf("node_%d", i+1), "default", tag, typ, ob)
	}
	if len(beamFile.Data.Nodes) == 0 {
		return nil, errors.New("no proxy nodes found in the config")
	}
	return m.storage.Add(beamFile)
}

func (m *Manager) importProtocolLink(link string) (*types.Profile, error) {
	outbound, err := m.subscription.Parser().Parse(link)
	if err != nil {
		return nil, err
	}

	name := "VPN Server"
	if tag, ok := outbound["tag"].(string); ok && tag != "" {
		name = tag
	}

	provider := "Custom"
	if server, ok := outbound["server"].(string); ok {
		provider = server
	}

	nodeType, _ := outbound["type"].(string)
	beamFile := infraBeam.New(name, provider, "")
	beamFile.Data.Categories = append(beamFile.Data.Categories, types.Category{
		ID:    "default",
		Name:  "Серверы",
		Order: 0,
	})
	beamFile.AddNode("node_1", "default", name, nodeType, outbound)
	beamFile.Data.Nodes[len(beamFile.Data.Nodes)-1].RawLink = link

	return m.storage.Add(beamFile)
}
