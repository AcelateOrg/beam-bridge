package profile

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"

	"beam-bridge/core/coreapi"
	domainSettings "beam-bridge/core/domain/settings"
	corePaths "beam-bridge/core/paths"
	"beam-bridge/core/platform"
	"beam-bridge/core/probe"
	"beam-bridge/core/types"
)

const isolatedPingStartBudget = 10 * time.Second

// pingConcurrency bounds parallel probes. Each probe keeps one connection
// and runs a few sequential exchanges, so this is cheap for the core.
const pingConcurrency = 10

type PingResult struct {
	NodeID  string `json:"nodeId"`
	Latency int64  `json:"latency"`
	Status  string `json:"status"`
}

type NodePinger struct {
	timeout time.Duration
	paths   corePaths.Paths
	// factory builds a throwaway core for isolated (protocol) ping. Nil when
	// no engine was wired, in which case isolated ping is unavailable and the
	// caller falls back to a plain TCP probe.
	factory coreapi.Factory
	// direct is the physical-interface route of the live session, nil when
	// no session is up. While the tunnel owns the default route every probe
	// must leave through it, otherwise it measures the tunnel plus the node.
	direct coreapi.DirectRoute
	// core carries fragmentation settings: a protocol probe must take the
	// same path as real traffic, or a node reachable only with
	// fragmentation would always time out.
	core domainSettings.CoreSettings
	// observe, when set, receives each result as soon as it is measured.
	observe func(PingResult)
}

func (p *NodePinger) emit(r PingResult) {
	if p.observe != nil {
		p.observe(r)
	}
}

func NewNodePinger(timeout time.Duration, paths corePaths.Paths, factory coreapi.Factory, direct coreapi.DirectRoute, core domainSettings.CoreSettings) *NodePinger {
	if timeout == 0 {
		timeout = 5 * time.Second
	}
	return &NodePinger{timeout: timeout, paths: paths, factory: factory, direct: direct, core: core}
}

func (p *NodePinger) dial() probe.DialFunc {
	if p.direct != nil {
		return p.direct.DialDirect
	}
	return probe.PlainDial
}

func (p *NodePinger) directInterface() string {
	if p.direct == nil {
		return ""
	}
	return p.direct.DirectInterface()
}

func (p *NodePinger) PingNodeTCP(ctx context.Context, node types.BeamNode) PingResult {
	result := PingResult{
		NodeID:  node.ID,
		Latency: -1,
		Status:  "error",
	}

	server, _ := node.Outbound["server"].(string)
	port := parsePort(node.Outbound["server_port"])

	if server == "" || port <= 0 || port > 65535 {
		result.Status = "invalid"
		return result
	}

	address := net.JoinHostPort(server, strconv.Itoa(port))

	dialCtx, dialCancel := context.WithTimeout(ctx, p.timeout)
	defer dialCancel()

	ms, err := probe.TCP(dialCtx, p.dial(), address)
	if err != nil {
		switch {
		case ctx.Err() == context.Canceled:
			result.Status = "cancelled"
		case dialCtx.Err() == context.DeadlineExceeded:
			result.Status = "timeout"
		default:
			result.Status = "error"
		}
		return result
	}
	result.Latency = ms
	result.Status = "ok"
	return result
}

func parsePort(v interface{}) int {
	switch val := v.(type) {
	case float64:
		return int(val)
	case int:
		return val
	case int64:
		return int(val)
	case string:
		p, err := strconv.Atoi(val)
		if err == nil {
			return p
		}
	}
	return 0
}

func (p *NodePinger) PingNodesTCP(ctx context.Context, nodes []types.BeamNode, concurrency int) []PingResult {
	if concurrency <= 0 {
		concurrency = pingConcurrency
	}

	results := make([]PingResult, len(nodes))
	var wg sync.WaitGroup
	sem := make(chan struct{}, concurrency)

	for i, node := range nodes {
		wg.Add(1)
		go func(idx int, n types.BeamNode) {
			defer wg.Done()
			defer func() {
				if r := recover(); r != nil {
					platform.LogCrashEvent("panic in PingNodeTCP(%s): %v", n.ID, r)
					results[idx] = PingResult{NodeID: n.ID, Latency: -1, Status: "error"}
					p.emit(results[idx])
				}
			}()
			sem <- struct{}{}
			defer func() { <-sem }()
			results[idx] = p.PingNodeTCP(ctx, n)
			p.emit(results[idx])
		}(i, node)
	}

	wg.Wait()
	return results
}

// buildIsolatedPingConfig builds a throwaway config with one outbound per
// node. Probes pick their outbound by tag directly, so no routing rules are
// needed. iface, when set, pins every outbound to the physical interface so
// probes taken while the tunnel is up do not travel through it.
func buildIsolatedPingConfig(nodes []types.BeamNode, iface string, core domainSettings.CoreSettings) (json.RawMessage, map[string]string) {
	unsupported := make(map[string]string)
	outbounds := make([]interface{}, 0, len(nodes)+2)
	tuning := nodeTuning{core: core}
	fragmentUsed := false

	for i := range nodes {
		node := nodes[i]
		source := node.EffectiveOutbound()
		if !usableOutbound(source) {
			unsupported[node.ID] = "node has no usable server address"
			continue
		}
		converted, err := convertOutbound(source)
		if err != nil {
			unsupported[node.ID] = err.Error()
			continue
		}
		converted["tag"] = node.ID
		chain := takeChain(converted)
		hops := linkChain(converted, node.ID, chain)
		if tuning.apply(source, converted, chain, false) {
			fragmentUsed = true
		}
		if iface != "" {
			bindInterface(lastHop(converted, chain), iface)
		}
		outbounds = append(outbounds, converted)
		outbounds = append(outbounds, hops...)
	}

	if len(outbounds) == 0 {
		return nil, unsupported
	}

	if fragmentUsed {
		// Nodes dial through this outbound, so it is the one that has to
		// leave via the physical interface.
		fragment := tuning.fragmentOutbound()
		if iface != "" {
			bindInterface(fragment, iface)
		}
		outbounds = append(outbounds, fragment)
	}

	outbounds = append(outbounds, map[string]interface{}{
		"tag":      outboundDirect,
		"protocol": "freedom",
	})

	config := map[string]interface{}{
		"log":       map[string]interface{}{"loglevel": "none"},
		"inbounds":  []interface{}{},
		"outbounds": outbounds,
	}

	encoded, err := json.Marshal(config)
	if err != nil {
		return nil, unsupported
	}
	return encoded, unsupported
}

// bindInterface sets streamSettings.sockopt.interface on an outbound.
func bindInterface(outbound map[string]interface{}, iface string) {
	stream, ok := outbound["streamSettings"].(map[string]interface{})
	if !ok {
		stream = map[string]interface{}{}
		outbound["streamSettings"] = stream
	}
	sockopt, ok := stream["sockopt"].(map[string]interface{})
	if !ok {
		sockopt = map[string]interface{}{}
		stream["sockopt"] = sockopt
	}
	sockopt["interface"] = iface
}

func (p *NodePinger) PingNodesIsolated(ctx context.Context, nodes []types.BeamNode, timeout time.Duration) ([]PingResult, error) {
	config, unsupported := buildIsolatedPingConfig(nodes, p.directInterface(), p.core)
	if config == nil {
		return nil, fmt.Errorf("no node can be measured by this core (%d rejected)", len(unsupported))
	}

	if p.factory == nil {
		return nil, fmt.Errorf("isolated ping unavailable: no core factory wired")
	}
	instance := p.factory(coreapi.Options{Paths: p.paths})

	startCtx, startCancel := context.WithTimeout(ctx, isolatedPingStartBudget)
	defer startCancel()
	if err := instance.Start(startCtx, config); err != nil {
		return nil, err
	}
	defer instance.Stop()

	if timeout <= 0 {
		timeout = 5 * time.Second
	}

	results := make([]PingResult, len(nodes))
	var wg sync.WaitGroup
	sem := make(chan struct{}, pingConcurrency)

	for i, node := range nodes {
		if _, dropped := unsupported[node.ID]; dropped {
			results[i] = PingResult{NodeID: node.ID, Latency: -1, Status: "invalid"}
			p.emit(results[i])
			continue
		}
		wg.Add(1)
		go func(idx int, n types.BeamNode) {
			defer wg.Done()
			defer func() {
				if r := recover(); r != nil {
					platform.LogCrashEvent("panic in isolated ping(%s): %v", n.ID, r)
					results[idx] = PingResult{NodeID: n.ID, Latency: -1, Status: "error"}
					p.emit(results[idx])
				}
			}()
			sem <- struct{}{}
			defer func() { <-sem }()
			results[idx] = delayResult(ctx, instance.Delay, n.ID, timeout)
			p.emit(results[idx])
		}(i, node)
	}

	wg.Wait()
	return results, nil
}

type delayProbe func(ctx context.Context, tag string, timeout time.Duration) (int64, error)

func delayResult(ctx context.Context, probe delayProbe, nodeID string, timeout time.Duration) PingResult {
	latency, err := probe(ctx, nodeID, timeout)
	if err != nil || latency <= 0 {
		return PingResult{NodeID: nodeID, Latency: -1, Status: "timeout"}
	}
	return PingResult{NodeID: nodeID, Latency: latency, Status: "ok"}
}

func (m *Manager) SetCore(core coreapi.Core) {
	m.mu.Lock()
	m.core = core
	m.mu.Unlock()
}

// SetPingObserver registers a callback for every finished ping probe. It is
// called from the probing goroutines, so it must not block.
func (m *Manager) SetPingObserver(observe func(PingResult)) {
	m.mu.Lock()
	m.pingObserver = observe
	m.mu.Unlock()
}

func (m *Manager) pingObserverFn() func(PingResult) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.pingObserver
}

func (m *Manager) liveCore() coreapi.Core {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.core
}

func (m *Manager) PingProfileNodes(profileID string, nodeIDs []string, timeout time.Duration, useLiveCore bool) ([]PingResult, error) {
	return m.PingProfileNodesObserved(profileID, nodeIDs, timeout, useLiveCore, nil)
}

// PingProfileNodesObserved is PingProfileNodes that also hands every result to
// observe as soon as it is measured, next to the manager-wide observer, so a
// caller can show results one by one without seeing other callers' probes.
// observe is called from the probing goroutines and must not block.
func (m *Manager) PingProfileNodesObserved(profileID string, nodeIDs []string, timeout time.Duration, useLiveCore bool, observe func(PingResult)) ([]PingResult, error) {
	beam, ok := m.storage.GetBeam(profileID)
	if !ok {
		return nil, ErrProfileNotFound
	}
	nodes := selectNodesByID(beam.Data.Nodes, nodeIDs)
	if len(nodes) == 0 {
		return []PingResult{}, nil
	}
	return m.pingNodes(m.newEntryExpander(profileID, beam).nodes(profileID, nodes), beam.Data.ProviderSettings, timeout, useLiveCore, observe)
}

func (m *Manager) PingCategoryNodes(profileID string, categoryID string, timeout time.Duration, useLiveCore bool) ([]PingResult, error) {
	beam, ok := m.storage.GetBeam(profileID)
	if !ok {
		return nil, ErrProfileNotFound
	}

	var nodes []types.BeamNode
	for _, n := range beam.Data.Nodes {
		if n.CategoryID == categoryID {
			nodes = append(nodes, n)
		}
	}
	if len(nodes) == 0 {
		return []PingResult{}, nil
	}
	return m.pingNodes(m.newEntryExpander(profileID, beam).nodes(profileID, nodes), beam.Data.ProviderSettings, timeout, useLiveCore, nil)
}

func (m *Manager) pingNodes(nodes []types.BeamNode, provider *types.ProviderSettings, timeout time.Duration, useLiveCore bool, observe func(PingResult)) ([]PingResult, error) {
	core := m.liveCore()
	var direct coreapi.DirectRoute
	if core != nil && core.Running() {
		direct, _ = core.(coreapi.DirectRoute)
	}
	settings := m.settingsRepo.Get()
	pinger := NewNodePinger(timeout, m.paths, m.coreFactory, direct, withProviderCore(settings.Core, provider))
	pinger.observe = joinObservers(m.pingObserverFn(), observe)

	mode := settings.Ping.NodeMode

	if mode == "tcp" {
		tcpCtx, tcpCancel := context.WithTimeout(context.Background(), timeout+2*time.Second)
		defer tcpCancel()
		return pinger.PingNodesTCP(tcpCtx, nodes, pingConcurrency), nil
	}

	// The live core already holds every node of the active profile as an
	// outbound tagged with the node ID; probing through it costs no extra
	// core and measures exactly the path traffic would take.
	if useLiveCore && core != nil && core.Running() {
		ctx, cancel := context.WithTimeout(context.Background(), timeout+5*time.Second)
		defer cancel()

		results := make([]PingResult, len(nodes))
		var wg sync.WaitGroup
		sem := make(chan struct{}, pingConcurrency)

		for i, node := range nodes {
			wg.Add(1)
			go func(idx int, n types.BeamNode) {
				defer wg.Done()
				defer func() {
					if r := recover(); r != nil {
						platform.LogCrashEvent("panic in live ping(%s): %v", n.ID, r)
						results[idx] = PingResult{NodeID: n.ID, Latency: -1, Status: "error"}
						pinger.emit(results[idx])
					}
				}()
				sem <- struct{}{}
				defer func() { <-sem }()
				results[idx] = delayResult(ctx, core.Delay, n.ID, timeout)
				pinger.emit(results[idx])
			}(i, node)
		}
		wg.Wait()
		return results, nil
	}

	isolatedCtx, isolatedCancel := context.WithTimeout(context.Background(), timeout+5*time.Second+isolatedPingStartBudget)
	defer isolatedCancel()
	results, err := pinger.PingNodesIsolated(isolatedCtx, nodes, timeout)
	if err == nil {
		return results, nil
	}

	if mode == "protocol" {
		return nil, err
	}

	tcpCtx, tcpCancel := context.WithTimeout(context.Background(), timeout+2*time.Second)
	defer tcpCancel()
	return pinger.PingNodesTCP(tcpCtx, nodes, pingConcurrency), nil
}

func joinObservers(a, b func(PingResult)) func(PingResult) {
	switch {
	case a == nil:
		return b
	case b == nil:
		return a
	}
	return func(r PingResult) {
		a(r)
		b(r)
	}
}

func selectNodesByID(nodes []types.BeamNode, nodeIDs []string) []types.BeamNode {
	if len(nodeIDs) == 0 {
		return nodes
	}

	byID := make(map[string]types.BeamNode, len(nodes))
	for _, node := range nodes {
		byID[node.ID] = node
	}

	selected := make([]types.BeamNode, 0, len(nodeIDs))
	for _, nodeID := range nodeIDs {
		if node, ok := byID[nodeID]; ok {
			selected = append(selected, node)
		}
	}
	return selected
}
