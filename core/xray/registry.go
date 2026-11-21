package xray

import (
	"io"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"beam-bridge/core/coreapi"
	"beam-tun"
)

// Route classes of the flow accounting.
const (
	RouteProxy  = "proxy"
	RouteDirect = "direct"
	RouteBlock  = "block"
	RouteDNS    = "dns"
)

// Why a route was taken (Connection.RuleKind).
const (
	RuleKindApp     = "app"
	RuleKindRules   = "rules"
	RuleKindDefault = "default"
	RuleKindLAN     = "lan"
	RuleKindDNS     = "dns"
)

const (
	// historyWindow is how long closed flows stay visible: short requests
	// live for a fraction of a second and would otherwise never be seen.
	historyWindow = 2 * time.Minute
	historyLimit  = 500
)

// Flow is one tracked tunnel flow. Its byte counters are updated live by
// the relay, so long connections are accounted for while they run, not only
// once they close.
type Flow struct {
	registry *Registry
	id       uint64

	up   atomic.Int64
	down atomic.Int64

	// Guarded by Registry.mu.
	entry        *flowEntry
	key          flowKey
	reportedUp   int64
	reportedDown int64
	closer       func()

	once sync.Once
}

type flowKey struct {
	process string
	route   string
}

type flowTotals struct {
	up      int64
	down    int64
	blocked int64
}

type flowEntry struct {
	connection coreapi.Connection
	flow       *Flow
}

// TrackInfo is what the tunnel knows about a flow when it opens.
type TrackInfo struct {
	Outbound string
	Route    string
	RuleKind string
	Domain   string
}

type Registry struct {
	mu     sync.RWMutex
	flows  map[uint64]*flowEntry
	lastID atomic.Uint64

	// pending is traffic of closed flows (and blocked flow counts) not yet
	// drained by the accounting.
	pending map[flowKey]*flowTotals

	// history holds recently closed flows, oldest first.
	history []coreapi.Connection
}

func NewRegistry() *Registry {
	return &Registry{
		flows:   make(map[uint64]*flowEntry),
		pending: make(map[flowKey]*flowTotals),
	}
}

// Track registers a live flow. Close must be called once it ends.
func (r *Registry) Track(meta tun.Metadata, info TrackInfo) *Flow {
	id := r.lastID.Add(1)
	flow := &Flow{registry: r, id: id, key: flowKey{process: meta.ProcessPath, route: accountingRoute(info.Route)}}

	entry := &flowEntry{
		flow: flow,
		connection: coreapi.Connection{
			ID:          strconv.FormatUint(id, 10),
			Network:     meta.Network,
			Host:        meta.Destination.Addr().Unmap().String(),
			Destination: meta.Destination.String(),
			Outbound:    info.Outbound,
			ProcessPath: meta.ProcessPath,
			Start:       time.Now(),
			Domain:      info.Domain,
			Route:       info.Route,
			RuleKind:    info.RuleKind,
		},
	}
	flow.entry = entry

	r.mu.Lock()
	r.flows[id] = entry
	r.mu.Unlock()
	return flow
}

// accountingRoute folds the route classes into what the statistics count.
func accountingRoute(route string) string {
	switch route {
	case RouteDirect, RouteBlock:
		return route
	default:
		return RouteProxy
	}
}

// Blocked records a flow dropped by the routing rules: it is counted and
// shown among the recent connections.
func (r *Registry) Blocked(meta tun.Metadata, info TrackInfo) {
	now := time.Now()
	id := r.lastID.Add(1)
	connection := coreapi.Connection{
		ID:          strconv.FormatUint(id, 10),
		Network:     meta.Network,
		Host:        meta.Destination.Addr().Unmap().String(),
		Destination: meta.Destination.String(),
		Outbound:    "block",
		ProcessPath: meta.ProcessPath,
		Start:       now,
		End:         now,
		Domain:      info.Domain,
		Route:       RouteBlock,
		RuleKind:    info.RuleKind,
	}
	r.mu.Lock()
	r.totalsLocked(flowKey{process: meta.ProcessPath, route: RouteBlock}).blocked++
	r.rememberLocked(connection, now)
	r.mu.Unlock()
}

func (r *Registry) totalsLocked(key flowKey) *flowTotals {
	totals := r.pending[key]
	if totals == nil {
		totals = &flowTotals{}
		r.pending[key] = totals
	}
	return totals
}

// rememberLocked appends a closed flow to the history and drops what fell
// out of the window.
func (r *Registry) rememberLocked(connection coreapi.Connection, now time.Time) {
	r.history = append(r.history, connection)
	r.pruneHistoryLocked(now)
}

func (r *Registry) pruneHistoryLocked(now time.Time) {
	cutoff := now.Add(-historyWindow)
	drop := 0
	for drop < len(r.history) && (r.history[drop].End.Before(cutoff) || len(r.history)-drop > historyLimit) {
		drop++
	}
	if drop > 0 {
		r.history = append(r.history[:0:0], r.history[drop:]...)
	}
}

// foldLocked moves the not yet drained bytes of a flow into pending under
// its current key.
func (r *Registry) foldLocked(f *Flow) {
	up := f.up.Load() - f.reportedUp
	down := f.down.Load() - f.reportedDown
	if up <= 0 && down <= 0 {
		return
	}
	f.reportedUp += up
	f.reportedDown += down
	totals := r.totalsLocked(f.key)
	totals.up += up
	totals.down += down
}

func (f *Flow) AddUp(n int64) {
	if f != nil && n > 0 {
		f.up.Add(n)
	}
}

func (f *Flow) AddDown(n int64) {
	if f != nil && n > 0 {
		f.down.Add(n)
	}
}

// SetCloser installs what tears the flow down when the user closes it.
func (f *Flow) SetCloser(closer func()) {
	if f == nil {
		return
	}
	f.registry.mu.Lock()
	f.closer = closer
	f.registry.mu.Unlock()
}

// update changes the flow's connection info. A route change re-files the
// traffic accrued so far under the old route, the rest under the new one.
func (f *Flow) update(change func(c *coreapi.Connection)) {
	if f == nil {
		return
	}
	r := f.registry
	r.mu.Lock()
	defer r.mu.Unlock()
	change(&f.entry.connection)
	if route := accountingRoute(f.entry.connection.Route); route != f.key.route {
		r.foldLocked(f)
		f.key.route = route
	}
}

// SetDomain records a domain learned outside the core (SNI, Host header).
// A domain already known is kept.
func (f *Flow) SetDomain(domain string) {
	if domain == "" {
		return
	}
	f.update(func(c *coreapi.Connection) {
		if c.Domain == "" {
			c.Domain = domain
		}
	})
}

// Close ends the flow: its not yet drained traffic moves to pending and it
// joins the history, even if the registry was reset meanwhile.
func (f *Flow) Close() {
	if f == nil {
		return
	}
	f.once.Do(func() {
		r := f.registry
		now := time.Now()
		r.mu.Lock()
		delete(r.flows, f.id)
		r.foldLocked(f)
		f.closer = nil
		connection := f.entry.connection
		connection.Upload = f.up.Load()
		connection.Download = f.down.Load()
		connection.End = now
		// DNS lookups are dozens per second and say nothing on their own:
		// they are shown while open, not kept.
		if connection.Route != RouteDNS && connection.RuleKind != RuleKindDNS {
			r.rememberLocked(connection, now)
		}
		r.mu.Unlock()
	})
}

// DrainFlowTraffic returns the traffic accrued since the previous drain,
// grouped by application and route.
func (r *Registry) DrainFlowTraffic() []coreapi.FlowTraffic {
	r.mu.Lock()
	defer r.mu.Unlock()

	for _, entry := range r.flows {
		r.foldLocked(entry.flow)
	}

	if len(r.pending) == 0 {
		return nil
	}
	result := make([]coreapi.FlowTraffic, 0, len(r.pending))
	for key, totals := range r.pending {
		if totals.up == 0 && totals.down == 0 && totals.blocked == 0 {
			continue
		}
		result = append(result, coreapi.FlowTraffic{
			ProcessPath: key.process,
			Route:       key.route,
			Upload:      totals.up,
			Download:    totals.down,
			Blocked:     totals.blocked,
		})
	}
	r.pending = make(map[flowKey]*flowTotals)
	return result
}

// Snapshot returns the live flows.
func (r *Registry) Snapshot() []coreapi.Connection {
	r.mu.RLock()
	defer r.mu.RUnlock()

	result := make([]coreapi.Connection, 0, len(r.flows))
	for _, entry := range r.flows {
		connection := entry.connection
		connection.Upload = entry.flow.up.Load()
		connection.Download = entry.flow.down.Load()
		result = append(result, connection)
	}
	return result
}

// RecentConnections returns the flows closed within the history window,
// newest first.
func (r *Registry) RecentConnections() []coreapi.Connection {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.pruneHistoryLocked(time.Now())
	result := make([]coreapi.Connection, len(r.history))
	for i, connection := range r.history {
		result[len(r.history)-1-i] = connection
	}
	return result
}

// CloseConnections closes the live flows with the given IDs and returns how
// many were found.
func (r *Registry) CloseConnections(ids []string) int {
	r.mu.RLock()
	closers := make([]func(), 0, len(ids))
	for _, raw := range ids {
		id, err := strconv.ParseUint(raw, 10, 64)
		if err != nil {
			continue
		}
		if entry, ok := r.flows[id]; ok && entry.flow.closer != nil {
			closers = append(closers, entry.flow.closer)
		}
	}
	r.mu.RUnlock()
	for _, closer := range closers {
		closer()
	}
	return len(closers)
}

// Reset forgets the live flows of a replaced core. Their traffic is still
// accounted for when they close; pending totals and the history are kept.
func (r *Registry) Reset() {
	r.mu.Lock()
	r.flows = make(map[uint64]*flowEntry)
	r.mu.Unlock()
}

// countingReader feeds the bytes read into a flow counter. first, when set,
// sees the first chunk (protocol sniffing).
type countingReader struct {
	r     io.Reader
	add   func(int64)
	first func([]byte)
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	if n > 0 {
		if c.first != nil {
			first := c.first
			c.first = nil
			first(p[:n])
		}
		c.add(int64(n))
	}
	return n, err
}
