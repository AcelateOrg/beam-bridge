package xray

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"beam-bridge/core/coreapi"
	"beam-tun"
	"beam-tun/dialer"

	"github.com/xtls/xray-core/common/crash"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	xcore "github.com/xtls/xray-core/core"
)

const (
	dialTimeout = 15 * time.Second

	udpRelayBuffer = 64 * 1024

	udpIdleTimeout = time.Minute
	// DNS exchanges are one query, one answer: holding the session (and a
	// core UDP dispatcher) for a whole minute per lookup only piles them up.
	dnsIdleTimeout = 10 * time.Second

	dnsPort = 53
)

// routeAction is what the tunnel does with a flow.
type routeAction int

const (
	// routeCore: the flow is dialed through the core, which routes it by
	// the app's inbound tag and its own rules.
	routeCore routeAction = iota
	// routeBypass: the flow goes straight out through the physical
	// interface without entering the core.
	routeBypass
	// routeBlock: the flow is dropped.
	routeBlock
)

// routeDecision is the per-flow routing verdict, also logged in developer
// mode so every OPEN line says where the flow went and why.
type routeDecision struct {
	action routeAction
	tag    string
	// outbound is the expected core outbound when known in advance.
	outbound string
	reason   string
	// kind is why the route was taken (RuleKind*).
	kind string
}

func (d routeDecision) String() string {
	var b strings.Builder
	switch d.action {
	case routeBypass:
		b.WriteString("bypass-direct")
	case routeBlock:
		b.WriteString("block")
	default:
		b.WriteString("core")
		if d.outbound != "" {
			b.WriteString("->")
			b.WriteString(d.outbound)
		}
	}
	if d.tag != "" {
		b.WriteString(" tag=")
		b.WriteString(d.tag)
	}
	if d.reason != "" {
		b.WriteString(" reason=")
		b.WriteString(d.reason)
	}
	return b.String()
}

type Tunnel struct {
	instance *Instance

	mu     sync.RWMutex
	routes coreapi.RoutePlan
	direct *dialer.Direct

	registry *Registry
	// names maps resolved addresses back to the names asked for.
	names *dnsCache

	dns   netip.AddrPort
	local netip.Prefix

	// Outbounds that refuse QUIC (XTLS Vision); see SetConfig.
	noQUIC    map[string]bool
	noQUICAll bool
}

func NewTunnel(instance *Instance) *Tunnel {
	return &Tunnel{
		instance: instance,
		routes:   coreapi.RoutePlan{Apps: map[string]coreapi.AppRoute{}},
		names:    newDNSCache(),
	}
}

// SetRoutePlan installs the per-app routing plan of the active config.
func (t *Tunnel) SetRoutePlan(plan coreapi.RoutePlan) {
	normalized := coreapi.RoutePlan{
		Apps:                  make(map[string]coreapi.AppRoute, len(plan.Apps)),
		FinalOutbound:         plan.FinalOutbound,
		DefaultBypass:         plan.DefaultBypass,
		DefaultBypassNetworks: plan.DefaultBypassNetworks,
		DisableBypass:         plan.DisableBypass,
	}
	for app, route := range plan.Apps {
		normalized.Apps[strings.ToLower(strings.TrimSpace(app))] = route
	}
	t.mu.Lock()
	t.routes = normalized
	t.mu.Unlock()
}

// SetDirectDialer installs the dialer bound to the physical interface used
// for bypassed flows. Nil disables bypassing (everything goes through the
// core, whose direct outbound is bound to the same interface).
func (t *Tunnel) SetDirectDialer(direct *dialer.Direct) {
	t.mu.Lock()
	t.direct = direct
	t.mu.Unlock()
}

// SetDNS installs the upstream resolver used for port 53 traffic. Resolvers
// inside the tunnel subnet are rejected because dialing them would send the
// query straight back into the tunnel.
func (t *Tunnel) SetDNS(resolver netip.AddrPort) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if resolver.IsValid() && containsAddr(t.local, resolver.Addr()) {
		t.dns = netip.AddrPort{}
		return
	}
	t.dns = resolver
}

// SetLocalPrefix records the tunnel subnet so traffic aimed at the tunnel
// itself is dropped instead of being dialed through the core.
func (t *Tunnel) SetLocalPrefix(prefix netip.Prefix) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.local = prefix
	if t.dns.IsValid() && containsAddr(prefix, t.dns.Addr()) {
		t.dns = netip.AddrPort{}
	}
}

// destinationFor resolves the address to dial for a tunnel flow. It reports
// false when the flow must be dropped to avoid re-entering the tunnel.
func (t *Tunnel) destinationFor(meta *tun.Metadata) (netip.AddrPort, bool) {
	t.mu.RLock()
	resolver := t.dns
	local := t.local
	t.mu.RUnlock()

	destination := meta.Destination
	if !destination.IsValid() {
		return netip.AddrPort{}, false
	}
	loopsBack := containsAddr(local, destination.Addr())

	if destination.Port() == dnsPort {
		if resolver.IsValid() {
			return resolver, true
		}
		return destination, !loopsBack
	}
	return destination, !loopsBack
}

func containsAddr(prefix netip.Prefix, addr netip.Addr) bool {
	if !prefix.IsValid() || !addr.IsValid() {
		return false
	}
	return prefix.Contains(addr.Unmap())
}

func (t *Tunnel) SetRegistry(registry *Registry) {
	t.mu.Lock()
	t.registry = registry
	t.mu.Unlock()
}

// appRouteFor finds the route of the flow's owning app. The resolver returns
// the full path (C:\...\steam.exe) while users usually write the file name
// (steam.exe), so both are tried.
func (t *Tunnel) appRouteFor(processPath string) (coreapi.AppRoute, bool) {
	if processPath == "" {
		return coreapi.AppRoute{}, false
	}
	t.mu.RLock()
	defer t.mu.RUnlock()
	lower := strings.ToLower(processPath)
	if route, ok := t.routes.Apps[lower]; ok {
		return route, true
	}
	if route, ok := t.routes.Apps[strings.ToLower(filepath.Base(processPath))]; ok {
		return route, true
	}
	// "All apps except ...": a known owner that no card names is one of
	// the "other" apps. (An unknown owner never gets here, see above.)
	route, ok := t.routes.Apps[coreapi.OtherAppsKey]
	return route, ok
}

// decide picks the route of a flow. Bypass and block are only taken when the
// core's own rules would give the same answer; everything else, and every
// DNS query (it must reach the core's DNS app), goes through the core.
func (t *Tunnel) decide(meta *tun.Metadata, target netip.AddrPort) routeDecision {
	route, matched := t.appRouteFor(meta.ProcessPath)

	t.mu.RLock()
	defaultBypass := t.routes.DefaultBypass
	if byNetwork := t.routes.DefaultBypassNetworks; byNetwork != nil {
		defaultBypass = byNetwork[meta.Network]
	}
	disableBypass := t.routes.DisableBypass
	final := t.routes.FinalOutbound
	hasAppRules := len(t.routes.Apps) > 0
	direct := t.direct
	t.mu.RUnlock()

	// Per-network rules decide only their network; the other one follows
	// the defaults like an unknown app.
	outbound, bypass, block := route.Outbound, route.Bypass, route.Block
	if matched && route.Networks != nil {
		if byNetwork, ok := route.Networks[meta.Network]; ok {
			outbound, bypass, block = byNetwork.Outbound, byNetwork.Bypass, byNetwork.Block
		} else {
			matched = false
		}
	}

	decision := routeDecision{action: routeCore, tag: route.Tag, outbound: outbound, kind: RuleKindApp}
	if !matched {
		decision.outbound = final
		decision.reason = "no-app-rule"
		if meta.ProcessPath == "" && hasAppRules {
			// Visible in the connections log: the owner lookup failed, so
			// app rules could not apply to this flow.
			decision.reason = "process-unknown"
		}
		decision.kind = RuleKindDefault
	} else if outbound == "" && !bypass && !block {
		decision.kind = RuleKindRules
	}
	if meta.Destination.Port() == dnsPort {
		decision.kind = RuleKindDNS
	}

	wantBypass := (matched && bypass) || (!matched && defaultBypass)
	// Fragmented direct traffic only exists inside the core.
	if wantBypass && disableBypass {
		wantBypass = false
		decision.reason = "direct-via-core"
	}
	wantBlock := matched && block
	if !wantBypass && !wantBlock {
		if matched && outbound == "" {
			decision.reason = "conditional-rules"
		}
		return decision
	}

	port := meta.Destination.Port()
	if port == dnsPort {
		decision.reason = "dns"
		return decision
	}
	// Private/LAN destinations are sent direct by a system rule that
	// precedes every user rule.
	if wantBlock {
		if isLocalNetwork(target.Addr()) {
			decision.outbound = "direct"
			decision.reason = "private-ip"
			decision.kind = RuleKindLAN
			return decision
		}
		decision.action = routeBlock
		return decision
	}
	if direct == nil || !direct.Ready() {
		decision.reason = "no-physical-interface"
		return decision
	}
	decision.action = routeBypass
	decision.outbound = ""
	return decision
}

func isLocalNetwork(addr netip.Addr) bool {
	addr = addr.Unmap()
	return addr.IsPrivate() || addr.IsLoopback() || addr.IsLinkLocalUnicast() ||
		addr.IsMulticast() || addr.IsUnspecified() || cgnatPrefix.Contains(addr)
}

var cgnatPrefix = netip.MustParsePrefix("100.64.0.0/10")

// routeHolder carries the core's routing outcome to the flow. The core may
// route before the flow is tracked (TCP dial) or after (sniffing waits for
// the first bytes, UDP routes per datagram), so either side can come first.
type routeHolder struct {
	mu   sync.Mutex
	info *session.RouteInfo
	flow *Flow
}

func (h *routeHolder) observe(info session.RouteInfo) {
	h.mu.Lock()
	h.info = &info
	flow := h.flow
	h.mu.Unlock()
	if flow != nil {
		applyRoute(flow, info)
	}
}

func (h *routeHolder) attach(flow *Flow) {
	if flow == nil {
		return
	}
	h.mu.Lock()
	h.flow = flow
	info := h.info
	h.mu.Unlock()
	if info != nil {
		applyRoute(flow, *info)
	}
}

// applyRoute records where the core actually sent a flow.
func applyRoute(flow *Flow, info session.RouteInfo) {
	flow.update(func(c *coreapi.Connection) {
		if info.OutboundTag != "" {
			c.Outbound = info.OutboundTag
			if c.Route != RouteDNS {
				c.Route = routeOfOutbound(info.OutboundTag)
			}
		}
		if info.Domain != "" {
			c.Domain = info.Domain
		}
		if info.Protocol != "" {
			c.Protocol = info.Protocol
		}
		// Rule tags are "<kind>|<n>|<label>" (profile.ruleTag).
		if info.RuleTag != "" {
			c.Rule = info.RuleTag
			kind, _, _ := strings.Cut(info.RuleTag, "|")
			switch kind {
			case "lan":
				c.RuleKind = RuleKindLAN
			case "dns":
				c.RuleKind = RuleKindDNS
			case "final":
				c.RuleKind = RuleKindDefault
			case "user":
				if c.RuleKind != RuleKindApp {
					c.RuleKind = RuleKindRules
				}
			}
		}
	})
}

func routeOfOutbound(tag string) string {
	switch {
	case tag == outboundBlockTag:
		return RouteBlock
	case tag == "dns-out":
		return RouteDNS
	case strings.HasPrefix(tag, outboundDirectTag):
		return RouteDirect
	}
	return RouteProxy
}

func (t *Tunnel) context(ctx context.Context, meta *tun.Metadata, decision routeDecision, holder *routeHolder) context.Context {
	inbound := &session.Inbound{
		Source: destinationOf(meta.Network, meta.Source),
		Tag:    decision.tag,
	}
	ctx = session.ContextWithInbound(ctx, inbound)
	ctx = session.ContextWithRouteObserver(ctx, holder.observe)
	return session.ContextWithContent(ctx, &session.Content{
		SniffingRequest: session.SniffingRequest{
			Enabled:                        true,
			OverrideDestinationForProtocol: []string{"http", "tls", "quic"},
			MetadataOnly:                   false,
			RouteOnly:                      true,
		},
	})
}

func (t *Tunnel) directDialer() *dialer.Direct {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.direct
}

func (t *Tunnel) HandleTCP(conn net.Conn, meta *tun.Metadata) {
	defer conn.Close()

	target, ok := t.destinationFor(meta)
	if !ok {
		t.instance.debugf("tcp DROP dst=%s src=%s proc=%q reason=loopback-or-invalid", meta.Destination, meta.Source, meta.ProcessPath)
		return
	}
	decision := t.decide(meta, target)

	switch decision.action {
	case routeBlock:
		t.instance.debugf("tcp BLOCK dst=%s src=%s proc=%q route=%s", target, meta.Source, meta.ProcessPath, decision)
		t.countBlocked(meta, decision)
		return
	case routeBypass:
		t.handleTCPBypass(conn, meta, target, decision)
		return
	}

	instance, coreSession := t.instance.Session()
	if instance == nil {
		return
	}

	// The core keeps this context for the whole session, not just for the
	// dial: everything it opens downstream is torn down as soon as the
	// context is done, so the dial deadline is enforced separately. It is
	// derived from the core's session, so the flow ends with that core.
	holder := &routeHolder{}
	ctx, cancel := context.WithCancel(t.context(coreSession, meta, decision, holder))
	defer cancel()

	dialStart := time.Now()
	remote, err := dialWithTimeout(ctx, instance, destinationOf("tcp", target), dialTimeout)
	t.instance.noteDial("tcp", target, appName(meta.ProcessPath), time.Since(dialStart), err)
	if err != nil {
		t.instance.debugf("tcp DIAL-FAIL dst=%s proc=%q route=%s afterMs=%d err=%v", target, meta.ProcessPath, decision, time.Since(dialStart).Milliseconds(), err)
		return
	}
	defer remote.Close()
	// A replaced or stopped core ends the flow on both sides: the app sees
	// the connection drop and reconnects through the new server instead of
	// staying on the old one over a kept-alive connection.
	defer context.AfterFunc(ctx, func() {
		_ = conn.Close()
		_ = remote.Close()
	})()

	t.instance.flowStarted()
	defer t.instance.flowFinished()
	flow := t.track(meta, decision)
	defer flow.Close()
	flow.SetCloser(func() {
		_ = conn.Close()
		_ = remote.Close()
	})
	holder.attach(flow)

	t.instance.debugf("tcp OPEN dst=%s src=%s proc=%q route=%s dialMs=%d", target, meta.Source, meta.ProcessPath, decision, time.Since(dialStart).Milliseconds())
	relayStart := time.Now()
	up, down, upErr, downErr := relay(conn, remote, flow, false)
	t.instance.debugf("tcp CLOSE dst=%s proc=%q route=%s up=%d down=%d durMs=%d upErr=%v downErr=%v", target, meta.ProcessPath, decision.action.short(), up, down, time.Since(relayStart).Milliseconds(), upErr, downErr)
}

func (t *Tunnel) handleTCPBypass(conn net.Conn, meta *tun.Metadata, target netip.AddrPort, decision routeDecision) {
	direct := t.directDialer()
	if direct == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), dialTimeout)
	dialStart := time.Now()
	remote, err := direct.DialContext(ctx, "tcp", target.String())
	cancel()
	if err != nil {
		t.instance.debugf("tcp DIAL-FAIL dst=%s proc=%q route=%s afterMs=%d err=%v", target, meta.ProcessPath, decision, time.Since(dialStart).Milliseconds(), err)
		return
	}
	defer remote.Close()

	t.instance.flowStarted()
	defer t.instance.flowFinished()
	flow := t.track(meta, decision)
	defer flow.Close()
	flow.SetCloser(func() {
		_ = conn.Close()
		_ = remote.Close()
	})

	t.instance.debugf("tcp OPEN dst=%s src=%s proc=%q route=%s dialMs=%d", target, meta.Source, meta.ProcessPath, decision, time.Since(dialStart).Milliseconds())
	relayStart := time.Now()
	up, down, upErr, downErr := relay(conn, remote, flow, true)
	t.instance.debugf("tcp CLOSE dst=%s proc=%q route=%s up=%d down=%d durMs=%d upErr=%v downErr=%v", target, meta.ProcessPath, decision.action.short(), up, down, time.Since(relayStart).Milliseconds(), upErr, downErr)
}

func (a routeAction) short() string {
	switch a {
	case routeBypass:
		return "bypass-direct"
	case routeBlock:
		return "block"
	}
	return "core"
}

// udpPacketConn is the common shape of the core and bypass UDP sockets.
type udpPacketConn interface {
	ReadFrom(p []byte) (int, net.Addr, error)
	WriteTo(p []byte, addr net.Addr) (int, error)
	SetReadDeadline(t time.Time) error
	Close() error
}

func (t *Tunnel) HandleUDP(conn net.PacketConn, meta *tun.Metadata) {
	defer conn.Close()

	target, ok := t.destinationFor(meta)
	if !ok {
		return
	}
	decision := t.decide(meta, target)
	// QUIC that the outbound would refuse after a whole server handshake is
	// refused here at once: the app falls back to TCP without waiting.
	if decision.action == routeCore && target.Port() == quicPort && decision.kind != RuleKindDNS && t.rejectsQUIC(decision) {
		t.instance.debugf("udp BLOCK dst=%s src=%s proc=%q route=%s reason=quic-vision", target, meta.Source, meta.ProcessPath, decision)
		return
	}

	var remote udpPacketConn
	var onlyFrom netip.AddrPort
	holder := &routeHolder{}
	switch decision.action {
	case routeBlock:
		t.instance.debugf("udp BLOCK dst=%s src=%s proc=%q route=%s", target, meta.Source, meta.ProcessPath, decision)
		t.countBlocked(meta, decision)
		return
	case routeBypass:
		direct := t.directDialer()
		if direct == nil {
			return
		}
		network := "udp4"
		if target.Addr().Is6() && !target.Addr().Is4In6() {
			network = "udp6"
		}
		pc, err := direct.ListenPacket(context.Background(), network, "")
		if err != nil {
			t.instance.debugf("udp DIAL-FAIL dst=%s proc=%q route=%s err=%v", target, meta.ProcessPath, decision, err)
			return
		}
		remote = pc
		// The session answers from its original destination, so only that
		// peer's datagrams belong to it.
		onlyFrom = netip.AddrPortFrom(target.Addr().Unmap(), target.Port())
	default:
		instance, coreSession := t.instance.Session()
		if instance == nil {
			return
		}
		ctx, cancel := context.WithCancel(t.context(coreSession, meta, decision, holder))
		defer cancel()
		pc, err := xcore.DialUDP(ctx, instance)
		if err != nil {
			t.instance.debugf("udp DIAL-FAIL dst=%s proc=%q route=%s err=%v", target, meta.ProcessPath, decision, err)
			return
		}
		// Ends with the core, like TCP flows: a QUIC session must not keep
		// talking through the previous server after a switch.
		defer context.AfterFunc(ctx, func() {
			_ = conn.Close()
			_ = pc.Close()
		})()
		remote = pc
	}
	defer remote.Close()

	t.instance.flowStarted()
	defer t.instance.flowFinished()
	flow := t.track(meta, decision)
	defer flow.Close()
	flow.SetCloser(func() {
		_ = conn.Close()
		_ = remote.Close()
	})
	holder.attach(flow)

	idle := udpIdleTimeout
	isDNS := meta.Destination.Port() == dnsPort
	if isDNS {
		idle = dnsIdleTimeout
	}
	destination := net.UDPAddrFromAddrPort(target)

	t.instance.debugf("udp OPEN dst=%s src=%s proc=%q route=%s", target, meta.Source, meta.ProcessPath, decision)
	udpStart := time.Now()
	var up, down atomic.Int64
	var upErr, downErr error

	// The session is idle only when neither direction moved for `idle`:
	// one-way traffic (a muted voice peer, a game server that only
	// listens) must not tear it down.
	// Monotonic offset from udpStart, not UnixNano: a system clock change
	// must neither drop live sessions nor keep dead ones for hours.
	var lastActive atomic.Int64
	touch := func() { lastActive.Store(int64(time.Since(udpStart))) }
	touch()
	stillActive := func(err error) bool {
		var netErr net.Error
		if !errors.As(err, &netErr) || !netErr.Timeout() {
			return false
		}
		return time.Since(udpStart)-time.Duration(lastActive.Load()) < idle
	}

	var wg sync.WaitGroup
	wg.Add(2)

	// app -> remote
	go func() {
		defer wg.Done()
		// Unblock the other direction once this one ends.
		defer remote.Close()
		defer crash.Recover("tunnel udp up")
		buf := make([]byte, udpRelayBuffer)
		for {
			_ = conn.SetReadDeadline(time.Now().Add(idle))
			n, _, err := conn.ReadFrom(buf)
			if n > 0 {
				touch()
				up.Add(int64(n))
				flow.AddUp(int64(n))
				if _, werr := remote.WriteTo(buf[:n], destination); werr != nil {
					upErr = werr
					return
				}
			}
			if err != nil {
				if stillActive(err) {
					continue
				}
				upErr = err
				return
			}
		}
	}()

	// remote -> app
	go func() {
		defer wg.Done()
		defer conn.Close()
		defer crash.Recover("tunnel udp down")
		source := net.UDPAddrFromAddrPort(meta.Source)
		buf := make([]byte, udpRelayBuffer)
		for {
			_ = remote.SetReadDeadline(time.Now().Add(idle))
			n, from, err := remote.ReadFrom(buf)
			if n > 0 && acceptFrom(onlyFrom, from) {
				touch()
				down.Add(int64(n))
				flow.AddDown(int64(n))
				if isDNS {
					t.names.observe(buf[:n])
				}
				if _, werr := conn.WriteTo(buf[:n], source); werr != nil {
					downErr = werr
					return
				}
			}
			if err != nil {
				if stillActive(err) {
					continue
				}
				downErr = err
				return
			}
		}
	}()

	wg.Wait()
	t.instance.debugf("udp CLOSE dst=%s proc=%q route=%s up=%d down=%d durMs=%d upErr=%v downErr=%v", target, meta.ProcessPath, decision.action.short(), up.Load(), down.Load(), time.Since(udpStart).Milliseconds(), upErr, downErr)
}

// acceptFrom filters bypass datagrams to the session's peer. The core path
// (want invalid) accepts everything.
func acceptFrom(want netip.AddrPort, from net.Addr) bool {
	if !want.IsValid() {
		return true
	}
	udp, ok := from.(*net.UDPAddr)
	if !ok {
		return false
	}
	got := udp.AddrPort()
	return got.Addr().Unmap() == want.Addr() && got.Port() == want.Port()
}

// dialWithTimeout bounds how long the core may take to hand back a connection
// without bounding the lifetime of that connection. The session context must
// outlive the dial, so the deadline is enforced here instead of on the context
// passed to the core.
func dialWithTimeout(
	ctx context.Context,
	instance *xcore.Instance,
	destination xnet.Destination,
	timeout time.Duration,
) (net.Conn, error) {
	results := make(chan dialResult, 1)
	go func() {
		defer crash.RecoverThen("tunnel dial", func() {
			results <- dialResult{err: errors.New("tunnel: dial panicked")}
		})
		conn, err := xcore.Dial(ctx, instance, destination)
		results <- dialResult{conn: conn, err: err}
	}()

	timer := time.NewTimer(timeout)
	defer timer.Stop()

	select {
	case result := <-results:
		return result.conn, result.err
	case <-ctx.Done():
		go discardLateDial(results)
		return nil, ctx.Err()
	case <-timer.C:
		go discardLateDial(results)
		return nil, context.DeadlineExceeded
	}
}

type dialResult struct {
	conn net.Conn
	err  error
}

// discardLateDial closes a connection that arrived after the caller gave up,
// so a slow dial cannot leak a live session.
func discardLateDial(results <-chan dialResult) {
	result := <-results
	if result.conn != nil {
		_ = result.conn.Close()
	}
}

func (t *Tunnel) track(meta *tun.Metadata, decision routeDecision) *Flow {
	t.mu.RLock()
	registry := t.registry
	t.mu.RUnlock()
	if registry == nil {
		return nil
	}
	outbound := decision.tag
	route := RouteProxy
	if decision.kind == RuleKindDNS {
		route = RouteDNS
	}
	switch decision.action {
	case routeBypass:
		outbound = "direct"
		route = RouteDirect
	case routeBlock:
		outbound = "block"
		route = RouteBlock
	default:
		if decision.outbound != "" {
			outbound = decision.outbound
		}
		// The core's own direct outbound (LAN, "direct" rules) is not VPN
		// traffic either.
		if decision.outbound == "direct" && route != RouteDNS {
			route = RouteDirect
		}
	}
	return registry.Track(*meta, TrackInfo{
		Outbound: outbound,
		Route:    route,
		RuleKind: decision.kind,
		Domain:   t.names.lookup(meta.Destination.Addr()),
	})
}

// countBlocked records a flow dropped by the routing rules.
func (t *Tunnel) countBlocked(meta *tun.Metadata, decision routeDecision) {
	t.mu.RLock()
	registry := t.registry
	t.mu.RUnlock()
	if registry != nil {
		registry.Blocked(*meta, TrackInfo{
			RuleKind: decision.kind,
			Domain:   t.names.lookup(meta.Destination.Addr()),
		})
	}
}

// relay copies both directions. sniff names the flow from its first bytes
// (TLS SNI, HTTP Host) when the core does not see it.
func relay(local, remote net.Conn, flow *Flow, sniff bool) (up, down int64, upErr, downErr error) {
	var wg sync.WaitGroup
	wg.Add(2)

	var upSrc, downSrc io.Reader = local, remote
	if flow != nil {
		upReader := &countingReader{r: local, add: flow.AddUp}
		if sniff {
			upReader.first = func(b []byte) { flow.SetDomain(sniffHost(b)) }
		}
		upSrc = upReader
		downSrc = &countingReader{r: remote, add: flow.AddDown}
	}

	go func() {
		defer wg.Done()
		defer crash.RecoverThen("tunnel tcp up", func() {
			upErr = io.ErrClosedPipe
			_ = remote.Close()
			_ = local.Close()
		})
		up, upErr = io.Copy(remote, upSrc) // local -> remote (upload)
		closeWrite(remote)
	}()
	go func() {
		defer wg.Done()
		defer crash.RecoverThen("tunnel tcp down", func() {
			downErr = io.ErrClosedPipe
			_ = remote.Close()
			_ = local.Close()
		})
		down, downErr = io.Copy(local, downSrc) // remote -> local (download)
		closeWrite(local)
	}()

	wg.Wait()
	return
}

type writeCloser interface{ CloseWrite() error }

func closeWrite(conn net.Conn) {
	if c, ok := conn.(writeCloser); ok {
		_ = c.CloseWrite()
		return
	}
	_ = conn.Close()
}

func destinationOf(network string, addr netip.AddrPort) xnet.Destination {
	address := xnet.IPAddress(addr.Addr().AsSlice())
	port := xnet.Port(addr.Port())
	if network == "udp" {
		return xnet.UDPDestination(address, port)
	}
	return xnet.TCPDestination(address, port)
}

// appName is the short owner of a flow for the journal (package or file name).
func appName(processPath string) string {
	if processPath == "" {
		return "system"
	}
	return filepath.Base(processPath)
}
