package vpn

import (
	"context"
	"fmt"
	"net"
	goruntime "runtime"
	"strconv"
	"sync/atomic"
	"time"

	"beam-bridge/core/coreapi"
	"beam-bridge/core/platform"
	"beam-bridge/core/probe"
	"beam-bridge/core/types"
)

const (
	statsInterval       = time.Second
	pingInterval        = 5 * time.Second
	pingTimeout         = 5 * time.Second
	trafficInterval     = 10 * time.Second
	suspendGapThreshold = 5 * time.Second
	// failedPingsNoInternet consecutive failed pings flip the status to
	// "connected, no internet".
	failedPingsNoInternet = 3
)

// startStatsLoop starts the per-session stats and ping loops. The first ping
// runs right away, so the value shows up within a moment of connecting.
func (m *Manager) startStatsLoop() {
	ctx, cancel := context.WithCancel(context.Background())
	m.mu.Lock()
	if m.stopStats != nil {
		m.stopStats()
	}
	m.stopStats = cancel
	m.mu.Unlock()
	go m.statsLoop(ctx)
}

func (m *Manager) stopStatsLoop() {
	m.mu.Lock()
	if m.stopStats != nil {
		m.stopStats()
		m.stopStats = nil
	}
	m.mu.Unlock()
}

func (m *Manager) statsLoop(ctx context.Context) {
	defer func() {
		if r := recover(); r != nil {
			buf := make([]byte, 8192)
			n := goruntime.Stack(buf, false)
			platform.LogCrashEvent("panic in stats-loop: %v\n%s", r, buf[:n])
			m.emitError(fmt.Sprintf("internal connection monitoring error: %v", r))
		}
	}()

	var lastPing atomic.Int64
	lastPing.Store(-1)
	kick := make(chan struct{}, 1)
	go m.pingLoop(ctx, &lastPing, kick)

	ticker := time.NewTicker(statsInterval)
	trafficTicker := time.NewTicker(trafficInterval)
	defer ticker.Stop()
	defer trafficTicker.Stop()

	lastTick := time.Now()
	for {
		select {
		case <-ctx.Done():
			return

		case <-trafficTicker.C:
			m.flushTraffic()

		case now := <-ticker.C:
			if gap := now.Sub(lastTick); gap > suspendGapThreshold {
				platform.LogCrashEvent("vpn stats loop: detected system suspend (%s gap), re-checking connection", gap.Round(time.Second))
				select {
				case kick <- struct{}{}:
				default:
				}
			}
			lastTick = now
			m.emitStats(ctx, lastPing.Load())
		}
	}
}

// pingLoop measures the latency of the active node right away and then every
// pingInterval (or on kick, after a suspend).
func (m *Manager) pingLoop(ctx context.Context, lastPing *atomic.Int64, kick <-chan struct{}) {
	defer platform.RecoverAndLog("vpn-ping-loop")

	timer := time.NewTimer(0)
	defer timer.Stop()
	failed := 0
	for {
		select {
		case <-ctx.Done():
			return
		case <-kick:
			failed = 0
		case <-timer.C:
		}

		p := m.measurePing(ctx)
		if ctx.Err() != nil {
			return
		}
		lastPing.Store(p)
		if p < 0 {
			failed++
		} else {
			failed = 0
		}
		m.updateReachability(failed)

		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		timer.Reset(pingInterval)
	}
}

// updateReachability flips between "connected" and "connected, no internet".
// Only those two states are touched: a switch or disconnect in progress owns
// the status.
func (m *Manager) updateReachability(failed int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	switch {
	case failed == 0 && m.status == types.StatusConnectedNoInternet:
		m.setStatusLocked(types.StatusConnected)
	case failed >= failedPingsNoInternet && m.status == types.StatusConnected:
		m.setStatusLocked(types.StatusConnectedNoInternet)
	}
}

// measurePing returns the latency of the active node in milliseconds, or -1.
//
// "http" (default) measures the real tunnel: a request through the active
// outbound of the running core, as the round trip of a warmed-up connection
// (see package probe) - no handshakes, no DNS, no cold-start spikes. "tcp"
// measures the TCP handshake to the server over the physical interface.
func (m *Manager) measurePing(ctx context.Context) int64 {
	node, hasNode := m.profiles.GetActiveNode()

	if m.settingsRepo.Get().Ping.ConnectionMode == "tcp" {
		if !hasNode {
			return -1
		}
		server, _ := node.Outbound["server"].(string)
		port := parsePortValue(node.Outbound["server_port"])
		if server == "" || port <= 0 || port > 65535 {
			return -1
		}
		dial := probe.PlainDial
		if direct, ok := m.core.(coreapi.DirectRoute); ok {
			dial = direct.DialDirect
		}
		probeCtx, cancel := context.WithTimeout(ctx, pingTimeout)
		defer cancel()
		ms, err := probe.TCP(probeCtx, dial, net.JoinHostPort(server, strconv.Itoa(port)))
		if err != nil {
			return -1
		}
		return ms
	}

	tag := ""
	if hasNode {
		tag = node.ID
	}
	ms, err := m.core.Delay(ctx, tag, pingTimeout)
	if err != nil || ms <= 0 {
		return -1
	}
	return ms
}

func (m *Manager) emitStats(ctx context.Context, ping int64) {
	stats := m.GetStats()
	stats.Ping = ping
	m.mu.RLock()
	if m.status == types.StatusConnectedNoInternet {
		stats.IsHealthy = false
	}
	m.mu.RUnlock()
	// A loop cancelled by a switch or stop must not publish a last frame of
	// the old core after the new state is already out.
	if ctx.Err() != nil {
		return
	}
	m.emit("vpn:stats", stats)
}

func parsePortValue(v interface{}) int {
	switch val := v.(type) {
	case float64:
		return int(val)
	case int:
		return val
	case int64:
		return int(val)
	case string:
		if p, err := strconv.Atoi(val); err == nil {
			return p
		}
	}
	return 0
}
