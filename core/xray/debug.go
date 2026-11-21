package xray

import (
	"context"
	"errors"
	"fmt"
	"time"

	"beam-bridge/core/types"
	"beam-tun"
)

// beam-debug: temporary maximum-debug harness for diagnosing the mid-transfer
// collapse. Everything here is diagnostics only and can be reverted once the
// root cause is found.

// debugf writes a high-visibility diagnostic line into the core log mirror
// (logs/core-*.log). Level Warn forces an immediate flush (see LogBuffer.Add),
// so the last lines before a crash or a kill are never lost.
func (i *Instance) debugf(format string, args ...interface{}) {
	if i == nil || i.logs == nil || !i.ExtendedLogsEnabled() {
		return
	}
	i.logs.Add(types.LogEntry{
		Level:   types.LogLevelWarn,
		Message: "beam-debug " + fmt.Sprintf(format, args...),
	})
}

// Debugf is debugf for the tunnel runner and the TUN engine (developer mode
// only; a no-op otherwise).
func (i *Instance) Debugf(format string, args ...any) {
	i.debugf(format, args...)
}

// startTrafficSampler logs cumulative outbound counters once per second so the
// exact byte offset where throughput stalls is visible in the log. It stops as
// soon as the run is superseded or the core is gone.
func (i *Instance) startTrafficSampler(runID uint64) {
	if !i.ExtendedLogsEnabled() {
		return
	}
	go func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()

		var prevDown, prevUp int64
		var prevMetrics tun.MetricsSnapshot
		var stall int

		i.debugf("sampler start run=%d", runID)
		for range ticker.C {
			i.mu.Lock()
			stale := i.runID != runID || i.instance == nil
			i.mu.Unlock()
			if stale {
				i.debugf("sampler stop run=%d", runID)
				return
			}

			down, up := i.stats.traffic(i.Core())
			active := i.stats.activeCount()
			idleMs := int64(-1)
			if last := i.stats.lastTrafficTime(); !last.IsZero() {
				idleMs = time.Since(last).Milliseconds()
			}
			m := tun.Metrics.Snapshot()
			i.debugf("sampler down=%d(+%d) up=%d(+%d) active=%d idleMs=%d tun: pktIn=%d(+%d) pktOut=%d(+%d) tcp=%d udp=%d ringDrop=%d udpQueueDrop=%d udpLimitDrop=%d tcpUnknown=%d natExhausted=%d unsupported=%d oversized=%d ping=%d pingFail=%d",
				down, down-prevDown, up, up-prevUp, active, idleMs,
				m.PacketsIn, m.PacketsIn-prevMetrics.PacketsIn, m.PacketsOut, m.PacketsOut-prevMetrics.PacketsOut,
				m.TCPActive, m.UDPActive, m.RingFullDrops, m.UDPQueueDrops, m.UDPSessionLimitDrops,
				m.TCPUnknownFlow, m.TCPPortExhausted, m.Unsupported, m.Oversized, m.ICMPEchoes, m.ICMPEchoFailures)
			prevMetrics = m

			if down == prevDown && up == prevUp {
				stall++
				if stall == 2 {
					i.debugf("sampler STALL: no delta for 2s at down=%d up=%d active=%d idleMs=%d",
						down, up, active, idleMs)
				}
			} else {
				stall = 0
			}
			prevDown, prevUp = down, up
		}
	}()
}

// slowDialAfter is how long a dial through the core may take before the
// journal notes it at the ordinary level: a stall on the way to the server
// shows as these lines instead of as an unexplained pause.
const slowDialAfter = 2 * time.Second

// noteDial records a dial through the core that failed or took long, at the
// "Основные" level, with how long it took. Quick, successful dials stay silent.
func (i *Instance) noteDial(network string, target any, proc string, took time.Duration, err error) {
	if i == nil || i.logs == nil {
		return
	}
	if err == nil && took < slowDialAfter {
		return
	}
	// A flow cut short by a server switch or a disconnect is not a stall.
	if errors.Is(err, context.Canceled) {
		return
	}
	msg := fmt.Sprintf("tunnel: slow dial %s %v (%s) took %.1fs", network, target, proc, took.Seconds())
	level := types.LogLevelWarn
	if err != nil {
		msg = fmt.Sprintf("tunnel: dial %s %v (%s) failed after %.1fs: %v", network, target, proc, took.Seconds(), err)
	}
	i.logs.Add(types.LogEntry{Level: level, Message: msg})
}
