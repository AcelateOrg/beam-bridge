package xray

import (
	"strings"
	"sync/atomic"
	"time"

	xcore "github.com/xtls/xray-core/core"
	featureStats "github.com/xtls/xray-core/features/stats"
)

// statsClient reads the core's traffic counters in-process.
//
// It used to query Xray's gRPC API on a loopback port. That API has no
// authentication and also exposed HandlerService, so any local program could
// add inbounds/outbounds to the elevated core. The counters live in the same
// process, so they are read straight from the stats manager now and the core
// opens no control port at all.
type statsClient struct {
	activeFlows int64
	lastTraffic int64
	lastTotal   int64
}

func newStatsClient() *statsClient {
	return &statsClient{}
}

func (s *statsClient) close() {
	atomic.StoreInt64(&s.activeFlows, 0)
	atomic.StoreInt64(&s.lastTraffic, 0)
	atomic.StoreInt64(&s.lastTotal, 0)
}

func (s *statsClient) flowStarted() {
	atomic.AddInt64(&s.activeFlows, 1)
	atomic.StoreInt64(&s.lastTraffic, time.Now().UnixNano())
}

func (s *statsClient) flowFinished() {
	if atomic.AddInt64(&s.activeFlows, -1) < 0 {
		atomic.StoreInt64(&s.activeFlows, 0)
	}
}

func (s *statsClient) activeCount() int {
	return int(atomic.LoadInt64(&s.activeFlows))
}

func (s *statsClient) lastTrafficTime() time.Time {
	nanos := atomic.LoadInt64(&s.lastTraffic)
	if nanos == 0 {
		return time.Time{}
	}
	return time.Unix(0, nanos)
}

// counterVisitor is implemented by Xray's stats manager (app/stats).
type counterVisitor interface {
	VisitCounters(func(string, featureStats.Counter) bool)
}

// traffic returns the bytes carried by the proxy outbounds. Direct and block
// outbounds are not VPN traffic and are not counted.
func (s *statsClient) traffic(core *xcore.Instance) (download, upload int64) {
	if core == nil {
		return 0, 0
	}
	manager, ok := core.GetFeature(featureStats.ManagerType()).(counterVisitor)
	if !ok || manager == nil {
		return 0, 0
	}

	manager.VisitCounters(func(name string, counter featureStats.Counter) bool {
		if counter == nil || !strings.HasPrefix(name, "outbound>>>") {
			return true
		}
		parts := strings.Split(name, ">>>")
		if len(parts) != 4 {
			return true
		}
		if parts[1] == outboundBlockTag {
			return true
		}
		// "direct" and helpers such as "direct-fragment": the latter
		// carries node connections, which the node outbound already counts.
		if strings.HasPrefix(parts[1], outboundDirectTag) {
			return true
		}
		switch parts[3] {
		case "downlink":
			download += counter.Value()
		case "uplink":
			upload += counter.Value()
		}
		return true
	})

	if total := download + upload; total != atomic.SwapInt64(&s.lastTotal, total) {
		atomic.StoreInt64(&s.lastTraffic, time.Now().UnixNano())
	}
	return download, upload
}

const (
	outboundDirectTag = "direct"
	outboundBlockTag  = "block"
)
