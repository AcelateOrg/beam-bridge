//go:build linux

package mobile

import (
	"net/netip"
	"sync"
	"time"

	"beam-bridge/core/analytics"
	"beam-bridge/core/runner"
)

// ProcessResolver is implemented by the Android app: Owner returns the package
// name of the app that owns a connection (ConnectivityManager.getConnectionOwnerUid),
// or "" when it is unknown.
type ProcessResolver interface {
	Owner(network, srcIP string, srcPort int, dstIP string, dstPort int) string
}

var (
	resolverMu  sync.Mutex
	appResolver ProcessResolver
)

// SetProcessResolver installs the connection-owner lookup used to attribute
// traffic to apps in the statistics. Call it before Connect.
func SetProcessResolver(r ProcessResolver) {
	resolverMu.Lock()
	appResolver = r
	resolverMu.Unlock()
}

// androidResolver adapts the app's lookup to the stack's resolver.
type androidResolver struct{}

func (androidResolver) Resolve(network string, src, dst netip.AddrPort) (string, error) {
	resolverMu.Lock()
	r := appResolver
	resolverMu.Unlock()
	if r == nil {
		return "", nil
	}
	return r.Owner(network, src.Addr().String(), int(src.Port()), dst.Addr().String(), int(dst.Port())), nil
}

const accountingInterval = 10 * time.Second

// accounting samples a live session every accountingInterval into the local
// statistics and the profile's data usage, as desktop's vpn.Manager does.
type accounting struct {
	svc  *runner.Service
	stop chan struct{}
	done chan struct{}

	lastDown, lastUp int64
	lastAt           time.Time
}

var (
	accountingMu sync.Mutex
	current      *accounting
)

func startAccounting(svc *runner.Service) {
	stopAccounting()
	store := usageStore()
	if store == nil {
		return
	}
	store.AddSession(time.Now())
	a := &accounting{svc: svc, stop: make(chan struct{}), done: make(chan struct{}), lastAt: time.Now()}
	accountingMu.Lock()
	current = a
	accountingMu.Unlock()
	go a.loop()
}

// stopAccounting accounts the last partial interval and writes the database.
func stopAccounting() {
	accountingMu.Lock()
	a := current
	current = nil
	accountingMu.Unlock()
	if a == nil {
		return
	}
	close(a.stop)
	<-a.done
}

func (a *accounting) loop() {
	defer close(a.done)
	ticker := time.NewTicker(accountingInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			a.flush()
		case <-a.stop:
			a.flush()
			if store := usageStore(); store != nil {
				_ = store.Flush()
			}
			return
		}
	}
}

func (a *accounting) flush() {
	store := usageStore()
	m, err := manager()
	if store == nil || err != nil || !a.svc.Running() {
		return
	}
	down, up := a.svc.Traffic()
	// A live server switch restarts the core and its counters from zero.
	deltaDown, deltaUp := down-a.lastDown, up-a.lastUp
	if deltaDown < 0 {
		deltaDown = down
	}
	if deltaUp < 0 {
		deltaUp = up
	}
	a.lastDown, a.lastUp = down, up

	now := time.Now()
	elapsed := now.Sub(a.lastAt)
	a.lastAt = now

	var source analytics.Source
	if p := m.GetActiveProfile(); p != nil {
		source.ProfileID, source.ProfileName = p.ID, p.Name
		if deltaDown+deltaUp > 0 {
			_ = m.AddDataUsed(p.ID, deltaDown+deltaUp)
		}
	}
	if node, ok := m.GetActiveNode(); ok && node != nil {
		source.NodeName = node.Name
		if source.NodeName == "" {
			source.NodeName = node.ID
		}
	}

	flows, _ := a.svc.DrainFlowTraffic()
	apps := make([]analytics.AppTraffic, 0, len(flows))
	for _, f := range flows {
		apps = append(apps, analytics.AppTraffic{
			Name:    f.ProcessPath,
			Path:    f.ProcessPath,
			Route:   f.Route,
			Up:      f.Upload,
			Down:    f.Download,
			Blocked: f.Blocked,
		})
	}
	store.Record(analytics.Sample{At: now, Source: source, Up: deltaUp, Down: deltaDown, Duration: elapsed, Apps: apps})
}

// Analytics returns the usage report of a period ("today", "week", "month",
// "all") as JSON (analytics.Report).
func Analytics(period string) (string, error) {
	store := usageStore()
	if store == nil {
		return "", errNotInitialized
	}
	return toJSON(store.Query(period))
}

// ResetAnalytics deletes the usage statistics.
func ResetAnalytics() error {
	store := usageStore()
	if store == nil {
		return errNotInitialized
	}
	return store.Reset()
}
