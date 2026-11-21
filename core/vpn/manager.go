package vpn

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"beam-bridge/core/analytics"
	"beam-bridge/core/coreapi"
	domainSettings "beam-bridge/core/domain/settings"
	"beam-bridge/core/platform"
	"beam-bridge/core/profile"
	"beam-bridge/core/types"
)

// Manager owns the connection lifecycle. It is a small reconciler: callers
// only state what they want (connected or not, "the active config changed")
// and a single serialized loop converges the core to it:
//
//	want && !up             -> start (adapter + core)
//	want && up && new config -> restart the core only; the adapter stays
//	!want && up             -> stop everything, the adapter included
//
// The outcome of every step is taken from its return value, never inferred
// from asynchronous core events, so a late "stopped" of a replaced core can
// no longer flip a live connection to "disconnected". Core events are used for
// one thing only: noticing that a running core died on its own.
type Manager struct {
	mu           sync.RWMutex
	ctx          context.Context
	emitter      Emitter
	profiles     *profile.Manager
	core         coreapi.Core
	settingsRepo domainSettings.Repository
	onStatus     func(types.VPNStatus)

	status    types.VPNStatus
	lastError string

	// want is the latest user intent; up is whether a session is running.
	want bool
	up   bool
	// teardown forces a stop even when no session is known to be up, so an
	// explicit disconnect always leaves no adapter behind.
	teardown bool
	// configGen is bumped on every config change, appliedGen is the one the
	// running core was started with. A burst of switches collapses into one
	// restart with the latest config.
	configGen  uint64
	appliedGen uint64

	connectedAt     time.Time
	activeProfileID string
	// baseDown/baseUp carry the traffic of cores replaced by a switch, so the
	// session counters continue instead of dropping to zero.
	baseDown  int64
	baseUp    int64
	stopStats context.CancelFunc

	// flushedDown/flushedUp are the session bytes already accounted for
	// (profile usage and statistics); accountedAt is when the connection
	// time was last accounted for.
	flushedDown int64
	flushedUp   int64
	accountedAt time.Time
	source      analytics.Source
	analytics   *analytics.Store
	flushMu     sync.Mutex

	// opMu serializes lifecycle steps (start, switch, stop).
	opMu sync.Mutex

	// Kill switch (killswitch.go): engaged after an unexpected drop, with
	// the cause; killError when it should have engaged but could not.
	killEngaged bool
	killReason  string
	killError   string

	statusNotify chan struct{}
}

func NewManager(
	profiles *profile.Manager,
	settingsRepo domainSettings.Repository,
	core coreapi.Core,
) *Manager {
	m := &Manager{
		profiles:     profiles,
		core:         core,
		settingsRepo: settingsRepo,
		status:       types.StatusDisconnected,
		statusNotify: make(chan struct{}, 1),
	}
	go m.dispatchStatus()

	m.applyLogOptions(settingsRepo.Get())
	m.core.SetStateCallback(m.onCoreStateChange)
	// The physical interface changed under a live tunnel (Wi-Fi came up
	// after an auto-connect at boot, Wi-Fi <-> Ethernet): the core has to
	// be restarted to re-pin its outbounds. Same path as a node switch.
	if notifier, ok := core.(interfaceChangeNotifier); ok {
		notifier.SetInterfaceChangeCallback(m.Restart)
	}
	return m
}

type interfaceChangeNotifier interface {
	SetInterfaceChangeCallback(func())
}

type networkWaiter interface {
	WaitForNetwork(ctx context.Context, timeout time.Duration) bool
}

// WaitForNetwork waits up to timeout for the host network (a default route)
// before an automatic connect. True when it is there or cannot be checked.
func (m *Manager) WaitForNetwork(ctx context.Context, timeout time.Duration) bool {
	if waiter, ok := m.core.(networkWaiter); ok {
		return waiter.WaitForNetwork(ctx, timeout)
	}
	return true
}

func (m *Manager) SetContext(ctx context.Context) {
	m.mu.Lock()
	m.ctx = ctx
	m.mu.Unlock()
}

func (m *Manager) SetStatusCallback(callback func(types.VPNStatus)) {
	m.mu.Lock()
	m.onStatus = callback
	m.mu.Unlock()
}

func (m *Manager) applyLogOptions(appSettings *domainSettings.Settings) {
	if appSettings == nil {
		return
	}
	m.core.SetLogOptions(coreapi.LogOptions{
		Trace:        appSettings.TraceLogging,
		CoreLogging:  !appSettings.DisableCoreLogging,
		RealityDebug: appSettings.RealityDebug,
		ExtendedLogs: appSettings.ExtendedLogs,
		MinLevel:     logLevelOf(appSettings),
	})
}

// logLevelOf выводит эффективный минимальный уровень буфера логов: явно
// выключенные логи ядра эквивалентны уровню "off", пустое значение
// (устаревший settings.json) — "info".
func logLevelOf(s *domainSettings.Settings) string {
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

func (m *Manager) currentLogOptions() coreapi.LogOptions {
	appSettings := m.settingsRepo.Get()
	if appSettings == nil {
		return coreapi.LogOptions{CoreLogging: true}
	}
	return coreapi.LogOptions{
		Trace:        appSettings.TraceLogging,
		CoreLogging:  !appSettings.DisableCoreLogging,
		RealityDebug: appSettings.RealityDebug,
		ExtendedLogs: appSettings.ExtendedLogs,
		MinLevel:     logLevelOf(appSettings),
	}
}

func (m *Manager) SetTraceLogging(enabled bool) {
	opts := m.currentLogOptions()
	opts.Trace = enabled
	m.core.SetLogOptions(opts)
}

func (m *Manager) SetCoreLogging(enabled bool) {
	opts := m.currentLogOptions()
	opts.CoreLogging = enabled
	m.core.SetLogOptions(opts)
}

func (m *Manager) SetRealityDebug(enabled bool) {
	opts := m.currentLogOptions()
	opts.RealityDebug = enabled
	m.core.SetLogOptions(opts)
}

func (m *Manager) SetExtendedLogs(enabled bool) {
	opts := m.currentLogOptions()
	opts.ExtendedLogs = enabled
	m.core.SetLogOptions(opts)
}

// SetLogLevel меняет минимальный уровень буфера логов на лету, без рестарта
// ядра. "off" гасит приём строк из ядра полностью.
func (m *Manager) SetLogLevel(level string) {
	opts := m.currentLogOptions()
	switch level {
	case "off", "error", "info", "debug":
		opts.MinLevel = level
	default:
		opts.MinLevel = "info"
	}
	opts.CoreLogging = opts.MinLevel != "off"
	m.core.SetLogOptions(opts)
}

func (m *Manager) GetActiveConfigJSON() json.RawMessage {
	return m.profiles.GetActiveConfig()
}

// Connect brings the connection up (adapter and core). Returns once it is up
// or failed.
func (m *Manager) Connect() error {
	m.mu.Lock()
	m.want = true
	if !m.up {
		m.lastError = ""
		m.setStatusLocked(types.StatusConnecting)
	}
	m.mu.Unlock()
	return m.reconcile()
}

// Disconnect tears the connection down completely: core, stack and adapter.
// It always runs the teardown, even when no session is known to be up.
func (m *Manager) Disconnect() error {
	// A manual disconnect never leaves the internet paused.
	_ = m.releaseKillSwitch()
	m.mu.Lock()
	m.want = false
	m.teardown = true
	if m.status != types.StatusDisconnected {
		m.setStatusLocked(types.StatusDisconnecting)
	}
	m.mu.Unlock()
	return m.reconcile()
}

// Restart applies the active config (profile or node switch) to a live
// connection by restarting the core only; the adapter stays up. It returns
// immediately: the switch runs in the background, bursts collapse into one
// restart with the latest config, and progress is reported through status
// events. Does nothing while disconnected - the next connect uses the new
// config anyway.
func (m *Manager) Restart() {
	m.mu.Lock()
	if !m.want {
		m.mu.Unlock()
		return
	}
	m.configGen++
	m.setStatusLocked(types.StatusConnecting)
	m.mu.Unlock()
	go func() {
		defer platform.RecoverAndLog("vpn-switch")
		_ = m.reconcile()
	}()
}

// reconcile converges the core to the wanted state, one step at a time,
// until nothing is left to do. Only one reconcile runs at a time; a caller
// that waited for the lock finds the work already done and returns.
func (m *Manager) reconcile() error {
	m.opMu.Lock()
	defer m.opMu.Unlock()

	for {
		m.mu.Lock()
		want, up, teardown := m.want, m.up, m.teardown
		gen, applied := m.configGen, m.appliedGen
		m.mu.Unlock()

		var err error
		switch {
		case !want && (up || teardown):
			err = m.stopSession()
		case want && !up:
			err = m.startSession(gen)
		case want && gen != applied:
			err = m.switchSession(gen)
		default:
			m.settle()
			return nil
		}
		if err != nil {
			return err
		}
	}
}

// settle publishes the final status once the core matches the intent.
func (m *Manager) settle() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.up {
		m.setStatusLocked(types.StatusDisconnected)
		return
	}
	if m.status != types.StatusConnectedNoInternet {
		m.setStatusLocked(types.StatusConnected)
	}
}

func (m *Manager) startSession(gen uint64) error {
	m.mu.Lock()
	m.lastError = ""
	m.setStatusLocked(types.StatusConnecting)
	m.mu.Unlock()

	began := time.Now()
	m.applyLogOptions(m.settingsRepo.Get())
	// A contradictory ProTun graph does not connect: it is unknown where the
	// disputed traffic should go.
	if err := m.profiles.ProTunConflictError(); err != nil {
		return m.failSession(err, false)
	}
	config := m.profiles.GetActiveConfig()
	if config == nil {
		return m.failSession(errors.New("Select a profile to connect"), false)
	}
	built := time.Now()
	// Under an engaged kill switch the server name still has to resolve.
	closeDNS := m.openKillSwitchDNS()
	if err := m.core.Start(m.startContext(), config); err != nil {
		closeDNS()
		return m.failSession(err, true)
	}
	m.core.Logs().Add(types.LogEntry{
		Timestamp: time.Now().UnixMilli(),
		Level:     types.LogLevelInfo,
		Source:    "vpn",
		Message: fmt.Sprintf("connected in %dms (config %dms, start %dms)",
			time.Since(began).Milliseconds(), built.Sub(began).Milliseconds(), time.Since(built).Milliseconds()),
	})
	// Up (in TUN mode with its leak protection): the internet is back.
	_ = m.releaseKillSwitch()

	source := m.activeSourceOf()
	now := time.Now()
	m.mu.Lock()
	m.up = true
	m.appliedGen = gen
	m.connectedAt = now
	m.accountedAt = now
	m.activeProfileID = source.ProfileID
	m.source = source
	m.baseDown, m.baseUp = 0, 0
	m.flushedDown, m.flushedUp = 0, 0
	store := m.analytics
	m.mu.Unlock()

	if store != nil {
		store.AddSession(now)
	}
	m.startStatsLoop()
	return nil
}

// switchSession swaps the core config of a live session. The adapter, its
// routes and the stack stay; connection time and traffic counters continue.
func (m *Manager) switchSession(gen uint64) error {
	m.stopStatsLoop()
	m.flushTraffic()

	m.mu.Lock()
	m.lastError = ""
	m.setStatusLocked(types.StatusConnecting)
	m.mu.Unlock()

	// Switching to a profile whose own ProTun layer contradicts itself.
	if err := m.profiles.ProTunConflictError(); err != nil {
		return m.failSession(err, true)
	}
	config := m.profiles.GetActiveConfig()
	if config == nil {
		return m.failSession(errors.New("Select a profile to connect"), true)
	}

	down, up := m.core.Traffic()
	m.mu.Lock()
	m.baseDown += down
	m.baseUp += up
	m.mu.Unlock()

	var err error
	if core, ok := m.core.(restarter); ok {
		err = core.Restart(m.startContext(), config)
	} else {
		_ = m.core.Stop()
		err = m.core.Start(m.startContext(), config)
	}
	if err != nil {
		// The connection was live and is lost: pause the internet first,
		// then tear down. Nothing half-working is left behind.
		m.engageKillSwitch(err)
		return m.failSession(err, true)
	}

	source := m.activeSourceOf()
	m.mu.Lock()
	m.appliedGen = gen
	m.activeProfileID = source.ProfileID
	m.source = source
	m.mu.Unlock()

	m.startStatsLoop()
	return nil
}

func (m *Manager) stopSession() error {
	m.stopStatsLoop()
	m.flushTraffic()

	err := m.stopCoreBounded()

	m.mu.Lock()
	m.up = false
	m.teardown = false
	m.connectedAt = time.Time{}
	m.baseDown, m.baseUp = 0, 0
	if err != nil {
		m.lastError = err.Error()
	}
	m.setStatusLocked(types.StatusDisconnected)
	store := m.analytics
	m.mu.Unlock()

	if store != nil {
		_ = store.Flush()
	}
	return err
}

// failSession ends a failed start or switch: the user has to connect again,
// and with stop set everything already brought up is torn down.
func (m *Manager) failSession(cause error, stop bool) error {
	m.stopStatsLoop()
	if stop {
		_ = m.stopCoreBounded()
	}
	msg := cause.Error()

	m.mu.Lock()
	m.want = false
	m.up = false
	m.teardown = false
	m.connectedAt = time.Time{}
	m.baseDown, m.baseUp = 0, 0
	m.lastError = msg
	m.setStatusLocked(types.StatusDisconnected)
	m.mu.Unlock()

	m.emitError(msg)
	return errors.New(msg)
}

// onCoreStateChange only watches for a running core that died on its own;
// every state the manager causes itself is known from return values.
func (m *Manager) onCoreStateChange(state coreapi.State, err error) {
	if state != coreapi.StateFailed {
		return
	}
	go m.handleCoreFailure(err)
}

func (m *Manager) handleCoreFailure(cause error) {
	defer platform.RecoverAndLog("vpn-core-failure")

	// Behind any in-flight step: afterwards Running() tells the truth, and a
	// stale event of a replaced core finds a healthy one and is ignored.
	m.opMu.Lock()
	defer m.opMu.Unlock()

	m.mu.RLock()
	up := m.up
	m.mu.RUnlock()
	if !up || m.core.Running() {
		return
	}
	if cause == nil {
		cause = errors.New("Failed to connect. Check the logs.")
	}
	m.mu.RLock()
	wanted := m.want
	m.mu.RUnlock()
	if wanted {
		m.engageKillSwitch(cause)
	}
	_ = m.failSession(cause, true)
}

// activeSourceOf names the active profile and config for the statistics.
func (m *Manager) activeSourceOf() analytics.Source {
	var source analytics.Source
	if active := m.profiles.GetActiveProfile(); active != nil {
		source.ProfileID = active.ID
		source.ProfileName = active.Name
	}
	if node, ok := m.profiles.GetActiveNode(); ok && node != nil {
		source.NodeName = node.Name
		if source.NodeName == "" {
			source.NodeName = node.ID
		}
	}
	return source
}

func (m *Manager) startContext() context.Context {
	m.mu.RLock()
	ctx := m.ctx
	m.mu.RUnlock()
	if ctx == nil {
		return context.Background()
	}
	return ctx
}

const stopCoreTimeout = 12 * time.Second

// stopCoreBounded останавливает ядро с верхней границей ожидания: зависший
// драйвер не должен оставлять UI в «disconnecting» навсегда. Если Stop всё
// же завершится позже в фоне — безобидно: lifecycleMu ядра сериализует его
// со следующим подключением.
func (m *Manager) stopCoreBounded() error {
	done := make(chan error, 1)
	go func() { done <- m.core.Stop() }()
	select {
	case err := <-done:
		return err
	case <-time.After(stopCoreTimeout):
		platform.LogCrashEvent("vpn: core stop timed out after %s", stopCoreTimeout)
		return fmt.Errorf("disconnect timed out after %s", stopCoreTimeout)
	}
}

// restarter — ядро с горячей сменой конфигурации (runner.Service). Через
// assertion, чтобы не раздувать интерфейс coreapi.Core.
type restarter interface {
	Restart(ctx context.Context, config json.RawMessage) error
}

func (m *Manager) emitError(msg string) {
	m.emit("vpn:error", msg)
}

// maxAccountedGap caps the connection time of one accounting step: a longer
// gap means the machine slept, and that is not time spent online.
const maxAccountedGap = 3 * trafficInterval

// SetAnalytics plugs in the local usage statistics.
func (m *Manager) SetAnalytics(store *analytics.Store) {
	m.mu.Lock()
	m.analytics = store
	m.mu.Unlock()
}

// flushTraffic accounts the session traffic since the previous step: the
// profile's data usage and the local statistics.
func (m *Manager) flushTraffic() {
	// One step at a time: the stats loop and a switch or stop must not
	// account the same bytes twice.
	m.flushMu.Lock()
	defer m.flushMu.Unlock()

	m.mu.RLock()
	profileID := m.activeProfileID
	source := m.source
	flushedDown, flushedUp := m.flushedDown, m.flushedUp
	baseDown, baseUp := m.baseDown, m.baseUp
	accountedAt := m.accountedAt
	up := m.up
	store := m.analytics
	m.mu.RUnlock()

	if profileID == "" || !up {
		return
	}

	download, upload := m.core.Traffic()
	totalDown, totalUp := baseDown+download, baseUp+upload
	deltaDown := max(totalDown-flushedDown, 0)
	deltaUp := max(totalUp-flushedUp, 0)

	if deltaDown+deltaUp > 0 {
		if err := m.profiles.AddDataUsed(profileID, deltaDown+deltaUp); err != nil {
			return
		}
	}

	now := time.Now()
	elapsed := now.Sub(accountedAt)
	if accountedAt.IsZero() || elapsed < 0 {
		elapsed = 0
	} else if elapsed > maxAccountedGap {
		elapsed = trafficInterval
	}

	m.mu.Lock()
	if m.activeProfileID == profileID {
		m.flushedDown, m.flushedUp = totalDown, totalUp
		m.accountedAt = now
	}
	m.mu.Unlock()

	if store == nil {
		return
	}
	store.Record(analytics.Sample{
		At:       now,
		Source:   source,
		Up:       deltaUp,
		Down:     deltaDown,
		Duration: elapsed,
		Apps:     m.drainApps(deltaUp, deltaDown),
	})
}

// drainApps takes the per-app traffic from the tunnel. Without a tunnel
// (system proxy mode) processes are unknown and the VPN traffic is reported
// as a whole.
func (m *Manager) drainApps(vpnUp, vpnDown int64) []analytics.AppTraffic {
	accounting, ok := m.core.(coreapi.FlowAccounting)
	var flows []coreapi.FlowTraffic
	tunnel := false
	if ok {
		flows, tunnel = accounting.DrainFlowTraffic()
	}
	if !tunnel && len(flows) == 0 {
		if vpnUp+vpnDown == 0 {
			return nil
		}
		return []analytics.AppTraffic{{
			Name:  analytics.ProxyAppKey,
			Route: analytics.RouteProxy,
			Up:    vpnUp,
			Down:  vpnDown,
		}}
	}
	apps := make([]analytics.AppTraffic, 0, len(flows))
	for _, flow := range flows {
		apps = append(apps, analytics.AppTraffic{
			Name:    processName(flow.ProcessPath),
			Path:    flow.ProcessPath,
			Route:   flow.Route,
			Up:      flow.Upload,
			Down:    flow.Download,
			Blocked: flow.Blocked,
		})
	}
	return apps
}

// GetAnalytics returns the usage statistics of a period (today, week,
// month, all). A running session is accounted for every trafficInterval.
func (m *Manager) GetAnalytics(period string) analytics.Report {
	m.mu.RLock()
	store := m.analytics
	m.mu.RUnlock()
	if store == nil {
		return analytics.Report{Period: period}
	}
	return store.Query(period)
}

// ResetAnalytics deletes the usage statistics.
func (m *Manager) ResetAnalytics() error {
	m.mu.RLock()
	store := m.analytics
	m.mu.RUnlock()
	if store == nil {
		return nil
	}
	return store.Reset()
}

func (m *Manager) GetStatus() types.VPNStatus {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.status
}

func (m *Manager) GetLastError() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.lastError
}

// sessionTraffic is the traffic of the whole session, cores replaced by
// switches included.
func (m *Manager) sessionTraffic() (download, upload int64) {
	down, up := m.core.Traffic()
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.baseDown + down, m.baseUp + up
}

func (m *Manager) GetStats() types.ConnectionStats {
	m.mu.RLock()
	status := m.status
	connectedAt := m.connectedAt
	m.mu.RUnlock()

	download, upload := m.sessionTraffic()

	var duration int64
	var connectedAtUnix int64
	if !connectedAt.IsZero() {
		duration = int64(time.Since(connectedAt).Seconds())
		connectedAtUnix = connectedAt.Unix()
	}

	isHealthy := status == types.StatusConnected && m.core.Healthy()

	activeConns := 0
	if stats, err := m.core.Stats(); err == nil && stats != nil {
		activeConns = stats.ActiveConns
	}

	lastActivity := m.core.LastTrafficTime()
	var lastActivityUnix int64
	if !lastActivity.IsZero() {
		lastActivityUnix = lastActivity.Unix()
	}

	return types.ConnectionStats{
		BytesReceived:  download,
		BytesSent:      upload,
		ConnectedAt:    connectedAtUnix,
		Duration:       duration,
		IsHealthy:      isHealthy,
		ActiveConns:    activeConns,
		LastActivityAt: lastActivityUnix,
	}
}

func (m *Manager) GetDetailedStats() (*types.DetailedStats, error) {
	if !m.core.Running() {
		return nil, nil
	}
	stats, err := m.core.Stats()
	if err != nil || stats == nil {
		return nil, err
	}
	download, upload := m.sessionTraffic()
	var duration int64
	m.mu.RLock()
	if !m.connectedAt.IsZero() {
		duration = int64(time.Since(m.connectedAt).Seconds())
	}
	m.mu.RUnlock()
	return &types.DetailedStats{
		Download:    download,
		Upload:      upload,
		ActiveConns: stats.ActiveConns,
		Duration:    duration,
	}, nil
}

// setStatusLocked records the status and wakes the dispatcher. m.mu is held.
func (m *Manager) setStatusLocked(status types.VPNStatus) {
	if m.status == status {
		return
	}
	m.status = status
	select {
	case m.statusNotify <- struct{}{}:
	default:
	}
}

// dispatchStatus delivers the current status, never a queued stale one:
// subscribers always converge to the real state and never see it reordered.
func (m *Manager) dispatchStatus() {
	var delivered types.VPNStatus
	for range m.statusNotify {
		m.mu.RLock()
		status := m.status
		emitter := m.emitter
		callback := m.onStatus
		m.mu.RUnlock()
		if status == delivered {
			continue
		}
		delivered = status
		deliverStatus(emitter, callback, status)
	}
}

func deliverStatus(emitter Emitter, callback func(types.VPNStatus), status types.VPNStatus) {
	defer platform.RecoverAndLog("vpn-status-callback")
	if emitter != nil {
		emitter("vpn:status", string(status))
	}
	if callback != nil {
		callback(status)
	}
}

func (m *Manager) GetLogBuffer() coreapi.LogStore {
	return m.core.Logs()
}
