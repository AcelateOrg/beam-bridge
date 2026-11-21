package xray

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"beam-bridge/core/coreapi"
	"beam-bridge/core/paths"

	xcore "github.com/xtls/xray-core/core"

	_ "github.com/xtls/xray-core/main/distro/all"
)

const (
	startupProbeBudget = 12 * time.Second
	stopCoreGrace      = 6 * time.Second
)

type Instance struct {
	mu            sync.Mutex
	state         coreapi.State
	instance      *xcore.Instance
	runID         uint64
	startInFlight bool
	lastError     error
	lastConfig    json.RawMessage
	// session lives exactly as long as the running core: every flow carried
	// by it (tunnel flows and inbound sessions alike) derives from it, so
	// stopping or replacing the core ends them instead of leaving them
	// attached to the old server.
	session    context.Context
	endSession context.CancelFunc

	stats *statsClient
	logs  *LogBuffer

	// extendedLogs — режим разработчика. Когда выключен (по умолчанию),
	// туннель не пишет ничего: ни beam-debug диагностику, ни файлы на диске.
	extendedLogs atomic.Bool

	connections func() []coreapi.Connection
	logOptions  coreapi.LogOptions

	onStateChange func(coreapi.State, error)
	stateEvents   chan stateEvent

	paths paths.Paths
}

type stateEvent struct {
	state coreapi.State
	err   error
}

type Options struct {
	Paths paths.Paths
}

func New(opts Options) *Instance {
	inst := &Instance{
		state:       coreapi.StateStopped,
		paths:       opts.Paths,
		logs:        NewLogBuffer(defaultLogBufferSize),
		stats:       newStatsClient(),
		stateEvents: make(chan stateEvent, 16),
		logOptions:  coreapi.LogOptions{CoreLogging: true},
	}
	inst.installCrashHook()
	go inst.dispatchStateEvents()
	return inst
}

func (i *Instance) SetStateCallback(cb func(coreapi.State, error)) {
	i.mu.Lock()
	i.onStateChange = cb
	i.mu.Unlock()
}

func (i *Instance) Start(ctx context.Context, config json.RawMessage) error {
	i.mu.Lock()
	if i.startInFlight {
		i.mu.Unlock()
		return errors.New("core is already starting")
	}
	if i.instance != nil {
		i.mu.Unlock()
		return errors.New("core is already running")
	}
	i.startInFlight = true
	i.runID++
	runID := i.runID
	i.lastConfig = config
	i.mu.Unlock()

	i.setState(coreapi.StateStarting, nil)

	// Зеркало лога и снимок конфига пишутся на диск только в режиме
	// разработчика — по умолчанию туннель не создаёт файлов вообще.
	if i.ExtendedLogsEnabled() && i.logs.CoreLoggingEnabled() {
		i.logs.EnableFileLog(i.paths.Data)
		i.logs.WriteSidecar("last-config.json", config)
	}

	session, endSession := context.WithCancel(context.Background())
	instance, err := i.buildInstance(session, config)
	if err != nil {
		endSession()
		i.finishFailedStart(runID, err)
		return err
	}

	if err := safeCoreStart(instance); err != nil {
		endSession()
		closeCoreWithTimeout(instance, stopCoreGrace)
		i.finishFailedStart(runID, err)
		return err
	}

	i.mu.Lock()
	if i.runID != runID {
		i.mu.Unlock()
		endSession()
		closeCoreWithTimeout(instance, stopCoreGrace)
		return errors.New("start superseded")
	}
	i.instance = instance
	i.session = session
	i.endSession = endSession
	i.startInFlight = false
	i.lastError = nil
	i.mu.Unlock()

	i.setState(coreapi.StateRunning, nil)
	i.installCoreLogSink(instance)
	i.startTrafficSampler(runID)
	go i.watchStartup(ctx, runID)
	return nil
}

func (i *Instance) LastConfig() json.RawMessage {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.lastConfig
}

func (i *Instance) buildInstance(session context.Context, config json.RawMessage) (*xcore.Instance, error) {
	parsed, err := safeLoadConfig(config)
	if err != nil {
		return nil, fmt.Errorf("invalid core config: %w", err)
	}
	instance, err := xcore.NewWithContext(session, parsed)
	if err != nil {
		return nil, fmt.Errorf("create core: %w", err)
	}
	return instance, nil
}

// safeLoadConfig contains panics raised while the core builds its config.
// Xray dereferences unset fields for some protocols, so a malformed outbound
// would otherwise take the whole app down instead of failing the connection.
func safeLoadConfig(config json.RawMessage) (parsed *xcore.Config, err error) {
	defer func() {
		if r := recover(); r != nil {
			parsed = nil
			err = fmt.Errorf("core panicked while loading config: %v", r)
		}
	}()
	return xcore.LoadConfig("json", bytes.NewReader(config))
}

func safeCoreStart(instance *xcore.Instance) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("core panicked on start: %v", r)
		}
	}()
	return instance.Start()
}

func safeCoreClose(instance *xcore.Instance) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("core panicked on close: %v", r)
		}
	}()
	return instance.Close()
}

func closeCoreWithTimeout(instance *xcore.Instance, grace time.Duration) error {
	done := make(chan error, 1)
	go func() { done <- safeCoreClose(instance) }()
	select {
	case err := <-done:
		return err
	case <-time.After(grace):
		return errors.New("core close timed out")
	}
}

func (i *Instance) watchStartup(ctx context.Context, runID uint64) {
	timer := time.NewTimer(startupProbeBudget)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return
	case <-timer.C:
	}

	i.mu.Lock()
	stale := i.runID != runID || i.instance == nil
	instance := i.instance
	i.mu.Unlock()
	if stale {
		return
	}
	if !instance.IsRunning() {
		i.setState(coreapi.StateFailed, errors.New("core stopped unexpectedly after start"))
	}
}

func (i *Instance) finishFailedStart(runID uint64, err error) {
	i.mu.Lock()
	if i.runID == runID {
		i.startInFlight = false
		i.lastError = err
		i.instance = nil
	}
	i.mu.Unlock()
	i.setState(coreapi.StateFailed, err)
}

func (i *Instance) Stop() error {
	i.mu.Lock()
	instance := i.instance
	endSession := i.endSession
	i.instance = nil
	i.session = nil
	i.endSession = nil
	i.startInFlight = false
	i.runID++
	i.mu.Unlock()

	i.stats.close()

	// End the flows first: the apps see their connections drop and
	// reconnect through whatever runs next, and Close does not wait on them.
	if endSession != nil {
		endSession()
	}

	if instance == nil {
		i.setState(coreapi.StateStopped, nil)
		return nil
	}
	err := closeCoreWithTimeout(instance, stopCoreGrace)
	i.setState(coreapi.StateStopped, nil)
	return err
}

func (i *Instance) Running() bool {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.instance != nil && i.instance.IsRunning()
}

func (i *Instance) Core() *xcore.Instance {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.instance
}

// Session returns the running core together with its session context, which
// is cancelled when that core stops. Flows must be bound to it.
func (i *Instance) Session() (*xcore.Instance, context.Context) {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.instance, i.session
}

func (i *Instance) GetState() coreapi.State {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.state
}

func (i *Instance) GetLastError() error {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.lastError
}

func (i *Instance) GetLogBuffer() *LogBuffer {
	return i.logs
}

func (i *Instance) setState(state coreapi.State, err error) {
	i.mu.Lock()
	if i.state == state && err == nil {
		i.mu.Unlock()
		return
	}
	i.state = state
	if err != nil {
		i.lastError = err
	}
	i.mu.Unlock()

	i.debugf("state -> %s err=%v", state, err)

	select {
	case i.stateEvents <- stateEvent{state: state, err: err}:
	default:
	}
}

func (i *Instance) dispatchStateEvents() {
	for event := range i.stateEvents {
		i.mu.Lock()
		cb := i.onStateChange
		i.mu.Unlock()
		if cb != nil {
			deliverStateEvent(cb, event)
		}
	}
}

func deliverStateEvent(cb func(coreapi.State, error), event stateEvent) {
	defer func() {
		_ = recover()
	}()
	cb(event.state, event.err)
}

func isTransientStartError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	for _, signature := range []string{
		"already exists",
		"already in use",
		"file exists",
		"device or resource busy",
	} {
		if strings.Contains(msg, signature) {
			return true
		}
	}
	return false
}
