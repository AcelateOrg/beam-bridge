package xray

import (
	"context"
	"errors"
	"net"
	"time"

	"beam-bridge/core/coreapi"
	"beam-bridge/core/probe"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	xcore "github.com/xtls/xray-core/core"
)

func (i *Instance) Traffic() (download, upload int64) {
	if !i.Running() {
		return 0, 0
	}
	return i.stats.traffic(i.Core())
}

func (i *Instance) Stats() (*coreapi.Stats, error) {
	if !i.Running() {
		return nil, nil
	}
	download, upload := i.stats.traffic(i.Core())
	return &coreapi.Stats{
		DownloadTotal: download,
		UploadTotal:   upload,
		ActiveConns:   i.stats.activeCount(),
	}, nil
}

func (i *Instance) Connections() ([]coreapi.Connection, error) {
	if !i.Running() {
		return nil, nil
	}
	i.mu.Lock()
	source := i.connections
	i.mu.Unlock()
	if source == nil {
		return nil, nil
	}
	return source(), nil
}

func (i *Instance) TrackConnections(source func() []coreapi.Connection) {
	i.mu.Lock()
	i.connections = source
	i.mu.Unlock()
}

func (i *Instance) flowStarted() { i.stats.flowStarted() }

func (i *Instance) flowFinished() { i.stats.flowFinished() }

func (i *Instance) Healthy() bool {
	return i.Running()
}

func (i *Instance) LastTrafficTime() time.Time {
	return i.stats.lastTrafficTime()
}

func (i *Instance) SetLogOptions(opts coreapi.LogOptions) {
	coreEnabled := opts.CoreLogging && opts.MinLevel != "off"
	i.logs.SetCoreLogging(coreEnabled)
	i.logs.SetMinLevel(opts.MinLevel)
	i.extendedLogs.Store(opts.ExtendedLogs)

	i.mu.Lock()
	i.logOptions = opts
	i.mu.Unlock()

	// Файловое зеркало живёт только в режиме разработчика: выключение режима
	// сразу закрывает файл, включение на работающем ядре — открывает.
	if !opts.ExtendedLogs {
		i.logs.DisableFileLog()
	} else if opts.CoreLogging && i.Running() {
		i.logs.EnableFileLog(i.paths.Data)
	}
}

// ExtendedLogsEnabled сообщает, включён ли режим разработчика с расширенной
// диагностикой. Выключен по умолчанию: beam-debug харнесс и запись на диск
// активны только когда он включён.
func (i *Instance) ExtendedLogsEnabled() bool {
	return i != nil && i.extendedLogs.Load()
}

func (i *Instance) LogOptions() coreapi.LogOptions {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.logOptions
}

func (i *Instance) Logs() coreapi.LogStore { return i.logs }

func (i *Instance) Delay(ctx context.Context, tag string, timeout time.Duration) (int64, error) {
	instance := i.Core()
	if instance == nil {
		return -1, errors.New("core is not running")
	}
	if timeout <= 0 {
		timeout = 5 * time.Second
	}

	probeCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// The probe goes straight to the outbound named by tag, bypassing
	// routing: an inbound tag alone matches no rule in the live config, so
	// every node used to be measured through the final (active) outbound.
	return probe.HTTP(probeCtx, func(dialCtx context.Context, _, address string) (net.Conn, error) {
		destination, err := probeDestination(address)
		if err != nil {
			return nil, err
		}
		if tag != "" {
			dialCtx = session.SetForcedOutboundTagToContext(dialCtx, tag)
		}
		return xcore.Dial(dialCtx, instance, destination)
	})
}

func probeDestination(address string) (xnet.Destination, error) {
	destination, err := xnet.ParseDestination("tcp:" + address)
	if err != nil {
		return xnet.Destination{}, err
	}
	return destination, nil
}
