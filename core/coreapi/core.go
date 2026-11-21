package coreapi

import (
	"context"
	"encoding/json"
	"net"
	"time"

	"beam-bridge/core/types"
)

type State string

const (
	StateStopped  State = "stopped"
	StateStarting State = "starting"
	StateRunning  State = "running"
	StateFailed   State = "failed"
)

type Connection struct {
	ID          string
	Network     string
	Host        string
	Destination string
	Outbound    string
	ProcessPath string
	Upload      int64
	Download    int64
	Start       time.Time

	// Domain is the sniffed or resolved domain, "" when unknown.
	Domain string
	// Protocol is the sniffed application protocol (tls, http1, quic...).
	Protocol string
	// Route is the route class: "proxy", "direct" or "block".
	Route string
	// RuleKind says why the route was taken: "app" (per-app rule),
	// "rules" (core routing rules), "default", "lan", "dns".
	RuleKind string
	// Rule is the ruleTag of the matched core rule, "" when none.
	Rule string
	// End is when the flow closed; zero while it is open.
	End time.Time
}

// ConnectionHistory is implemented by cores that keep recently closed
// connections and can close live ones.
type ConnectionHistory interface {
	// RecentConnections returns flows closed within the history window,
	// newest first.
	RecentConnections() []Connection
	// CloseConnections closes the live flows with the given IDs.
	CloseConnections(ids []string) int
}

// FlowTraffic is tunnel traffic accrued since the previous drain, grouped by
// application and route ("proxy", "direct", "block").
type FlowTraffic struct {
	ProcessPath string
	Route       string
	Upload      int64
	Download    int64
	// Blocked is the number of flows dropped by the routing rules.
	Blocked int64
}

// FlowAccounting is implemented by cores that attribute traffic to apps.
type FlowAccounting interface {
	// DrainFlowTraffic returns the traffic since the previous call and
	// whether the tunnel (per-app attribution) is up.
	DrainFlowTraffic() (flows []FlowTraffic, tunnel bool)
}

type Stats struct {
	DownloadTotal int64
	UploadTotal   int64
	ActiveConns   int
}

type LogOptions struct {
	Trace        bool
	CoreLogging  bool
	RealityDebug bool
	// ExtendedLogs — режим разработчика: beam-debug харнесс (сэмплер, OPEN/CLOSE
	// потоков, логи монитора сети) и запись логов на диск. По умолчанию выключено.
	ExtendedLogs bool
	// MinLevel — минимальный уровень сообщений, попадающих в буфер вкладки
	// «Логи»: "error" | "info" | "debug" | "off". Пустая строка = "info".
	// "off" эквивалентно CoreLogging=false. Даёт пользователю осмысленные
	// события (старт/стоп, маршруты, ошибки) без потока рутины ядра.
	MinLevel string
}

type LogStore interface {
	Add(entry types.LogEntry)
	GetAll() []types.LogEntry
	GetSince(afterID int64, limit int) []types.LogEntry
	GetFiltered(level types.LogLevel, source string, limit int) []types.LogEntry
	Clear()
	SetSink(sink func(types.LogEntry))
}

type Core interface {
	Start(ctx context.Context, config json.RawMessage) error

	Stop() error

	Running() bool

	Traffic() (download, upload int64)

	Stats() (*Stats, error)

	Connections() ([]Connection, error)

	Delay(ctx context.Context, tag string, timeout time.Duration) (int64, error)

	Healthy() bool

	LastTrafficTime() time.Time

	SetLogOptions(opts LogOptions)

	Logs() LogStore

	SetStateCallback(func(State, error))
}

// DirectRoute is implemented by cores that own a tunnel holding the default
// route. Measurements use it so that a probe never runs through the very VPN
// it is judging.
type DirectRoute interface {
	// DirectInterface is the physical interface while the tunnel is up and
	// "" otherwise (plain sockets already leave the host directly then).
	DirectInterface() string
	// DialDirect opens a connection that leaves through the physical
	// interface.
	DialDirect(ctx context.Context, network, address string) (net.Conn, error)
}
