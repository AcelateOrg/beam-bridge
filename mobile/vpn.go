//go:build linux

package mobile

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	domainSettings "beam-bridge/core/domain/settings"
	"beam-bridge/core/profile"
	"beam-bridge/core/runner"
	"beam-bridge/core/xray"
	"beam-tun/device"
)

// SocketProtector is implemented by the Android VpnService: Protect(fd) calls
// VpnService.protect so the socket leaves through the physical network
// instead of looping back into the tunnel.
type SocketProtector interface {
	Protect(fd int) bool
}

var (
	coreMu    sync.Mutex
	core      *runner.Service
	protector atomic.Value // SocketProtector

	registerControllers sync.Once
	errProtect          = errors.New("VpnService.protect refused the socket")

	// tunnelUp: a socket protect refused while the tunnel runs would loop into it;
	// with no tunnel (server checks while disconnected) it simply goes out as is.
	tunnelUp atomic.Bool
)

// TunAddress (CIDR) and TunDNS are what VpnService.Builder must configure:
// the stack listens on that address and answers DNS on that resolver.
const (
	TunAddress = runner.TunAddress
	TunDNS     = runner.TunResolver
)

// SetProtector installs the VpnService protect hook on every socket the core
// opens (dialed and listening). Call it before Connect.
func SetProtector(p SocketProtector) {
	if p != nil {
		protector.Store(p)
	}
	registerControllers.Do(func() {
		_ = xray.RegisterSocketControl(protectSocket)
		// Server names are resolved after establish(): through the system
		// resolver that lookup would ride the VPN network into a core that
		// is not running yet, or that needs this very address to answer.
		profile.SetResolverDialControl(protectSocket)
	})
}

func protectSocket(network, address string, conn syscall.RawConn) error {
	p, _ := protector.Load().(SocketProtector)
	if p == nil {
		return nil
	}
	var ok bool
	if err := conn.Control(func(fd uintptr) { ok = p.Protect(int(fd)) }); err != nil {
		return err
	}
	if !ok && tunnelUp.Load() {
		return errProtect
	}
	return nil
}

func runnerService() (*runner.Service, error) {
	m, err := manager()
	if err != nil {
		return nil, err
	}
	coreMu.Lock()
	defer coreMu.Unlock()
	if core == nil {
		mu.Lock()
		s, p := settings, paths
		mu.Unlock()
		core = runner.New(runner.Options{
			Paths:      p,
			Connection: func() domainSettings.ConnectionSettings { return s.Get().Connection },
			Routes:     m.GetRoutePlan,
		})
		// The bridge's own probes (TCP server checks, the TCP connection ping)
		// are plain Go sockets: unprotected, they would be answered by the
		// tunnel's own stack in a millisecond instead of by the server.
		core.SetDeviceDialControl(protectSocket)
		// Server checks reuse the running core when connected.
		m.SetCore(core)
		// The journal level is a stored setting, applied as soon as the core exists.
		applyLogLevel(core.SetLogOptions, LogLevel())
	}
	return core, nil
}

// Connect builds the Xray config of the active profile and node and runs it
// on the TUN descriptor from VpnService.Builder.establish(). Ownership of fd
// passes to the bridge (use ParcelFileDescriptor.detachFd()); it is closed
// on failure and on Disconnect.
func Connect(fd int, mtu int) error {
	m, err := manager()
	if err != nil {
		closeFD(fd)
		return err
	}
	config := m.GetActiveConfig()
	if len(config) == 0 {
		closeFD(fd)
		return errors.New("нет активного профиля или сервера для подключения")
	}
	svc, err := runnerService()
	if err != nil {
		closeFD(fd)
		return err
	}
	dev, err := device.OpenFD(fd, mtu)
	if err != nil {
		closeFD(fd)
		return err
	}
	svc.SetProcessResolver(androidResolver{})
	svc.SetDeviceIPv6(deviceIPv6.Load())
	if err := svc.StartOnDevice(context.Background(), config, dev); err != nil {
		return err
	}
	tunnelUp.Store(true)
	startAccounting(svc)
	return nil
}

// Reconnect rebuilds the core from the current active profile and node while
// the tunnel stays up: call it after SetActiveProfile or SelectNode on a live
// connection to switch servers without dropping the interface, or to recover
// a core that stopped passing traffic. It blocks until the new core runs. On
// error the core is down; calling Reconnect again may still recover it.
func Reconnect() error {
	m, err := manager()
	if err != nil {
		return err
	}
	config := m.GetActiveConfig()
	if len(config) == 0 {
		return errors.New("нет активного профиля или сервера для подключения")
	}
	coreMu.Lock()
	svc := core
	coreMu.Unlock()
	if svc == nil || !tunnelUp.Load() {
		return errors.New("VPN не запущен")
	}
	return svc.RestartOnDevice(context.Background(), config)
}

func closeFD(fd int) {
	if fd >= 0 {
		_ = syscall.Close(fd)
	}
}

// Disconnect stops the stack and the core. Safe to call when not connected.
func Disconnect() error {
	coreMu.Lock()
	svc := core
	coreMu.Unlock()
	if svc == nil {
		return nil
	}
	tunnelUp.Store(false)
	stopAccounting()
	return svc.Stop()
}

// IsRunning reports whether the core is up.
func IsRunning() bool {
	coreMu.Lock()
	svc := core
	coreMu.Unlock()
	return svc != nil && svc.Running()
}

// TrafficDown and TrafficUp are the bytes moved since Connect.
func TrafficDown() int64 {
	d, _ := traffic()
	return d
}

func TrafficUp() int64 {
	_, u := traffic()
	return u
}

func traffic() (int64, int64) {
	coreMu.Lock()
	svc := core
	coreMu.Unlock()
	if svc == nil || !svc.Running() {
		return 0, 0
	}
	return svc.Traffic()
}

// Delay measures a real request through the active proxy outbound, in ms;
// -1 when it fails. It blocks for up to timeoutMs.
func Delay(timeoutMs int) int64 {
	m, err := manager()
	if err != nil {
		return -1
	}
	coreMu.Lock()
	svc := core
	coreMu.Unlock()
	if svc == nil || !svc.Running() {
		return -1
	}
	timeout := time.Duration(timeoutMs) * time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	// "Пинг подключения": TCP is the handshake to the server, HTTP a real
	// request through the tunnel.
	if mu.Lock(); settings != nil && settings.Get().Ping.ConnectionMode == "tcp" {
		mu.Unlock()
		return tcpConnectionPing(ctx)
	}
	mu.Unlock()
	return proxyDelay(ctx, svc, m.GetProxyTag(), timeout)
}

// ProxyDelay is a real request through the active proxy outbound, in ms, -1
// when it fails, whatever the "Пинг подключения" setting: unlike a handshake
// with the server it tells whether traffic actually passes the tunnel. It
// blocks for up to timeoutMs.
func ProxyDelay(timeoutMs int) int64 {
	m, err := manager()
	if err != nil {
		return -1
	}
	coreMu.Lock()
	svc := core
	coreMu.Unlock()
	if svc == nil || !svc.Running() {
		return -1
	}
	timeout := time.Duration(timeoutMs) * time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return proxyDelay(ctx, svc, m.GetProxyTag(), timeout)
}

func proxyDelay(ctx context.Context, svc *runner.Service, tag string, timeout time.Duration) int64 {
	ms, err := svc.Delay(ctx, tag, timeout)
	if err != nil {
		return -1
	}
	return ms
}
