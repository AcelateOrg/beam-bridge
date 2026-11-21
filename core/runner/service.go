package runner

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"beam-bridge/core/coreapi"
	domainSettings "beam-bridge/core/domain/settings"
	"beam-bridge/core/paths"
	"beam-bridge/core/platform"
	"beam-bridge/core/sysproxy"
	"beam-bridge/core/types"
	"beam-bridge/core/xray"
	tun "beam-tun"
	"beam-tun/device"
	"beam-tun/dialer"
	"beam-tun/firewall"
	"beam-tun/netcfg"
	"beam-tun/process"
	"beam-tun/stack"
)

const tunModeName = "tun"

const defaultTunName = "beam-tun"

const tunAddress = "172.19.0.1/30"

const tunResolver = "172.19.0.2"

const defaultUpstreamDNS = "1.1.1.1"

const dnsPort = 53

const systemProxyModeName = "system_proxy"

const defaultProxyPort = 2080

type Options struct {
	Paths      paths.Paths
	Connection func() domainSettings.ConnectionSettings
	// Routes returns the tunnel routing plan of the active config (per-app
	// inbound tags, bypass/block decisions).
	Routes func() coreapi.RoutePlan
}

type Service struct {
	instance *xray.Instance
	tunnel   *xray.Tunnel
	registry *xray.Registry
	opts     Options

	// direct opens sockets pinned to the physical interface: bypassed apps
	// and relayed pings leave through it without entering the core.
	direct *dialer.Direct

	// proxy points the OS proxy settings at the local inbound in
	// system_proxy mode and restores the user's own on disconnect.
	proxy *sysproxy.Manager

	// lifecycleMu сериализует Start и Stop: пока один не завершился, другой
	// ждёт. Без этого Stop во время медленного Start видел пустые поля и
	// завершался «успешно», а запоздавший Start создавал адаптер и стек уже
	// после остановки — отсюда виснущий BeamTunnel в системе и 0x800700B7 /
	// 0x4DF при следующем подключении.
	lifecycleMu sync.Mutex

	mu      sync.Mutex
	stack   *stack.Stack
	network netcfg.Network
	monitor *netcfg.Monitor
	tunName string

	// deviceProcess is the flow-to-app resolver of a StartOnDevice session.
	deviceProcess tun.ProcessResolver
	deviceIPv6    bool
	// deviceControl keeps a socket out of a StartOnDevice tunnel
	// (VpnService.protect). Such a session has no physical interface to pin
	// to, so without it DialDirect would loop into the tunnel.
	deviceControl func(network, address string, c syscall.RawConn) error

	// boundIface is the physical interface the running core config was
	// built with (sockopt.interface of its outbounds); "" when none was
	// known at start. The core cannot re-pin live outbounds, so a change
	// of the physical interface has to restart it (onIfaceChange).
	boundIface    string
	onIfaceChange func()
}

func New(opts Options) *Service {
	instance := xray.New(xray.Options{Paths: opts.Paths})
	registry := xray.NewRegistry()

	direct := dialer.New()
	tunnel := xray.NewTunnel(instance)
	tunnel.SetRegistry(registry)
	tunnel.SetDirectDialer(direct)
	instance.TrackConnections(registry.Snapshot)

	s := &Service{
		instance: instance,
		tunnel:   tunnel,
		registry: registry,
		opts:     opts,
		direct:   direct,
		proxy:    sysproxy.New(opts.Paths.Data),
	}
	netcfg.Warnings = s.reportTunnelWarning
	// A proxy left pointing at a dead port by a crash cuts the user off.
	go func() {
		defer platform.RecoverAndLog("sysproxy-recover")
		s.proxy.Recover()
	}()
	if runtime.GOOS != "windows" {
		// A crash with the tunnel up leaves DNS overrides, IPv6 cut-off
		// routes and firewall rules behind; undo them before anything else.
		go func() {
			defer platform.RecoverAndLog("tun-recover")
			netcfg.RecoverStale()
			firewall.Default().Recover()
		}()
	}
	return s
}

// Start brings up the core and, in TUN mode, the adapter, its network
// configuration and the stack. Whatever a previous session may have left
// behind is torn down first, so there is never a second adapter.
func (s *Service) Start(ctx context.Context, config json.RawMessage) error {
	// Start, Restart and Stop are mutually exclusive: a disconnect in the
	// middle of a connect cannot leave a half-built adapter alive.
	s.lifecycleMu.Lock()
	defer s.lifecycleMu.Unlock()
	_ = s.stopLocked()
	return s.startLocked(ctx, config)
}

// startLocked is the body of Start; lifecycleMu is held and nothing is up.
//
// In TUN mode the adapter is opened in parallel with the core start: the two
// do not depend on each other, and on the first connect after launch the
// adapter may still be getting registered by Windows.
func (s *Service) startLocked(ctx context.Context, config json.RawMessage) error {
	connection := s.connectionSettings()
	tunMode := connection.Mode == tunModeName
	timer := newStageTimer()

	var opened <-chan openedDevice
	if tunMode {
		opened = openDeviceAsync(tunNameOf(connection), connection.MTU)
		iface := s.physicalInterface(tunNameOf(connection))
		s.setBoundInterface(iface)
		config = bindDirectOutbound(config, iface, socketMark())
		timer.mark("iface")
	} else {
		s.setBoundInterface("")
		config = bindDirectOutbound(config, "", socketMark())
	}

	if err := s.instance.Start(ctx, config); err != nil {
		if opened != nil {
			// Wait for it: a session left open would make the next connect
			// fail with "adapter busy".
			if r := <-opened; r.dev != nil {
				_ = r.dev.Close()
			}
		}
		return err
	}

	timer.mark("core")
	s.applyRoutes(config)

	if !tunMode {
		s.applySystemProxy(connection)
		s.logTiming("proxy up in", timer)
		return nil
	}

	r := <-opened
	timer.mark("adapter wait")
	timer.note("adapter open", r.took)
	if r.err != nil {
		_ = s.instance.Stop()
		return r.err
	}
	if err := s.startTunnel(connection, config, r.dev, timer); err != nil {
		_ = s.instance.Stop()
		return err
	}
	s.logTiming("tunnel up in", timer)
	return nil
}

type openedDevice struct {
	dev  tun.Device
	err  error
	took time.Duration
}

// openDeviceAsync checks the tunnel address is free and opens the adapter in
// the background. The channel always receives exactly one result.
func openDeviceAsync(name string, mtu int) <-chan openedDevice {
	out := make(chan openedDevice, 1)
	go func() {
		var result openedDevice
		started := time.Now()
		defer func() {
			if r := recover(); r != nil {
				result = openedDevice{err: fmt.Errorf("open tunnel interface: panic: %v", r)}
			}
			result.took = time.Since(started)
			out <- result
		}()
		// A second tunnel on the same address (e.g. the release build and a
		// dev build connected at once) would fight over the default route:
		// packets bounce between the two, ping multiplies and ICMP dies.
		// Refuse early with a clear message instead.
		prefix := netip.MustParsePrefix(tunAddress)
		if err := netcfg.CheckAddressFree(prefix.Addr(), name); err != nil {
			result.err = err
			return
		}
		dev, err := device.Open(name, mtu)
		if err != nil {
			result.err = fmt.Errorf("open tunnel interface: %w", err)
			return
		}
		result.dev = dev
	}()
	return out
}

// Prewarm creates the TUN adapter in the background at app start, so the
// first Connect does not wait for Windows to install and register it.
// Harmless outside TUN mode and on platforms where creation is cheap.
func (s *Service) Prewarm() {
	connection := s.connectionSettings()
	if connection.Mode != tunModeName {
		return
	}
	name := tunNameOf(connection)
	go func() {
		defer platform.RecoverAndLog("tun-prewarm")
		if err := device.Prepare(name); err != nil {
			s.instance.Debugf("tun prewarm: %v", err)
		}
	}()
}

// bindDirectOutbound pins every freedom outbound to the physical interface.
//
// In TUN mode the default route belongs to the tunnel, so a socket opened by
// the core itself goes straight back into it: the packet re-enters the stack,
// routing picks the same outbound again and the core loops, opening thousands
// of connections per second (visible as "proxy/freedom: connection opened ...
// local endpoint 172.19.0.1"). Binding the socket to the interface that holds
// the host default route makes it leave the machine for real.
//
// Proxy outbounds need exactly the same treatment. A bypass route for the
// server address is not enough on its own: it is installed for one address at
// a time, it is lost whenever the host routing table is rebuilt, and Xray has
// no auto-detect-interface of its own. Without the binding the dial to the
// server follows the tunnel's own default route, so the connection dies as
// soon as the tunnel is up - the symptom being a few seconds of working
// traffic followed by "dial tcp <server>: operation was canceled" and
// "connectex: a socket operation was attempted to an unreachable host".
//
// On Linux every outbound socket also carries tun.SocketMark: the kill
// switch and leak protection (nftables) let marked sockets through.
func bindDirectOutbound(config json.RawMessage, iface string, mark int) json.RawMessage {
	iface = strings.TrimSpace(iface)
	if iface == "" && mark == 0 {
		return config
	}

	var parsed map[string]any
	if err := json.Unmarshal(config, &parsed); err != nil {
		return config
	}
	outbounds, ok := parsed["outbounds"].([]any)
	if !ok {
		return config
	}

	changed := false
	for _, item := range outbounds {
		outbound, ok := item.(map[string]any)
		if !ok {
			continue
		}
		// dns and blackhole never open a socket of their own, everything
		// else (freedom and every proxy outbound) does and must leave the
		// machine through the physical interface.
		switch protocol, _ := outbound["protocol"].(string); protocol {
		case "", "dns", "blackhole":
			continue
		}
		stream, ok := outbound["streamSettings"].(map[string]any)
		if !ok {
			stream = map[string]any{}
			outbound["streamSettings"] = stream
		}
		sockopt, ok := stream["sockopt"].(map[string]any)
		if !ok {
			sockopt = map[string]any{}
			stream["sockopt"] = sockopt
		}
		if iface != "" {
			sockopt["interface"] = iface
		}
		if mark != 0 {
			sockopt["mark"] = mark
		}
		changed = true
	}
	if !changed {
		return config
	}

	updated, err := json.Marshal(parsed)
	if err != nil {
		return config
	}
	return updated
}

// physicalInterface finds the interface holding the host default route (the
// tunnel excluded) and pins the direct dialer to it. Returns "" when none is
// known; bypassing then falls back to the core's direct outbound.
func (s *Service) physicalInterface(tunName string) string {
	iface, err := netcfg.DefaultInterface(tunName)
	iface = strings.TrimSpace(iface)
	if err != nil || iface == "" {
		_ = s.direct.SetInterface("")
		return ""
	}
	if err := s.direct.SetInterface(iface); err != nil {
		s.reportTunnelWarning(err)
	}
	s.instance.Debugf("direct dialer bound to %q %+v", iface, s.direct.Interface())
	return iface
}

func (s *Service) setBoundInterface(iface string) {
	s.mu.Lock()
	s.boundIface = strings.TrimSpace(iface)
	s.mu.Unlock()
}

// SetInterfaceChangeCallback subscribes to "the physical interface is no
// longer the one the core is bound to". The callback must re-apply the
// active config (Restart); it is called on its own goroutine.
func (s *Service) SetInterfaceChangeCallback(cb func()) {
	s.mu.Lock()
	s.onIfaceChange = cb
	s.mu.Unlock()
}

// checkBinding asks for a core restart when the physical interface differs
// from the one baked into the running config. The typical case is a boot on
// Wi-Fi: auto-connect runs before Wi-Fi has a default route, the config is
// built with no binding at all, the core's dial to the server follows the
// tunnel's own default route and nothing works (0 B / 0 B, no ping) until a
// manual reconnect. Rebinding the dialer alone does not help: the outbounds
// of the core keep their sockopt from the start.
func (s *Service) checkBinding(iface string) {
	iface = strings.TrimSpace(iface)
	if iface == "" {
		return
	}
	s.mu.Lock()
	bound := s.boundIface
	cb := s.onIfaceChange
	up := s.stack != nil
	s.mu.Unlock()
	if !up || cb == nil || strings.EqualFold(iface, bound) {
		return
	}
	s.instance.Logs().Add(types.LogEntry{
		Timestamp: time.Now().UnixMilli(),
		Level:     types.LogLevelInfo,
		Source:    "tunnel",
		Message:   fmt.Sprintf("physical interface changed (%q -> %q), restarting core", bound, iface),
	})
	// Not inline: the callback ends up in Restart (lifecycleMu), while Stop
	// holds lifecycleMu and waits for the monitor that called us.
	go func() {
		defer platform.RecoverAndLog("tun-rebind")
		cb()
	}()
}

// WaitForNetwork waits until the host has a default route (Wi-Fi comes up
// seconds after logon, later than an autostarted Beam). Returns false on
// timeout or ctx cancel; true right away where it cannot be checked.
func (s *Service) WaitForNetwork(ctx context.Context, timeout time.Duration) bool {
	name := tunNameOf(s.connectionSettings())
	deadline := time.Now().Add(timeout)
	for {
		iface, err := netcfg.DefaultInterface(name)
		if errors.Is(err, netcfg.ErrUnsupported) {
			return true
		}
		if err == nil && strings.TrimSpace(iface) != "" {
			return true
		}
		if !time.Now().Before(deadline) {
			return false
		}
		select {
		case <-ctx.Done():
			return false
		case <-time.After(500 * time.Millisecond):
		}
	}
}

func tunNameOf(connection domainSettings.ConnectionSettings) string {
	name := strings.TrimSpace(connection.TunName)
	if runtime.GOOS == "darwin" {
		// macOS only creates utun devices; "utun" lets the kernel pick
		// the next free number, the real name comes back from the device.
		if strings.HasPrefix(name, "utun") {
			return name
		}
		return "utun"
	}
	if name != "" {
		return name
	}
	return defaultTunName
}

// socketMark is the SO_MARK put on the core's sockets (Linux only, and only
// when the process may set it: a failing sockopt would fail every dial).
func socketMark() int {
	if tun.SocketMarkUsable() {
		return tun.SocketMark
	}
	return 0
}

// applyRoutes hands the routing plan of the active config to the tunnel and,
// in developer mode, logs every per-app decision.
func (s *Service) applyRoutes(config json.RawMessage) {
	s.tunnel.SetConfig(config)
	if s.opts.Routes == nil {
		return
	}
	plan := s.opts.Routes()
	s.tunnel.SetRoutePlan(plan)
	if !s.instance.ExtendedLogsEnabled() {
		return
	}
	s.instance.Debugf("routes: final=%s defaultBypass=%v byNetwork=%v disableBypass=%v apps=%d", plan.FinalOutbound, plan.DefaultBypass, plan.DefaultBypassNetworks, plan.DisableBypass, len(plan.Apps))
	for app, route := range plan.Apps {
		action := "core"
		switch {
		case route.Bypass:
			action = "bypass-direct"
		case route.Block:
			action = "block"
		}
		outbound := route.Outbound
		if outbound == "" {
			outbound = "(conditional)"
		}
		s.instance.Debugf("routes: app=%q tag=%s outbound=%s action=%s", app, route.Tag, outbound, action)
	}
}

func (s *Service) connectionSettings() domainSettings.ConnectionSettings {
	if s.opts.Connection == nil {
		return domainSettings.ConnectionSettings{Mode: tunModeName}
	}
	return s.opts.Connection()
}

func (s *Service) startTunnel(connection domainSettings.ConnectionSettings, config json.RawMessage, dev tun.Device, timer *stageTimer) error {
	name := tunNameOf(connection)

	prefix := netip.MustParsePrefix(tunAddress)
	s.tunnel.SetLocalPrefix(prefix.Masked())
	s.tunnel.SetDNS(upstreamResolver(connection, prefix.Masked()))

	// The OS does not always keep the requested name. Configuring and
	// monitoring the adapter under a name it does not answer to makes every
	// netsh call fail, so prefer the name the device reports back.
	if named, ok := dev.(interface{ Name() string }); ok {
		if actual := strings.TrimSpace(named.Name()); actual != "" {
			name = actual
		}
	}

	network, err := netcfg.Configure(netcfg.Config{
		Name:    name,
		Address: prefix,
		DNS:     netip.MustParseAddr(tunResolver),
		MTU:     connection.MTU,
		Bypass:  serverAddresses(config),
	})
	if err != nil {
		_ = dev.Close()
		return fmt.Errorf("configure tunnel interface: %w", err)
	}
	timer.mark("netcfg")
	firewall.Default().SetTunnelInterface(name)

	// Inbound to the NAT listener and the IPv6 cut-off, natively through
	// WFP. Only if that fails does the stack add its netsh firewall rule.
	inboundAllowed := false
	if withLUID, ok := network.(interface{ LUID() uint64 }); ok && firewall.Supported() {
		if err := firewall.Default().AttachTunnel(withLUID.LUID()); err != nil {
			s.reportTunnelWarning(err)
		} else {
			inboundAllowed = true
		}
	}
	timer.mark("firewall")

	engine, err := stack.New(stack.Options{
		Device:         dev,
		Handler:        s.tunnel,
		Process:        process.NewResolver(),
		Inet4Address:   prefix,
		EchoSource:     s.direct.Inet4,
		InboundAllowed: inboundAllowed,
		OnError:        s.reportTunnelError,
		OnWarn:         s.reportTunnelWarning,
		Debugf:         s.instance.Debugf,
	})
	if err != nil {
		_ = firewall.Default().DetachTunnel()
		_ = network.Close()
		_ = dev.Close()
		return fmt.Errorf("start tunnel stack: %w", err)
	}
	timer.mark("stack")

	s.mu.Lock()
	s.stack = engine
	s.network = network
	s.monitor = netcfg.NewMonitor(name, prefix.Masked(), s.reapplyNetwork)
	s.tunName = name
	s.mu.Unlock()

	// The network may have come up while the adapter was opening: the
	// monitor took that state as its baseline and will never report it.
	s.checkBinding(s.physicalInterface(name))

	if connection.KillSwitch && killSwitchAvailable {
		s.protectNetwork(network)
		timer.mark("leak guard")
	}
	return nil
}

// reapplyNetwork reinstalls the tunnel routes and DNS after the host network
// changed, for example when switching between Wi-Fi and Ethernet.
func (s *Service) reapplyNetwork(prev, curr string) {
	s.mu.Lock()
	network := s.network
	s.mu.Unlock()
	if network == nil {
		return
	}
	// Диагностика реапплая — только в режиме разработчика. Молчаливый
	// 4s цикл monitor->reapply, найденный по этим строкам, починен в
	// monitor.go (исключены transition-интерфейсы + debounce).
	if s.instance.ExtendedLogsEnabled() {
		s.instance.Logs().Add(types.LogEntry{
			Timestamp: time.Now().UnixMilli(),
			Level:     types.LogLevelWarn,
			Source:    "tunnel",
			Message:   fmt.Sprintf("beam-debug monitor: network change, reapplying routes/DNS\nprev: %s\ncurr: %s", prev, curr),
		})
	}
	if err := network.Reapply(); err != nil {
		s.reportTunnelError(err)
	}
	// The physical interface may have changed (Wi-Fi <-> Ethernet): re-pin
	// the direct dialer so bypassed apps and pings follow it.
	s.mu.Lock()
	name := s.tunName
	s.mu.Unlock()
	// The core's outbounds are pinned too, and only a restart re-pins them.
	s.checkBinding(s.physicalInterface(name))
}

// upstreamResolver picks the resolver used for DNS queries captured by the
// tunnel. Addresses that belong to the tunnel itself or that cannot be dialed
// through the core are skipped so a query can never be routed back into the
// tunnel. The built-in default is used when no candidate is usable.
func upstreamResolver(connection domainSettings.ConnectionSettings, local netip.Prefix) netip.AddrPort {
	candidates := []string{connection.PrimaryDNS, connection.SecondaryDNS, defaultUpstreamDNS}
	for _, candidate := range candidates {
		addr, err := netip.ParseAddr(strings.TrimSpace(candidate))
		if err != nil || !addr.Is4() {
			continue
		}
		if !routableResolver(addr, local) {
			continue
		}
		return netip.AddrPortFrom(addr, dnsPort)
	}
	return netip.AddrPortFrom(netip.MustParseAddr(defaultUpstreamDNS), dnsPort)
}

func routableResolver(addr netip.Addr, local netip.Prefix) bool {
	if local.IsValid() && local.Contains(addr.Unmap()) {
		return false
	}
	return !addr.IsLoopback() &&
		!addr.IsUnspecified() &&
		!addr.IsMulticast() &&
		!addr.IsLinkLocalUnicast() &&
		!addr.IsLinkLocalMulticast()
}

func serverAddresses(config json.RawMessage) []netip.Addr {
	var parsed struct {
		Outbounds []map[string]any `json:"outbounds"`
	}
	if err := json.Unmarshal(config, &parsed); err != nil {
		return nil
	}

	seen := make(map[netip.Addr]struct{})
	var addresses []netip.Addr
	for _, outbound := range parsed.Outbounds {
		for _, value := range collectStrings(outbound["settings"]) {
			addr, err := netip.ParseAddr(value)
			if err != nil || addr.IsLoopback() || addr.IsUnspecified() {
				continue
			}
			if _, duplicate := seen[addr]; duplicate {
				continue
			}
			seen[addr] = struct{}{}
			addresses = append(addresses, addr)
		}
	}
	return addresses
}

func collectStrings(value any) []string {
	switch typed := value.(type) {
	case map[string]any:
		var out []string
		for key, nested := range typed {
			if key == "address" || key == "server" {
				if text, ok := nested.(string); ok {
					out = append(out, text)
					continue
				}
			}
			out = append(out, collectStrings(nested)...)
		}
		return out
	case []any:
		var out []string
		for _, nested := range typed {
			out = append(out, collectStrings(nested)...)
		}
		return out
	default:
		return nil
	}
}

func (s *Service) reportTunnelError(err error) {
	if err == nil {
		return
	}
	platform.LogCrashEvent("tunnel: %v", err)
	// The in-app log store is invisible while developing, and a tunnel that
	// fails here is the difference between "slow" and "nothing works at all".
	fmt.Fprintf(os.Stderr, "[beam] tunnel: %v\n", err)
	s.instance.Logs().Add(types.LogEntry{
		Timestamp: time.Now().UnixMilli(),
		Level:     types.LogLevelError,
		Source:    "tunnel",
		Message:   err.Error(),
	})
}

// reportTunnelWarning — для ожидаемых, самовосстанавливающихся ситуаций
// (например, хост отозвал SYN до завершения рукопожатия). Не пишется в
// crash.log и не срёт в ERROR: на уровне «Основные» остаются только
// содержательные строки, а это видно в «Подробных».
func (s *Service) reportTunnelWarning(err error) {
	if err == nil {
		return
	}
	s.instance.Logs().Add(types.LogEntry{
		Timestamp: time.Now().UnixMilli(),
		Level:     types.LogLevelDebug,
		Source:    "tunnel",
		Message:   err.Error(),
	})
}

// Restart меняет конфигурацию ядра на лету, НЕ трогая TUN-адаптер и стек:
// пересоздаются только Xray и маршруты под новые серверы. Адаптер удаляется
// только при настоящем отключении (Stop). Если горячая замена невозможна
// (ядро не работает, туннель не поднят или сменился режим подключения),
// выполняется честный полный цикл Stop+Start.
func (s *Service) Restart(ctx context.Context, config json.RawMessage) error {
	s.lifecycleMu.Lock()
	defer s.lifecycleMu.Unlock()

	connection := s.connectionSettings()
	tunMode := connection.Mode == tunModeName

	s.mu.Lock()
	tunnelUp := s.stack != nil
	s.mu.Unlock()

	if !s.instance.Running() || tunMode != tunnelUp {
		_ = s.stopLocked()
		return s.startLocked(ctx, config)
	}

	if tunMode {
		iface := s.physicalInterface(tunNameOf(connection))
		s.setBoundInterface(iface)
		config = bindDirectOutbound(config, iface, socketMark())
	} else {
		s.setBoundInterface("")
		config = bindDirectOutbound(config, "", socketMark())
	}

	// Гасим только ядро: адаптер, стек и монитор живут дальше.
	_ = s.instance.Stop()

	if err := s.instance.Start(ctx, config); err != nil {
		return err
	}

	s.applyRoutes(config)

	if !tunMode {
		s.applySystemProxy(connection)
		return nil
	}

	s.registry.Reset()

	// Маршруты/DNS под новые серверы — адаптер и стек не пересоздаются.
	return s.refreshTunnelNetwork(connection, config)
}

// refreshTunnelNetwork переводит bypass-маршруты на серверы новой
// конфигурации. Адрес, DNS, MTU и split-маршруты от смены ноды не зависят,
// поэтому полный teardown+setup (пара десятков процессов netsh и заметные
// секунды «отключено» в UI) нужен только если точечное обновление не
// удалось или сетевой слой ещё не поднят.
func (s *Service) refreshTunnelNetwork(connection domainSettings.ConnectionSettings, config json.RawMessage) error {
	s.mu.Lock()
	network := s.network
	name := s.tunName
	s.mu.Unlock()

	newBypass := serverAddresses(config)
	if network != nil {
		if updater, ok := network.(interface {
			UpdateBypass([]netip.Addr) error
		}); ok {
			if err := updater.UpdateBypass(newBypass); err == nil {
				return nil
			} else {
				platform.LogCrashEvent("tunnel: bypass refresh failed, doing full reconfigure: %v", err)
			}
		}
	}

	// Запасной путь: полная переконфигурация.
	s.mu.Lock()
	old := s.network
	s.network = nil
	s.mu.Unlock()

	if old != nil {
		_ = old.Close()
	}

	if name == "" {
		name = tunNameOf(connection)
	}

	prefix := netip.MustParsePrefix(tunAddress)
	network, err := netcfg.Configure(netcfg.Config{
		Name:    name,
		Address: prefix,
		DNS:     netip.MustParseAddr(tunResolver),
		MTU:     connection.MTU,
		Bypass:  serverAddresses(config),
	})
	if err != nil {
		return fmt.Errorf("reconfigure tunnel interface: %w", err)
	}

	s.mu.Lock()
	s.network = network
	s.mu.Unlock()

	if connection.KillSwitch && killSwitchAvailable {
		s.protectNetwork(network)
	}
	return nil
}

// Stop tears everything down: the adapter (with its routes and DNS), the
// stack and the core. Idempotent.
func (s *Service) Stop() error {
	// Ждём завершения возможного Start, иначе он создаст адаптер и стек уже
	// после нашего возврата: адаптер останется висеть в системе, а следующий
	// StartSession упадёт с ERROR_ALREADY_INITIALIZED (0x4DF).
	s.lifecycleMu.Lock()
	defer s.lifecycleMu.Unlock()
	return s.stopLocked()
}

func (s *Service) stopLocked() error {
	// Give the user's proxy settings back first: apps must not keep
	// talking to a port that is about to close.
	if err := s.proxy.Disable(); err != nil {
		s.reportTunnelError(err)
	}

	s.mu.Lock()
	stack := s.stack
	network := s.network
	monitor := s.monitor
	s.stack = nil
	s.network = nil
	s.monitor = nil
	s.boundIface = ""
	s.mu.Unlock()

	monitor.Close()

	// Restore the host network before tearing the stack down: closing the
	// stack removes the adapter, and netsh cannot clean up routes, DNS or
	// the address of an interface that no longer exists.
	var tunnelErr error
	if network != nil {
		tunnelErr = network.Close()
	}
	if stack != nil {
		if err := stack.Close(); err != nil && tunnelErr == nil {
			tunnelErr = err
		}
	}
	s.registry.Reset()

	// The tunnel is gone: nothing left to protect. If the VPN dropped on
	// its own, the kill switch lockdown is already in place by now.
	if network != nil || stack != nil {
		if err := firewall.Default().Unprotect(); err != nil {
			s.reportTunnelError(err)
		}
		if err := firewall.Default().DetachTunnel(); err != nil {
			s.reportTunnelError(err)
		}
	}

	coreErr := s.instance.Stop()
	if coreErr != nil {
		return coreErr
	}
	return tunnelErr
}

// applySystemProxy points the OS proxy at the local mixed inbound in
// system_proxy mode and gives it back in the plain proxy mode. A failure is
// logged but does not drop the connection: the inbound itself still works
// for apps configured by hand.
func (s *Service) applySystemProxy(connection domainSettings.ConnectionSettings) {
	if connection.Mode != systemProxyModeName {
		if err := s.proxy.Disable(); err != nil {
			s.reportTunnelError(err)
		}
		return
	}
	port := connection.ProxyPort
	if port <= 0 || port > 65535 {
		port = defaultProxyPort
	}
	if err := s.proxy.Enable("127.0.0.1", port); err != nil {
		s.reportTunnelError(err)
	}
}

// SystemProxyActive reports whether the OS proxy currently points at Beam.
func (s *Service) SystemProxyActive() bool { return s.proxy.Active() }

// --- kill switch ---

// killSwitchAvailable switches the kill switch and the leak protection off as
// a whole: the UI hides the setting (KillSwitchSupported) and a saved "on" has
// no effect. TODO: turn back on once it stops breaking server connections.
const killSwitchAvailable = false

// KillSwitchSupported reports whether the platform has a kill switch.
func (s *Service) KillSwitchSupported() bool { return killSwitchAvailable && firewall.Supported() }

// EngageKillSwitch cuts the internet off for everything but Beam, loopback
// and the local network until ReleaseKillSwitch.
func (s *Service) EngageKillSwitch() error { return firewall.Default().Lockdown() }

// AllowKillSwitchDNS lets plain DNS through an engaged kill switch for the
// duration of a reconnect attempt.
func (s *Service) AllowKillSwitchDNS(allow bool) error { return firewall.Default().AllowDNS(allow) }

// ReleaseKillSwitch gives the internet back.
func (s *Service) ReleaseKillSwitch() error { return firewall.Default().Unlock() }

// SetLeakProtection turns the DNS/IPv6 leak protection of a live tunnel on
// or off. Without a tunnel there is nothing to protect.
func (s *Service) SetLeakProtection(enabled bool) error {
	s.mu.Lock()
	network := s.network
	up := s.stack != nil
	s.mu.Unlock()
	if !enabled || !up || network == nil {
		return firewall.Default().Unprotect()
	}
	return protectWith(network)
}

// protectWith enables the leak guard for network. Windows filters by the
// adapter LUID; Linux/macOS rules use the interface name set earlier with
// SetTunnelInterface.
func protectWith(network netcfg.Network) error {
	if withLUID, ok := network.(interface{ LUID() uint64 }); ok {
		return firewall.Default().Protect(withLUID.LUID())
	}
	if runtime.GOOS == "windows" {
		return nil
	}
	return firewall.Default().Protect(0)
}

// protectNetwork enables the leak protection for a freshly configured
// tunnel. A failure is reported but does not fail the connection.
func (s *Service) protectNetwork(network netcfg.Network) {
	if !firewall.Supported() {
		return
	}
	if err := protectWith(network); err != nil {
		s.reportTunnelError(err)
	}
}

func (s *Service) Instance() *xray.Instance { return s.instance }

func (s *Service) Running() bool { return s.instance.Running() }

func (s *Service) Traffic() (download, upload int64) { return s.instance.Traffic() }

func (s *Service) Stats() (*coreapi.Stats, error) { return s.instance.Stats() }

func (s *Service) Connections() ([]coreapi.Connection, error) { return s.instance.Connections() }

// RecentConnections returns the tunnel flows closed within the last minutes.
func (s *Service) RecentConnections() []coreapi.Connection { return s.registry.RecentConnections() }

// CloseConnections tears down live tunnel flows by ID.
func (s *Service) CloseConnections(ids []string) int { return s.registry.CloseConnections(ids) }

// DrainFlowTraffic hands the per-app traffic since the previous call to the
// statistics. tunnel tells whether apps are attributed at all (TUN mode).
func (s *Service) DrainFlowTraffic() ([]coreapi.FlowTraffic, bool) {
	s.mu.Lock()
	tunnel := s.stack != nil
	s.mu.Unlock()
	return s.registry.DrainFlowTraffic(), tunnel
}

func (s *Service) Delay(ctx context.Context, tag string, timeout time.Duration) (int64, error) {
	return s.instance.Delay(ctx, tag, timeout)
}

func (s *Service) Healthy() bool {
	if !s.instance.Healthy() {
		return false
	}
	if s.connectionSettings().Mode != tunModeName {
		return true
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.stack != nil
}

func (s *Service) LastTrafficTime() time.Time { return s.instance.LastTrafficTime() }

func (s *Service) SetLogOptions(opts coreapi.LogOptions) { s.instance.SetLogOptions(opts) }

func (s *Service) Logs() coreapi.LogStore { return s.instance.Logs() }

// SetStateCallback subscribes to core state events. They are informational:
// the caller learns the outcome of Start/Restart/Stop from their return
// values, events only report what happens on their own (a core dying).
func (s *Service) SetStateCallback(cb func(coreapi.State, error)) {
	s.instance.SetStateCallback(cb)
}

// DirectInterface implements coreapi.DirectRoute.
func (s *Service) DirectInterface() string {
	s.mu.Lock()
	up := s.stack != nil
	s.mu.Unlock()
	if !up {
		return ""
	}
	return s.direct.Interface().Name
}

// DialDirect implements coreapi.DirectRoute.
func (s *Service) DialDirect(ctx context.Context, network, address string) (net.Conn, error) {
	if s.DirectInterface() != "" && s.direct.Ready() {
		return s.direct.DialContext(ctx, network, address)
	}
	var d net.Dialer
	s.mu.Lock()
	if s.stack != nil {
		d.Control = s.deviceControl
	}
	s.mu.Unlock()
	return d.DialContext(ctx, network, address)
}
