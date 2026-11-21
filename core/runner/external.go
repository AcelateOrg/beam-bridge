package runner

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"syscall"

	tun "beam-tun"
	"beam-tun/process"
	"beam-tun/stack"
)

// TunAddress and TunResolver are the tunnel interface address and the DNS
// server the stack answers on. A platform that builds the interface itself
// (Android's VpnService) must configure exactly these.
const (
	TunAddress  = tunAddress
	TunResolver = tunResolver
)

// StartOnDevice runs the core and the packet stack on an interface the
// platform created and configured itself, as Android's VpnService does:
// routes, DNS and the address are already in place, and the platform keeps
// the core's own sockets out of the tunnel (VpnService.protect), so there is
// no netcfg, firewall, interface pinning or network monitor here. dev is
// closed on failure and by Stop.
func (s *Service) StartOnDevice(ctx context.Context, config json.RawMessage, dev tun.Device) error {
	s.lifecycleMu.Lock()
	defer s.lifecycleMu.Unlock()
	_ = s.stopLocked()

	connection := s.connectionSettings()
	timer := newStageTimer()
	s.setBoundInterface("")

	if err := s.instance.Start(ctx, config); err != nil {
		_ = dev.Close()
		return err
	}
	timer.mark("core")
	s.applyRoutes(config)

	prefix := netip.MustParsePrefix(tunAddress)
	var prefix6 netip.Prefix
	s.mu.Lock()
	if s.deviceIPv6 {
		prefix6 = netip.MustParsePrefix(TunAddress6)
	}
	s.mu.Unlock()
	s.tunnel.SetLocalPrefix(prefix.Masked())
	s.tunnel.SetDNS(upstreamResolver(connection, prefix.Masked()))

	engine, err := stack.New(stack.Options{
		Device:       dev,
		Handler:      s.tunnel,
		Process:      s.deviceResolver(),
		Inet4Address: prefix,
		Inet6Address: prefix6,
		EchoSource:   s.direct.Inet4,
		// Android routes the kernel NAT listener's replies past the VPN
		// interface, so TCP is terminated in userspace there.
		UserspaceTCP: true,
		OnError:      s.reportTunnelError,
		OnWarn:       s.reportTunnelWarning,
		Debugf:       s.instance.Debugf,
	})
	if err != nil {
		_ = dev.Close()
		_ = s.instance.Stop()
		return fmt.Errorf("start tunnel stack: %w", err)
	}
	timer.mark("stack")

	s.mu.Lock()
	s.stack = engine
	if named, ok := dev.(interface{ Name() string }); ok {
		s.tunName = named.Name()
	}
	s.mu.Unlock()

	s.logTiming("tunnel up in", timer)
	return nil
}

// RestartOnDevice swaps the core's configuration on a live StartOnDevice
// session, as Restart does on desktop: only Xray and its routes are rebuilt,
// the platform's TUN descriptor and the packet stack stay up, so apps keep
// their interface and the switch to another server is not a disconnect.
// Flows of the old core end with it; new ones go through the new server.
// If the new core fails to start the tunnel is left without one; a later
// RestartOnDevice may still bring one up, or the caller can Stop it.
func (s *Service) RestartOnDevice(ctx context.Context, config json.RawMessage) error {
	s.lifecycleMu.Lock()
	defer s.lifecycleMu.Unlock()

	s.mu.Lock()
	tunnelUp := s.stack != nil
	s.mu.Unlock()
	if !tunnelUp {
		return errors.New("tunnel is not running")
	}

	_ = s.instance.Stop()
	if err := s.instance.Start(ctx, config); err != nil {
		return err
	}
	s.applyRoutes(config)
	s.registry.Reset()
	return nil
}

// TunAddress6 is the IPv6 address a platform interface carries; the stack
// handles IPv6 only when SetDeviceIPv6 enabled it.
const TunAddress6 = "fdfe:dcba:9876::1/126"

// SetDeviceIPv6 makes the next StartOnDevice relay IPv6; otherwise IPv6 that
// reaches the interface is dropped and apps fall back to IPv4.
func (s *Service) SetDeviceIPv6(enabled bool) {
	s.mu.Lock()
	s.deviceIPv6 = enabled
	s.mu.Unlock()
}

// SetProcessResolver installs the platform's flow-to-app resolver used by
// StartOnDevice (Android: the owner UID of a connection). Without one flows
// are not attributed to apps.
func (s *Service) SetProcessResolver(r tun.ProcessResolver) {
	s.mu.Lock()
	s.deviceProcess = r
	s.mu.Unlock()
}

func (s *Service) deviceResolver() tun.ProcessResolver {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.deviceProcess != nil {
		return s.deviceProcess
	}
	return process.NewResolver()
}

// SetDeviceDialControl installs the platform hook that keeps DialDirect's
// sockets out of a StartOnDevice tunnel (Android: VpnService.protect).
func (s *Service) SetDeviceDialControl(control func(network, address string, c syscall.RawConn) error) {
	s.mu.Lock()
	s.deviceControl = control
	s.mu.Unlock()
}
