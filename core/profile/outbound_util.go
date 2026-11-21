package profile

import (
	"context"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

const (
	resolveTimeout = 3 * time.Second
	// A cached address younger than resolveFresh is used without a lookup;
	// an older one only bounds the lookup to resolveStaleTimeout and serves
	// as the fallback. Reconnects then skip DNS entirely.
	resolveFresh        = 10 * time.Minute
	resolveStaleTimeout = 800 * time.Millisecond
	// directResolveTimeout bounds one query of the fallback resolver.
	directResolveTimeout = 2 * time.Second
)

// directResolvers are asked by Beam itself, over plain UDP, when the system
// resolver fails. On Windows the system resolver runs in a service outside
// Beam, and the kill switch's leak protection blocks every DNS query of other
// processes while the tunnel is up: a server name could then never be resolved
// to switch to it. Queries from Beam itself are allowed through.
var directResolvers = []string{"1.1.1.1:53", "8.8.8.8:53"}

type resolvedHost struct {
	address string
	at      time.Time
}

var (
	resolveMu    sync.Mutex
	resolveCache = map[string]resolvedHost{}
)

func copyOutbound(ob map[string]interface{}) map[string]interface{} {
	copied := make(map[string]interface{}, len(ob))
	for key, value := range ob {
		copied[key] = value
	}
	return copied
}

func usableOutbound(ob map[string]interface{}) bool {
	server, ok := ob["server"].(string)
	if !ok {
		return true
	}
	server = strings.TrimSpace(server)
	if server == "" {
		return false
	}
	if ip := net.ParseIP(server); ip != nil && ip.IsUnspecified() {
		return false
	}
	if port, ok := outboundPort(ob); ok && (port <= 0 || port > 65535) {
		return false
	}
	return true
}

func outboundPort(ob map[string]interface{}) (int, bool) {
	switch value := ob["server_port"].(type) {
	case int:
		return value, true
	case int64:
		return int(value), true
	case float64:
		return int(value), true
	}
	return 0, false
}

// resolveOutboundAddress replaces the server name of an outbound (and of
// every hop of its chain) with its IPv4 address, so the core never asks a
// resolver for it while the tunnel is up. The name stays wherever the
// protocol needs it on the wire: the TLS server name and, for transports
// without TLS, the HTTP Host / gRPC authority. Without that a plain ws, xhttp
// or httpupgrade node behind a CDN would send its IP as Host and get a 403.
func resolveOutboundAddress(ob map[string]interface{}) map[string]interface{} {
	return resolveOutboundAt(ob, 0)
}

func resolveOutboundAt(ob map[string]interface{}, depth int) map[string]interface{} {
	resolved := copyOutbound(ob)

	if detour, ok := resolved["detour"].(map[string]interface{}); ok && depth < maxDetourDepth {
		resolved["detour"] = resolveOutboundAt(detour, depth+1)
	}

	server, ok := resolved["server"].(string)
	if !ok || server == "" {
		return resolved
	}

	address := resolveIPv4(server)
	if address == server {
		return resolved
	}
	resolved["server"] = address

	// Nested sections are shared with the stored node: copy before writing.
	tlsEnabled := false
	if tls, ok := resolved["tls"].(map[string]interface{}); ok {
		tlsEnabled = boolValue(tls["enabled"])
		if name, ok := tls["server_name"].(string); !ok || name == "" {
			tls = copyOutbound(tls)
			tls["server_name"] = server
			resolved["tls"] = tls
		}
	}
	if !tlsEnabled {
		if transport, ok := resolved["transport"].(map[string]interface{}); ok {
			if withHost := transportWithHost(transport, server); withHost != nil {
				resolved["transport"] = withHost
			}
		}
	}
	return resolved
}

// transportWithHost returns a copy of transport carrying host as its HTTP
// Host (or gRPC authority) when the node did not set one, nil when nothing
// changes. With TLS the core already falls back to the server name.
func transportWithHost(transport map[string]interface{}, host string) map[string]interface{} {
	switch strings.ToLower(getStr(transport, "type")) {
	case "ws":
		if getStr(transport, "host") != "" {
			return nil
		}
		for k, v := range getMap(transport, "headers") {
			if s, _ := v.(string); strings.EqualFold(k, "host") && s != "" {
				return nil
			}
		}
		out := copyOutbound(transport)
		out["host"] = host
		return out
	case "httpupgrade", "xhttp", "splithttp":
		if getStr(transport, "host") != "" {
			return nil
		}
		out := copyOutbound(transport)
		out["host"] = host
		return out
	case "grpc":
		if getStr(transport, "authority") != "" {
			return nil
		}
		out := copyOutbound(transport)
		out["authority"] = host
		return out
	case "raw", "tcp":
		header := getMap(transport, "header")
		if header == nil || !strings.EqualFold(getStr(header, "type"), "http") {
			return nil
		}
		request := getMap(header, "request")
		headers := getMap(request, "headers")
		for k := range headers {
			if strings.EqualFold(k, "host") {
				return nil
			}
		}
		newHeaders := copyOutbound(headers)
		newHeaders["Host"] = []interface{}{host}
		newRequest := copyOutbound(request)
		newRequest["headers"] = newHeaders
		newHeader := copyOutbound(header)
		newHeader["request"] = newRequest
		out := copyOutbound(transport)
		out["header"] = newHeader
		return out
	}
	return nil
}

func resolveIPv4(host string) string {
	if net.ParseIP(host) != nil {
		return host
	}

	resolveMu.Lock()
	cached, ok := resolveCache[host]
	resolveMu.Unlock()
	if ok && time.Since(cached.at) < resolveFresh {
		return cached.address
	}

	timeout := resolveTimeout
	if ok {
		timeout = resolveStaleTimeout
	}

	var ips []net.IP
	var err error
	protected := resolverDialControl() != nil
	if protected {
		// Android: the system resolver answers over the VPN network, which
		// is either not up yet or served by this very core. Beam's own
		// resolver on protected sockets goes out through the real network.
		ips, err = lookupDirect(host, timeout)
	}
	if err != nil || len(ips) == 0 {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		ips, err = net.DefaultResolver.LookupIP(ctx, "ip4", host)
		cancel()
	}
	if (err != nil || len(ips) == 0) && !ok && !protected {
		ips, err = lookupDirect(host, directResolveTimeout)
	}
	if err != nil || len(ips) == 0 {
		if ok {
			return cached.address
		}
		return host
	}
	address := ips[0].String()
	resolveMu.Lock()
	resolveCache[host] = resolvedHost{address: address, at: time.Now()}
	resolveMu.Unlock()
	return address
}

// dialControl, when set, runs on every socket of Beam's own resolver before
// it connects (Android: VpnService.protect).
var dialControl atomic.Pointer[func(network, address string, c syscall.RawConn) error]

// SetResolverDialControl installs the hook that keeps the resolver's sockets
// out of the tunnel. Set it before the first connect.
func SetResolverDialControl(control func(network, address string, c syscall.RawConn) error) {
	if control == nil {
		dialControl.Store(nil)
		return
	}
	dialControl.Store(&control)
}

func resolverDialControl() func(network, address string, c syscall.RawConn) error {
	if p := dialControl.Load(); p != nil {
		return *p
	}
	return nil
}

// lookupDirect resolves host with a DNS client inside Beam, bypassing the
// system resolver. timeout bounds each server.
func lookupDirect(host string, timeout time.Duration) ([]net.IP, error) {
	control := resolverDialControl()
	var lastErr error
	for _, server := range directResolvers {
		resolver := &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
				dialer := net.Dialer{Control: control}
				return dialer.DialContext(ctx, network, server)
			},
		}
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		ips, err := resolver.LookupIP(ctx, "ip4", host)
		cancel()
		if err == nil && len(ips) > 0 {
			return ips, nil
		}
		lastErr = err
	}
	return nil, lastErr
}
