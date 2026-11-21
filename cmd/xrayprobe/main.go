// Command xrayprobe starts the Xray core with the config generated for a
// profile and sends one plain HTTP request through the selected node, without
// touching the TUN layer. It answers a single question: is the core plus the
// generated config able to move bytes at all?
//
//	BEAM_DUMP_PROFILE=...beam go run ./cmd/xrayprobe
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"time"

	domainSettings "beam-bridge/core/domain/settings"
	infraBeam "beam-bridge/core/infrastructure/beam"
	"beam-bridge/core/profile"
	"beam-bridge/core/types"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	xcore "github.com/xtls/xray-core/core"

	_ "github.com/xtls/xray-core/main/distro/all"
)

func main() {
	path := os.Getenv("BEAM_DUMP_PROFILE")
	if path == "" {
		fail("BEAM_DUMP_PROFILE is not set")
	}

	beamFile, err := infraBeam.ReadFromFile(path)
	if err != nil {
		fail("read profile: %v", err)
	}

	builder := profile.NewXrayConfigBuilder(
		domainSettings.ConnectionSettings{Mode: "tun", PrimaryDNS: "8.8.8.8"},
		types.SplitTunnelSettings{},
	)
	generated := builder.BuildFromBeam(beamFile)
	if generated == nil || generated.Config == nil {
		fail("config was not generated")
	}
	fmt.Printf("proxy tag: %s\n", generated.ProxyTag)

	if tag := os.Getenv("BEAM_PROBE_NODE"); tag != "" {
		if !promoteOutbound(generated.Config, tag, generated.ProxyTag) {
			fail("outbound %q was not found", tag)
		}
		fmt.Printf("probing outbound: %s\n", tag)
	}

	if os.Getenv("BEAM_PROBE_NOFLOW") != "" {
		stripFlow(generated.Config)
		fmt.Println("flow stripped from all vless users")
	}

	if os.Getenv("BEAM_PROBE_DEBUG") != "" {
		if logCfg, ok := generated.Config["log"].(map[string]any); ok {
			logCfg["loglevel"] = "debug"
		} else {
			generated.Config["log"] = map[string]any{"loglevel": "debug"}
		}
	}

	raw, err := json.Marshal(generated.Config)
	if err != nil {
		fail("marshal config: %v", err)
	}

	parsed, err := xcore.LoadConfig("json", bytes.NewReader(raw))
	if err != nil {
		fail("load config: %v", err)
	}
	instance, err := xcore.New(parsed)
	if err != nil {
		fail("create core: %v", err)
	}
	if err := instance.Start(); err != nil {
		fail("start core: %v", err)
	}
	defer instance.Close()

	if os.Getenv("BEAM_PROBE_TLS") != "" {
		probeTLS(instance, "142.250.185.99", 443, "www.google.com")
		return
	}

	probe(instance, "142.250.185.99", 80, "www.google.com")
}

// probeTLS runs a real TLS handshake through the tunnel, which is the traffic
// shape the Vision flow is designed for.
func probeTLS(instance *xcore.Instance, ip string, port int, host string) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ctx = session.ContextWithInbound(ctx, &session.Inbound{
		Source: xnet.TCPDestination(xnet.ParseAddress("172.19.0.2"), 40001),
	})
	ctx = session.ContextWithContent(ctx, &session.Content{
		SniffingRequest: session.SniffingRequest{
			Enabled:                        true,
			OverrideDestinationForProtocol: []string{"http", "tls", "quic"},
			MetadataOnly:                   false,
			RouteOnly:                      true,
		},
	})

	destination := xnet.TCPDestination(xnet.ParseAddress(ip), xnet.Port(port))
	started := time.Now()
	conn, err := xcore.Dial(ctx, instance, destination)
	if err != nil {
		fail("dial %s: %v", destination, err)
	}
	defer conn.Close()
	fmt.Printf("dialed %s in %v\n", destination, time.Since(started))

	_ = conn.SetDeadline(time.Now().Add(20 * time.Second))
	tlsConn := tls.Client(conn, &tls.Config{ServerName: host})
	if err := tlsConn.Handshake(); err != nil {
		fmt.Printf("tls handshake failed after %v: %v\n", time.Since(started), err)
		return
	}
	fmt.Printf("tls handshake ok after %v\n", time.Since(started))

	request := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", host)
	if _, err := tlsConn.Write([]byte(request)); err != nil {
		fail("tls write: %v", err)
	}
	buf := make([]byte, 4096)
	n, err := tlsConn.Read(buf)
	fmt.Printf("tls first read after %v: n=%d err=%v\n", time.Since(started), n, err)
	if n > 0 {
		fmt.Printf("payload: %q\n", buf[:min(n, 120)])
	}
}

func probe(instance *xcore.Instance, ip string, port int, host string) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ctx = session.ContextWithInbound(ctx, &session.Inbound{
		Source: xnet.TCPDestination(xnet.ParseAddress("172.19.0.2"), 40000),
	})
	ctx = session.ContextWithContent(ctx, &session.Content{
		SniffingRequest: session.SniffingRequest{
			Enabled:                        true,
			OverrideDestinationForProtocol: []string{"http", "tls", "quic"},
			MetadataOnly:                   false,
			RouteOnly:                      true,
		},
	})

	destination := xnet.TCPDestination(xnet.ParseAddress(ip), xnet.Port(port))
	started := time.Now()
	conn, err := xcore.Dial(ctx, instance, destination)
	if err != nil {
		fail("dial %s: %v", destination, err)
	}
	defer conn.Close()
	fmt.Printf("dialed %s in %v\n", destination, time.Since(started))

	request := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\nUser-Agent: beam-probe\r\n\r\n", host)
	if _, err := conn.Write([]byte(request)); err != nil {
		fail("write: %v", err)
	}
	fmt.Printf("request sent after %v\n", time.Since(started))

	_ = conn.SetReadDeadline(time.Now().Add(15 * time.Second))
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	fmt.Printf("first read after %v: n=%d err=%v\n", time.Since(started), n, err)
	if n > 0 {
		preview := buf[:min(n, 200)]
		fmt.Printf("payload: %q\n", preview)
	}
}

// promoteOutbound swaps the tags of the requested node and the selected node so
// existing routing rules send the probe traffic through the requested node.
func promoteOutbound(config map[string]any, tag string, selected string) bool {
	if tag == selected {
		return true
	}
	outbounds, _ := config["outbounds"].([]any)
	var target, current map[string]any
	for _, item := range outbounds {
		outbound, _ := item.(map[string]any)
		switch outbound["tag"] {
		case tag:
			target = outbound
		case selected:
			current = outbound
		}
	}
	if target == nil || current == nil {
		return false
	}
	target["tag"] = selected
	current["tag"] = tag
	return true
}

// stripFlow removes the xtls-rprx-vision flow from every VLESS user so the
// probe can tell a broken Vision layer apart from a broken REALITY handshake.
func stripFlow(config map[string]any) {
	outbounds, _ := config["outbounds"].([]any)
	for _, item := range outbounds {
		outbound, _ := item.(map[string]any)
		settings, _ := outbound["settings"].(map[string]any)
		vnext, _ := settings["vnext"].([]any)
		for _, entry := range vnext {
			server, _ := entry.(map[string]any)
			users, _ := server["users"].([]any)
			for _, raw := range users {
				if user, ok := raw.(map[string]any); ok {
					delete(user, "flow")
				}
			}
		}
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "probe: "+format+"\n", args...)
	os.Exit(1)
}

var _ = net.Dial
