//go:build linux

package mobile

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"strconv"
	"strings"
	"sync/atomic"

	domainSettings "beam-bridge/core/domain/settings"
	"beam-bridge/core/probe"
)

// The phone's "Соединение" and "Приложение" options, stored in the same
// settings the profile builder reads, so they reach the Xray config exactly as
// desktop's do.

// dnsPresets are the resolver pairs behind the app's DNS tiles.
var dnsPresets = map[string][2]string{
	"google":     {"8.8.8.8", "8.8.4.4"},
	"cloudflare": {"1.1.1.1", "1.0.0.1"},
	"quad9":      {"9.9.9.9", "149.112.112.112"},
	"adguard":    {"94.140.14.14", "94.140.15.15"},
	"yandex":     {"77.88.8.8", "77.88.8.1"},
}

// dnsCustom selects the user's own resolvers (DNSPrimary, DNSSecondary).
const dnsCustom = "custom"

// ConnectionOptions mirrors the app's settings screen.
type connectionOptions struct {
	// DNS is a dnsPresets key or dnsCustom.
	DNS string `json:"dns"`
	// DNSPrimary and DNSSecondary are the resolvers for dnsCustom; the
	// secondary is optional.
	DNSPrimary   string `json:"dnsPrimary,omitempty"`
	DNSSecondary string `json:"dnsSecondary,omitempty"`
	// ProfileDNS prefers the DNS of the profile's own config; DNS above
	// stays the fallback for servers that bring none.
	ProfileDNS bool `json:"profileDns"`
	// Fragmentation is "off", "standard", "strong" or "custom".
	Fragmentation string `json:"fragmentation"`
	// FragmentCustom holds the "custom" parameters; ignored otherwise.
	FragmentCustom *fragmentCustom `json:"fragmentCustom,omitempty"`
	Mux            bool            `json:"mux"`
	// AutoRefresh keeps subscriptions updating on their schedule.
	AutoRefresh bool `json:"autoRefresh"`
	// NodePing is how servers are checked: "tcp" (handshake) or "auto"
	// (a real request through the server, TCP when that is impossible).
	NodePing string `json:"nodePing"`
	// ConnectionPing is the live connection's ping: "http" or "tcp".
	ConnectionPing string `json:"connectionPing"`
}

// fragmentCustom mirrors the desktop «Вручную» fields. Invalid values are
// replaced by the repository's defaults (see validateCore).
type fragmentCustom struct {
	Packets  string `json:"packets"`
	Length   string `json:"length"`
	Interval string `json:"interval"`
	MaxSplit string `json:"maxSplit"`
}

var deviceIPv6 atomic.Bool

// SetIPv6 lets IPv6 traffic through the tunnel on the next Connect; off, it is
// captured by the interface and dropped, so apps fall back to IPv4.
func SetIPv6(enabled bool) { deviceIPv6.Store(enabled) }

// SetConnectionOptions stores the options (JSON of connectionOptions). Call
// Reconnect afterwards when DNS, fragmentation or Mux changed on a live tunnel.
func SetConnectionOptions(jsonOptions string) error {
	mu.Lock()
	s := settings
	mu.Unlock()
	if s == nil {
		return errNotInitialized
	}
	var o connectionOptions
	if err := json.Unmarshal([]byte(jsonOptions), &o); err != nil {
		return err
	}
	cur := s.Get()

	dns := cur.DNS
	dns.UseProfileDNS = o.ProfileDNS
	pair, ok := dnsPresets[o.DNS]
	if o.DNS == dnsCustom {
		pair, ok = [2]string{strings.TrimSpace(o.DNSPrimary), strings.TrimSpace(o.DNSSecondary)}, true
		if net.ParseIP(pair[0]) == nil || (pair[1] != "" && net.ParseIP(pair[1]) == nil) {
			return errors.New("DNS-сервер должен быть IP-адресом")
		}
		// The store fills an empty secondary with a public resolver the user never chose.
		if pair[1] == "" {
			pair[1] = pair[0]
		}
	}
	if ok {
		conn := cur.Connection
		conn.PrimaryDNS, conn.SecondaryDNS = pair[0], pair[1]
		if err := s.UpdateConnection(conn); err != nil {
			return err
		}
		dns.Servers = []domainSettings.DNSServer{{Address: pair[0]}}
		if pair[1] != pair[0] {
			dns.Servers = append(dns.Servers, domainSettings.DNSServer{Address: pair[1]})
		}
		// Queries go through the server as UDP; where the server or its
		// path drops UDP nothing resolves at all. The core tries servers in
		// order, so the same resolver over TCP answers after a UDP timeout.
		dns.Servers = append(dns.Servers, domainSettings.DNSServer{Address: "tcp://" + net.JoinHostPort(pair[0], "53")})
	}
	if err := s.UpdateDNS(dns); err != nil {
		return err
	}

	coreSettings := cur.Core
	switch o.Fragmentation {
	case "standard", "strong":
		coreSettings.Fragment.Enabled = true
		coreSettings.Fragment.Preset = o.Fragmentation
	case "custom":
		coreSettings.Fragment.Enabled = true
		coreSettings.Fragment.Preset = "custom"
		if c := o.FragmentCustom; c != nil {
			coreSettings.Fragment.Packets = c.Packets
			coreSettings.Fragment.Length = c.Length
			coreSettings.Fragment.Interval = c.Interval
			coreSettings.Fragment.MaxSplit = c.MaxSplit
		}
	default:
		coreSettings.Fragment.Enabled = false
	}
	coreSettings.Mux.Enabled = o.Mux
	if coreSettings.Mux.Concurrency == 0 {
		coreSettings.Mux.Concurrency = 8
	}
	if coreSettings.Mux.XUDPConcurrency == 0 {
		coreSettings.Mux.XUDPConcurrency = 16
	}
	if coreSettings.Mux.XUDPProxyUDP443 == "" {
		coreSettings.Mux.XUDPProxyUDP443 = "reject"
	}
	if err := s.UpdateCore(coreSettings); err != nil {
		return err
	}

	app := cur.Application
	app.DisableSubscriptionAutoRefresh = !o.AutoRefresh
	if err := s.UpdateApplication(app); err != nil {
		return err
	}

	return s.UpdatePing(domainSettings.PingSettings{NodeMode: o.NodePing, ConnectionMode: o.ConnectionPing})
}

// FragmentSettings returns the stored fragmentation as JSON of
// fragmentCustom, already normalized ("20-10" -> "10-20", junk -> defaults),
// so the app can show what the core actually gets.
func FragmentSettings() (string, error) {
	mu.Lock()
	s := settings
	mu.Unlock()
	if s == nil {
		return "", errNotInitialized
	}
	f := s.Get().Core.Fragment
	return toJSON(fragmentCustom{Packets: f.Packets, Length: f.Length, Interval: f.Interval, MaxSplit: f.MaxSplit})
}

// ExportBeam returns the profile as a .beam document.
func ExportBeam(profileID string) ([]byte, error) {
	m, err := manager()
	if err != nil {
		return nil, err
	}
	return m.ExportBeam(profileID)
}

// ExportLinks returns the profile's original server links as JSON
// ([]types.ExportedLink: {"name","link"}). Edited servers have none.
func ExportLinks(profileID string) (string, error) {
	m, err := manager()
	if err != nil {
		return "", err
	}
	links, err := m.ExportRawLinks(profileID)
	if err != nil {
		return "", err
	}
	return toJSON(links)
}

// SetAutoRefresh turns one subscription's automatic updates on or off.
func SetAutoRefresh(profileID string, disabled bool) error {
	m, err := manager()
	if err != nil {
		return err
	}
	return m.SetAutoRefresh(profileID, disabled)
}

// SetUpdateInterval overrides the provider's update interval in hours (0 =
// the provider's schedule).
func SetUpdateInterval(profileID string, hours int) error {
	m, err := manager()
	if err != nil {
		return err
	}
	return m.SetUpdateIntervalOverride(profileID, hours)
}

// tcpConnectionPing measures the TCP handshake to the active server through
// the physical network (the core's protected direct path).
func tcpConnectionPing(ctx context.Context) int64 {
	m, err := manager()
	if err != nil {
		return -1
	}
	node, ok := m.GetActiveNode()
	if !ok || node == nil {
		return -1
	}
	server, _ := node.Outbound["server"].(string)
	port := 0
	switch v := node.Outbound["server_port"].(type) {
	case float64:
		port = int(v)
	case int:
		port = v
	case string:
		port, _ = strconv.Atoi(v)
	}
	if server == "" || port <= 0 || port > 65535 {
		return -1
	}
	coreMu.Lock()
	svc := core
	coreMu.Unlock()
	if svc == nil {
		return -1
	}
	ms, err := probe.TCP(ctx, svc.DialDirect, net.JoinHostPort(server, strconv.Itoa(port)))
	if err != nil {
		return -1
	}
	return ms
}
