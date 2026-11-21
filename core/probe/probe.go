// Package probe measures latency the way a user feels it: the round trip of an
// already established path, not the one-off cost of setting that path up.
//
// A cold request through a proxy pays for the TCP handshake to the server, the
// proxy/TLS handshake, the TCP and TLS handshakes to the probe host and only
// then one request: four or five round trips reported as "ping". Here the first
// exchange only warms the path up; the result is the median of the following
// samples, so one lost packet or scheduler hiccup does not show up either.
package probe

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/netip"
	"slices"
	"strconv"
	"time"
)

// URL answers with an empty 204 from a host that sits close to almost every
// proxy server, so the measured round trip is dominated by the proxy hop.
const URL = "https://www.gstatic.com/generate_204"

// Samples is how many measured exchanges follow the warm-up.
const Samples = 3

// DialFunc opens the connection a probe runs over.
type DialFunc func(ctx context.Context, network, address string) (net.Conn, error)

// ErrNoSample is returned when every measured exchange failed.
var ErrNoSample = errors.New("probe: no successful sample")

// HTTP measures the round trip of an HTTP exchange with URL over one kept-alive
// connection opened by dial. Returns milliseconds (at least 1).
func HTTP(ctx context.Context, dial DialFunc) (int64, error) {
	transport := &http.Transport{
		DialContext:         dial,
		MaxIdleConns:        1,
		MaxIdleConnsPerHost: 1,
		IdleConnTimeout:     30 * time.Second,
		DisableCompression:  true,
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{
		Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	if _, _, err := exchange(ctx, client); err != nil {
		return -1, err
	}

	rtts := make([]time.Duration, 0, Samples)
	var lastErr error
	for range Samples {
		rtt, reused, err := exchange(ctx, client)
		if err != nil {
			lastErr = err
			if ctx.Err() != nil {
				break
			}
			continue
		}
		// A dropped connection makes the next exchange pay for the setup
		// again: that sample measures a handshake, not the path.
		if reused {
			rtts = append(rtts, rtt)
		}
	}
	return result(rtts, lastErr)
}

// exchange sends one request and times it from the moment a connection is in
// hand to the first response byte.
func exchange(ctx context.Context, client *http.Client) (time.Duration, bool, error) {
	var (
		got    time.Time
		first  time.Time
		reused bool
	)
	trace := &httptrace.ClientTrace{
		GotConn: func(info httptrace.GotConnInfo) {
			got = time.Now()
			reused = info.Reused
		},
		GotFirstResponseByte: func() { first = time.Now() },
	}
	request, err := http.NewRequestWithContext(httptrace.WithClientTrace(ctx, trace), http.MethodGet, URL, nil)
	if err != nil {
		return 0, false, err
	}
	response, err := client.Do(request)
	if err != nil {
		return 0, false, err
	}
	// Drain so the connection goes back to the pool for the next sample.
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 64<<10))
	_ = response.Body.Close()
	if response.StatusCode >= http.StatusInternalServerError {
		return 0, false, errors.New("probe: " + response.Status)
	}
	if got.IsZero() || first.Before(got) {
		return 0, false, errors.New("probe: incomplete trace")
	}
	return first.Sub(got), reused, nil
}

// TCP measures the TCP handshake time to address (host:port). The host is
// resolved once up front so a DNS lookup never lands in a sample.
func TCP(ctx context.Context, dial DialFunc, address string) (int64, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return -1, err
	}
	if _, err := netip.ParseAddr(host); err != nil {
		addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		if err != nil {
			return -1, err
		}
		if len(addrs) == 0 {
			return -1, errors.New("probe: no address for " + host)
		}
		ip := addrs[0]
		for _, candidate := range addrs {
			if candidate.Unmap().Is4() {
				ip = candidate
				break
			}
		}
		address = net.JoinHostPort(ip.Unmap().String(), port)
	}
	if _, err := strconv.Atoi(port); err != nil {
		return -1, err
	}

	rtts := make([]time.Duration, 0, Samples)
	var lastErr error
	for range Samples {
		start := time.Now()
		conn, err := dial(ctx, "tcp", address)
		if err != nil {
			lastErr = err
			if ctx.Err() != nil {
				break
			}
			continue
		}
		rtts = append(rtts, time.Since(start))
		_ = conn.Close()
	}
	return result(rtts, lastErr)
}

func result(rtts []time.Duration, lastErr error) (int64, error) {
	if len(rtts) == 0 {
		if lastErr == nil {
			lastErr = ErrNoSample
		}
		return -1, lastErr
	}
	slices.Sort(rtts)
	ms := rtts[len(rtts)/2].Milliseconds()
	if ms < 1 {
		ms = 1
	}
	return ms, nil
}

// PlainDial is the default dialer for probes that need no special routing.
func PlainDial(ctx context.Context, network, address string) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, network, address)
}
