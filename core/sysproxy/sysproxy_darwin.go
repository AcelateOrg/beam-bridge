//go:build darwin

package sysproxy

import (
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
)

// macOS keeps proxies per network service (Wi-Fi, Ethernet, ...); every
// enabled service is switched so changing the uplink keeps the proxy.

const goos = "darwin"

const networksetup = "/usr/sbin/networksetup"

// proxyKinds are the networksetup verbs: web (HTTP), secure web (HTTPS) and
// SOCKS. The local inbound answers all three on one port.
var proxyKinds = []string{"webproxy", "securewebproxy", "socksfirewallproxy"}

type proxyState struct {
	Enabled bool   `json:"enabled"`
	Server  string `json:"server"`
	Port    int    `json:"port"`
}

type serviceState struct {
	Proxies map[string]proxyState `json:"proxies"`
	Bypass  []string              `json:"bypass"`
}

type savedSettings struct {
	Services map[string]serviceState `json:"services"`
}

func prepareCommand(*exec.Cmd) {}

func supported() bool { return available(networksetup) }

// services lists the enabled network services. The first line of the
// output is a legend; disabled services start with '*'.
func services() ([]string, error) {
	out, err := run(networksetup, "-listallnetworkservices")
	if err != nil {
		return nil, err
	}
	var list []string
	for i, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if i == 0 && strings.Contains(line, "asterisk") {
			continue
		}
		if line == "" || strings.HasPrefix(line, "*") {
			continue
		}
		list = append(list, line)
	}
	if len(list) == 0 {
		return nil, errors.New("no enabled network services")
	}
	return list, nil
}

func capture() (json.RawMessage, error) {
	list, err := services()
	if err != nil {
		return nil, err
	}
	saved := savedSettings{Services: make(map[string]serviceState, len(list))}
	for _, service := range list {
		state := serviceState{Proxies: make(map[string]proxyState, len(proxyKinds))}
		for _, kind := range proxyKinds {
			out, err := run(networksetup, "-get"+kind, service)
			if err != nil {
				return nil, err
			}
			state.Proxies[kind] = parseProxy(out)
		}
		if out, err := run(networksetup, "-getproxybypassdomains", service); err == nil {
			state.Bypass = parseBypass(out)
		}
		saved.Services[service] = state
	}
	return json.Marshal(saved)
}

// parseProxy reads "Enabled: Yes / Server: x / Port: n" output.
func parseProxy(out string) proxyState {
	var state proxyState
	for _, line := range strings.Split(out, "\n") {
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		value = strings.TrimSpace(value)
		switch strings.TrimSpace(key) {
		case "Enabled":
			state.Enabled = strings.EqualFold(value, "Yes")
		case "Server":
			state.Server = value
		case "Port":
			state.Port, _ = strconv.Atoi(value)
		}
	}
	return state
}

func parseBypass(out string) []string {
	if strings.Contains(out, "There aren't any") {
		return nil
	}
	var list []string
	for _, line := range strings.Split(out, "\n") {
		if line = strings.TrimSpace(line); line != "" {
			list = append(list, line)
		}
	}
	return list
}

func apply(host string, port int) error {
	list, err := services()
	if err != nil {
		return err
	}
	p := strconv.Itoa(port)
	bypass := []string{"localhost", "127.0.0.1", "::1", "*.local", "169.254/16", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"}
	var errs []error
	applied := 0
	for _, service := range list {
		ok := true
		for _, kind := range proxyKinds {
			// Setting the server also turns the proxy on.
			if _, err := run(networksetup, "-set"+kind, service, host, p); err != nil {
				errs = append(errs, err)
				ok = false
			}
		}
		args := append([]string{"-setproxybypassdomains", service}, bypass...)
		if _, err := run(networksetup, args...); err != nil {
			errs = append(errs, err)
		}
		if ok {
			applied++
		}
	}
	if applied == 0 {
		return errors.Join(errs...)
	}
	return nil
}

func restore(raw json.RawMessage) error {
	var saved savedSettings
	if err := json.Unmarshal(raw, &saved); err != nil {
		return err
	}
	var errs []error
	for service, state := range saved.Services {
		for _, kind := range proxyKinds {
			proxy := state.Proxies[kind]
			if proxy.Server != "" && proxy.Port > 0 {
				if _, err := run(networksetup, "-set"+kind, service, proxy.Server, strconv.Itoa(proxy.Port)); err != nil {
					errs = append(errs, err)
				}
			}
			stateArg := "off"
			if proxy.Enabled {
				stateArg = "on"
			}
			if _, err := run(networksetup, "-set"+kind+"state", service, stateArg); err != nil {
				errs = append(errs, err)
			}
		}
		bypass := state.Bypass
		if len(bypass) == 0 {
			bypass = []string{"Empty"}
		}
		if _, err := run(networksetup, append([]string{"-setproxybypassdomains", service}, bypass...)...); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func clearProxy() error {
	list, err := services()
	if err != nil {
		return err
	}
	var errs []error
	for _, service := range list {
		for _, kind := range proxyKinds {
			if _, err := run(networksetup, "-set"+kind+"state", service, "off"); err != nil {
				errs = append(errs, fmt.Errorf("%s: %w", service, err))
			}
		}
	}
	return errors.Join(errs...)
}
