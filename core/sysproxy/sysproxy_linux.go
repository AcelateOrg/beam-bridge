//go:build linux && !android

package sysproxy

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

// Linux has no single system proxy. GNOME and everything built on its
// settings (Cinnamon, Budgie, Unity, most GTK apps, Chromium) read
// org.gnome.system.proxy through gsettings; KDE apps read kioslaverc. Both
// are set when their tool is present.

const goos = "linux"

var gnomeKeys = [][2]string{
	{"org.gnome.system.proxy", "mode"},
	{"org.gnome.system.proxy", "ignore-hosts"},
	{"org.gnome.system.proxy.http", "host"},
	{"org.gnome.system.proxy.http", "port"},
	{"org.gnome.system.proxy.https", "host"},
	{"org.gnome.system.proxy.https", "port"},
	{"org.gnome.system.proxy.socks", "host"},
	{"org.gnome.system.proxy.socks", "port"},
}

var kdeKeys = []string{"ProxyType", "httpProxy", "httpsProxy", "socksProxy", "NoProxyFor"}

const kdeGroup = "Proxy Settings"

type savedSettings struct {
	Gnome map[string]string `json:"gnome,omitempty"`
	KDE   map[string]string `json:"kde,omitempty"`
}

func prepareCommand(*exec.Cmd) {}

func supported() bool { return hasGnome() || kdeTool("kwriteconfig") != "" }

func hasGnome() bool {
	if !available("gsettings") {
		return false
	}
	_, err := run("gsettings", "get", "org.gnome.system.proxy", "mode")
	return err == nil
}

// kdeTool returns the installed kwriteconfig/kreadconfig (Plasma 6 first).
func kdeTool(base string) string {
	for _, name := range []string{base + "6", base + "5"} {
		if available(name) {
			return name
		}
	}
	return ""
}

func isKDE() bool {
	desktop := strings.ToUpper(os.Getenv("XDG_CURRENT_DESKTOP") + ":" + os.Getenv("DESKTOP_SESSION"))
	return strings.Contains(desktop, "KDE") || strings.Contains(desktop, "PLASMA") || os.Getenv("KDE_FULL_SESSION") != ""
}

func capture() (json.RawMessage, error) {
	var saved savedSettings
	if hasGnome() {
		saved.Gnome = make(map[string]string, len(gnomeKeys))
		for _, key := range gnomeKeys {
			value, err := run("gsettings", "get", key[0], key[1])
			if err != nil {
				return nil, err
			}
			saved.Gnome[key[0]+" "+key[1]] = value
		}
	}
	if reader := kdeTool("kreadconfig"); reader != "" && isKDE() {
		saved.KDE = make(map[string]string, len(kdeKeys))
		for _, key := range kdeKeys {
			value, _ := run(reader, "--file", "kioslaverc", "--group", kdeGroup, "--key", key)
			saved.KDE[key] = value
		}
	}
	if saved.Gnome == nil && saved.KDE == nil {
		return nil, errors.New("no supported desktop proxy settings (GNOME/KDE) found")
	}
	return json.Marshal(saved)
}

func apply(host string, port int) error {
	p := strconv.Itoa(port)
	applied := false
	var errs []error

	if hasGnome() {
		ignore := make([]string, len(cidrBypass))
		for i, h := range cidrBypass {
			ignore[i] = "'" + h + "'"
		}
		steps := [][]string{
			{"org.gnome.system.proxy.http", "host", host},
			{"org.gnome.system.proxy.http", "port", p},
			{"org.gnome.system.proxy.https", "host", host},
			{"org.gnome.system.proxy.https", "port", p},
			{"org.gnome.system.proxy.socks", "host", host},
			{"org.gnome.system.proxy.socks", "port", p},
			{"org.gnome.system.proxy", "ignore-hosts", "[" + strings.Join(ignore, ", ") + "]"},
			// The mode goes last: apps switch over only once the rest is set.
			{"org.gnome.system.proxy", "mode", "manual"},
		}
		if err := gsettingsSet(steps); err != nil {
			errs = append(errs, err)
		} else {
			applied = true
		}
	}

	if writer := kdeTool("kwriteconfig"); writer != "" && isKDE() {
		values := map[string]string{
			"httpProxy":  "http://" + host + " " + p,
			"httpsProxy": "http://" + host + " " + p,
			"socksProxy": "socks://" + host + " " + p,
			"NoProxyFor": strings.Join(cidrBypass, ","),
			"ProxyType":  "1",
		}
		if err := kdeWrite(writer, values); err != nil {
			errs = append(errs, err)
		} else {
			applied = true
		}
	}

	if !applied {
		if len(errs) == 0 {
			return errors.New("no supported desktop proxy settings (GNOME/KDE) found")
		}
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
	if saved.Gnome != nil && available("gsettings") {
		var steps [][]string
		var mode []string
		for _, key := range gnomeKeys {
			value, ok := saved.Gnome[key[0]+" "+key[1]]
			if !ok || value == "" {
				continue
			}
			step := []string{key[0], key[1], value}
			if key[1] == "mode" {
				mode = step
				continue
			}
			steps = append(steps, step)
		}
		// Mode first this time: apps stop using the proxy before it changes.
		if mode != nil {
			steps = append([][]string{mode}, steps...)
		}
		if err := gsettingsSet(steps); err != nil {
			errs = append(errs, err)
		}
	}
	if saved.KDE != nil {
		if writer := kdeTool("kwriteconfig"); writer != "" {
			if err := kdeWrite(writer, saved.KDE); err != nil {
				errs = append(errs, err)
			}
		}
	}
	return errors.Join(errs...)
}

func clearProxy() error {
	var errs []error
	if available("gsettings") {
		if err := gsettingsSet([][]string{{"org.gnome.system.proxy", "mode", "none"}}); err != nil {
			errs = append(errs, err)
		}
	}
	if writer := kdeTool("kwriteconfig"); writer != "" && isKDE() {
		if err := kdeWrite(writer, map[string]string{"ProxyType": "0"}); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func gsettingsSet(steps [][]string) error {
	for _, step := range steps {
		if _, err := run("gsettings", "set", step[0], step[1], step[2]); err != nil {
			return err
		}
	}
	return nil
}

func kdeWrite(writer string, values map[string]string) error {
	// ProxyType last so KIO switches only once the addresses are in place.
	for _, key := range kdeKeys {
		if key == "ProxyType" {
			continue
		}
		if err := kdeWriteKey(writer, key, values); err != nil {
			return err
		}
	}
	if err := kdeWriteKey(writer, "ProxyType", values); err != nil {
		return err
	}
	// Tell running KIO slaves to re-read the configuration.
	if available("dbus-send") {
		_, _ = run("dbus-send", "--type=signal", "/KIO/Scheduler",
			"org.kde.KIO.Scheduler.reparseSlaveConfiguration", "string:")
	}
	return nil
}

func kdeWriteKey(writer, key string, values map[string]string) error {
	value, ok := values[key]
	if !ok {
		return nil
	}
	args := []string{"--file", "kioslaverc", "--group", kdeGroup, "--key", key}
	if value == "" {
		args = append(args, "--delete")
	} else {
		args = append(args, value)
	}
	if _, err := run(writer, args...); err != nil {
		return fmt.Errorf("kde proxy %s: %w", key, err)
	}
	return nil
}
