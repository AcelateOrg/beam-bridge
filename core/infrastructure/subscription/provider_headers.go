package subscription

import (
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"beam-bridge/core/types"
)

// providerKeys — ключи Happ (happ.su/main/dev-docs/app-management) и INCY
// (docs.incy.cc/en/subscription-format), которые панели шлют заголовками
// или строками "#key: value" в теле подписки.
var providerKeys = []string{
	"fragmentation-enable", "fragmentation-packets", "fragmentation-length",
	"fragmentation-interval", "fragmentation-maxsplit",
	"noises-enable", "noises-type", "noises-packet-type", "noises-packet",
	"noises-delay", "noises-rand", "noises-rand-range",
	"mux-enable", "mux-tcp-connections", "mux-xudp-connections", "mux-quic",
	"dns-from-json-enable",
	"new-url", "new-domain", "fallback-url",
	"profile-description", "support-email",
	"hide-settings", "subscription-pin",
	"subscription-ping-onopen-enabled", "subscription-auto-update-enable",
	"subscription-auto-update-open-enable",
	"subscription-autoconnect", "subscription-autoconnect-type",
	"ping-type", "check-url-via-proxy", "ping-result",
	"subscriptions-sort-type", "sort-order", "sniffing-enable",
	"exclude-routes", "exclude-routes-set",
	"per-app-proxy-mode", "per-app-proxy-mode-windows", "per-app-proxy-mode-macos",
	"per-app-proxy-mode-linux", "per-app-proxy-list", "per-app-proxy-list-invert",
	"per-app-proxy-list-set",
	"routing", "autorouting", "routing-enable", "routing-geo-update-interval",
	"server-address-resolve-enable", "server-address-resolve-dns-domain",
	"server-address-resolve-dns-ip",
	"subscriptions-collapse", "subscriptions-expand-now",
	"proxy-enable", "tun-enable", "tun-mode", "xray-tun-mtu",
	"change-user-agent", "subscription-request-timeout",
	"sub-info-color", "sub-info-text", "sub-info-button-text", "sub-info-button-link",
	"sub-expire", "sub-expire-button-link", "notification-subs-expire",
	"premium-url", "hide-url",
	"subscription-userinfo",
}

// providerValues собирает значения из тела и заголовков; заголовок важнее —
// его выставляет панель, а тело часто генерирует шаблон.
func providerValues(header http.Header, meta *SubscriptionMeta) map[string]string {
	values := map[string]string{}
	if meta != nil {
		for k, v := range meta.Raw {
			values[k] = v
		}
	}
	for _, key := range providerKeys {
		if v := strings.TrimSpace(header.Get(key)); v != "" && !strings.ContainsAny(v, "\r\n") {
			values[key] = v
		}
	}
	return values
}

// providerSettings разбирает известные ключи; nil — панель ничего не прислала.
func providerSettings(header http.Header, meta *SubscriptionMeta, subscriptionURL string) *types.ProviderSettings {
	v := providerValues(header, meta)
	known := make(map[string]bool, len(providerKeys))
	for _, key := range providerKeys {
		known[key] = true
	}
	s := &types.ProviderSettings{}
	used := map[string]bool{}
	get := func(key string) string {
		used[key] = true
		return v[key]
	}
	flag := func(key string) bool { return parseBoolMeta(get(key)) }

	if flag("fragmentation-enable") {
		s.Fragment = &types.ProviderFragment{
			Packets:  orDefault(get("fragmentation-packets"), "tlshello"),
			Length:   orDefault(get("fragmentation-length"), "100-200"),
			Interval: orDefault(get("fragmentation-interval"), "10-20"),
			MaxSplit: get("fragmentation-maxsplit"),
		}
	}
	if flag("noises-enable") {
		s.Noises = providerNoises(get("noises-packet-type"), get("noises-type"), get("noises-packet"), get("noises-rand"), get("noises-delay"))
	}
	if flag("mux-enable") {
		s.Mux = &types.ProviderMux{
			Concurrency:     atoiOr(get("mux-tcp-connections"), 0),
			XUDPConcurrency: atoiOr(get("mux-xudp-connections"), 0),
		}
		switch q := strings.ToLower(get("mux-quic")); q {
		case "reject", "allow", "skip":
			s.Mux.XUDPProxyUDP443 = q
		}
	}
	s.ProfileDNS = flag("dns-from-json-enable")

	s.NewURL = resolveNewURL(subscriptionURL, get("new-url"), get("new-domain"))
	if u := get("fallback-url"); isHTTPURL(u) {
		s.FallbackURL = u
	}
	s.Description = decodeIfBase64(get("profile-description"))
	s.SupportEmail = get("support-email")
	s.HideTraffic = strings.TrimSpace(get("subscription-userinfo")) == "0"
	s.HideSettings = flag("hide-settings")
	s.Pin = flag("subscription-pin")
	s.PingOnOpen = flag("subscription-ping-onopen-enabled")
	s.AutoUpdate = flag("subscription-auto-update-enable")
	s.AutoUpdateOnOpen = flag("subscription-auto-update-open-enable")
	s.AutoConnect = flag("subscription-autoconnect")
	s.AutoConnectType = strings.ToLower(get("subscription-autoconnect-type"))
	s.PingType = strings.ToLower(get("ping-type"))
	if u := get("check-url-via-proxy"); isHTTPURL(u) {
		s.PingURL = u
	}
	s.SortOrder = strings.ToLower(orDefault(get("subscriptions-sort-type"), get("sort-order")))
	if raw := get("sniffing-enable"); raw != "" {
		on := parseBoolMeta(raw)
		s.Sniffing = &on
	}
	s.ExcludeRoutes = splitValues(orDefault(get("exclude-routes-set"), get("exclude-routes")))
	s.PerAppMode = strings.ToLower(get("per-app-proxy-mode"))
	if list := get("per-app-proxy-list-invert"); list != "" {
		s.PerAppList, s.PerAppInvert = splitValues(list), true
	} else {
		s.PerAppList = splitValues(orDefault(get("per-app-proxy-list-set"), get("per-app-proxy-list")))
	}
	s.RoutingURL = orDefault(get("routing"), get("autorouting"))

	for key, value := range v {
		if known[key] && !used[key] {
			if s.Extra == nil {
				s.Extra = map[string]string{}
			}
			s.Extra[key] = value
		}
	}
	if isEmptyProvider(s) {
		return nil
	}
	return s
}

// providerNoises: Happ шлёт тип "array" (случайные байты длиной
// noises-rand), str/hex/base64 — готовые данные списком через запятую.
func providerNoises(happType, incyType, packets, randLen, delay string) []types.ProviderNoise {
	kind := strings.ToLower(orDefault(happType, incyType))
	delay = orDefault(delay, "10-16")
	switch kind {
	case "str", "hex", "base64":
		var out []types.ProviderNoise
		for _, p := range strings.Split(packets, ",") {
			if p = strings.TrimSpace(p); p != "" {
				out = append(out, types.ProviderNoise{Type: kind, Packet: p, Delay: delay})
			}
		}
		return out
	default:
		return []types.ProviderNoise{{Type: "rand", Packet: orDefault(randLen, orDefault(packets, "10-20")), Delay: delay}}
	}
}

// resolveNewURL: new-url — полный новый адрес, new-domain — тот же путь на
// другом хосте. Адрес, совпадающий с текущим, не считается переездом.
func resolveNewURL(current, newURL, newDomain string) string {
	if isHTTPURL(newURL) && newURL != current {
		return newURL
	}
	if newDomain == "" || current == "" {
		return ""
	}
	u, err := url.Parse(current)
	if err != nil || u.Host == "" {
		return ""
	}
	host := strings.TrimSuffix(strings.TrimPrefix(strings.TrimPrefix(newDomain, "https://"), "http://"), "/")
	if host == "" || strings.ContainsAny(host, "/?#@ ") || strings.EqualFold(host, u.Host) {
		return ""
	}
	u.Host = host
	return u.String()
}

func isHTTPURL(s string) bool {
	u, err := url.Parse(s)
	return err == nil && (u.Scheme == "https" || u.Scheme == "http") && u.Host != ""
}

func splitValues(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' || r == ';' })
}

func orDefault(v, fallback string) string {
	if strings.TrimSpace(v) == "" {
		return fallback
	}
	return strings.TrimSpace(v)
}

func atoiOr(s string, fallback int) int {
	if n, err := strconv.Atoi(strings.TrimSpace(s)); err == nil {
		return n
	}
	return fallback
}

func isEmptyProvider(s *types.ProviderSettings) bool {
	return s.Fragment == nil && len(s.Noises) == 0 && s.Mux == nil && !s.ProfileDNS &&
		s.NewURL == "" && s.FallbackURL == "" && s.Description == "" && s.SupportEmail == "" &&
		!s.HideTraffic && !s.HideSettings && !s.Pin && !s.PingOnOpen && !s.AutoUpdate &&
		!s.AutoUpdateOnOpen && !s.AutoConnect && s.AutoConnectType == "" && s.PingType == "" &&
		s.PingURL == "" && s.SortOrder == "" && s.Sniffing == nil && len(s.ExcludeRoutes) == 0 &&
		s.PerAppMode == "" && len(s.PerAppList) == 0 && s.RoutingURL == "" && len(s.Extra) == 0
}
