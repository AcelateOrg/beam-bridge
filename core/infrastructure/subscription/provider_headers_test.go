package subscription

import (
	"net/http"
	"testing"
)

func TestProviderSettingsFromHeaders(t *testing.T) {
	h := http.Header{}
	h.Set("fragmentation-enable", "1")
	h.Set("fragmentation-packets", "1-3")
	h.Set("fragmentation-length", "50-100")
	h.Set("noises-enable", "true")
	h.Set("noises-packet-type", "str")
	h.Set("noises-packet", "abc, def")
	h.Set("mux-enable", "1")
	h.Set("mux-tcp-connections", "4")
	h.Set("mux-quic", "skip")
	h.Set("dns-from-json-enable", "1")
	h.Set("new-domain", "new.example.com")
	h.Set("fallback-url", "https://backup.example.com/sub/abc")
	h.Set("exclude-routes", "192.168.1.0/24, 10.0.0.0/8")
	h.Set("per-app-proxy-list-invert", "com.a,com.b")
	h.Set("subscription-userinfo", "0")
	h.Set("xray-tun-mtu", "1400")

	meta := ParseSubscriptionMeta([]string{"#fragmentation-length: 10-20", "#profile-description: base64:0J/RgNC40LLQtdGC"})
	ps := providerSettings(h, meta, "https://old.example.com/sub/abc?x=1")
	if ps == nil {
		t.Fatal("nil settings")
	}
	if ps.Fragment == nil || ps.Fragment.Packets != "1-3" || ps.Fragment.Length != "50-100" || ps.Fragment.Interval != "10-20" {
		t.Errorf("fragment = %+v", ps.Fragment)
	}
	if len(ps.Noises) != 2 || ps.Noises[1].Packet != "def" || ps.Noises[0].Type != "str" {
		t.Errorf("noises = %+v", ps.Noises)
	}
	if ps.Mux == nil || ps.Mux.Concurrency != 4 || ps.Mux.XUDPProxyUDP443 != "skip" {
		t.Errorf("mux = %+v", ps.Mux)
	}
	if !ps.ProfileDNS || !ps.HideTraffic {
		t.Errorf("profileDns=%v hideTraffic=%v", ps.ProfileDNS, ps.HideTraffic)
	}
	if ps.NewURL != "https://new.example.com/sub/abc?x=1" {
		t.Errorf("newUrl = %q", ps.NewURL)
	}
	if ps.FallbackURL != "https://backup.example.com/sub/abc" {
		t.Errorf("fallbackUrl = %q", ps.FallbackURL)
	}
	if len(ps.ExcludeRoutes) != 2 || !ps.PerAppInvert || len(ps.PerAppList) != 2 {
		t.Errorf("routes=%v perApp=%v invert=%v", ps.ExcludeRoutes, ps.PerAppList, ps.PerAppInvert)
	}
	if ps.Description != "Привет" {
		t.Errorf("description = %q", ps.Description)
	}
	if ps.Extra["xray-tun-mtu"] != "1400" {
		t.Errorf("extra = %v", ps.Extra)
	}
}

func TestProviderSettingsEmpty(t *testing.T) {
	if ps := providerSettings(http.Header{}, nil, "https://a.com/s"); ps != nil {
		t.Errorf("want nil, got %+v", ps)
	}
	h := http.Header{}
	h.Set("new-url", "https://a.com/s")
	if ps := providerSettings(h, nil, "https://a.com/s"); ps != nil {
		t.Errorf("same url is not a move, got %+v", ps)
	}
}

func TestExpireMilliseconds(t *testing.T) {
	h := http.Header{}
	h.Set("Subscription-Userinfo", "upload=1; download=2; total=3; expire=1767225600000")
	if info := parseSubscriptionInfo(h); info.Expire != 1767225600 {
		t.Errorf("expire = %d", info.Expire)
	}
}

func TestSingBoxDetour(t *testing.T) {
	outbounds := []interface{}{
		map[string]interface{}{"type": "vless", "tag": "exit", "server": "b.com", "detour": "entry"},
		map[string]interface{}{"type": "trojan", "tag": "entry", "server": "a.com"},
		map[string]interface{}{"type": "vless", "tag": "plain", "server": "c.com", "detour": "direct"},
		map[string]interface{}{"type": "direct", "tag": "direct"},
		map[string]interface{}{"type": "vless", "tag": "loop", "server": "d.com", "detour": "loop"},
	}
	got := SingBoxProxies(outbounds)
	if len(got) != 4 {
		t.Fatalf("want 4 proxies, got %d", len(got))
	}
	if d, ok := got[0]["detour"].(map[string]interface{}); !ok || d["server"] != "a.com" {
		t.Errorf("exit detour = %v", got[0]["detour"])
	}
	if _, has := got[2]["detour"]; has {
		t.Errorf("bare direct detour must be dropped: %v", got[2]["detour"])
	}
	if _, has := got[3]["detour"]; has {
		t.Errorf("self-detour must be dropped: %v", got[3]["detour"])
	}
}
