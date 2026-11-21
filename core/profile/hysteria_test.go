package profile

import "testing"

func TestHysteria2QuicParamsLiveInFinalmask(t *testing.T) {
	out, err := convertOutbound(map[string]interface{}{
		"type":         "hysteria2",
		"server":       "1.2.3.4",
		"server_port":  float64(443),
		"password":     "pw",
		"up_mbps":      float64(50),
		"down_mbps":    float64(200),
		"hop_ports":    "20000:30000",
		"hop_interval": float64(30),
		"obfs":         map[string]interface{}{"type": "salamander", "password": "mask"},
		"tls":          map[string]interface{}{"enabled": true, "server_name": "example.com"},
	})
	if err != nil {
		t.Fatal(err)
	}
	stream := getMap(out, "streamSettings")
	hs := getMap(stream, "hysteriaSettings")
	for _, key := range []string{"up", "down", "udphop", "congestion"} {
		if _, ok := hs[key]; ok {
			t.Fatalf("hysteriaSettings.%s is ignored by the core and must not be emitted", key)
		}
	}
	finalmask := getMap(stream, "finalmask")
	if finalmask["udp"] == nil {
		t.Fatal("salamander mask is missing")
	}
	quic := getMap(finalmask, "quicParams")
	if quic["brutalUp"] != "50 mbps" || quic["brutalDown"] != "200 mbps" {
		t.Fatalf("bandwidth = %v / %v", quic["brutalUp"], quic["brutalDown"])
	}
	hop := getMap(quic, "udpHop")
	if hop["ports"] != "20000-30000" || hop["interval"] != 30 {
		t.Fatalf("udpHop = %v", hop)
	}
}

func TestHysteria2WithoutTuningHasNoQuicParams(t *testing.T) {
	out, err := convertOutbound(map[string]interface{}{
		"type":        "hysteria2",
		"server":      "1.2.3.4",
		"server_port": float64(443),
		"password":    "pw",
		"tls":         map[string]interface{}{"enabled": true, "server_name": "example.com"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if getMap(out, "streamSettings")["finalmask"] != nil {
		t.Fatal("no finalmask expected")
	}
}
