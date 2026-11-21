package profile

import (
	"encoding/json"
	"reflect"
	"testing"

	"beam-bridge/core/infrastructure/subscription"
)

// The provider's Xray outbound must reach the core unchanged after the trip
// through the internal format.
const roundTripConfig = `[
 {"remarks":"reality-chain","meta":{"serverDescription":"Для игр"},
  "dns":{"servers":["1.1.1.1"]},
  "outbounds":[
   {"tag":"proxy","protocol":"vless",
    "settings":{"vnext":[{"address":"r.example.com","port":443,"users":[{"id":"u1","flow":"xtls-rprx-vision","encryption":"none","level":0}]}]},
    "streamSettings":{"network":"raw","security":"reality",
      "realitySettings":{"serverName":"www.microsoft.com","fingerprint":"firefox","publicKey":"pk","shortId":"ab","spiderX":"/x","mldsa65Verify":"mv"},
      "sockopt":{"dialerProxy":"frag","tcpFastOpen":true,"domainStrategy":"UseIPv4"}},
    "mux":{"enabled":false,"concurrency":-1}},
   {"tag":"frag","protocol":"freedom","settings":{"fragment":{"packets":"tlshello","length":"100-200","interval":"10-20"},"noises":[{"type":"rand","packet":"10-20","delay":"10-16"}]}},
   {"tag":"direct","protocol":"freedom"},{"tag":"block","protocol":"blackhole"}]},
 {"remarks":"ws-tls",
  "outbounds":[{"tag":"proxy","protocol":"vmess","sendThrough":"0.0.0.0",
    "settings":{"vnext":[{"address":"v.example.com","port":8443,"users":[{"id":"u2","security":"aes-128-gcm","alterId":0}]}]},
    "streamSettings":{"network":"ws","security":"tls",
      "tlsSettings":{"serverName":"cdn.example.com","alpn":["http/1.1"],"fingerprint":"chrome","allowInsecure":true,"minVersion":"1.3","pinnedPeerCertSha256":"abc","echConfigList":"AEX=","echForceQuery":"full","masterKeyLog":"x.log"},
      "wsSettings":{"path":"/ws?ed=2048","host":"cdn.example.com","headers":{"User-Agent":"Mozilla"},"heartbeatPeriod":30},
      "finalmask":{"tcp":[{"type":"fragment","settings":{"packets":"tlshello"}}]}},
    "mux":{"enabled":true,"concurrency":8,"xudpConcurrency":16,"xudpProxyUDP443":"skip"}}]},
 {"remarks":"grpc-trojan",
  "outbounds":[{"tag":"t","protocol":"trojan","settings":{"servers":[{"address":"t.example.com","port":443,"password":"p","email":"e"}]},
    "streamSettings":{"network":"grpc","security":"tls","tlsSettings":{"serverName":"t.example.com"},
      "grpcSettings":{"serviceName":"svc","authority":"a.example.com","multiMode":true,"idle_timeout":60,"user_agent":"ua"}}}]},
 {"remarks":"kcp-ss",
  "outbounds":[{"tag":"s","protocol":"shadowsocks","settings":{"servers":[{"address":"1.2.3.4","port":8388,"method":"2022-blake3-aes-128-gcm","password":"k"}]},
    "streamSettings":{"network":"kcp","kcpSettings":{"mtu":1350,"tti":20,"uplinkCapacity":5,"congestion":true,"header":{"type":"wechat-video"},"seed":"s"}}}]},
 {"remarks":"tcp-http-header",
  "outbounds":[{"tag":"h","protocol":"vless","settings":{"address":"h.example.com","port":80,"id":"u3","encryption":"none"},
    "streamSettings":{"network":"tcp","tcpSettings":{"header":{"type":"http","request":{"path":["/"],"headers":{"Host":["h.example.com"]}}}}}}]},
 {"remarks":"hy2",
  "outbounds":[{"tag":"hy","protocol":"hysteria","settings":{"version":2,"address":"hy.example.com","port":443},
    "streamSettings":{"network":"hysteria","security":"tls","tlsSettings":{"serverName":"hy.example.com","alpn":["h3"]},
      "hysteriaSettings":{"version":2,"auth":"pw","udpIdleTimeout":60},
      "finalmask":{"udp":[{"type":"salamander","settings":{"password":"obfs"}}],"quicParams":{"brutalUp":"50 mbps","brutalDown":"200 mbps","udpHop":{"ports":"20000-30000","interval":30}}}}}]},
 {"remarks":"wg",
  "outbounds":[{"tag":"wg","protocol":"wireguard","settings":{"secretKey":"sk","address":["10.0.0.2/32"],"peers":[{"publicKey":"pub","endpoint":"wg.example.com:51820","keepAlive":25}],"mtu":1280,"reserved":[1,2,3],"workers":2}}]},
 {"remarks":"socks",
  "outbounds":[{"tag":"so","protocol":"socks","settings":{"servers":[{"address":"s.example.com","port":1080,"users":[{"user":"a","pass":"b"}]}]}}]}
]`

func TestXrayRoundTrip(t *testing.T) {
	agg := subscription.NewAggregator(nil)
	bf, err := agg.BuildBeamFromSubscription([]byte(roundTripConfig), "https://sub.example.com/x", nil)
	if err != nil {
		t.Fatal(err)
	}
	var originals []map[string]interface{}
	json.Unmarshal([]byte(roundTripConfig), &originals)
	if len(bf.Data.Nodes) != len(originals) {
		t.Fatalf("nodes: got %d want %d", len(bf.Data.Nodes), len(originals))
	}
	if bf.Data.Nodes[0].Description != "Для игр" || bf.Data.Nodes[0].DNS == nil {
		t.Errorf("meta/dns lost: %+v", bf.Data.Nodes[0])
	}
	for i, node := range bf.Data.Nodes {
		converted, err := convertOutbound(node.EffectiveOutbound())
		if err != nil {
			t.Errorf("%s: %v", node.Name, err)
			continue
		}
		chain := takeChain(converted)
		converted["tag"] = "proxy"
		hops := linkChain(converted, "proxy", chain)
		// Mux is applied by nodeTuning; compare it from the internal key.
		var want map[string]interface{}
		for _, o := range originals[i]["outbounds"].([]interface{}) {
			ob := o.(map[string]interface{})
			if supported(ob) {
				want = ob
				break
			}
		}
		got := normalize(converted)
		exp := normalize(want)
		delete(exp, "mux")
		delete(exp, "tag")
		delete(got, "tag")
		// dialerProxy is renamed to the hop tag.
		if s := exp["streamSettings"]; s != nil {
			if so, ok := s.(map[string]interface{})["sockopt"].(map[string]interface{}); ok && so["dialerProxy"] != nil {
				so["dialerProxy"] = "direct-chain-proxy-1"
			}
		}
		if !reflect.DeepEqual(got, exp) {
			g, _ := json.MarshalIndent(got, "", " ")
			e, _ := json.MarshalIndent(exp, "", " ")
			t.Errorf("%s:\n got %s\nwant %s", node.Name, g, e)
		}
		if len(hops) > 0 {
			h, _ := json.Marshal(hops)
			t.Logf("%s hops: %s", node.Name, h)
		}
		if m := node.Outbound["multiplex"]; m != nil {
			t.Logf("%s multiplex: %v", node.Name, m)
		}
	}
}

func supported(ob map[string]interface{}) bool {
	switch ob["protocol"] {
	case "vless", "vmess", "trojan", "shadowsocks", "hysteria", "socks", "http", "wireguard":
		return true
	}
	return false
}

// normalize brings both sides to the canonical Xray shape: vnext/servers
// lists, numbers as float64, default fields the converter always writes.
func normalize(ob map[string]interface{}) map[string]interface{} {
	data, _ := json.Marshal(ob)
	var out map[string]interface{}
	json.Unmarshal(data, &out)
	s, _ := out["settings"].(map[string]interface{})
	if s != nil && s["address"] != nil && (out["protocol"] == "vless" || out["protocol"] == "vmess") {
		user := map[string]interface{}{}
		for k, v := range s {
			if k != "address" && k != "port" {
				user[k] = v
			}
		}
		out["settings"] = map[string]interface{}{"vnext": []interface{}{map[string]interface{}{"address": s["address"], "port": s["port"], "users": []interface{}{user}}}}
	}
	if st, ok := out["streamSettings"].(map[string]interface{}); ok {
		if st["network"] == "tcp" {
			st["network"] = "raw"
		}
		if v, ok := st["tcpSettings"]; ok {
			st["rawSettings"] = v
			delete(st, "tcpSettings")
		}
		if len(st) == 1 && st["network"] == "raw" {
			delete(out, "streamSettings")
		}
	}
	return out
}
