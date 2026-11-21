package parsers

import (
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
)

func lookup(v interface{}, path string) interface{} {
	for _, key := range strings.Split(path, ".") {
		m, ok := v.(map[string]interface{})
		if !ok {
			return nil
		}
		v = m[key]
	}
	return v
}

func TestParseLinks(t *testing.T) {
	vmess := base64.StdEncoding.EncodeToString([]byte(`{"v":"2","ps":"vm","add":"a.com","port":"80","id":"uuid","aid":"0","scy":"auto","net":"tcp","type":"http","host":"h.com","path":"/p","tls":""}`))
	legacySS := base64.StdEncoding.EncodeToString([]byte("aes-256-gcm:pw@1.2.3.4:8388"))

	cases := []struct {
		name string
		link string
		want map[string]string
	}{
		{"vless reality grpc", "vless://uuid@1.2.3.4:443?security=reality&pbk=PK&sid=ab&spx=%2Fx&pqv=MLD&sni=x.com&fp=chrome&type=grpc&serviceName=svc&mode=multi&flow=xtls-rprx-vision#r", map[string]string{
			"tls.reality.public_key":     "PK",
			"tls.reality.short_id":       "ab",
			"tls.reality.spider_x":       "/x",
			"tls.reality.mldsa65_verify": "MLD",
			"tls.server_name":            "x.com",
			"tls.utls.fingerprint":       "chrome",
			"transport.type":             "grpc",
			"transport.multi_mode":       "true",
			"flow":                       "xtls-rprx-vision",
		}},
		{"trojan security none", "trojan://pw@t.com:443?security=none&type=ws&path=%2Fws&host=t.com#t", map[string]string{
			"tls":               "<nil>",
			"transport.type":    "ws",
			"transport.path":    "/ws",
			"transport.headers": "map[Host:t.com]",
		}},
		{"trojan implied tls", "trojan://pw@t.com:443#t2", map[string]string{
			"tls.enabled":     "true",
			"tls.server_name": "t.com",
		}},
		{"vmess tcp http header", "vmess://" + vmess, map[string]string{
			"security":                 "auto",
			"transport.type":           "raw",
			"transport.header.type":    "http",
			"transport.header.request": "map[headers:map[Host:[h.com]] path:[/p]]",
			"tls":                      "<nil>",
		}},
		{"ss legacy base64", "ss://" + legacySS + "#legacy", map[string]string{
			"method":      "aes-256-gcm",
			"password":    "pw",
			"server":      "1.2.3.4",
			"server_port": "8388",
		}},
		{"ss plugin", "ss://YWVzLTI1Ni1nY206cHc@s.com:8388?plugin=obfs-local%3Bobfs%3Dhttp#plug", map[string]string{
			"plugin":      "obfs-local",
			"plugin_opts": "obfs=http",
		}},
		{"hy2 multiport obfs pin", "hy2://auth@h.com:443,20000-30000/?sni=s.com&obfs=salamander&obfs-password=op&pinSHA256=AB:CD:EF&upmbps=50#hy", map[string]string{
			"server_port":                 "443",
			"hop_ports":                   "443,20000-30000",
			"password":                    "auth",
			"obfs.type":                   "salamander",
			"obfs.password":               "op",
			"tls.pinned_peer_cert_sha256": "abcdef",
			"up_mbps":                     "50",
		}},
		{"socks base64 userinfo", "socks://dXNlcjpwYXNz@1.1.1.1:1080#s", map[string]string{
			"type":     "socks",
			"username": "user",
			"password": "pass",
		}},
		{"wireguard", "wireguard://privkey@w.com:51820?publickey=pub&address=10.0.0.2/32,fd00::2/128&mtu=1280&reserved=1,2,3#wg", map[string]string{
			"private_key":     "privkey",
			"peer_public_key": "pub",
			"local_address":   "[10.0.0.2/32 fd00::2/128]",
			"mtu":             "1280",
			"reserved":        "[1 2 3]",
		}},
	}

	registry := NewRegistry()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, err := registry.Parse(tc.link)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			for path, want := range tc.want {
				if got := fmt.Sprint(lookup(out, path)); got != want {
					t.Errorf("%s = %s, want %s", path, got, want)
				}
			}
		})
	}
}
