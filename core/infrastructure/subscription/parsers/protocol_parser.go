package parsers

import (
	"errors"
	"strings"
)

type ProtocolParser interface {
	Supports(link string) bool
	Parse(link string) (map[string]interface{}, error)
}

type ParserRegistry struct {
	parsers []ProtocolParser
}

func NewRegistry() *ParserRegistry {
	return &ParserRegistry{
		parsers: []ProtocolParser{
			&VLESSParser{},
			&VMESSParser{},
			&TrojanParser{},
			&ShadowsocksParser{},
			&Hysteria2Parser{},
			&SocksParser{},
			&WireGuardParser{},
		},
	}
}

func (r *ParserRegistry) Parse(link string) (map[string]interface{}, error) {
	link = strings.TrimSpace(link)
	for _, parser := range r.parsers {
		if parser.Supports(link) {
			return parser.Parse(link)
		}
	}
	return nil, errors.New("unsupported protocol")
}

func (r *ParserRegistry) IsProtocolLink(link string) bool {
	link = strings.TrimSpace(link)
	lower := strings.ToLower(link)
	protocols := []string{"vless://", "vmess://", "trojan://", "ss://", "shadowsocks://", "hy2://", "hysteria2://", "socks://", "socks5://", "wireguard://", "wg://"}
	for _, proto := range protocols {
		if strings.HasPrefix(lower, proto) {
			return true
		}
	}
	return false
}
