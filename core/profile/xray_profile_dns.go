package profile

import (
	"log"
	"net/url"
	"strings"

	"beam-bridge/core/geodata"
)

// DNS из конфига профиля. Провайдеры (Remnawave, Marzban и т.п.) кладут в
// Xray JSON свой раздел "dns"; с DNSSettings.UseProfileDNS он заменяет
// DNS из настроек BEAM. Раздел берётся как есть, кроме того, что сломает
// туннель или старт ядра.

// geoKeeper сообщает, есть ли запись ("ru", "category-ads-all@ads") в
// локальной базе file. nil — базы не проверяются.
type geoKeeper func(file, entry string) bool

// profileDNSKeys — поля верхнего уровня, которые переносятся из профиля.
// tag и queryStrategy задаёт BEAM: tag нужен маршрутизации, чтобы запросы
// DNS-приложения шли через прокси, а UseIPv4 — потому что туннель
// без включённого IPv6 его отбрасывает.
var profileDNSKeys = map[string]bool{
	"hosts":                  true,
	"clientIp":               true,
	"disableCache":           true,
	"disableFallback":        true,
	"disableFallbackIfMatch": true,
	"serveStale":             true,
	"serveExpiredTTL":        true,
	"enableParallelQuery":    true,
	"useSystemHosts":         true,
}

// buildProfileDNS возвращает готовый раздел "dns" для ядра или nil, если
// в профиле нет ни одного пригодного сервера (тогда работает DNS BEAM).
func buildProfileDNS(raw map[string]interface{}, keep geoKeeper) map[string]interface{} {
	if len(raw) == 0 {
		return nil
	}
	list, _ := raw["servers"].([]interface{})
	servers := make([]interface{}, 0, len(list))
	for _, item := range list {
		if server, ok := profileDNSServer(item, keep); ok {
			servers = append(servers, server)
		}
	}
	if len(servers) == 0 {
		log.Printf("dns: profile DNS has no usable servers, BEAM DNS is used")
		return nil
	}

	dns := map[string]interface{}{
		"servers":       servers,
		"queryStrategy": "UseIPv4",
		"tag":           dnsInboundTag,
	}
	for key, value := range raw {
		if profileDNSKeys[key] {
			dns[key] = value
		}
	}
	if hosts, ok := dns["hosts"].(map[string]interface{}); ok {
		dns["hosts"] = profileDNSHosts(hosts, keep)
	}
	return dns
}

// profileDNSServer приводит сервер профиля к виду, безопасному для туннеля.
// Строка — просто адрес; объект может ограничивать домены и ожидаемые IP.
func profileDNSServer(item interface{}, keep geoKeeper) (interface{}, bool) {
	switch v := item.(type) {
	case string:
		return v, profileDNSAddressOK(v)
	case map[string]interface{}:
		address, _ := v["address"].(string)
		if !profileDNSAddressOK(address) {
			return nil, false
		}
		server := make(map[string]interface{}, len(v))
		for key, value := range v {
			server[key] = value
		}
		// Свой tag увёл бы запросы мимо правила dns-in -> прокси прямо в
		// правило порта 53, то есть обратно в DNS-приложение: петля.
		delete(server, "tag")
		delete(server, "queryStrategy")

		if domains, ok := server["domains"].([]interface{}); ok {
			kept := filterGeo(domains, "geosite:", geodata.FileSite, keep)
			// Сервер, у которого не осталось доменов, стал бы общим и
			// начал отвечать на всё подряд.
			if len(kept) == 0 {
				return nil, false
			}
			server["domains"] = kept
		}
		for _, key := range []string{"expectIPs", "expectedIPs", "unexpectedIPs"} {
			ips, ok := server[key].([]interface{})
			if !ok {
				continue
			}
			if kept := filterGeo(ips, "geoip:", geodata.FileIP, keep); len(kept) > 0 {
				server[key] = kept
			} else {
				delete(server, key)
			}
		}
		return server, true
	}
	return nil, false
}

// profileDNSAddressOK отсекает адреса, которые в туннеле не работают:
// localhost и loopback спрашивают сам туннель, fakedns требует своего
// раздела в конфиге, которого BEAM не строит.
func profileDNSAddressOK(address string) bool {
	address = strings.TrimSpace(address)
	switch strings.ToLower(address) {
	case "", "localhost", "fakedns":
		return false
	}
	host := address
	if strings.Contains(address, "://") {
		u, err := url.Parse(address)
		if err != nil || u.Hostname() == "" {
			return false
		}
		host = u.Hostname()
	}
	_, ok := usableResolver(host)
	return ok
}

func profileDNSHosts(hosts map[string]interface{}, keep geoKeeper) map[string]interface{} {
	out := make(map[string]interface{}, len(hosts))
	for domain, value := range hosts {
		if entry, ok := strings.CutPrefix(domain, "geosite:"); ok {
			if keep != nil && !keep(geodata.FileSite, strings.ToLower(entry)) {
				continue
			}
		}
		out[domain] = value
	}
	return out
}

func filterGeo(items []interface{}, prefix, file string, keep geoKeeper) []interface{} {
	kept := make([]interface{}, 0, len(items))
	for _, item := range items {
		s, ok := item.(string)
		// ext: читает сторонние .dat-файлы, которых у BEAM нет.
		if !ok || strings.HasPrefix(s, "ext:") {
			continue
		}
		if entry, isGeo := strings.CutPrefix(s, prefix); isGeo && keep != nil {
			if !keep(file, strings.ToLower(entry)) {
				log.Printf("dns: profile DNS entry %q not found in %s, skipped", s, file)
				continue
			}
		}
		kept = append(kept, s)
	}
	return kept
}
