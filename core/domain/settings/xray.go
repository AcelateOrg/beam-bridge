package settings

// Тонкие настройки ядра Xray: фрагментация, мультиплексирование и
// DNS. Все они попадают в генерируемый конфиг ядра
// (profile.XrayConfigBuilder) и применяются при следующем подключении.

// CoreSettings — раздел «Ядро».
type CoreSettings struct {
	Fragment FragmentSettings `json:"fragment"`
	Mux      MuxSettings      `json:"mux"`
}

// FragmentSettings — фрагментация первых пакетов соединения (обычно
// TLS ClientHello) через freedom-outbound, который подставляется нодам как
// dialerProxy. Пресет задаёт параметры целиком; "custom" берёт поля ниже.
type FragmentSettings struct {
	Enabled bool   `json:"enabled"`
	Preset  string `json:"preset"` // "standard" | "strong" | "custom"
	// Packets — "tlshello" или диапазон номеров TCP-записей "1-3".
	Packets  string `json:"packets"`
	Length   string `json:"length"`   // байт в фрагменте: "100-200"
	Interval string `json:"interval"` // пауза между фрагментами, мс: "10-20"
	// MaxSplit — предел числа фрагментов, "" — без предела.
	MaxSplit string          `json:"maxSplit"`
	Noises   []NoiseSettings `json:"noises"`
	// Direct — фрагментировать и прямой (мимо VPN) трафик.
	Direct bool `json:"direct"`
}

// NoiseSettings — мусорный UDP-пакет, который ядро отправляет перед
// первым настоящим.
type NoiseSettings struct {
	Type   string `json:"type"`   // "rand" | "str" | "hex" | "base64"
	Packet string `json:"packet"` // для rand — длина "10-20", иначе данные
	Delay  string `json:"delay"`  // мс: "10-16"
}

// FragmentParams — итоговые параметры фрагментации после применения пресета.
type FragmentParams struct {
	Packets  string
	Length   string
	Interval string
	MaxSplit string
}

// FragmentPresets — готовые наборы. Значения подобраны так, чтобы
// рукопожатие оставалось быстрым: даже «сильный» режим добавляет к нему
// считанные десятки миллисекунд.
var FragmentPresets = map[string]FragmentParams{
	"standard": {Packets: "tlshello", Length: "100-200", Interval: "10-20"},
	"strong":   {Packets: "1-3", Length: "30-60", Interval: "2-5", MaxSplit: "16-32"},
}

// Params возвращает параметры с учётом пресета.
func (f FragmentSettings) Params() FragmentParams {
	if preset, ok := FragmentPresets[f.Preset]; ok {
		return preset
	}
	return FragmentParams{Packets: f.Packets, Length: f.Length, Interval: f.Interval, MaxSplit: f.MaxSplit}
}

// MuxSettings — Mux.Cool и XUDP. Ноды с XHTTP, Hysteria и XTLS Vision
// автоматически остаются без мультиплексирования.
type MuxSettings struct {
	Enabled bool `json:"enabled"`
	// Concurrency — TCP-потоков на одно соединение (1..1024), -1 — TCP без mux.
	Concurrency int `json:"concurrency"`
	// XUDPConcurrency — UDP-потоков XUDP (1..1024), -1 — UDP без mux.
	XUDPConcurrency int `json:"xudpConcurrency"`
	// XUDPProxyUDP443 — что делать с UDP/443 (QUIC): "reject" | "allow" | "skip".
	XUDPProxyUDP443 string `json:"xudpProxyUDP443"`
}

// DNSSettings — раздел «DNS».
type DNSSettings struct {
	// Servers — основные серверы по порядку приоритета.
	Servers []DNSServer `json:"servers"`
	// Rules — домены, которые резолвятся отдельным сервером.
	Rules []DNSRule `json:"rules"`
	// Hosts — статические записи.
	Hosts         []DNSHost `json:"hosts"`
	ServeStale    bool      `json:"serveStale"`
	DisableCache  bool      `json:"disableCache"`
	ParallelQuery bool      `json:"parallelQuery"`
	SystemHosts   bool      `json:"systemHosts"`
	// UseProfileDNS — брать DNS из конфига профиля (Xray JSON подписки),
	// если он там есть; у нод без своего DNS остаются настройки выше.
	UseProfileDNS bool `json:"useProfileDns"`
}

// DNSServer — адрес в синтаксисе Xray: "1.1.1.1", "1.1.1.1:53",
// "tcp://1.1.1.1", "https://1.1.1.1/dns-query", "quic+local://dns.adguard.com"
// и т.д. Direct — запросы идут мимо VPN.
type DNSServer struct {
	Address string `json:"address"`
	Direct  bool   `json:"direct"`
}

// DNSRule отправляет перечисленные домены ("example.com", "geosite:ru",
// "domain:", "full:", "keyword:", "regexp:") на свой сервер.
type DNSRule struct {
	Domains []string `json:"domains"`
	Server  string   `json:"server"`
	Direct  bool     `json:"direct"`
}

// DNSHost — статическая запись: домен -> IP-адреса или другой домен.
type DNSHost struct {
	Domain  string   `json:"domain"`
	Address []string `json:"address"`
}
