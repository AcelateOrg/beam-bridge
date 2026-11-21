package types

// ProviderSettings — настройки, которые панель (Remnawave, Marzban, Happ,
// INCY) присылает заголовками подписки или строками "#key: value" в теле.
// Сетевые (фрагментация, шум, Mux, DNS) работают как значения по
// умолчанию для нод профиля: включённое пользователем в BEAM важнее.
// Остальное хранится для UI.
type ProviderSettings struct {
	Fragment *ProviderFragment `json:"fragment,omitempty"`
	Noises   []ProviderNoise   `json:"noises,omitempty"`
	Mux      *ProviderMux      `json:"mux,omitempty"`
	// ProfileDNS — dns-from-json-enable: брать DNS из Xray JSON ноды.
	ProfileDNS bool `json:"profileDns,omitempty"`

	// NewURL — new-url / new-domain: адрес, с которого подписку надо
	// обновлять дальше. FallbackURL — запасной адрес, если основной не
	// ответил.
	NewURL      string `json:"newUrl,omitempty"`
	FallbackURL string `json:"fallbackUrl,omitempty"`

	Description  string `json:"description,omitempty"`
	SupportEmail string `json:"supportEmail,omitempty"`
	// HideTraffic — subscription-userinfo: 0, блок трафика не показывается.
	HideTraffic  bool `json:"hideTraffic,omitempty"`
	HideSettings bool `json:"hideSettings,omitempty"`
	Pin          bool `json:"pin,omitempty"`
	PingOnOpen   bool `json:"pingOnOpen,omitempty"`
	AutoUpdate   bool `json:"autoUpdate,omitempty"`
	// AutoUpdateOnOpen — обновлять подписку при запуске приложения.
	AutoUpdateOnOpen bool   `json:"autoUpdateOnOpen,omitempty"`
	AutoConnect      bool   `json:"autoConnect,omitempty"`
	AutoConnectType  string `json:"autoConnectType,omitempty"`
	PingType         string `json:"pingType,omitempty"`
	PingURL          string `json:"pingUrl,omitempty"`
	SortOrder        string `json:"sortOrder,omitempty"`
	Sniffing         *bool  `json:"sniffing,omitempty"`
	// ExcludeRoutes — подсети, которые не надо заворачивать в туннель.
	ExcludeRoutes []string `json:"excludeRoutes,omitempty"`
	// PerAppMode — "on" | "off", PerAppList — пакеты для режима, PerAppInvert:
	// список — это исключения, а не единственные приложения в VPN.
	PerAppMode   string   `json:"perAppMode,omitempty"`
	PerAppList   []string `json:"perAppList,omitempty"`
	PerAppInvert bool     `json:"perAppInvert,omitempty"`
	// RoutingURL — routing / autorouting: ссылка на набор правил провайдера.
	RoutingURL string `json:"routingUrl,omitempty"`
	// Extra — остальные распознанные ключи как пришли, нижним регистром.
	Extra map[string]string `json:"extra,omitempty"`
}

type ProviderFragment struct {
	Packets  string `json:"packets,omitempty"`
	Length   string `json:"length,omitempty"`
	Interval string `json:"interval,omitempty"`
	MaxSplit string `json:"maxSplit,omitempty"`
}

type ProviderNoise struct {
	Type   string `json:"type"`
	Packet string `json:"packet"`
	Delay  string `json:"delay,omitempty"`
}

type ProviderMux struct {
	Concurrency     int    `json:"concurrency,omitempty"`
	XUDPConcurrency int    `json:"xudpConcurrency,omitempty"`
	XUDPProxyUDP443 string `json:"xudpProxyUDP443,omitempty"`
}
