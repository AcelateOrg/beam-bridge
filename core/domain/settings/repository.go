package settings

import (
	"beam-bridge/core/types"
)

type Repository interface {
	Get() *Settings
	UpdateConnection(conn ConnectionSettings) error
	UpdateApplication(app ApplicationSettings) error
	UpdateSplitTunnel(st types.SplitTunnelSettings) error
	UpdateAppearance(app AppearanceSettings) error
	SetOnboardingCompleted(completed bool) error
	SetSplitTunnelEnabled(enabled bool) error
	SetDeveloperMode(enabled bool) error
	SetExtendedLogs(enabled bool) error
	SetTraceLogging(enabled bool) error
	SetCoreLogging(enabled bool) error
	SetLogLevel(level string) error
	SetRealityDebug(enabled bool) error
	UpdateRoutingMode(mode string) error
	UpdateProTunGraph(graph types.ProTunGraph) error
	// UpdateProTunProfileGraph sets the ProTun layer of one profile (nil
	// removes it).
	UpdateProTunProfileGraph(profileID string, graph *types.ProTunGraph) error
	UpdateHwid(h HwidSettings) error
	UpdatePing(ping PingSettings) error
	UpdateCore(core CoreSettings) error
	UpdateDNS(dns DNSSettings) error
	ResetToDefaults() error
}

type Settings struct {
	SchemaVersion int

	Connection  ConnectionSettings
	Appearance  AppearanceSettings
	Application ApplicationSettings
	SplitTunnel types.SplitTunnelSettings
	RoutingMode string
	ProTunGraph types.ProTunGraph
	// ProTunProfiles holds per-profile ProTun layers (profile ID -> graph).
	// A layer applies only while its profile is active, before ProTunGraph.
	ProTunProfiles      map[string]types.ProTunGraph
	APISecret         string
	APIPort           int
	OnboardingCompleted bool
	DeveloperMode       bool
	ExtendedLogs        bool
	TraceLogging        bool
	DisableCoreLogging  bool
	// LogLevel — пользовательский уровень логов вкладки «Логи»:
	// "off" | "error" | "info" | "debug". Пустое = "info" (или "off", если
	// логи явно выключены через DisableCoreLogging).
	LogLevel     string
	RealityDebug bool
	Hwid         HwidSettings
	HappCompat   *LegacyHappCompatSettings `json:"HappCompat,omitempty"`
	Ping         PingSettings
	Core         CoreSettings
	DNS          DNSSettings
}

// HwidSettings — самостоятельная настройка аппаратного идентификатора.
// Панелям (Remnawave и совместимым) достаточно заголовков X-Hwid и
// Device-Name, чтобы идентифицировать устройство как BEAM-клиент.
type HwidSettings struct {
	Enabled bool
	Mode    string // "auto" | "manual"
	Value   string
}

// LegacyHappCompatSettings — формат до переезда на HwidSettings. Читается
// только для миграции существующего settings.json и сразу выбрасывается.
type LegacyHappCompatSettings struct {
	Enabled  bool
	HWIDMode string
	HWID     string
}

type ConnectionSettings struct {
	Mode         string
	ProxyType    string
	ProxyHost    string
	ProxyPort    int
	TunName      string
	PrimaryDNS   string
	SecondaryDNS string
	ProxyDNS     string
	DNSOverVPN   bool
	MTU          int
	Stack        string
	// KillSwitch — если VPN упал сам, интернет ставится на паузу до переподключения;
	// в TUN заодно закрываются утечки DNS и IPv6 мимо туннеля.
	KillSwitch bool
}

type PingSettings struct {
	NodeMode       string
	ConnectionMode string
}

type AppearanceSettings struct {
	// Theme — id встроенной темы, "system" или "custom:<id>" для
	// пользовательской.
	Theme        string
	Font         string
	Radius       string
	Animation    string
	CustomThemes []CustomTheme
	Backdrop     BackdropSettings
	// Accent — свой акцентный цвет поверх готовой темы (#rrggbb); пусто —
	// акцент самой темы. На пользовательские темы и «Из обоев» не влияет.
	Accent string
}

// Режимы фона под интерфейсом.
const (
	BackdropOff       = "off"
	BackdropWallpaper = "wallpaper" // обои рабочего стола ОС
	BackdropPhoto     = "photo"     // фото, загруженное пользователем

	BackdropStyleContent = "content"
	BackdropStyleSidebar = "sidebar"
)

// BackdropSettings — картинка под интерфейсом. Само фото лежит файлом
// в каталоге данных приложения, здесь только параметры.
type BackdropSettings struct {
	Mode string `json:"mode"`
	// Blur — размытие в px, 0..40.
	Blur int `json:"blur"`
	// Dim — затемнение в процентах, -100..90: положительное — подложка
	// цветом фона темы, отрицательное — осветление картинки (для тёмных фото).
	Dim int `json:"dim"`
	// Density — плотность панелей относительно стиля, -50..50; 0 — как задумано стилем.
	Density int `json:"density"`
	// Style — что из двух областей плотнее: BackdropStyleContent — страница (сайдбар
	// стеклянный), BackdropStyleSidebar — тёмный сайдбар и светлая страница.
	Style string `json:"style"`
	// PhotoVersion меняется при каждой загрузке фото: сбрасывает кэш webview.
	PhotoVersion string `json:"photoVersion,omitempty"`
}

// CustomTheme — пользовательская тема. Хранится только «семя»: один цвет,
// база и насыщенность фона. Всю палитру из него строит фронтенд, тем же
// генератором, что и встроенные темы.
type CustomTheme struct {
	ID    string  `json:"id"`
	Name  string  `json:"name"`
	Color string  `json:"color"` // #rrggbb
	Base  string  `json:"base"`  // "dark" | "light" | "amoled"
	Tint  float64 `json:"tint"`  // 0..1 — насыщенность фона
	// SurfaceHue — оттенок фона 0..360; nil — как у акцентного цвета.
	SurfaceHue *float64 `json:"surfaceHue,omitempty"`
	// Depth — светлота фона -1..1: отрицательная глубже, положительная светлее.
	// В AMOLED не используется: фон всегда чёрный.
	Depth float64 `json:"depth"`
}

type ApplicationSettings struct {
	LaunchOnStartup                bool
	MinimizeToTray                 bool
	AutoConnect                    bool
	DisableSubscriptionAutoRefresh bool
}
