package settings

// On-disk shape of config.json. It is deliberately decoupled from the domain
// model: the rest of the app works with domainSettings.Settings, and only this
// file knows how settings are laid out on disk. The layout can change again
// without touching a single caller; the old flat settings.json is read once
// by the repository and migrated into this format.

import (
	domainSettings "beam-bridge/core/domain/settings"
	"beam-bridge/core/types"
)

type configFile struct {
	Version   int              `json:"version"`
	Network   networkSection   `json:"network"`
	Routing   routingSection   `json:"routing"`
	Ping      pingSection      `json:"ping"`
	Interface interfaceSection `json:"interface"`
	App       appSection       `json:"app"`
	Device    deviceSection    `json:"device"`
	Core      coreSection      `json:"core"`
	Developer developerSection `json:"developer"`
}

type networkSection struct {
	Mode  string       `json:"mode"`
	Tun   tunSection   `json:"tun"`
	Proxy proxySection `json:"proxy"`
	DNS   dnsSection   `json:"dns"`
	// KillSwitch: missing in older configs means off.
	KillSwitch bool `json:"killSwitch,omitempty"`
}

type tunSection struct {
	Name  string `json:"name"`
	MTU   int    `json:"mtu"`
	Stack string `json:"stack"`
}

type proxySection struct {
	Type string `json:"type"`
	Host string `json:"host"`
	Port int    `json:"port"`
}

type dnsSection struct {
	Primary    string `json:"primary"`
	Secondary  string `json:"secondary"`
	Proxy      string `json:"proxy"`
	ThroughVPN bool   `json:"throughVpn"`

	// Primary/Secondary выше — упстрим туннеля для порта 53; полный список
	// серверов ядра живёт здесь. nil — старый конфиг, список собирается
	// из Primary/Secondary при миграции.
	Servers       []domainSettings.DNSServer `json:"servers,omitempty"`
	Rules         []domainSettings.DNSRule   `json:"rules,omitempty"`
	Hosts         []domainSettings.DNSHost   `json:"hosts,omitempty"`
	ServeStale    bool                       `json:"serveStale,omitempty"`
	DisableCache  bool                       `json:"disableCache,omitempty"`
	ParallelQuery bool                       `json:"parallelQuery,omitempty"`
	SystemHosts   bool                       `json:"systemHosts,omitempty"`
	UseProfile    bool                       `json:"useProfile,omitempty"`
}

// routingSection groups both routing engines: "easy" is the split-tunnel
// lists, "pro" is the ProTun graph. Only the one named by Mode is applied.
type routingSection struct {
	Mode string                    `json:"mode"`
	Easy types.SplitTunnelSettings `json:"easy"`
	Pro  types.ProTunGraph         `json:"pro"`
	// Profiles are per-profile ProTun layers keyed by profile ID.
	Profiles map[string]types.ProTunGraph `json:"profiles,omitempty"`
}

type pingSection struct {
	Nodes      string `json:"nodes"`
	Connection string `json:"connection"`
}

type interfaceSection struct {
	Theme        string                           `json:"theme"`
	Font         string                           `json:"font"`
	Radius       string                           `json:"radius"`
	Animation    string                           `json:"animation"`
	CustomThemes []domainSettings.CustomTheme     `json:"customThemes,omitempty"`
	Backdrop     *domainSettings.BackdropSettings `json:"backdrop,omitempty"`
	Accent       string                           `json:"accent,omitempty"`
}

type appSection struct {
	Onboarded       bool `json:"onboarded"`
	LaunchOnStartup bool `json:"launchOnStartup"`
	MinimizeToTray  bool `json:"minimizeToTray"`
	AutoConnect     bool `json:"autoConnect"`
	// Positive wording on disk; nil (field missing) means the default, on.
	AutoRefreshSubscriptions *bool `json:"autoRefreshSubscriptions,omitempty"`
}

type deviceSection struct {
	Hwid hwidSection `json:"hwid"`
}

type hwidSection struct {
	Enabled bool   `json:"enabled"`
	Mode    string `json:"mode"`
	Value   string `json:"value"`
}

type coreSection struct {
	API      apiSection                       `json:"api"`
	Logs     logsSection                      `json:"logs"`
	Fragment *domainSettings.FragmentSettings `json:"fragment,omitempty"`
	Mux      *domainSettings.MuxSettings      `json:"mux,omitempty"`
}

type apiSection struct {
	Port   int    `json:"port"`
	Secret string `json:"secret"`
}

type logsSection struct {
	Level string `json:"level"`
	// Positive wording on disk; nil (field missing) means the default, on.
	Enabled *bool `json:"enabled,omitempty"`
}

type developerSection struct {
	Enabled      bool `json:"enabled"`
	ExtendedLogs bool `json:"extendedLogs"`
	TraceLogging bool `json:"traceLogging"`
	RealityDebug bool `json:"realityDebug"`
}

func boolPtr(v bool) *bool { return &v }

// backdropFromFile: старый конфиг без блока backdrop — фон выключен с
// параметрами по умолчанию.
func backdropFromFile(b *domainSettings.BackdropSettings) domainSettings.BackdropSettings {
	if b == nil {
		return defaultBackdrop()
	}
	return validateBackdrop(*b)
}

func boolOr(p *bool, def bool) bool {
	if p == nil {
		return def
	}
	return *p
}

func configFromDomain(s *domainSettings.Settings) configFile {
	fragment := s.Core.Fragment
	mux := s.Core.Mux
	backdrop := s.Appearance.Backdrop
	return configFile{
		Version: s.SchemaVersion,
		Network: networkSection{
			Mode:       s.Connection.Mode,
			KillSwitch: s.Connection.KillSwitch,
			Tun: tunSection{
				Name:  s.Connection.TunName,
				MTU:   s.Connection.MTU,
				Stack: s.Connection.Stack,
			},
			Proxy: proxySection{
				Type: s.Connection.ProxyType,
				Host: s.Connection.ProxyHost,
				Port: s.Connection.ProxyPort,
			},
			DNS: dnsSection{
				Primary:    s.Connection.PrimaryDNS,
				Secondary:  s.Connection.SecondaryDNS,
				Proxy:      s.Connection.ProxyDNS,
				ThroughVPN: s.Connection.DNSOverVPN,

				Servers:       s.DNS.Servers,
				Rules:         s.DNS.Rules,
				Hosts:         s.DNS.Hosts,
				ServeStale:    s.DNS.ServeStale,
				DisableCache:  s.DNS.DisableCache,
				ParallelQuery: s.DNS.ParallelQuery,
				SystemHosts:   s.DNS.SystemHosts,
				UseProfile:    s.DNS.UseProfileDNS,
			},
		},
		Routing: routingSection{
			Mode:     s.RoutingMode,
			Easy:     s.SplitTunnel,
			Pro:      s.ProTunGraph,
			Profiles: s.ProTunProfiles,
		},
		Ping: pingSection{
			Nodes:      s.Ping.NodeMode,
			Connection: s.Ping.ConnectionMode,
		},
		Interface: interfaceSection{
			Theme:        s.Appearance.Theme,
			Font:         s.Appearance.Font,
			Radius:       s.Appearance.Radius,
			Animation:    s.Appearance.Animation,
			CustomThemes: s.Appearance.CustomThemes,
			Backdrop:     &backdrop,
			Accent:       s.Appearance.Accent,
		},
		App: appSection{
			Onboarded:                s.OnboardingCompleted,
			LaunchOnStartup:          s.Application.LaunchOnStartup,
			MinimizeToTray:           s.Application.MinimizeToTray,
			AutoConnect:              s.Application.AutoConnect,
			AutoRefreshSubscriptions: boolPtr(!s.Application.DisableSubscriptionAutoRefresh),
		},
		Device: deviceSection{
			Hwid: hwidSection{
				Enabled: s.Hwid.Enabled,
				Mode:    s.Hwid.Mode,
				Value:   s.Hwid.Value,
			},
		},
		Core: coreSection{
			API: apiSection{
				Port:   s.APIPort,
				Secret: s.APISecret,
			},
			Logs: logsSection{
				Level:   s.LogLevel,
				Enabled: boolPtr(!s.DisableCoreLogging),
			},
			Fragment: &fragment,
			Mux:      &mux,
		},
		Developer: developerSection{
			Enabled:      s.DeveloperMode,
			ExtendedLogs: s.ExtendedLogs,
			TraceLogging: s.TraceLogging,
			RealityDebug: s.RealityDebug,
		},
	}
}

func (f configFile) toDomain() *domainSettings.Settings {
	return &domainSettings.Settings{
		SchemaVersion: f.Version,
		Connection: domainSettings.ConnectionSettings{
			Mode:         f.Network.Mode,
			ProxyType:    f.Network.Proxy.Type,
			ProxyHost:    f.Network.Proxy.Host,
			ProxyPort:    f.Network.Proxy.Port,
			TunName:      f.Network.Tun.Name,
			PrimaryDNS:   f.Network.DNS.Primary,
			SecondaryDNS: f.Network.DNS.Secondary,
			ProxyDNS:     f.Network.DNS.Proxy,
			DNSOverVPN:   f.Network.DNS.ThroughVPN,
			MTU:          f.Network.Tun.MTU,
			Stack:        f.Network.Tun.Stack,
			KillSwitch:   f.Network.KillSwitch,
		},
		Appearance: domainSettings.AppearanceSettings{
			Theme:        f.Interface.Theme,
			Font:         f.Interface.Font,
			Radius:       f.Interface.Radius,
			Animation:    f.Interface.Animation,
			CustomThemes: f.Interface.CustomThemes,
			Backdrop:     backdropFromFile(f.Interface.Backdrop),
			Accent:       validateAccent(f.Interface.Accent),
		},
		Application: domainSettings.ApplicationSettings{
			LaunchOnStartup:                f.App.LaunchOnStartup,
			MinimizeToTray:                 f.App.MinimizeToTray,
			AutoConnect:                    f.App.AutoConnect,
			DisableSubscriptionAutoRefresh: !boolOr(f.App.AutoRefreshSubscriptions, true),
		},
		SplitTunnel:         f.Routing.Easy,
		RoutingMode:         f.Routing.Mode,
		ProTunGraph:         f.Routing.Pro,
		ProTunProfiles:      f.Routing.Profiles,
		APISecret:         f.Core.API.Secret,
		APIPort:           f.Core.API.Port,
		OnboardingCompleted: f.App.Onboarded,
		DeveloperMode:       f.Developer.Enabled,
		ExtendedLogs:        f.Developer.ExtendedLogs,
		TraceLogging:        f.Developer.TraceLogging,
		DisableCoreLogging:  !boolOr(f.Core.Logs.Enabled, true),
		LogLevel:            f.Core.Logs.Level,
		RealityDebug:        f.Developer.RealityDebug,
		Hwid: domainSettings.HwidSettings{
			Enabled: f.Device.Hwid.Enabled,
			Mode:    f.Device.Hwid.Mode,
			Value:   f.Device.Hwid.Value,
		},
		Ping: domainSettings.PingSettings{
			NodeMode:       f.Ping.Nodes,
			ConnectionMode: f.Ping.Connection,
		},
		Core: domainSettings.CoreSettings{
			Fragment: derefOr(f.Core.Fragment),
			Mux:      derefOr(f.Core.Mux),
		},
		DNS: domainSettings.DNSSettings{
			Servers:       f.Network.DNS.Servers,
			Rules:         f.Network.DNS.Rules,
			Hosts:         f.Network.DNS.Hosts,
			ServeStale:    f.Network.DNS.ServeStale,
			DisableCache:  f.Network.DNS.DisableCache,
			ParallelQuery: f.Network.DNS.ParallelQuery,
			SystemHosts:   f.Network.DNS.SystemHosts,
			UseProfileDNS: f.Network.DNS.UseProfile,
		},
	}
}

// derefOr разыменовывает необязательную секцию; отсутствующая становится
// нулевым значением, дефолты заполняет fillMissingDefaults.
func derefOr[T any](p *T) T {
	var zero T
	if p == nil {
		return zero
	}
	return *p
}
