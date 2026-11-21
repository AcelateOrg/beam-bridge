package types

import (
	"strings"
	"time"
)

type VPNStatus string

const (
	StatusDisconnected        VPNStatus = "disconnected"
	StatusConnecting          VPNStatus = "connecting"
	StatusConnected           VPNStatus = "connected"
	StatusConnectedNoInternet VPNStatus = "connected_no_internet"
	StatusDisconnecting       VPNStatus = "disconnecting"
	StatusError               VPNStatus = "error"
)

type Profile struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	Provider     string `json:"provider"`
	URL          string `json:"url"`
	Announce     string `json:"announce,omitempty"`
	SupportURL   string `json:"supportUrl,omitempty"`
	IconURL      string `json:"iconUrl,omitempty"`
	CommunityURL string `json:"communityUrl,omitempty"`
	// Branding — блок провайдерского оформления из .beam. Плоские поля выше
	// (Announce/IconURL/...) — legacy-зеркало для старых клиентов; UI читает
	// Branding в первую очередь.
	Branding                    *Branding         `json:"branding,omitempty"`
	ProTunLocked                bool              `json:"proTunLocked,omitempty"`
	HasProTunPreset             bool              `json:"hasProTunPreset,omitempty"`
	HideProvider                bool              `json:"hideProvider,omitempty"`
	ProviderSettings            *ProviderSettings `json:"providerSettings,omitempty"`
	DataLimit                   int64             `json:"dataLimit"`
	DataUsed                    int64             `json:"dataUsed"`
	ExpiresAt                   time.Time         `json:"expiresAt"`
	CreatedAt                   time.Time         `json:"createdAt"`
	UpdatedAt                   time.Time         `json:"updatedAt"`
	IsActive                    bool              `json:"isActive"`
	UpdateIntervalHours         int               `json:"updateIntervalHours,omitempty"`
	AutoRefreshDisabled         bool              `json:"autoRefreshDisabled,omitempty"`
	UpdateIntervalOverrideHours int               `json:"updateIntervalOverrideHours,omitempty"`
}

func (p *Profile) IsUnlimited() bool {
	return p.DataLimit <= 0
}

func (p *Profile) NeverExpires() bool {
	return p.ExpiresAt.IsZero() || p.ExpiresAt.Year() > 2100
}

type ProfileSummary struct {
	ID                          string            `json:"id"`
	Name                        string            `json:"name"`
	Provider                    string            `json:"provider"`
	Announce                    string            `json:"announce,omitempty"`
	SupportURL                  string            `json:"supportUrl,omitempty"`
	IconURL                     string            `json:"iconUrl,omitempty"`
	CommunityURL                string            `json:"communityUrl,omitempty"`
	Branding                    *Branding         `json:"branding,omitempty"`
	ProTunLocked                bool              `json:"proTunLocked,omitempty"`
	HideProvider                bool              `json:"hideProvider,omitempty"`
	ProviderSettings            *ProviderSettings `json:"providerSettings,omitempty"`
	DataLimit                   int64             `json:"dataLimit"`
	DataUsed                    int64             `json:"dataUsed"`
	DaysLeft                    int               `json:"daysLeft"`
	IsExpired                   bool              `json:"isExpired,omitempty"`
	UsedPercent                 float64           `json:"usedPercent"`
	IsActive                    bool              `json:"isActive"`
	HasSubscription             bool              `json:"hasSubscription"`
	URL                         string            `json:"url,omitempty"`
	UpdateIntervalHours         int               `json:"updateIntervalHours,omitempty"`
	AutoRefreshDisabled         bool              `json:"autoRefreshDisabled,omitempty"`
	UpdateIntervalOverrideHours int               `json:"updateIntervalOverrideHours,omitempty"`
}

type Category struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Icon  string `json:"icon,omitempty"`
	Order int    `json:"order"`
	// Emoji — the provider's own icon for the group (taken from a separator
	// like "🎮 —— Игровые ——"); shown instead of Icon.
	Emoji string `json:"emoji,omitempty"`
	// Collapsed — the group starts folded in the list.
	Collapsed bool `json:"collapsed,omitempty"`
}

type BeamNode struct {
	ID             string                 `json:"id"`
	CategoryID     string                 `json:"categoryId"`
	Name           string                 `json:"name"`
	Type           string                 `json:"type"`
	Outbound       map[string]interface{} `json:"outbound"`
	RawLink        string                 `json:"rawLink,omitempty"`
	BaseName       string                 `json:"baseName,omitempty"`
	NameOverride   string                 `json:"nameOverride,omitempty"`
	Overrides      map[string]interface{} `json:"overrides,omitempty"`
	PinnedOutbound map[string]interface{} `json:"pinnedOutbound,omitempty"`
	// Description — provider's subtitle for the card ("Для игр", "10 Гбит").
	Description string `json:"description,omitempty"`
	// Badge — short chip on the card ("NEW", "🔥").
	Badge string `json:"badge,omitempty"`
	// DNS — the "dns" object of the provider's Xray config, kept verbatim;
	// used instead of BEAM's DNS when DNSSettings.UseProfileDNS is on.
	DNS map[string]interface{} `json:"dns,omitempty"`
}

// Node card subtitle modes (BeamFileData.NodeSubtitle).
const (
	NodeSubtitleProtocol = "protocol" // default: "VLESS / REALITY"
	NodeSubtitleNone     = "none"     // description only, protocol hidden
)

func (n *BeamNode) DisplayName() string {
	if n.NameOverride != "" {
		return n.NameOverride
	}
	return n.Name
}

func (n *BeamNode) IsEdited() bool {
	return n.NameOverride != "" || len(n.Overrides) > 0 || n.PinnedOutbound != nil
}

func (n *BeamNode) IsPinned() bool {
	return n.PinnedOutbound != nil
}

func (n *BeamNode) EffectiveOutbound() map[string]interface{} {
	if n.PinnedOutbound != nil {
		return deepCopyMap(n.PinnedOutbound)
	}
	return ApplyOverrides(n.Outbound, n.Overrides)
}

func (n *BeamNode) BaseOutbound() map[string]interface{} {
	if n.PinnedOutbound != nil {
		return n.PinnedOutbound
	}
	return n.Outbound
}

func ApplyOverrides(base map[string]interface{}, overrides map[string]interface{}) map[string]interface{} {
	result := deepCopyMap(base)
	for path, value := range overrides {
		setByPath(result, path, value)
	}
	return result
}

func deepCopyMap(src map[string]interface{}) map[string]interface{} {
	if src == nil {
		return map[string]interface{}{}
	}
	dst := make(map[string]interface{}, len(src))
	for k, v := range src {
		dst[k] = deepCopyValue(v)
	}
	return dst
}

func deepCopyValue(v interface{}) interface{} {
	switch typed := v.(type) {
	case map[string]interface{}:
		return deepCopyMap(typed)
	case []interface{}:
		arr := make([]interface{}, len(typed))
		for i, item := range typed {
			arr[i] = deepCopyValue(item)
		}
		return arr
	default:
		return v
	}
}

func setByPath(target map[string]interface{}, path string, value interface{}) {
	if path == "" || target == nil {
		return
	}

	keys := strings.Split(path, ".")
	current := target
	for _, key := range keys[:len(keys)-1] {
		next, ok := current[key].(map[string]interface{})
		if !ok {
			next = map[string]interface{}{}
			current[key] = next
		}
		current = next
	}

	last := keys[len(keys)-1]
	if value == nil {
		delete(current, last)
		return
	}
	current[last] = value
}

type ExportedLink struct {
	Name string `json:"name"`
	Link string `json:"link"`
}

// Branding — провайдерское оформление профиля: логотип, баннер, ссылки.
// Живёт внутри .beam (поле branding) и заполняется либо руками в файле,
// либо из мета-заголовков подписки при обновлении. При конфликте выигрывает
// файл: то, что провайдер вписал в .beam явно, хедеры не затирают.
type Branding struct {
	IconURL     string `json:"iconUrl,omitempty"`
	BannerText  string `json:"bannerText,omitempty"`
	BannerURL   string `json:"bannerUrl,omitempty"`
	BannerColor string `json:"bannerColor,omitempty"`
	// BannerImage — фоновая картинка карточки профиля (URL). Клиент всегда
	// кладёт поверх затемняющий слой, так что белый баннер текст не съест.
	BannerImage  string `json:"bannerImage,omitempty"`
	WebPageURL   string `json:"webPageUrl,omitempty"`
	SupportURL   string `json:"supportUrl,omitempty"`
	CommunityURL string `json:"communityUrl,omitempty"`
}

// Empty сообщает, что блок пустой и его не стоит писать в файл.
func (b *Branding) Empty() bool {
	return b == nil || (b.IconURL == "" && b.BannerText == "" && b.BannerURL == "" &&
		b.BannerColor == "" && b.BannerImage == "" && b.WebPageURL == "" && b.SupportURL == "" && b.CommunityURL == "")
}

type BeamFileData struct {
	Version      uint8     `json:"version"`
	Name         string    `json:"name"`
	Provider     string    `json:"provider"`
	URL          string    `json:"url,omitempty"`
	Announce     string    `json:"announce,omitempty"`
	SupportURL   string    `json:"supportUrl,omitempty"`
	IconURL      string    `json:"iconUrl,omitempty"`
	CommunityURL string    `json:"communityUrl,omitempty"`
	Branding     *Branding `json:"branding,omitempty"`
	// ProTunPreset — маршрутизация от провайдера. При ProTunLocked=true
	// пресет применяется принудительно, а редактирование в UI блокируется.
	ProTunPreset *ProTunGraph `json:"proTunPreset,omitempty"`
	ProTunLocked bool         `json:"proTunLocked,omitempty"`
	ExpiresAt    int64        `json:"expiresAt,omitempty"`
	DataLimit    int64        `json:"dataLimit,omitempty"`
	DataUsed     int64        `json:"dataUsed,omitempty"`
	Categories   []Category   `json:"categories"`
	Nodes        []BeamNode   `json:"nodes"`
	// Links — короткая форма нод для генераторов (панели подписок): share-
	// ссылки (vless://, trojan://, ...) и маркеры групп ("[Игровые]").
	// Разворачиваются в Nodes при импорте и в файле не хранятся.
	Links      []string `json:"links,omitempty"`
	SelectedID string   `json:"selectedId,omitempty"`
	// NodeSubtitle — what the card shows under the server name: "protocol"
	// (default) or "none". A node description always wins.
	NodeSubtitle string `json:"nodeSubtitle,omitempty"`
	// HideProvider hides the provider chip (subscription domain) on the
	// profile card.
	HideProvider                bool              `json:"hideProvider,omitempty"`
	CreatedAt                   int64             `json:"createdAt,omitempty"`
	UpdatedAt                   int64             `json:"updatedAt,omitempty"`
	UpdateIntervalHours         int               `json:"updateIntervalHours,omitempty"`
	AutoRefreshDisabled         bool              `json:"autoRefreshDisabled,omitempty"`
	UpdateIntervalOverrideHours int               `json:"updateIntervalOverrideHours,omitempty"`
	ProviderSettings            *ProviderSettings `json:"providerSettings,omitempty"`
}

// EffectiveBranding возвращает блок брендинга с фолбэком на плоские
// legacy-поля файла (announce/iconUrl/supportUrl/communityUrl), чтобы
// старые .beam без объекта branding выглядели в UI как раньше. Поля,
// заполненные в branding, всегда выигрывают.
func (d *BeamFileData) EffectiveBranding() *Branding {
	b := Branding{}
	if d.Branding != nil {
		b = *d.Branding
	}
	if b.BannerText == "" {
		b.BannerText = d.Announce
	}
	if b.IconURL == "" {
		b.IconURL = d.IconURL
	}
	if b.SupportURL == "" {
		b.SupportURL = d.SupportURL
	}
	if b.CommunityURL == "" {
		b.CommunityURL = d.CommunityURL
	}
	if b.Empty() {
		return nil
	}
	return &b
}

// MergeBrandingFrom дополняет branding значениями из другого блока только
// там, где свои поля пустые: явно записанное в файл не затирается.
func (d *BeamFileData) MergeBrandingFrom(src *Branding) {
	if src == nil || src.Empty() {
		return
	}
	if d.Branding == nil {
		copy := *src
		d.Branding = &copy
		return
	}
	b := d.Branding
	if b.IconURL == "" {
		b.IconURL = src.IconURL
	}
	if b.BannerText == "" {
		b.BannerText = src.BannerText
	}
	if b.BannerURL == "" {
		b.BannerURL = src.BannerURL
	}
	if b.BannerColor == "" {
		b.BannerColor = src.BannerColor
	}
	if b.BannerImage == "" {
		b.BannerImage = src.BannerImage
	}
	if b.WebPageURL == "" {
		b.WebPageURL = src.WebPageURL
	}
	if b.SupportURL == "" {
		b.SupportURL = src.SupportURL
	}
	if b.CommunityURL == "" {
		b.CommunityURL = src.CommunityURL
	}
}

type LegacyBeamFileData struct {
	Version   uint8                  `json:"version"`
	Profile   *LegacyProfileMetadata `json:"profile,omitempty"`
	Config    interface{}            `json:"config,omitempty"`
	ExpiresAt int64                  `json:"expiresAt,omitempty"`
	DataLimit int64                  `json:"dataLimit,omitempty"`
}

type LegacyProfileMetadata struct {
	Name     string `json:"name"`
	Provider string `json:"provider"`
	URL      string `json:"url"`
}

type SubscriptionInfo struct {
	Upload   int64 `json:"upload"`
	Download int64 `json:"download"`
	Total    int64 `json:"total"`
	Expire   int64 `json:"expire"`
}

type CategoryWithNodes struct {
	Category Category   `json:"category"`
	Nodes    []NodeInfo `json:"nodes"`
}

type NodeInfo struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Type       string `json:"type"`
	CategoryID string `json:"categoryId"`
	IsSelected bool   `json:"isSelected"`
	IsEdited   bool   `json:"isEdited,omitempty"`
	IsPinned   bool   `json:"isPinned,omitempty"`
	// Transport — ws, grpc, httpupgrade, xhttp, h2; empty for raw TCP.
	Transport string `json:"transport,omitempty"`
	// Security — tls or reality; empty when absent or implied by the
	// protocol (Hysteria2 always runs over QUIC+TLS).
	Security     string `json:"security,omitempty"`
	Description  string `json:"description,omitempty"`
	Badge        string `json:"badge,omitempty"`
	HideProtocol bool   `json:"hideProtocol,omitempty"`
	// Insecure — the server certificate is not verified (allowInsecure).
	Insecure bool `json:"insecure,omitempty"`
}

type ProfileNodesResponse struct {
	Categories []CategoryWithNodes `json:"categories"`
	SelectedID string              `json:"selectedId"`
	TotalNodes int                 `json:"totalNodes"`
}

type NodeConfig struct {
	NodeID          string                 `json:"nodeId"`
	Name            string                 `json:"name"`
	BaseName        string                 `json:"baseName"`
	Type            string                 `json:"type"`
	Outbound        map[string]interface{} `json:"outbound"`
	Original        map[string]interface{} `json:"original"`
	Overrides       map[string]interface{} `json:"overrides"`
	IsEdited        bool                   `json:"isEdited"`
	IsPinned        bool                   `json:"isPinned"`
	HasSubscription bool                   `json:"hasSubscription"`
	RawLinkStale    bool                   `json:"rawLinkStale"`
}

type NodeConfigUpdate struct {
	Name      string                 `json:"name"`
	Overrides map[string]interface{} `json:"overrides"`
	Pinned    bool                   `json:"pinned"`
}

type ConnectionStats struct {
	Ping           int64 `json:"ping"`
	BytesReceived  int64 `json:"bytesReceived"`
	BytesSent      int64 `json:"bytesSent"`
	ConnectedAt    int64 `json:"connectedAt"`
	Duration       int64 `json:"duration"`
	IsHealthy      bool  `json:"isHealthy"`
	ActiveConns    int   `json:"activeConns"`
	LastActivityAt int64 `json:"lastActivityAt"`
}

type DetailedStats struct {
	Download    int64 `json:"download"`
	Upload      int64 `json:"upload"`
	ActiveConns int   `json:"activeConns"`
	Duration    int64 `json:"duration"`
}

type LogLevel string

const (
	LogLevelTrace LogLevel = "trace"
	LogLevelDebug LogLevel = "debug"
	LogLevelInfo  LogLevel = "info"
	LogLevelWarn  LogLevel = "warn"
	LogLevelError LogLevel = "error"
	LogLevelFatal LogLevel = "fatal"
)

type ActiveConnection struct {
	ID          string   `json:"id"`
	Network     string   `json:"network"`
	Host        string   `json:"host"`
	Destination string   `json:"destination"`
	Source      string   `json:"source"`
	Outbound    string   `json:"outbound"`
	Chains      []string `json:"chains"`
	Rule        string   `json:"rule"`
	Process     string   `json:"process"`
	Upload      int64    `json:"upload"`
	Download    int64    `json:"download"`
	StartedAt   int64    `json:"startedAt"`
	Duration    int64    `json:"duration"`

	// ProcessPath is the full path of the owning app (icons, grouping).
	ProcessPath string `json:"processPath"`
	// Domain is the sniffed or resolved name, "" when only the IP is known.
	Domain string `json:"domain"`
	// Protocol is the sniffed protocol: tls, http1, quic...
	Protocol string `json:"protocol"`
	// Route is proxy, direct, block or dns; "" outside the tunnel.
	Route string `json:"route"`
	// RuleKind says why: app, rules, default, lan, dns.
	RuleKind string `json:"ruleKind"`
	// NodeName is the server the flow goes through when routed via VPN.
	NodeName string `json:"nodeName"`
	// Closed marks recently closed flows; EndedAt is when they closed (ms).
	Closed  bool  `json:"closed"`
	EndedAt int64 `json:"endedAt"`
}

type LogEntry struct {
	ID        int64    `json:"id"`
	Timestamp int64    `json:"timestamp"`
	Level     LogLevel `json:"level"`
	Message   string   `json:"message"`
	Source    string   `json:"source,omitempty"`
}

type Response struct {
	Success bool   `json:"success"`
	Message string `json:"message,omitempty"`
}

type APIResponse[T any] struct {
	Success bool   `json:"success"`
	Data    T      `json:"data"`
	Error   string `json:"error,omitempty"`
}

type BuildInfo struct {
	Version   string `json:"version"`
	Variant   string `json:"variant"`
	BuildHash string `json:"buildHash"`
	IsDev     bool   `json:"isDev"`
	// BetaTag is the closed-beta tag of the build ("FD1"); empty for stable.
	BetaTag string `json:"betaTag"`

	OS string `json:"os"`
}

type UpdateFileEntry struct {
	Path   string   `json:"path"`
	URLs   []string `json:"urls"`
	SHA256 string   `json:"sha256"`
	Size   int64    `json:"size"`
}

type UpdateInfo struct {
	Available      bool   `json:"available"`
	CurrentVersion string `json:"currentVersion"`
	LatestVersion  string `json:"latestVersion,omitempty"`
	// Mandatory: the update cannot be postponed (flagged by the release or
	// the running build is below its minimum supported version).
	Mandatory  bool   `json:"mandatory,omitempty"`
	ReleasedAt string `json:"releasedAt,omitempty"`
	// Notes: changelog lines in the user's language.
	Notes []string          `json:"notes,omitempty"`
	Files []UpdateFileEntry `json:"files,omitempty"`
}

type UpdateProgress struct {
	Stage      string `json:"stage"`
	FileName   string `json:"fileName,omitempty"`
	BytesDone  int64  `json:"bytesDone"`
	BytesTotal int64  `json:"bytesTotal"`
}

type RunningApplication struct {
	Name string `json:"name"`
	Path string `json:"path,omitempty"`
	Icon string `json:"icon,omitempty"`
}

type SplitTunnelSettings struct {
	Enabled bool     `json:"enabled"`
	Mode    string   `json:"mode"`
	Apps    []string `json:"apps"`
	Domains []string `json:"domains"`
	IPs     []string `json:"ips"`
}

func DefaultSplitTunnel() SplitTunnelSettings {
	return SplitTunnelSettings{
		Enabled: false,
		Mode:    "exclude",
		Apps:    []string{},
		Domains: []string{},
		IPs:     []string{},
	}
}

type ProTunNodeKind string

const (
	ProTunKindApps     ProTunNodeKind = "apps"
	ProTunKindDomains  ProTunNodeKind = "domains"
	ProTunKindIPRanges ProTunNodeKind = "ip_ranges"
	// ProTunKindProtocols matches traffic by the protocol the core sniffs
	// from its first bytes (Items: "bittorrent", "quic", "tls", "http").
	ProTunKindProtocols ProTunNodeKind = "protocols"
	// ProTunKindPorts matches destination ports (Items: "443", "1000-2000").
	ProTunKindPorts ProTunNodeKind = "ports"
	// ProTunKindGeoIP / ProTunKindGeoSite match by the geoip.dat country or
	// list codes and the geosite.dat category codes (Items: "ru", "youtube").
	ProTunKindGeoIP   ProTunNodeKind = "geoip"
	ProTunKindGeoSite ProTunNodeKind = "geosite"
	// ProTunKindNetwork matches the transport (Items: "tcp", "udp").
	ProTunKindNetwork ProTunNodeKind = "network"
	ProTunKindVPN     ProTunNodeKind = "vpn"
	ProTunKindDirect  ProTunNodeKind = "direct"
	ProTunKindBlock   ProTunNodeKind = "block"
	// ProTunKindServer sends traffic to one specific server of any profile
	// (Server), not the currently selected one.
	ProTunKindServer  ProTunNodeKind = "server"
	ProTunKindComment ProTunNodeKind = "comment"
	ProTunKindLogic   ProTunNodeKind = "logic"
	ProTunKindOther   ProTunNodeKind = "other"
)

type ProTunLogicOp string

const (
	ProTunLogicAnd ProTunLogicOp = "and"
	ProTunLogicOr  ProTunLogicOp = "or"
)

type ProTunPosition struct {
	X float64 `json:"x"`
	Y float64 `json:"y"`
}

type ProTunSize struct {
	Width  float64 `json:"width"`
	Height float64 `json:"height"`
}

type ProTunNode struct {
	ID       string           `json:"id"`
	Kind     ProTunNodeKind   `json:"kind"`
	Position ProTunPosition   `json:"position"`
	Label    string           `json:"label,omitempty"`
	Items    []string         `json:"items,omitempty"`
	Text     string           `json:"text,omitempty"`
	Size     *ProTunSize      `json:"size,omitempty"`
	Op       ProTunLogicOp    `json:"op,omitempty"`
	Server   *ProTunServerRef `json:"server,omitempty"`
	// Invert (apps, domain, IP and geo cards): the card matches everything
	// except Items.
	Invert bool `json:"invert,omitempty"`
	// Except (domain/IP/geo cards): values carved out of the card. They go
	// where everything else goes (the «Остальное» route).
	Except []string `json:"except,omitempty"`
}

// ProTunServerRef points a «Сервер» destination at a node of a profile. The
// node is looked up by ID, then by Name (subscriptions may regenerate IDs);
// names are kept for display when the server is gone.
type ProTunServerRef struct {
	ProfileID   string `json:"profileId"`
	NodeID      string `json:"nodeId"`
	Name        string `json:"name,omitempty"`
	ProfileName string `json:"profileName,omitempty"`
	// Via is the entry hop of a chain: the traffic reaches the server through
	// this one (the same as beam.entry of a node, set on the card instead).
	Via *ProTunServerRef `json:"via,omitempty"`
}

type ProTunEdge struct {
	ID     string `json:"id"`
	Source string `json:"source"`
	Target string `json:"target"`
}

type ProTunViewport struct {
	X    float64 `json:"x"`
	Y    float64 `json:"y"`
	Zoom float64 `json:"zoom"`
}

type ProTunGraph struct {
	Nodes    []ProTunNode    `json:"nodes"`
	Edges    []ProTunEdge    `json:"edges"`
	Viewport *ProTunViewport `json:"viewport,omitempty"`
}

// ProTunConflict is a contradiction in a ProTun graph: the same traffic is
// sent to two different destinations and neither rule is narrower than the
// other, so nothing tells which one should win. A graph with conflicts does
// not connect.
type ProTunConflict struct {
	// Nodes: the source cards whose values collide.
	Nodes []string `json:"nodes"`
	// Targets: the two destination cards.
	Targets []string `json:"targets"`
	// Values: what is sent both ways ("fdm.exe", "youtube.com").
	Values []string `json:"values"`
	// Identical: both rules match exactly the same traffic.
	Identical bool   `json:"identical"`
	Message   string `json:"message"`
}

// ProTunRuleInfo is one rule of a graph in the order the core checks them.
// Where two rules overlap and go to different places, the card higher on the
// canvas wins.
type ProTunRuleInfo struct {
	// NodeID is the card that feeds the destination (a source or a logic card).
	NodeID string `json:"nodeId"`
	// NodeKind is the kind of that card ("apps", "ip_ranges", "logic", ...).
	NodeKind string `json:"nodeKind"`
	// Rank is the place in the check order, from 1.
	Rank int `json:"rank"`
	// Label summarises what the rule matches ("YandexBrowser, ...").
	Label string `json:"label"`
	// DestID and DestKind describe where the rule sends traffic.
	DestID   string `json:"destId"`
	DestKind string `json:"destKind"`
	// Overrides: the lower rules whose traffic it can take over, because
	// they go elsewhere and the two share some flows.
	Overrides []string `json:"overrides"`
	// ShadowedBy: a higher rule that takes all the traffic of this one
	// somewhere else, so it never fires ("" if it can).
	ShadowedBy string `json:"shadowedBy,omitempty"`
}

func DefaultProTunGraph() ProTunGraph {
	return ProTunGraph{Nodes: []ProTunNode{}, Edges: []ProTunEdge{}}
}
