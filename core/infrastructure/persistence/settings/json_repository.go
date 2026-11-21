package settings

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"math"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"

	domainSettings "beam-bridge/core/domain/settings"
	infraBeam "beam-bridge/core/infrastructure/beam"
	corePaths "beam-bridge/core/paths"
	"beam-bridge/core/platform"
	"beam-bridge/core/types"
)

// customFontPattern — свой шрифт из beam-desktop: custom:<12 hex>.
var customFontPattern = regexp.MustCompile(`^custom:[a-f0-9]{12}$`)

const (
	ModeTun         = "tun"
	ModeSystemProxy = "system_proxy"
	ModeProxy       = "proxy"
)

type JSONRepository struct {
	mu          sync.RWMutex
	settings    *domainSettings.Settings
	path        string
	legacyPath  string
	defaultMode string
}

func NewJSONRepository(paths corePaths.Paths, defaultMode string) (*JSONRepository, error) {
	r := &JSONRepository{
		path:        paths.Config(),
		legacyPath:  paths.LegacySettings(),
		defaultMode: defaultMode,
		settings:    &domainSettings.Settings{},
	}
	if err := r.load(); err != nil {
		return nil, err
	}
	return r, nil
}

func (r *JSONRepository) Get() *domainSettings.Settings {
	r.mu.RLock()
	defer r.mu.RUnlock()
	copy := *r.settings
	return &copy
}

func (r *JSONRepository) UpdateConnection(conn domainSettings.ConnectionSettings) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.settings.Connection = validateConnection(conn)
	return r.save()
}

func (r *JSONRepository) UpdateApplication(app domainSettings.ApplicationSettings) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.settings.Application = app
	return r.save()
}

func (r *JSONRepository) UpdateSplitTunnel(st types.SplitTunnelSettings) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.settings.SplitTunnel = validateSplitTunnel(st)
	return r.save()
}

func (r *JSONRepository) UpdateAppearance(app domainSettings.AppearanceSettings) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	app.CustomThemes = validateCustomThemes(app.CustomThemes)
	app.Theme = validateTheme(app.Theme, app.CustomThemes)
	app.Backdrop = validateBackdrop(app.Backdrop)
	app.Accent = validateAccent(app.Accent)
	validFonts := map[string]bool{"rubik": true, "manrope": true, "geologica": true, "onest": true, "nunito": true}
	if !validFonts[app.Font] && !customFontPattern.MatchString(app.Font) {
		app.Font = "rubik"
	}
	validRadii := map[string]bool{"small": true, "medium": true, "large": true, "round": true}
	if !validRadii[app.Radius] {
		app.Radius = "medium"
	}
	validAnimations := map[string]bool{"slide": true, "fade": true, "slide-up": true, "none": true}
	if !validAnimations[app.Animation] {
		app.Animation = "slide"
	}
	r.settings.Appearance = app
	return r.save()
}

func (r *JSONRepository) SetOnboardingCompleted(completed bool) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.settings.OnboardingCompleted = completed
	return r.save()
}

func (r *JSONRepository) SetSplitTunnelEnabled(enabled bool) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.settings.SplitTunnel.Enabled = enabled
	return r.save()
}

func (r *JSONRepository) UpdateRoutingMode(mode string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.settings.RoutingMode = validateRoutingMode(mode)
	return r.save()
}

func (r *JSONRepository) UpdateProTunGraph(graph types.ProTunGraph) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.settings.ProTunGraph = validateProTunGraph(graph)
	return r.save()
}

// UpdateProTunProfileGraph stores the ProTun layer of one profile; nil or an
// empty graph removes it. The map is replaced, not mutated: Get hands out
// shallow copies that must not change under the caller.
func (r *JSONRepository) UpdateProTunProfileGraph(profileID string, graph *types.ProTunGraph) error {
	if profileID == "" {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	next := make(map[string]types.ProTunGraph, len(r.settings.ProTunProfiles)+1)
	for id, g := range r.settings.ProTunProfiles {
		if id != profileID {
			next[id] = g
		}
	}
	if graph != nil && len(graph.Nodes) > 0 {
		next[profileID] = validateProTunGraph(*graph)
	}
	r.settings.ProTunProfiles = next
	return r.save()
}

func (r *JSONRepository) UpdateHwid(h domainSettings.HwidSettings) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.settings.Hwid = validateHwid(h)
	return r.save()
}

func (r *JSONRepository) UpdatePing(ping domainSettings.PingSettings) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.settings.Ping = validatePing(ping)
	return r.save()
}

func (r *JSONRepository) SetDeveloperMode(enabled bool) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.settings.DeveloperMode = enabled
	return r.save()
}

func (r *JSONRepository) SetExtendedLogs(enabled bool) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.settings.ExtendedLogs = enabled
	return r.save()
}

func (r *JSONRepository) SetTraceLogging(enabled bool) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.settings.TraceLogging = enabled
	return r.save()
}

func (r *JSONRepository) SetCoreLogging(enabled bool) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.settings.DisableCoreLogging = !enabled
	return r.save()
}

// SetLogLevel сохраняет пользовательский уровень логов вкладки «Логи».
// "off" дополнительно выключает логи ядра, любое другое значение — включает.
func (r *JSONRepository) SetLogLevel(level string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.settings.LogLevel = validateLogLevel(level)
	if r.settings.LogLevel == "off" {
		r.settings.DisableCoreLogging = true
	} else {
		r.settings.DisableCoreLogging = false
	}
	return r.save()
}

// validateLogLevel приводит уровень к допустимому набору. Пустое значение
// (старые settings.json без поля) становится "info": информативно, но без
// спама отладкой.
func validateLogLevel(level string) string {
	switch level {
	case "off", "error", "info", "debug":
		return level
	default:
		return "info"
	}
}

func (r *JSONRepository) SetRealityDebug(enabled bool) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.settings.RealityDebug = enabled
	return r.save()
}

func (r *JSONRepository) load() error {
	fromLegacy := false
	data, err := os.ReadFile(r.path)
	switch {
	case err == nil:
		var file configFile
		if err := json.Unmarshal(data, &file); err != nil {
			return err
		}
		r.settings = file.toDomain()
	case os.IsNotExist(err):
		// No config.json yet: either a fresh install or the old flat
		// settings.json, which maps 1:1 onto the domain struct.
		legacy, lerr := os.ReadFile(r.legacyPath)
		if os.IsNotExist(lerr) {
			r.settings = r.defaultSettings()
			return r.save()
		}
		if lerr != nil {
			return lerr
		}
		if err := json.Unmarshal(legacy, r.settings); err != nil {
			return err
		}
		fromLegacy = true
	default:
		return err
	}

	// The HWID is stored sealed at rest; unseal it into memory. A value that
	// is sealed but cannot be opened (key lost, different machine) is dropped
	// so a fresh one is generated rather than sending a garbage id.
	changed := fromLegacy
	if infraBeam.IsSealed(r.settings.Hwid.Value) {
		if plain, oerr := infraBeam.OpenString("hwid", r.settings.Hwid.Value); oerr == nil {
			r.settings.Hwid.Value = plain
		} else {
			r.settings.Hwid.Value = ""
			changed = true
		}
	}
	if r.fillMissingDefaults() {
		changed = true
	}
	if r.migrate() {
		changed = true
	}
	if changed {
		if err := r.save(); err != nil {
			return err
		}
	}
	// Only after config.json is safely on disk: drop the old flat file so
	// nothing keeps reading or resurrecting it.
	if fromLegacy {
		_ = os.Remove(r.legacyPath)
	}
	return nil
}

// v6: config.json with sectioned layout (file_format.go) replaces the flat
// settings.json; the domain model is unchanged.
// v7: разделы «Ядро», «DNS» и «Игровой режим»; список DNS-серверов
// собирается из старых Primary/Secondary (fillXrayDefaults).
const currentSchemaVersion = 7

func (r *JSONRepository) migrate() bool {
	if r.settings.SchemaVersion >= currentSchemaVersion {
		return false
	}
	from := r.settings.SchemaVersion
	// v5: TUN на mixed-стеке (TCP терминирует ядро ОС, gVisor удалён). Старые
	// дефолты MTU (1400/1420/1500) были подогнаны под userspace-TCP и внешний
	// путь; теперь большой MTU просто уменьшает число пакетов.
	if from < 5 {
		switch r.settings.Connection.MTU {
		case 0, 1400, 1420, 1500:
			r.settings.Connection.MTU = defaultMTU()
		}
		if r.settings.Connection.Stack == "gvisor" {
			r.settings.Connection.Stack = defaultStack()
		}
	}
	// v4: Happ-совместимость расформирована — HWID стал самостоятельным и
	// включён по умолчанию. Значение переносим, чтобы панель не потеряла
	// устройство; режим manual сохраняем, всё остальное становится auto.
	if legacy := r.settings.HappCompat; legacy != nil {
		mode := "auto"
		if legacy.HWIDMode == "manual" {
			mode = "manual"
		}
		value := legacy.HWID
		if value == "" {
			value = newUUID()
		}
		r.settings.Hwid = domainSettings.HwidSettings{
			Enabled: true,
			Mode:    mode,
			Value:   value,
		}
		r.settings.HappCompat = nil
	}
	r.settings.SchemaVersion = currentSchemaVersion
	return true
}

func (r *JSONRepository) fillMissingDefaults() bool {
	changed := false
	if r.settings.APISecret == "" {
		r.settings.APISecret = generateSecret(32)
		changed = true
	}
	if r.settings.APIPort == 0 {
		r.settings.APIPort = getFreePort(9090)
		changed = true
	}
	if r.settings.Connection.Mode == "" {
		r.settings.Connection = defaultConnection(r.defaultMode)
		changed = true
	}
	if r.settings.Connection.PrimaryDNS == "" {
		r.settings.Connection.PrimaryDNS = "8.8.8.8"
		changed = true
	}
	if r.settings.Connection.SecondaryDNS == "" {
		r.settings.Connection.SecondaryDNS = "1.1.1.1"
		changed = true
	}
	if r.settings.Connection.ProxyDNS == "" {
		r.settings.Connection.ProxyDNS = "8.8.8.8"
		changed = true
	}
	if r.settings.Connection.MTU == 0 {
		r.settings.Connection.MTU = defaultMTU()
		changed = true
	}
	if r.settings.Connection.Stack == "" {
		r.settings.Connection.Stack = defaultStack()
		changed = true
	}
	if r.settings.Connection.ProxyHost == "" {
		r.settings.Connection.ProxyHost = "127.0.0.1"
		changed = true
	}
	if r.settings.Connection.ProxyPort == 0 {
		r.settings.Connection.ProxyPort = 2080
		changed = true
	}
	if r.settings.Connection.ProxyType == "" {
		r.settings.Connection.ProxyType = "mixed"
		changed = true
	}
	if r.settings.Appearance.Theme == "" {
		r.settings.Appearance = defaultAppearance()
		changed = true
	}
	if r.settings.Appearance.Font == "" {
		r.settings.Appearance.Font = "rubik"
		changed = true
	}
	if r.settings.Appearance.Radius == "" {
		r.settings.Appearance.Radius = "medium"
		changed = true
	}
	if r.settings.Appearance.Animation == "" {
		r.settings.Appearance.Animation = "slide"
		changed = true
	}
	if r.settings.SplitTunnel.Mode == "" {
		r.settings.SplitTunnel = types.DefaultSplitTunnel()
		changed = true
	}
	if r.settings.SplitTunnel.Apps == nil {
		r.settings.SplitTunnel.Apps = []string{}
		changed = true
	}
	if r.settings.SplitTunnel.Domains == nil {
		r.settings.SplitTunnel.Domains = []string{}
		changed = true
	}
	if r.settings.SplitTunnel.IPs == nil {
		r.settings.SplitTunnel.IPs = []string{}
		changed = true
	}
	if validated := validateRoutingMode(r.settings.RoutingMode); validated != r.settings.RoutingMode {
		r.settings.RoutingMode = validated
		changed = true
	}
	if r.settings.ProTunGraph.Nodes == nil {
		r.settings.ProTunGraph.Nodes = []types.ProTunNode{}
		changed = true
	}
	if r.settings.ProTunGraph.Edges == nil {
		r.settings.ProTunGraph.Edges = []types.ProTunEdge{}
		changed = true
	}
	for id, g := range r.settings.ProTunProfiles {
		if g.Nodes == nil || g.Edges == nil {
			r.settings.ProTunProfiles[id] = validateProTunGraph(g)
			changed = true
		}
	}
	if validated := validateHwidMode(r.settings.Hwid.Mode); validated != r.settings.Hwid.Mode {
		r.settings.Hwid.Mode = validated
		changed = true
	}
	if r.settings.Hwid.Value == "" {
		r.settings.Hwid.Value = newUUID()
		changed = true
	}
	if validated := validateLogLevel(r.settings.LogLevel); validated != r.settings.LogLevel {
		r.settings.LogLevel = validated
		changed = true
	}
	if r.settings.Ping.NodeMode == "" {
		r.settings.Ping.NodeMode = "auto"
		changed = true
	}
	if r.settings.Ping.ConnectionMode == "" {
		r.settings.Ping.ConnectionMode = "http"
		changed = true
	}
	if r.fillXrayDefaults() {
		changed = true
	}
	return changed
}

func (r *JSONRepository) ResetToDefaults() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	apiSecret := r.settings.APISecret
	apiPort := r.settings.APIPort
	r.settings = r.defaultSettings()
	r.settings.APISecret = apiSecret
	r.settings.APIPort = apiPort
	r.settings.DeveloperMode = true
	return r.save()
}

func (r *JSONRepository) save() error {
	// Serialize a shallow copy with the HWID sealed, so the plaintext id never
	// touches disk. In-memory settings keep the real value. When the keystore
	// is unavailable the value is written as-is.
	file := configFromDomain(r.settings)
	if v := file.Device.Hwid.Value; v != "" && !infraBeam.IsSealed(v) {
		if sealed, serr := infraBeam.SealString("hwid", v); serr == nil {
			file.Device.Hwid.Value = sealed
		}
	}
	data, err := json.MarshalIndent(&file, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(r.path, data)
}

// writeFileAtomic replaces path via a temp file in the same directory, so a
// crash mid-write never leaves a truncated config behind.
func writeFileAtomic(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".config-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmpName, 0o600); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

func (r *JSONRepository) defaultSettings() *domainSettings.Settings {
	return &domainSettings.Settings{
		SchemaVersion:       currentSchemaVersion,
		Connection:          defaultConnection(r.defaultMode),
		Appearance:          defaultAppearance(),
		Application:         defaultApplication(),
		SplitTunnel:         types.DefaultSplitTunnel(),
		RoutingMode:         "easy",
		ProTunGraph:         types.DefaultProTunGraph(),
		APISecret:         generateSecret(32),
		APIPort:           getFreePort(9090),
		OnboardingCompleted: false,
		DeveloperMode:       false,
		ExtendedLogs:        false,
		TraceLogging:        false,
		DisableCoreLogging:  false,
		LogLevel:            "info",
		RealityDebug:        false,
		Hwid:                defaultHwid(),
		Ping:                domainSettings.PingSettings{NodeMode: "auto", ConnectionMode: "http"},
		Core:                defaultCore(),
		DNS:                 defaultDNSFrom(defaultConnection(r.defaultMode)),
	}
}

func defaultHwid() domainSettings.HwidSettings {
	return domainSettings.HwidSettings{
		Enabled: true,
		Mode:    "auto",
		Value:   newUUID(),
	}
}

func defaultConnection(mode string) domainSettings.ConnectionSettings {
	if mode == "" {
		mode = ModeTun
	}
	return domainSettings.ConnectionSettings{
		Mode:         mode,
		ProxyType:    "mixed",
		ProxyHost:    "127.0.0.1",
		ProxyPort:    getFreePort(2080),
		TunName:      defaultTunName(),
		PrimaryDNS:   "8.8.8.8",
		SecondaryDNS: "8.8.4.4",
		ProxyDNS:     "8.8.8.8",
		DNSOverVPN:   false,
		MTU:          defaultMTU(),
		Stack:        defaultStack(),
	}
}

func defaultStack() string {
	if runtime.GOOS == "darwin" || runtime.GOOS == "linux" {
		return "system"
	}
	return "mixed"
}

func defaultTunName() string {
	if platform.IsDevBuild() {
		return "BeamTUN-Dev"
	}
	return "BeamTUN"
}

// defaultMTU — см. tun.DefaultMTU: TCP пересегментируется ядром ОС и Xray под
// реальный путь, поэтому крупный MTU туннеля = меньше пакетов и системных
// вызовов на тот же трафик; память от MTU не зависит (буферы по факту).
func defaultMTU() int {
	return 9000
}

func defaultAppearance() domainSettings.AppearanceSettings {
	return domainSettings.AppearanceSettings{
		Theme:     "system",
		Font:      "rubik",
		Radius:    "medium",
		Animation: "slide",
		Backdrop:  defaultBackdrop(),
	}
}

func defaultBackdrop() domainSettings.BackdropSettings {
	return domainSettings.BackdropSettings{
		Mode:  domainSettings.BackdropOff,
		Blur:  12,
		Dim:   55,
		Style: domainSettings.BackdropStyleContent,
	}
}

func validateBackdrop(b domainSettings.BackdropSettings) domainSettings.BackdropSettings {
	switch b.Mode {
	case domainSettings.BackdropOff, domainSettings.BackdropWallpaper, domainSettings.BackdropPhoto:
	default:
		b.Mode = domainSettings.BackdropOff
	}
	if b.Style != domainSettings.BackdropStyleSidebar {
		b.Style = domainSettings.BackdropStyleContent
	}
	b.Blur = min(max(b.Blur, 0), 40)
	b.Dim = min(max(b.Dim, -100), 90)
	b.Density = min(max(b.Density, -50), 50)
	b.PhotoVersion = strings.TrimSpace(b.PhotoVersion)
	if len(b.PhotoVersion) > 64 {
		b.PhotoVersion = b.PhotoVersion[:64]
	}
	// Режим «фото» без загруженного фото бессмысленен.
	if b.Mode == domainSettings.BackdropPhoto && b.PhotoVersion == "" {
		b.Mode = domainSettings.BackdropOff
	}
	return b
}

func defaultApplication() domainSettings.ApplicationSettings {
	return domainSettings.ApplicationSettings{
		LaunchOnStartup: false,
		MinimizeToTray:  false,
	}
}

func validateConnection(conn domainSettings.ConnectionSettings) domainSettings.ConnectionSettings {
	validModes := map[string]bool{ModeTun: true, ModeSystemProxy: true, ModeProxy: true}
	if !validModes[conn.Mode] {
		conn.Mode = ModeTun
	}
	validProxyTypes := map[string]bool{"mixed": true, "http": true, "socks": true}
	if !validProxyTypes[conn.ProxyType] {
		conn.ProxyType = "mixed"
	}
	if conn.Mode == "system_proxy" && conn.ProxyType == "socks" {
		conn.ProxyType = "mixed"
	}
	conn.ProxyHost = strings.TrimSpace(conn.ProxyHost)
	if conn.ProxyHost == "" {
		conn.ProxyHost = "127.0.0.1"
	}
	if conn.ProxyPort <= 0 || conn.ProxyPort > 65535 {
		conn.ProxyPort = 2080
	}
	conn.TunName = strings.TrimSpace(conn.TunName)
	if conn.PrimaryDNS == "" {
		conn.PrimaryDNS = "8.8.8.8"
	}
	if conn.SecondaryDNS == "" {
		conn.SecondaryDNS = "1.1.1.1"
	}
	if conn.ProxyDNS == "" {
		conn.ProxyDNS = "8.8.8.8"
	}
	if conn.MTU <= 0 || conn.MTU > 65535 {
		conn.MTU = defaultMTU()
	}
	if conn.MTU < 1280 {
		conn.MTU = 1280
	}
	validStacks := map[string]bool{"mixed": true, "system": true}
	if !validStacks[conn.Stack] {
		conn.Stack = defaultStack()
	}
	return conn
}

func validateSplitTunnel(st types.SplitTunnelSettings) types.SplitTunnelSettings {
	if st.Mode != "exclude" && st.Mode != "include" {
		st.Mode = "exclude"
	}
	if st.Apps == nil {
		st.Apps = []string{}
	}
	if st.Domains == nil {
		st.Domains = []string{}
	}
	if st.IPs == nil {
		st.IPs = []string{}
	}
	return st
}

var builtinThemes = map[string]bool{
	"system": true, "light": true, "dark": true, "amoled": true,
	"cosmic": true, "blue": true, "slate": true, "stone": true, "purple": true,
	"emerald": true, "sunset": true, "nord": true, "rose": true, "mocha": true,
	"latte": true, "dracula": true, "tokyo": true, "gruvbox": true,
	// Палитра из цвета обоев (или своего фото фона) — строится на фронте.
	"wallpaper": true,
}

const customThemePrefix = "custom:"

// validateAccent: "" (акцент темы) или #rrggbb в нижнем регистре.
func validateAccent(color string) string {
	color = strings.ToLower(strings.TrimSpace(color))
	if !hexColorRe.MatchString(color) {
		return ""
	}
	return color
}

// maxCustomThemes caps the list so a runaway import cannot bloat config.json.
const maxCustomThemes = 64

var (
	hexColorRe = regexp.MustCompile(`^#[0-9a-fA-F]{6}$`)
	themeIDRe  = regexp.MustCompile(`^[a-z0-9]{4,32}$`)
)

// validateTheme accepts a built-in id or "custom:<id>" of an existing custom
// theme. A dangling custom reference (theme was deleted) falls back to dark,
// which is what every custom theme defaults to.
func validateTheme(theme string, custom []domainSettings.CustomTheme) string {
	// «Beam Old» слита с «Тёмной»: её палитра теперь у dark.
	if theme == "beam-old" {
		return "dark"
	}
	if builtinThemes[theme] {
		return theme
	}
	if id, ok := strings.CutPrefix(theme, customThemePrefix); ok {
		for _, t := range custom {
			if t.ID == id {
				return theme
			}
		}
		return "dark"
	}
	return "system"
}

func validateCustomThemes(in []domainSettings.CustomTheme) []domainSettings.CustomTheme {
	out := make([]domainSettings.CustomTheme, 0, len(in))
	seen := make(map[string]bool, len(in))
	for _, t := range in {
		if len(out) >= maxCustomThemes {
			break
		}
		if !themeIDRe.MatchString(t.ID) || seen[t.ID] || !hexColorRe.MatchString(t.Color) {
			continue
		}
		seen[t.ID] = true

		t.Name = strings.TrimSpace(t.Name)
		if t.Name == "" {
			t.Name = "Моя тема"
		}
		if runes := []rune(t.Name); len(runes) > 40 {
			t.Name = string(runes[:40])
		}
		t.Color = strings.ToLower(t.Color)
		switch t.Base {
		case "dark", "light", "amoled":
		default:
			t.Base = "dark"
		}
		t.Tint = clampFinite(t.Tint, 0, 1)
		t.Depth = clampFinite(t.Depth, -1, 1)
		if t.SurfaceHue != nil {
			if h := *t.SurfaceHue; math.IsNaN(h) || math.IsInf(h, 0) {
				t.SurfaceHue = nil
			} else {
				h = math.Mod(h, 360)
				if h < 0 {
					h += 360
				}
				t.SurfaceHue = &h
			}
		}
		out = append(out, t)
	}
	return out
}

// clampFinite зажимает v в [lo, hi]; NaN становится 0 (затем зажимается).
func clampFinite(v, lo, hi float64) float64 {
	if math.IsNaN(v) {
		v = 0
	}
	return math.Max(lo, math.Min(hi, v))
}

func validateRoutingMode(mode string) string {
	if mode != "easy" && mode != "pro" {
		return "easy"
	}
	return mode
}

func validateHwidMode(mode string) string {
	if mode != "auto" && mode != "manual" {
		return "auto"
	}
	return mode
}

func validateHwid(h domainSettings.HwidSettings) domainSettings.HwidSettings {
	h.Mode = validateHwidMode(h.Mode)
	h.Value = strings.TrimSpace(h.Value)
	if h.Value == "" {
		h.Value = newUUID()
	}
	return h
}

// newUUID генерирует случайный UUIDv4 без внешних зависимостей.
func newUUID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return ""
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}

func validatePing(ping domainSettings.PingSettings) domainSettings.PingSettings {
	validNodeModes := map[string]bool{"auto": true, "protocol": true, "tcp": true}
	if !validNodeModes[ping.NodeMode] {
		ping.NodeMode = "auto"
	}
	validConnectionModes := map[string]bool{"http": true, "tcp": true}
	if !validConnectionModes[ping.ConnectionMode] {
		ping.ConnectionMode = "http"
	}
	return ping
}

func validateProTunGraph(graph types.ProTunGraph) types.ProTunGraph {
	if graph.Nodes == nil {
		graph.Nodes = []types.ProTunNode{}
	}
	if graph.Edges == nil {
		graph.Edges = []types.ProTunEdge{}
	}

	nodeByID := make(map[string]bool, len(graph.Nodes))
	for _, n := range graph.Nodes {
		nodeByID[n.ID] = true
	}

	validEdges := make([]types.ProTunEdge, 0, len(graph.Edges))
	for _, e := range graph.Edges {
		if nodeByID[e.Source] && nodeByID[e.Target] {
			validEdges = append(validEdges, e)
		}
	}
	graph.Edges = validEdges

	return graph
}

func generateSecret(length int) string {
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	if length <= 0 {
		length = 32
	}
	b := make([]byte, length)
	_, err := rand.Read(b)
	if err != nil {
		return ""
	}
	for i := range b {
		b[i] = letters[int(b[i])%len(letters)]
	}
	return string(b)
}

func getFreePort(defaultPort int) int {
	addr, err := net.ResolveTCPAddr("tcp", "127.0.0.1:0")
	if err != nil {
		return defaultPort
	}
	l, err := net.ListenTCP("tcp", addr)
	if err != nil {
		return defaultPort
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}
