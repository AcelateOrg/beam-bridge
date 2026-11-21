//go:build linux

// Package mobile is the gomobile surface of beam-bridge for beam-mobile.
// Only gomobile-friendly types (strings, numbers, []byte, error) cross this
// boundary; structured data goes over as JSON in the same shapes the desktop
// frontend receives (types.ProfileSummary, types.ProfileNodesResponse, ...).
package mobile

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"time"

	"beam-bridge/core/analytics"
	domainSettings "beam-bridge/core/domain/settings"
	infraBeam "beam-bridge/core/infrastructure/beam"
	"beam-bridge/core/infrastructure/mediacache"
	infraProfile "beam-bridge/core/infrastructure/persistence/profile"
	infraSettings "beam-bridge/core/infrastructure/persistence/settings"
	"beam-bridge/core/infrastructure/subscription"
	corePaths "beam-bridge/core/paths"
	"beam-bridge/core/platform"
	"beam-bridge/core/profile"
	"beam-bridge/core/runner"
	"beam-bridge/core/target"
	"beam-bridge/core/types"
)

// BridgeVersion is bumped when the mobile API changes shape.
const BridgeVersion = "0.5.0"

// Version reports the bridge API version, so the app can show what it linked.
func Version() string {
	return BridgeVersion
}

var (
	mu       sync.Mutex
	settings *infraSettings.JSONRepository
	profiles *profile.Manager
	paths    corePaths.Paths
	usage    *analytics.Store
)

var errNotInitialized = errors.New("beam-bridge is not initialized")

// Init opens the profile store and settings under dataDir (the app's private
// files directory). It is safe to call more than once; later calls are no-ops.
// appVersion and osVersion end up in subscription request headers.
func Init(dataDir, appVersion, osVersion, locale string) error {
	mu.Lock()
	defer mu.Unlock()
	if profiles != nil {
		return nil
	}

	platform.Install(platform.Provider{
		GetAppVersion:   func() string { return appVersion },
		GetOSVersion:    func() string { return osVersion },
		GetSystemLocale: func() string { return locale },
		DeviceOSLabel:   func() string { return "Android" },
	})

	paths = corePaths.New(dataDir)
	if err := paths.EnsureDirs(); err != nil {
		return err
	}
	// Device-bound key for the at-rest profile store. Without it the store
	// falls back to the portable plaintext format, as on desktop.
	_ = infraBeam.InitKeystore(paths.Data)

	repo := infraProfile.NewFileRepository(paths)
	if err := repo.Load(); err != nil {
		return err
	}
	s, err := infraSettings.NewJSONRepository(paths, infraSettings.ModeTun)
	if err != nil {
		return err
	}
	m := profile.NewManager(repo, s, paths)
	if err := m.Load(); err != nil {
		return err
	}
	settings, profiles = s, m
	usage = analytics.Open(paths.Data)
	// Isolated cores measure servers while the VPN is off.
	m.SetCoreFactory(runner.CoreFactory)
	// Subscriptions refresh on their schedule while the app process lives,
	// unless "Автообновление подписок" is off (the loop reads the setting).
	go m.RunAutoRefreshLoop(context.Background())
	return nil
}

func usageStore() *analytics.Store {
	mu.Lock()
	defer mu.Unlock()
	return usage
}

func manager() (*profile.Manager, error) {
	mu.Lock()
	defer mu.Unlock()
	if profiles == nil {
		return nil, errNotInitialized
	}
	return profiles, nil
}

func toJSON(v any) (string, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// Profiles returns []types.ProfileSummary as JSON.
func Profiles() (string, error) {
	m, err := manager()
	if err != nil {
		return "", err
	}
	return toJSON(m.GetProfiles())
}

// ImportProfile adds a profile from what the user pasted or scanned: a
// subscription URL, a single protocol link (vless://, vmess://, ...), or
// several links one per line, or a pasted Xray / sing-box config. Returns
// the new types.ProfileSummary as JSON.
func ImportProfile(input string) (string, error) {
	m, err := manager()
	if err != nil {
		return "", err
	}
	input = strings.TrimSpace(input)
	if input == "" {
		return "", errors.New("empty input")
	}

	var p *types.Profile
	switch {
	case subscription.LooksLikeXrayConfig(input):
		p, err = m.ImportRawConfig("", input)
	case strings.HasPrefix(input, "{"):
		// A .beam document pasted as text, or a sing-box config.
		p, err = m.ImportFromBeam([]byte(input))
		if err != nil && strings.Contains(input, `"outbounds"`) {
			p, err = m.ImportRawConfig("", input)
		}
	case strings.HasPrefix(strings.ToLower(firstLine(input)), "beam:"):
		p, err = target.NewResolver(m).Open(firstLine(input))
	default:
		p, err = m.ImportFromURL(firstLine(input))
	}
	if err != nil {
		return "", err
	}
	return summaryJSON(m, p.ID)
}

// ImportBeam adds a profile from the bytes of a .beam file.
func ImportBeam(data []byte) (string, error) {
	m, err := manager()
	if err != nil {
		return "", err
	}
	p, err := m.ImportFromBeam(data)
	if err != nil {
		return "", err
	}
	return summaryJSON(m, p.ID)
}

func firstLine(s string) string {
	if i := strings.IndexAny(s, "\r\n"); i >= 0 {
		return strings.TrimSpace(s[:i])
	}
	return s
}

func summaryJSON(m *profile.Manager, id string) (string, error) {
	for _, s := range m.GetProfiles() {
		if s.ID == id {
			return toJSON(s)
		}
	}
	return "", profile.ErrProfileNotFound
}

func SetActiveProfile(id string) error {
	m, err := manager()
	if err != nil {
		return err
	}
	return m.SetActive(id)
}

func DeleteProfile(id string) error {
	m, err := manager()
	if err != nil {
		return err
	}
	return m.Delete(id)
}

// RefreshProfile re-downloads a subscription profile.
func RefreshProfile(id string) error {
	m, err := manager()
	if err != nil {
		return err
	}
	return m.RefreshProfile(id)
}

// ProfileNodes returns types.ProfileNodesResponse for a profile as JSON.
func ProfileNodes(profileID string) (string, error) {
	m, err := manager()
	if err != nil {
		return "", err
	}
	nodes, err := m.GetProfileNodes(profileID)
	if err != nil {
		return "", err
	}
	return toJSON(nodes)
}

func SelectNode(profileID, nodeID string) error {
	m, err := manager()
	if err != nil {
		return err
	}
	return m.SelectProfileNode(profileID, nodeID)
}

// PingListener receives server check results one by one, as desktop's
// ping events do. status is profile.PingResult's ("ok", "timeout", ...).
// It is called from probing goroutines, several at a time.
type PingListener interface {
	OnPing(profileID, nodeID string, latency int64, status string)
}

// PingNodes probes the given nodes of a profile (nodeIDsJSON is a JSON array
// of ids; empty means every node) and returns []profile.PingResult as JSON.
// It blocks, so call it off the main thread.
func PingNodes(profileID, nodeIDsJSON string, timeoutMs int) (string, error) {
	return PingNodesStream(profileID, nodeIDsJSON, timeoutMs, nil)
}

// PingNodesStream is PingNodes that also reports each result to listener the
// moment it is measured. The returned JSON still holds every result.
func PingNodesStream(profileID, nodeIDsJSON string, timeoutMs int, listener PingListener) (string, error) {
	// Install the protected direct dialer even before the first connection.
	// A concurrent connect/reconnect must never turn a TCP probe into a TUN handshake.
	if _, err := runnerService(); err != nil {
		return "", err
	}
	m, err := manager()
	if err != nil {
		return "", err
	}
	var ids []string
	if nodeIDsJSON != "" {
		if err := json.Unmarshal([]byte(nodeIDsJSON), &ids); err != nil {
			return "", err
		}
	}
	var observe func(profile.PingResult)
	if listener != nil {
		observe = func(r profile.PingResult) { listener.OnPing(profileID, r.NodeID, r.Latency, r.Status) }
	}
	// "Проверка серверов": TCP is a handshake; otherwise a real request through
	// each server. The running core holds only the active profile's servers as
	// outbounds, so other profiles are measured by an isolated core.
	useLiveCore := IsRunning() && m.GetActiveProfileID() == profileID
	results, err := m.PingProfileNodesObserved(profileID, ids, time.Duration(timeoutMs)*time.Millisecond, useLiveCore, observe)
	if err != nil {
		return "", err
	}
	return toJSON(results)
}

// SetHwid controls the X-Hwid header sent with subscription requests.
func SetHwid(enabled bool, value string) error {
	mu.Lock()
	s := settings
	mu.Unlock()
	if s == nil {
		return errNotInitialized
	}
	return s.UpdateHwid(domainSettings.HwidSettings{Enabled: enabled, Mode: "manual", Value: value})
}

// MediaPath resolves a "/beam-media/<name>" URL from a profile summary (the
// cached provider icon or banner) to the file on disk, or "" if it is gone.
// Desktop serves these URLs from its asset server; on a phone the app loads the
// file directly. Accepts the URL with or without its "?v=" suffix.
func MediaPath(url string) string {
	m, err := manager()
	if err != nil {
		return ""
	}
	name := strings.TrimPrefix(url, mediacache.Prefix)
	if i := strings.IndexByte(name, '?'); i >= 0 {
		name = name[:i]
	}
	path, ok := m.MediaFile(name)
	if !ok {
		return ""
	}
	return path
}
